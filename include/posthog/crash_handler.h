/**
 * @file crash_handler.h
 * @brief Cross-platform crash handler for unhandled exceptions and signals
 *
 * Captures crash information and saves to file for later upload.
 * Signal handlers cannot use malloc/network, so we write to a pre-allocated buffer.
 *
 * Usage:
 *   PostHog::CrashHandler::install("/path/to/crash/dir");
 *   // ... app runs ...
 *   // On next startup:
 *   auto report = PostHog::CrashHandler::loadPendingReport();
 *   if (report.has_value()) {
 *       // Filter out crashes not from our module (e.g. host app crashes)
 *       if (PostHog::CrashHandler::hasAddressesFromOurModule(*report)) {
 *           // Send to analytics - this crash involves our code
 *       }
 *       PostHog::CrashHandler::clearPendingReport();
 *   }
 */

#ifndef POSTHOG_CRASH_HANDLER_H
#define POSTHOG_CRASH_HANDLER_H

#include <string>
#include <map>
#include <optional>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include <cstdint>
#include <deque>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#endif
#endif

namespace PostHog {
namespace CrashHandler {

/**
 * @brief Crash report data structure
 */
struct Report {
    std::string signalName;      ///< Signal/exception type (SIGSEGV, EXCEPTION, etc)
    std::string exceptionCode;   ///< Windows: Exception code (0xC0000005), Unix: signal code
    std::string faultAddress;    ///< Address that caused the crash (if available)
    std::string timestamp;       ///< When crash occurred (unix timestamp)
    std::string stacktrace;      ///< Raw stacktrace
    std::string message;         ///< Exception message (uncaught C++ exception via std::terminate)
    std::string platform;        ///< OS info
    std::string loadAddress;     ///< Load address for symbolication
    std::string moduleSize;      ///< Size of our module (for address range filtering)
    std::string execPath;        ///< Path to executable
};

/**
 * @brief Additional metadata to include with crash reports
 * @details Saved separately from crash file (can use malloc) and loaded when sending report
 */
struct Metadata {
    std::map<std::string, std::string> properties;  ///< Custom properties to include
};

/**
 * @brief Log file configuration for crash reports
 * @details Stores the path to a log file and max lines to include in crash reports
 */
struct LogFileConfig {
    std::string path;     ///< Full path to the log file
    int maxLines = 50;    ///< Maximum lines to read from end of file
};

namespace Internal {
    inline char g_crashFilePath[512] = {0};
    inline char g_crashBuffer[8192] = {0};
    inline bool g_installed = false;
    inline std::uintptr_t g_loadAddress = 0;
    inline std::size_t g_moduleSize = 0;  // Size of our module for address filtering
    inline char g_execPath[512] = {0};
    // Set by the std::terminate hook right before it calls std::abort(). It tells the
    // SIGABRT handler that a full TERMINATE record (with the exception message) is
    // already on disk, so the handler must not truncate and overwrite it.
    // Lock-free atomics can be read in a signal handler and across crashing threads.
    static_assert(std::atomic<bool>::is_always_lock_free,
                  "Crash reporting requires lock-free bool atomics");
    inline std::atomic<bool> g_terminateHandled{false};

    inline void safeCopy(char* dest, const char* src, size_t maxLen) {
        size_t i = 0;
        while (i < maxLen - 1 && src[i] != '\0') {
            dest[i] = src[i];
            i++;
        }
        dest[i] = '\0';
    }

    inline void safeItoa(std::int64_t value, char* buffer, size_t bufferSize) {
        if (bufferSize == 0) return;

        char temp[32];
        int i = 0;
        bool negative = value < 0;

        if (negative) value = -value;

        do {
            temp[i++] = '0' + (value % 10);
            value /= 10;
        } while (value > 0 && i < 30);

        if (negative && i < 30) temp[i++] = '-';

        size_t j = 0;
        while (i > 0 && j < bufferSize - 1) {
            buffer[j++] = temp[--i];
        }
        buffer[j] = '\0';
    }

    inline void safeUlongToHex(std::uintptr_t value, char* buffer, size_t bufferSize) {
        if (bufferSize < 3) return;

        buffer[0] = '0';
        buffer[1] = 'x';

        char hexChars[] = "0123456789abcdef";
        char temp[20];
        int i = 0;

        if (value == 0) {
            temp[i++] = '0';
        } else {
            while (value > 0 && i < 16) {
                temp[i++] = hexChars[value & 0xF];
                value >>= 4;
            }
        }

        size_t j = 2;
        while (i > 0 && j < bufferSize - 1) {
            buffer[j++] = temp[--i];
        }
        buffer[j] = '\0';
    }

    inline const char* getSignalName(int sig) {
#ifdef _WIN32
        return "EXCEPTION";
#else
        switch (sig) {
            case SIGSEGV: return "SIGSEGV";
            case SIGABRT: return "SIGABRT";
            case SIGBUS:  return "SIGBUS";
            case SIGFPE:  return "SIGFPE";
            case SIGILL:  return "SIGILL";
            default:      return "UNKNOWN";
        }
#endif
    }

#ifndef _WIN32
    inline void signalHandlerWithInfo(int sig, siginfo_t* info, void* ucontext) {
        (void)ucontext;  // Unused for now

        // An uncaught C++ exception routes through std::terminate, which already wrote
        // a full TERMINATE record (with the exception message) before calling
        // std::abort(). Do not overwrite that record with a message-less SIGABRT one.
        if (sig == SIGABRT && g_terminateHandled.load(std::memory_order_relaxed)) {
            signal(sig, SIG_DFL);
            raise(sig);
            return;
        }

        char* ptr = g_crashBuffer;
        size_t remaining = sizeof(g_crashBuffer);

        const char* sigName = getSignalName(sig);
        safeCopy(ptr, "SIGNAL: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, sigName, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        // Save signal code (e.g., SEGV_MAPERR, SEGV_ACCERR)
        safeCopy(ptr, "\nCODE: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        char codeStr[16];
        safeItoa(info ? info->si_code : 0, codeStr, sizeof(codeStr));
        safeCopy(ptr, codeStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        // Save fault address if available
        if (info && info->si_addr) {
            safeCopy(ptr, "\nFAULT_ADDR: ", remaining);
            ptr += strlen(ptr);
            remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

            char addrStr[32];
            safeUlongToHex(reinterpret_cast<std::uintptr_t>(info->si_addr), addrStr, sizeof(addrStr));
            safeCopy(ptr, addrStr, remaining);
            ptr += strlen(ptr);
            remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);
        }

        safeCopy(ptr, "\nTIME: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        time_t now = time(nullptr);
        char timeStr[32];
        safeItoa(static_cast<long>(now), timeStr, sizeof(timeStr));
        safeCopy(ptr, timeStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "\nLOAD_ADDR: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        char loadAddrStr[32];
        safeUlongToHex(g_loadAddress, loadAddrStr, sizeof(loadAddrStr));
        safeCopy(ptr, loadAddrStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "\nMODULE_SIZE: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        char moduleSizeStr[32];
        safeUlongToHex(g_moduleSize, moduleSizeStr, sizeof(moduleSizeStr));
        safeCopy(ptr, moduleSizeStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "\nEXEC_PATH: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, g_execPath, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "\nSTACKTRACE:\n", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        void* frames[32];
        int frameCount = backtrace(frames, 32);

        for (int i = 0; i < frameCount && remaining > 64; i++) {
            std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(frames[i]);
            char hexChars[] = "0123456789abcdef";
            int j = 0;
            char temp[20];
            do {
                temp[j++] = hexChars[addr & 0xF];
                addr >>= 4;
            } while (addr > 0);

            safeCopy(ptr, "  0x", remaining);
            ptr += strlen(ptr);
            remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

            while (j > 0 && remaining > 1) {
                *ptr++ = temp[--j];
                remaining--;
            }
            *ptr++ = '\n';
            remaining--;
        }
        *ptr = '\0';

        int fd = open(g_crashFilePath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            ssize_t result = write(fd, g_crashBuffer, strlen(g_crashBuffer));
            (void)result;  // Suppress unused result warning
            close(fd);
        }

        signal(sig, SIG_DFL);
        raise(sig);
    }
#endif

#ifdef _WIN32
    inline LPTOP_LEVEL_EXCEPTION_FILTER g_previousExceptionFilter = nullptr;

    // One writer for the lifetime of this installation. Never wait on a faulting
    // thread or reset on exit: a later exception must not replace the first one.
    inline volatile LONG g_exceptionFilterEntered = 0;

    struct WindowsCrashWriter {
        size_t size = 0;

        void append(const char* text) {
            while (*text && size + 1 < sizeof(g_crashBuffer)) {
                g_crashBuffer[size++] = *text++;
            }
            g_crashBuffer[size] = '\0';
        }

        void hex(std::uintptr_t value) {
            char text[2 + sizeof(value) * 2 + 1];
            safeUlongToHex(value, text, sizeof(text));
            append(text);
        }
    };

    inline bool writeWindowsCrashFile(const char* data, size_t size, bool append) {
        HANDLE file = CreateFileA(g_crashFilePath,
            append ? FILE_APPEND_DATA : GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            append ? OPEN_EXISTING : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        bool success = true;
        while (size > 0) {
            DWORD written = 0;
            if (!WriteFile(file, data, static_cast<DWORD>(size), &written, nullptr)
                || written == 0) {
                success = false;
                break;
            }
            data += written;
            size -= written;
        }
        CloseHandle(file);
        return success;
    }

    // The capture function is supplied separately so interrupted/re-entrant
    // capture can be exercised without provoking undefined behavior in tests.
    inline LONG writeWindowsException(EXCEPTION_POINTERS* exceptionInfo,
        USHORT (WINAPI *captureStack)(ULONG, ULONG, PVOID*, PULONG)) {
        if (InterlockedExchange(&g_exceptionFilterEntered, 1) != 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        WindowsCrashWriter report;
        report.append("SIGNAL: EXCEPTION\nCODE: ");
        report.hex(exceptionInfo->ExceptionRecord->ExceptionCode);
        report.append("\nFAULT_ADDR: ");
        const auto fault = reinterpret_cast<std::uintptr_t>(
            exceptionInfo->ExceptionRecord->ExceptionAddress);
        report.hex(fault);
        report.append("\nTIME: ");
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER ticks;
        ticks.LowPart = now.dwLowDateTime;
        ticks.HighPart = now.dwHighDateTime;
        char timestamp[32];
        safeItoa(static_cast<std::int64_t>(ticks.QuadPart / 10000000ULL)
            - 11644473600LL, timestamp, sizeof(timestamp));
        report.append(timestamp);
        report.append("\nLOAD_ADDR: ");
        report.hex(g_loadAddress);
        report.append("\nMODULE_SIZE: ");
        report.hex(g_moduleSize);
        report.append("\nEXEC_PATH: ");
        report.append(g_execPath);
        report.append("\nSTACKTRACE:\n  ");
        report.hex(fault);
        report.append("\n");

        // Preserve the exception record before best-effort stack capture. A
        // nested fault may terminate the process rather than resume this filter.
        const size_t saved = report.size;
        if (!writeWindowsCrashFile(g_crashBuffer, saved, false)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // These are handler-thread return addresses, not a context unwind from
        // the fault. Keep the original instruction address above as frame zero.
        // No heap allocation, CRT formatting, or DbgHelp symbol lookup here.
        void* stack[64];
        const WORD frames = captureStack(0, 64, stack, nullptr);
        for (WORD i = 0; i < frames; ++i) {
            report.append("  ");
            report.hex(reinterpret_cast<std::uintptr_t>(stack[i]));
            report.append("\n");
        }
        // Append only: losing the optional frames must not erase the fallback.
        writeWindowsCrashFile(g_crashBuffer + saved, report.size - saved, true);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    inline LONG WINAPI exceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
        // The std::terminate hook already wrote a full TERMINATE record with the
        // exception message. Keep it instead of overwriting with the abort exception.
        if (g_terminateHandled.load(std::memory_order_relaxed)) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The MSVC runtime's filter routes uncaught C++ exceptions through
        // std::terminate with current_exception() populated. Replacing that
        // filter without chaining it bypasses our message capture entirely.
        // Other native faults, or a missing previous filter, use our raw report.
        constexpr DWORD msvcExceptionCode = 0xe06d7363;
        if (exceptionInfo->ExceptionRecord->ExceptionCode == msvcExceptionCode &&
            g_previousExceptionFilter) {
            return g_previousExceptionFilter(exceptionInfo);
        }

        return writeWindowsException(exceptionInfo, CaptureStackBackTrace);
    }
#endif

} // namespace Internal

/**
 * @brief Get default crash reports directory for platform
 * @param appName Application name for directory path
 * @return Platform-specific path (user-writable directory)
 *
 * Default paths:
 * - Windows: %APPDATA%/{appName}/CrashReports
 * - macOS: ~/Library/Application Support/{appName}/CrashReports
 * - Linux: ~/.local/share/{appName}/crash_reports
 */
inline std::string getDefaultCrashDir(const std::string& appName) {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path) + "\\" + appName + "\\CrashReports";
    }
    // Fallback to APPDATA env var
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        return std::string(appdata) + "\\" + appName + "\\CrashReports";
    }
    return "C:\\Users\\Public\\" + appName + "\\CrashReports";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/Library/Application Support/" + appName + "/CrashReports";
    }
    return "/tmp/" + appName + "/CrashReports";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.local/share/" + appName + "/crash_reports";
    }
    // Fallback to XDG_DATA_HOME
    const char* xdgData = std::getenv("XDG_DATA_HOME");
    if (xdgData) {
        return std::string(xdgData) + "/" + appName + "/crash_reports";
    }
    return "/tmp/" + appName + "/crash_reports";
#endif
}

/**
 * @brief Install crash handlers
 * @param crashDir Directory to store crash reports
 * @return true if handlers installed successfully
 */
inline bool install(const std::string& crashDir) {
    if (Internal::g_installed) {
        return true;
    }

#ifdef _WIN32
    CreateDirectoryA(crashDir.c_str(), NULL);
    std::string crashFile = crashDir + "\\pending_crash.txt";

    char exePath[512];
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    Internal::safeCopy(Internal::g_execPath, exePath, sizeof(Internal::g_execPath));

    // Get module base address and size
    HMODULE hModule = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&install), &hModule);
    if (hModule) {
        Internal::g_loadAddress = reinterpret_cast<std::uintptr_t>(hModule);
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            Internal::g_moduleSize = modInfo.SizeOfImage;
        }
    } else {
        Internal::g_loadAddress = reinterpret_cast<std::uintptr_t>(GetModuleHandle(NULL));
    }
#else
    mkdir(crashDir.c_str(), 0755);
    std::string crashFile = crashDir + "/pending_crash.txt";

#ifdef __APPLE__
    uint32_t pathSize = sizeof(Internal::g_execPath);
    if (_NSGetExecutablePath(Internal::g_execPath, &pathSize) != 0) {
        Internal::g_execPath[0] = '\0';
    }
#else
    ssize_t len = readlink("/proc/self/exe", Internal::g_execPath, sizeof(Internal::g_execPath) - 1);
    if (len > 0) {
        Internal::g_execPath[len] = '\0';
    }
#endif

    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(&install), &info)) {
        Internal::g_loadAddress = reinterpret_cast<std::uintptr_t>(info.dli_fbase);

        // Get module size by finding the loaded image
#ifdef __APPLE__
        uint32_t imageCount = _dyld_image_count();
        for (uint32_t i = 0; i < imageCount; i++) {
            const struct mach_header* header = _dyld_get_image_header(i);
            if (reinterpret_cast<const void*>(header) == info.dli_fbase) {
                // Calculate size from mach-o header
                if (header->magic == MH_MAGIC_64) {
                    const struct mach_header_64* header64 = reinterpret_cast<const struct mach_header_64*>(header);
                    const struct load_command* cmd = reinterpret_cast<const struct load_command*>(header64 + 1);
                    for (uint32_t j = 0; j < header64->ncmds; j++) {
                        if (cmd->cmd == LC_SEGMENT_64) {
                            const struct segment_command_64* seg = reinterpret_cast<const struct segment_command_64*>(cmd);
                            unsigned long segEnd = seg->vmaddr + seg->vmsize;
                            if (segEnd > Internal::g_moduleSize) {
                                Internal::g_moduleSize = segEnd;
                            }
                        }
                        cmd = reinterpret_cast<const struct load_command*>(reinterpret_cast<const char*>(cmd) + cmd->cmdsize);
                    }
                }
                break;
            }
        }
#endif
    }
#endif

    Internal::safeCopy(Internal::g_crashFilePath, crashFile.c_str(), sizeof(Internal::g_crashFilePath));

#ifdef _WIN32
    auto previousFilter = SetUnhandledExceptionFilter(Internal::exceptionFilter);
    if (previousFilter != Internal::exceptionFilter) {
        Internal::g_previousExceptionFilter = previousFilter;
    }
#else
    struct sigaction sa;
    sa.sa_sigaction = Internal::signalHandlerWithInfo;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_SIGINFO;  // SA_SIGINFO to get siginfo_t

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
#endif

    std::set_terminate([]() {
        char msg[1024] = "std::terminate called";
        try {
            if (auto eptr = std::current_exception()) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& e) {
            // Copy while the exception is alive; avoid allocating another string
            // when termination itself may have been caused by allocation failure.
            const char* what = e.what();
            Internal::safeCopy(msg, what, sizeof(msg));
            size_t length = std::strlen(msg);
            if (length == sizeof(msg) - 1 && what[length] != '\0') {
                // Do not split a UTF-8 character at the message limit: a broken
                // suffix would make next-launch JSON serialization fail.
                while (length > 0 && (static_cast<unsigned char>(what[length]) & 0xc0) == 0x80) {
                    --length;
                }
                msg[length] = '\0';
            }
        } catch (...) {
            Internal::safeCopy(msg, "Unknown exception", sizeof(msg));
        }

        // Collapse the message to a single line so it stays one MESSAGE record.
        for (char& c : msg) {
            if (c == '\n' || c == '\r') c = ' ';
        }

        try {
            std::ofstream f(Internal::g_crashFilePath, std::ios::trunc);
            if (f.is_open()) {
                f << "SIGNAL: TERMINATE\n";
                f << "TIME: " << time(nullptr) << "\n";
                f << "LOAD_ADDR: 0x" << std::hex << Internal::g_loadAddress << "\n";
                f << "MODULE_SIZE: 0x" << std::hex << Internal::g_moduleSize << std::dec << "\n";
                f << "EXEC_PATH: " << Internal::g_execPath << "\n";
                f << "MESSAGE: " << msg << "\n";
                // Best-effort capture before abort(), on both supported platform paths.
                // Termination may follow resource exhaustion; this is not guaranteed
                // to succeed just because we are outside a signal handler.
                void* frames[32];
#ifdef _WIN32
                int frameCount = CaptureStackBackTrace(0, 32, frames, nullptr);
#else
                int frameCount = backtrace(frames, 32);
#endif
                f << "STACKTRACE:\n";
                for (int i = 0; i < frameCount; i++) {
                    f << "  0x" << std::hex << reinterpret_cast<std::uintptr_t>(frames[i]) << std::dec << "\n";
                }
                f.close();
                // close() flushes buffered output and reports write/close failures.
                // Preserve only a complete record; otherwise leave abort's fallback.
                if (f.good()) {
                    Internal::g_terminateHandled.store(true, std::memory_order_relaxed);
                }
            }
        } catch (...) {
            // Stream setup can allocate. Still reach abort's fallback if it fails.
        }
        std::abort();
    });

    Internal::g_installed = true;
    return true;
}

/**
 * @brief Check if stacktrace contains addresses within our module's address range
 * @param report The crash report to check
 * @return true if at least one address in stacktrace is from our module
 * @details Excludes the crash handler's own frame (signalHandler/exceptionFilter)
 */
inline bool hasAddressesFromOurModule(const Report& report) {
    if (report.loadAddress.empty() || report.moduleSize.empty()) {
        // No address info - can't filter, assume it's ours
        return true;
    }

    unsigned long long loadAddr = 0;
    unsigned long long modSize = 0;

    try {
        loadAddr = std::stoull(report.loadAddress, nullptr, 16);
        modSize = std::stoull(report.moduleSize, nullptr, 16);
    } catch (...) {
        // Parse error - can't filter, assume it's ours
        return true;
    }

    if (modSize == 0) {
        // No size info - can't filter, assume it's ours
        return true;
    }

    unsigned long long moduleEnd = loadAddr + modSize;

    // Windows FAULT_ADDR is the instruction pointer (Unix uses the accessed
    // address). A fallback report can contain only this one frame.
    if (report.signalName == "EXCEPTION" && !report.faultAddress.empty()) {
        try {
            const auto fault = std::stoull(report.faultAddress, nullptr, 16);
            if (fault >= loadAddr && fault - loadAddr < modSize) return true;
        } catch (...) {
            // Fall through to the existing stack-based check.
        }
    }


    // Parse stacktrace for addresses
    std::istringstream iss(report.stacktrace);
    std::string line;
    int framesFromOurModule = 0;

    while (std::getline(iss, line)) {
        // Find hex addresses in the line (format: "  0x..." or "0x...")
        size_t pos = line.find("0x");
        while (pos != std::string::npos) {
            size_t endPos = pos + 2;
            while (endPos < line.size() && std::isxdigit(line[endPos])) {
                endPos++;
            }

            if (endPos > pos + 2) {
                std::string addrStr = line.substr(pos, endPos - pos);
                try {
                    unsigned long long addr = std::stoull(addrStr, nullptr, 16);
                    if (addr >= loadAddr && addr < moduleEnd) {
                        framesFromOurModule++;
                        // Need at least 2 frames from our module
                        // (1 is always the crash handler itself)
                        if (framesFromOurModule >= 2) {
                            return true;
                        }
                    }
                } catch (...) {
                    // Ignore parse errors
                }
            }

            pos = line.find("0x", endPos);
        }
    }

    return false;
}

/**
 * @brief Check if there's a pending crash report from previous run
 * @return Crash report if exists
 */
inline std::optional<Report> loadPendingReport() {
    std::ifstream f(Internal::g_crashFilePath);
    if (!f.is_open()) {
        return std::nullopt;
    }

    Report report;
    std::string line;
    bool inStacktrace = false;

    while (std::getline(f, line)) {
        if (line.rfind("SIGNAL: ", 0) == 0) {
            report.signalName = line.substr(8);
            inStacktrace = false;
        } else if (line.rfind("CODE: ", 0) == 0) {
            report.exceptionCode = line.substr(6);
            inStacktrace = false;
        } else if (line.rfind("FAULT_ADDR: ", 0) == 0) {
            report.faultAddress = line.substr(12);
            inStacktrace = false;
        } else if (line.rfind("TIME: ", 0) == 0) {
            report.timestamp = line.substr(6);
            inStacktrace = false;
        } else if (line.rfind("LOAD_ADDR: ", 0) == 0) {
            report.loadAddress = line.substr(11);
            inStacktrace = false;
        } else if (line.rfind("MODULE_SIZE: ", 0) == 0) {
            report.moduleSize = line.substr(13);
            inStacktrace = false;
        } else if (line.rfind("EXEC_PATH: ", 0) == 0) {
            report.execPath = line.substr(11);
            inStacktrace = false;
        } else if (line.rfind("MESSAGE: ", 0) == 0) {
            report.message = line.substr(9);
            inStacktrace = false;
        } else if (line == "STACKTRACE:") {
            inStacktrace = true;
        } else if (inStacktrace) {
            report.stacktrace += line + "\n";
        }
    }

#ifdef _WIN32
    report.platform = "Windows";
#elif defined(__APPLE__)
    report.platform = "macOS";
#else
    report.platform = "Linux";
#endif

    return report;
}

/**
 * @brief Clear pending crash report after it's been sent
 */
inline void clearPendingReport() {
#ifdef _WIN32
    DeleteFileA(Internal::g_crashFilePath);
#else
    unlink(Internal::g_crashFilePath);
#endif
}

/**
 * @brief Get the crash file path
 */
inline std::string getCrashFilePath() {
    return Internal::g_crashFilePath;
}

/**
 * @brief Check if crash handler is installed
 */
inline bool isInstalled() {
    return Internal::g_installed;
}

/**
 * @brief Get metadata file path (based on crash file path)
 */
inline std::string getMetadataFilePath() {
    std::string crashPath = Internal::g_crashFilePath;
    if (crashPath.empty()) return "";

    // Replace pending_crash.txt with crash_metadata.txt
    size_t pos = crashPath.rfind("pending_crash.txt");
    if (pos != std::string::npos) {
        return crashPath.substr(0, pos) + "crash_metadata.txt";
    }
    return crashPath + ".metadata";
}

/**
 * @brief Save metadata to file for use in crash reports
 * @details Call this after initializing analytics with all relevant properties.
 *          The metadata will be included when sending crash reports from previous sessions.
 * @param metadata Metadata to save
 * @return true if saved successfully
 */
inline bool saveMetadata(const Metadata& metadata) {
    std::string metadataPath = getMetadataFilePath();
    if (metadataPath.empty()) return false;

    std::ofstream f(metadataPath);
    if (!f.is_open()) return false;

    // Simple key=value format (one per line)
    for (const auto& [key, value] : metadata.properties) {
        // Escape newlines in values
        std::string escapedValue = value;
        size_t pos = 0;
        while ((pos = escapedValue.find('\n', pos)) != std::string::npos) {
            escapedValue.replace(pos, 1, "\\n");
            pos += 2;
        }
        f << key << "=" << escapedValue << "\n";
    }

    return true;
}

/**
 * @brief Load metadata from file
 * @return Metadata if file exists, empty metadata otherwise
 */
inline Metadata loadMetadata() {
    Metadata metadata;
    std::string metadataPath = getMetadataFilePath();
    if (metadataPath.empty()) return metadata;

    std::ifstream f(metadataPath);
    if (!f.is_open()) return metadata;

    std::string line;
    while (std::getline(f, line)) {
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = line.substr(0, eqPos);
            std::string value = line.substr(eqPos + 1);

            // Unescape newlines
            size_t pos = 0;
            while ((pos = value.find("\\n", pos)) != std::string::npos) {
                value.replace(pos, 2, "\n");
                pos += 1;
            }

            metadata.properties[key] = value;
        }
    }

    return metadata;
}

/**
 * @brief Clear metadata file after crash report is sent
 */
inline void clearMetadata() {
    std::string metadataPath = getMetadataFilePath();
    if (metadataPath.empty()) return;

#ifdef _WIN32
    DeleteFileA(metadataPath.c_str());
#else
    unlink(metadataPath.c_str());
#endif
}

/**
 * @brief Get log file config path (based on crash file path)
 */
inline std::string getLogFileConfigPath() {
    std::string crashPath = Internal::g_crashFilePath;
    if (crashPath.empty()) return "";

    // Replace pending_crash.txt with crash_logfile.txt
    size_t pos = crashPath.rfind("pending_crash.txt");
    if (pos != std::string::npos) {
        return crashPath.substr(0, pos) + "crash_logfile.txt";
    }
    return crashPath + ".logfile";
}

/**
 * @brief Save log file configuration for use in crash reports
 * @param config Log file configuration (path and max lines)
 * @return true if saved successfully
 */
inline bool saveLogFileConfig(const LogFileConfig& config) {
    std::string configPath = getLogFileConfigPath();
    if (configPath.empty()) return false;

    std::ofstream f(configPath);
    if (!f.is_open()) return false;

    f << "path=" << config.path << "\n";
    f << "maxLines=" << config.maxLines << "\n";

    return true;
}

/**
 * @brief Load log file configuration
 * @return LogFileConfig if file exists, empty config otherwise
 */
inline LogFileConfig loadLogFileConfig() {
    LogFileConfig config;
    std::string configPath = getLogFileConfigPath();
    if (configPath.empty()) return config;

    std::ifstream f(configPath);
    if (!f.is_open()) return config;

    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("path=", 0) == 0) {
            config.path = line.substr(5);
        } else if (line.rfind("maxLines=", 0) == 0) {
            try {
                config.maxLines = std::stoi(line.substr(9));
            } catch (...) {
                config.maxLines = 50;
            }
        }
    }

    return config;
}

/**
 * @brief Clear log file config after crash report is sent
 */
inline void clearLogFileConfig() {
    std::string configPath = getLogFileConfigPath();
    if (configPath.empty()) return;

#ifdef _WIN32
    DeleteFileA(configPath.c_str());
#else
    unlink(configPath.c_str());
#endif
}

/**
 * @brief Read last N lines from a file
 * @param filePath Path to the file to read
 * @param maxLines Maximum number of lines to read from end
 * @return String containing the last N lines (newline separated)
 */
inline std::string readLastLines(const std::string& filePath, int maxLines) {
    std::ifstream file(filePath);
    if (!file.is_open()) return "";

    // Read all lines into a deque (efficient for removing from front)
    std::deque<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
        if (static_cast<int>(lines.size()) > maxLines) {
            lines.pop_front();
        }
    }

    // Join lines
    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) result += "\n";
        result += lines[i];
    }

    return result;
}

} // namespace CrashHandler
} // namespace PostHog

#endif // POSTHOG_CRASH_HANDLER_H
