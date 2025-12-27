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

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <psapi.h>
#pragma comment(lib, "dbghelp.lib")
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
    std::string signalName;      ///< Signal/exception type
    std::string timestamp;       ///< When crash occurred (unix timestamp)
    std::string stacktrace;      ///< Raw stacktrace
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

namespace Internal {
    static char g_crashFilePath[512] = {0};
    static char g_crashBuffer[8192] = {0};
    static bool g_installed = false;
    static unsigned long g_loadAddress = 0;
    static unsigned long g_moduleSize = 0;  // Size of our module for address filtering
    static char g_execPath[512] = {0};

    inline void safeCopy(char* dest, const char* src, size_t maxLen) {
        size_t i = 0;
        while (i < maxLen - 1 && src[i] != '\0') {
            dest[i] = src[i];
            i++;
        }
        dest[i] = '\0';
    }

    inline void safeItoa(long value, char* buffer, size_t bufferSize) {
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

    inline void safeUlongToHex(unsigned long value, char* buffer, size_t bufferSize) {
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
    inline void signalHandler(int sig) {
        char* ptr = g_crashBuffer;
        size_t remaining = sizeof(g_crashBuffer);

        const char* sigName = getSignalName(sig);
        safeCopy(ptr, "SIGNAL: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, sigName, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

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
            unsigned long addr = reinterpret_cast<unsigned long>(frames[i]);
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
    inline LONG WINAPI exceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
        char* ptr = g_crashBuffer;
        size_t remaining = sizeof(g_crashBuffer);

        safeCopy(ptr, "SIGNAL: EXCEPTION\n", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "CODE: 0x", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        DWORD code = exceptionInfo->ExceptionRecord->ExceptionCode;
        char codeStr[16];
        sprintf(codeStr, "%08lX", code);
        safeCopy(ptr, codeStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

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

        // Exception address
        safeCopy(ptr, "  Exception at: 0x", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        char addrStr[32];
        sprintf(addrStr, "%p\n", exceptionInfo->ExceptionRecord->ExceptionAddress);
        safeCopy(ptr, addrStr, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        // Capture stack trace using CaptureStackBackTrace
        void* stack[64];
        WORD frames = CaptureStackBackTrace(0, 64, stack, NULL);

        // Try to symbolize with DbgHelp (best effort)
        HANDLE process = GetCurrentProcess();
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + 256);
        if (symbol) {
            symbol->MaxNameLen = 255;
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        }

        IMAGEHLP_LINE64 line;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

        for (WORD i = 0; i < frames && remaining > 80; i++) {
            safeCopy(ptr, "  ", remaining);
            ptr += strlen(ptr);
            remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

            // Try to get symbol name
            if (symbol && SymFromAddr(process, (DWORD64)stack[i], 0, symbol)) {
                // Got symbol name
                safeCopy(ptr, symbol->Name, remaining);
                ptr += strlen(ptr);
                remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                // Try to get file and line
                DWORD displacement = 0;
                if (SymGetLineFromAddr64(process, (DWORD64)stack[i], &displacement, &line)) {
                    safeCopy(ptr, " (", remaining);
                    ptr += strlen(ptr);
                    remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                    // Extract filename from full path
                    const char* filename = line.FileName;
                    const char* lastSlash = strrchr(filename, '\\');
                    if (lastSlash) filename = lastSlash + 1;

                    safeCopy(ptr, filename, remaining);
                    ptr += strlen(ptr);
                    remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                    safeCopy(ptr, ":", remaining);
                    ptr += strlen(ptr);
                    remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                    char lineStr[16];
                    safeItoa(line.LineNumber, lineStr, sizeof(lineStr));
                    safeCopy(ptr, lineStr, remaining);
                    ptr += strlen(ptr);
                    remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                    safeCopy(ptr, ")", remaining);
                    ptr += strlen(ptr);
                    remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);
                }

                safeCopy(ptr, " [0x", remaining);
                ptr += strlen(ptr);
                remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

                sprintf(addrStr, "%p]\n", stack[i]);
                safeCopy(ptr, addrStr, remaining);
            } else {
                // Symbol not found, just print address
                sprintf(addrStr, "0x%p\n", stack[i]);
                safeCopy(ptr, addrStr, remaining);
            }

            ptr += strlen(ptr);
            remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);
        }

        if (symbol) {
            free(symbol);
        }

        HANDLE hFile = CreateFileA(g_crashFilePath, GENERIC_WRITE, 0, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, g_crashBuffer, (DWORD)strlen(g_crashBuffer), &written, NULL);
            CloseHandle(hFile);
        }

        return EXCEPTION_CONTINUE_SEARCH;
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
        Internal::g_loadAddress = reinterpret_cast<unsigned long>(hModule);
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            Internal::g_moduleSize = modInfo.SizeOfImage;
        }
    } else {
        Internal::g_loadAddress = reinterpret_cast<unsigned long>(GetModuleHandle(NULL));
    }

    // Initialize symbol handler for better stack traces (best effort, ignore errors)
    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    SymInitialize(process, NULL, TRUE);
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
        Internal::g_loadAddress = reinterpret_cast<unsigned long>(info.dli_fbase);

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
    SetUnhandledExceptionFilter(Internal::exceptionFilter);
#else
    struct sigaction sa;
    sa.sa_handler = Internal::signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
#endif

    std::set_terminate([]() {
        const char* msg = "std::terminate called";
        try {
            if (auto eptr = std::current_exception()) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& e) {
            msg = e.what();
        } catch (...) {
            msg = "Unknown exception";
        }

        std::ofstream f(Internal::g_crashFilePath);
        if (f.is_open()) {
            f << "SIGNAL: TERMINATE\n";
            f << "TIME: " << time(nullptr) << "\n";
            f << "LOAD_ADDR: 0x" << std::hex << Internal::g_loadAddress << "\n";
            f << "MODULE_SIZE: 0x" << std::hex << Internal::g_moduleSize << "\n";
            f << "EXEC_PATH: " << Internal::g_execPath << "\n";
            f << "MESSAGE: " << msg << "\n";
            f.close();
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
            report.stacktrace = line.substr(9);
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

} // namespace CrashHandler
} // namespace PostHog

#endif // POSTHOG_CRASH_HANDLER_H
