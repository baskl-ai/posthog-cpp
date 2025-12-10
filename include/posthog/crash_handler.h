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
 *       // Send to analytics
 *       PostHog::CrashHandler::clearPendingReport();
 *   }
 */

#ifndef POSTHOG_CRASH_HANDLER_H
#define POSTHOG_CRASH_HANDLER_H

#include <string>
#include <optional>
#include <fstream>
#include <ctime>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#include <shlobj.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
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
    std::string execPath;        ///< Path to executable
};

namespace Internal {
    static char g_crashFilePath[512] = {0};
    static char g_crashBuffer[8192] = {0};
    static bool g_installed = false;
    static unsigned long g_loadAddress = 0;
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

        safeCopy(ptr, "\nEXEC_PATH: ", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, g_execPath, remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        safeCopy(ptr, "\nSTACKTRACE:\n", remaining);
        ptr += strlen(ptr);

        safeCopy(ptr, "  Exception at: 0x", remaining);
        ptr += strlen(ptr);
        remaining = sizeof(g_crashBuffer) - (ptr - g_crashBuffer);

        char addrStr[32];
        sprintf(addrStr, "%p\n", exceptionInfo->ExceptionRecord->ExceptionAddress);
        safeCopy(ptr, addrStr, remaining);

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
 * @return Platform-specific path
 */
inline std::string getDefaultCrashDir(const std::string& appName) {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path))) {
        return std::string(path) + "\\" + appName + "\\CrashReports";
    }
    return "C:\\ProgramData\\" + appName + "\\CrashReports";
#elif defined(__APPLE__)
    return "/Library/Application Support/" + appName + "/CrashReports";
#else
    return "/var/lib/" + appName + "/crash_reports";
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
    Internal::g_loadAddress = reinterpret_cast<unsigned long>(GetModuleHandle(NULL));
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

} // namespace CrashHandler
} // namespace PostHog

#endif // POSTHOG_CRASH_HANDLER_H
