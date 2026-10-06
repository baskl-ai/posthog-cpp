/**
 * @file stacktrace.h
 * @brief Cross-platform stacktrace capture (header-only)
 *
 * Supports:
 * - macOS/Linux: execinfo.h (backtrace, backtrace_symbols)
 * - Windows: StackWalk64 API with symbol resolution
 *
 * Usage:
 *   std::string trace = PostHog::Stacktrace::capture(10);
 */

#ifndef POSTHOG_STACKTRACE_H
#define POSTHOG_STACKTRACE_H

#include <cstdint>
#include <limits>
#include <string>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#elif defined(__APPLE__) || defined(__linux__)
#include <execinfo.h>
#include <cxxabi.h>
#include <dlfcn.h>
#endif

namespace PostHog {
namespace Stacktrace {

/**
 * @brief Structured stack frame for $exception format
 */
struct Frame {
    std::string function;    ///< Function name, or "<module>+0x<offset>" when no symbol is available
    std::string filename;    ///< Source file (optional)
    std::string module;      ///< Module name (optional)
    int lineno = 0;          ///< Line number (optional)
    int colno = 0;           ///< Column number (optional)
    bool inApp = true;       ///< Is this frame from app code
    bool resolved = false;   ///< True when function is a real symbol name, false for a raw offset
};

namespace detail {
inline std::string moduleName(const std::string& path) {
    const auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Keep address-derived identities stable for the same binary across ASLR slides.
// Without a module base there is no stable offset; never use the runtime address
// as a function name, since PostHog includes that field in its fingerprint.
inline Frame unresolvedFrame(uintptr_t address, uintptr_t base,
                             const std::string& path) {
    Frame frame;
    frame.module = moduleName(path);
    if (base && address >= base) {
        std::ostringstream name;
        name << "<module>+0x" << std::hex << (address - base);
        frame.function = name.str();
    } else {
        frame.function = "(unknown)";
    }
    return frame;
}
} // namespace detail

/**
 * @brief Capture current stack trace as formatted string
 * @param maxFrames Maximum number of stack frames to capture (default: 32)
 * @param skip Number of frames to skip from the top (default: 1)
 * @return Stack trace as formatted string
 */
inline std::string capture(int maxFrames = 32, int skip = 1) {
    std::ostringstream ss;

#if defined(_WIN32)
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    SymInitialize(process, NULL, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    CONTEXT context;
    RtlCaptureContext(&context);

    STACKFRAME64 frame = {};
#ifdef _M_X64
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#else
    frame.AddrPC.Offset = context.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
    DWORD machineType = IMAGE_FILE_MACHINE_I386;
#endif

    int frameIndex = 0;
    int capturedFrames = 0;

    while (StackWalk64(machineType, process, thread, &frame, &context,
                       NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        if (frameIndex++ < skip) continue;
        if (capturedFrames >= maxFrames) break;

        DWORD64 address = frame.AddrPC.Offset;
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(process, address, &displacement, symbol)) {
            ss << "#" << capturedFrames << "  " << symbol->Name;

            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD lineDisplacement = 0;

            if (SymGetLineFromAddr64(process, address, &lineDisplacement, &line)) {
                ss << " (" << line.FileName << ":" << line.LineNumber << ")";
            }
        } else {
            ss << "#" << capturedFrames << "  0x" << std::hex << address << std::dec;
        }

        ss << "\n";
        capturedFrames++;
    }

    SymCleanup(process);

#elif defined(__APPLE__) || defined(__linux__)
    std::vector<void*> buffer(maxFrames + skip);
    int frameCount = backtrace(buffer.data(), buffer.size());

    if (frameCount <= skip) {
        ss << "(no stack trace available)";
        return ss.str();
    }

    char** symbols = backtrace_symbols(buffer.data(), frameCount);
    if (!symbols) {
        ss << "(failed to resolve symbols)";
        return ss.str();
    }

    for (int i = skip; i < frameCount && (i - skip) < maxFrames; i++) {
        ss << "#" << (i - skip) << "  ";

        Dl_info info;
        if (dladdr(buffer[i], &info) && info.dli_sname) {
            int status = 0;
            char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);

            if (status == 0 && demangled) {
                ss << demangled;
                free(demangled);
            } else {
                ss << info.dli_sname;
            }

            if (info.dli_saddr) {
                long offset = (char*)buffer[i] - (char*)info.dli_saddr;
                ss << " + " << offset;
            }
        } else {
            ss << symbols[i];
        }

        ss << "\n";
    }

    free(symbols);

#else
    ss << "(stacktrace not supported on this platform)";
#endif

    return ss.str();
}

/**
 * @brief Capture stack trace as vector of strings
 * @param maxFrames Maximum number of stack frames to capture
 * @param skip Number of frames to skip from the top
 * @return Vector of stack frame strings
 */
inline std::vector<std::string> captureAsVector(int maxFrames = 32, int skip = 1) {
    std::vector<std::string> frames;
    std::string trace = capture(maxFrames, skip + 1);

    std::istringstream ss(trace);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) {
            frames.push_back(line);
        }
    }

    return frames;
}

/**
 * @brief Capture stack trace as structured frames
 * @param maxFrames Maximum number of stack frames to capture
 * @param skip Number of frames to skip from the top
 * @param appIdentifier String to identify app frames (e.g., app name)
 * @return Vector of Frame structs
 */
inline std::vector<Frame> captureStructured(int maxFrames = 32, int skip = 1,
                                             const std::string& appIdentifier = "") {
    std::vector<Frame> frames;
    if (maxFrames <= 0 || skip < 0 ||
        skip > (std::numeric_limits<int>::max)() - maxFrames) return frames;

#if defined(_WIN32)
    HANDLE process = GetCurrentProcess();

    SymInitialize(process, NULL, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

    // Uses the platform unwinder, including x64 unwind metadata; no frame
    // pointer assumption is needed.
    std::vector<void*> buffer(maxFrames);
    USHORT captured = CaptureStackBackTrace(skip, static_cast<DWORD>(maxFrames),
                                            buffer.data(), NULL);

    std::vector<char> fullPath(32768);
    for (USHORT i = 0; i < captured; i++) {
        DWORD64 address = reinterpret_cast<DWORD64>(buffer[i]);

        // Resolve the module base and name from the address. The module base
        // lets us turn an ASLR-slid absolute address into a stable
        // module-relative offset when no symbol is available.
        DWORD64 moduleBase = 0;
        std::string modulePath;
        HMODULE hModule = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(buffer[i]), &hModule) && hModule) {
            moduleBase = reinterpret_cast<DWORD64>(hModule);
            // A truncated module name is not a reliable grouping identity.
            const DWORD length = GetModuleFileNameA(hModule, fullPath.data(),
                                                     static_cast<DWORD>(fullPath.size()));
            if (length > 0 && length < fullPath.size()) {
                modulePath.assign(fullPath.data(), length);
            }
        }
        Frame sf = detail::unresolvedFrame(static_cast<uintptr_t>(address),
                                           static_cast<uintptr_t>(moduleBase), modulePath);

        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(process, address, &displacement, symbol)) {
            sf.function = symbol->Name;
            sf.resolved = true;

            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD lineDisplacement = 0;

            if (SymGetLineFromAddr64(process, address, &lineDisplacement, &line)) {
                sf.filename = line.FileName;
                sf.lineno = line.LineNumber;
            }
        }

        // Determine if this is app code
        if (!appIdentifier.empty()) {
            sf.inApp = (sf.module.find(appIdentifier) != std::string::npos ||
                        sf.filename.find(appIdentifier) != std::string::npos ||
                        sf.function.find(appIdentifier) != std::string::npos);
        }

        frames.push_back(sf);
    }

    SymCleanup(process);

#elif defined(__APPLE__) || defined(__linux__)
    std::vector<void*> buffer(maxFrames + skip);
    int frameCount = backtrace(buffer.data(), buffer.size());

    if (frameCount <= skip) {
        return frames;
    }

    for (int i = skip; i < frameCount && (i - skip) < maxFrames; i++) {
        Dl_info info = {};
        const bool foundModule = dladdr(buffer[i], &info) != 0;
        Frame sf = detail::unresolvedFrame(reinterpret_cast<uintptr_t>(buffer[i]),
            foundModule ? reinterpret_cast<uintptr_t>(info.dli_fbase) : 0,
            foundModule && info.dli_fname ? info.dli_fname : "");
        // dladdr returns a binary path, not a source file. Keep only its basename
        // so different installation directories do not change the fingerprint.
        sf.filename = sf.module;

        if (foundModule && info.dli_sname) {
            int status = 0;
            char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
            sf.function = status == 0 && demangled ? demangled : info.dli_sname;
            free(demangled);
            sf.resolved = true;
        }

        if (!appIdentifier.empty()) {
            sf.inApp = (sf.module.find(appIdentifier) != std::string::npos ||
                        sf.function.find(appIdentifier) != std::string::npos);
        }

        frames.push_back(sf);
    }
#endif

    return frames;
}

/**
 * @brief Capture raw addresses for signal-safe crash handler
 * @param buffer Output buffer for addresses
 * @param maxFrames Maximum frames to capture
 * @param skip Frames to skip
 * @return Number of frames captured
 *
 * This function is signal-safe (no heap allocation).
 */
inline int captureAddresses(void** buffer, int maxFrames, int skip = 0) {
#if defined(__APPLE__) || defined(__linux__)
    int total = backtrace(buffer, maxFrames + skip);
    if (total <= skip) return 0;

    // Shift addresses to skip frames
    for (int i = 0; i < total - skip; i++) {
        buffer[i] = buffer[i + skip];
    }
    return total - skip;
#elif defined(_WIN32)
    return CaptureStackBackTrace(skip, maxFrames, buffer, NULL);
#else
    return 0;
#endif
}

} // namespace Stacktrace
} // namespace PostHog

#endif // POSTHOG_STACKTRACE_H
