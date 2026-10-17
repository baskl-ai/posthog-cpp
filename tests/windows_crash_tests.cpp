// Use the real Windows APIs except for controlled interruption/re-entry at the
// stack-capture boundary. Assertions stay active in Release builds.
#include <windows.h>
#include <string>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <iterator>
#include <cstdlib>

#include <posthog/crash_handler.h>

namespace Crash = PostHog::CrashHandler;
namespace Internal = PostHog::CrashHandler::Internal;

LONG callFilterFromOtherTranslationUnit();
std::uintptr_t moduleAddressFromOtherTranslationUnit();

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "FAILED: " #condition << " at line " << __LINE__ << std::endl; \
    std::exit(1); \
} } while (0)

static bool interruptCapture = false;
static const std::uintptr_t moduleBase = sizeof(void*) == 8
    ? static_cast<std::uintptr_t>(0x123456780000ULL) : 0x12340000;
static const std::uintptr_t faultAddress = moduleBase + 0x1234;

static std::string readReport() {
    std::ifstream file(Crash::getCrashFilePath(), std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

static USHORT WINAPI captureForTest(ULONG, ULONG, PVOID* frames, PULONG) {
    const std::string buffer = Internal::g_crashBuffer;
    const std::string disk = readReport();
    CHECK(disk == buffer);
    CHECK(disk.find("STACKTRACE:\n  0x") != std::string::npos);
    if (interruptCapture) ExitProcess(42);

    // The owner is paused at stack capture. Nested entry, entry from a second
    // translation unit, and competing threads must bail before touching data.
    CHECK(Internal::exceptionFilter(nullptr) == EXCEPTION_CONTINUE_SEARCH);
    CHECK(callFilterFromOtherTranslationUnit() == EXCEPTION_CONTINUE_SEARCH);
    std::vector<std::thread> contenders;
    for (int i = 0; i < 8; ++i) {
        contenders.emplace_back([] {
            CHECK(Internal::exceptionFilter(nullptr) == EXCEPTION_CONTINUE_SEARCH);
        });
    }
    for (auto& contender : contenders) contender.join();
    CHECK(buffer == Internal::g_crashBuffer);
    CHECK(disk == readReport());
    frames[0] = reinterpret_cast<void*>(moduleBase + 0x5678);
    return 1;
}

static void prepare(const std::string& directory) {
    CHECK(Crash::install(directory));
    // Check real installation before using predictable ASLR-independent values.
    CHECK(Internal::g_loadAddress != 0);
    CHECK(moduleAddressFromOtherTranslationUnit() == Internal::g_loadAddress);
    const auto address = reinterpret_cast<std::uintptr_t>(&Crash::install);
    CHECK(address >= Internal::g_loadAddress);
    CHECK(address - Internal::g_loadAddress < Internal::g_moduleSize);
    Internal::g_loadAddress = moduleBase;
    Internal::g_moduleSize = 0x10000;
}

static void invokeFilter() {
    EXCEPTION_RECORD record{};
    record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    record.ExceptionAddress = reinterpret_cast<void*>(faultAddress);
    CONTEXT context{};
    EXCEPTION_POINTERS pointers{&record, &context};
    CHECK(Internal::writeWindowsException(&pointers, captureForTest) == EXCEPTION_CONTINUE_SEARCH);
}

static DWORD runChild(const char* mode, const std::string& directory) {
    char executable[MAX_PATH];
    CHECK(GetModuleFileNameA(nullptr, executable, MAX_PATH) > 0);
    std::string command = "\"" + std::string(executable) + "\" " + mode + " \"" + directory + "\"";
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    CHECK(CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &startup, &process));
    const DWORD wait = WaitForSingleObject(process.hProcess, 15000);
    if (wait != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
    CHECK(wait == WAIT_OBJECT_0);
    DWORD code;
    CHECK(GetExitCodeProcess(process.hProcess, &code));
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

static void checkSyntheticReport(bool complete) {
    const auto report = Crash::loadPendingReport();
    CHECK(report.has_value());
    CHECK(report->signalName == "EXCEPTION");
    CHECK(report->exceptionCode == "0xc0000005");
    CHECK(std::stoull(report->faultAddress, nullptr, 16) == faultAddress);
    CHECK(std::stoull(report->loadAddress, nullptr, 16) == moduleBase);
    CHECK(std::stoull(report->moduleSize, nullptr, 16) == 0x10000);
    CHECK(std::stoll(report->timestamp) > 1700000000);
    CHECK(Crash::hasAddressesFromOurModule(*report));
    const std::string fault = sizeof(void*) == 8 ? "0x123456781234" : "0x12341234";
    const std::string frame = sizeof(void*) == 8 ? "0x123456785678" : "0x12345678";
    CHECK(report->stacktrace == "  " + fault + "\n" + (complete ? "  " + frame + "\n" : ""));
    auto foreign = *report;
    foreign.faultAddress = "0x1";
    foreign.stacktrace = "  0x1\n";
    CHECK(!Crash::hasAddressesFromOurModule(foreign));
}

int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 3) {
        if (std::string(argv[1]) == "--interrupt") {
            prepare(argv[2]);
            interruptCapture = true;
            invokeFilter();
            return 1;
        }
        if (std::string(argv[1]) == "--crash") {
            CHECK(Crash::install(argv[2]));
            RaiseException(0xe0424242, EXCEPTION_NONCONTINUABLE, 0, nullptr);
            return 1;
        }
        return 1;
    }

    char temporary[MAX_PATH];
    CHECK(GetTempPathA(MAX_PATH, temporary) > 0);
    const std::string directory = std::string(temporary) + "posthog-crash-" + std::to_string(GetCurrentProcessId());
    prepare(directory);
    // A completed terminate record also takes priority, before filter dispatch
    // inspects any exception pointers or claims the native writer.
    Internal::g_terminateHandled.store(true, std::memory_order_relaxed);
    CHECK(Internal::exceptionFilter(nullptr) == EXCEPTION_CONTINUE_SEARCH);
    CHECK(Internal::g_exceptionFilterEntered == 0);
    Internal::g_terminateHandled.store(false, std::memory_order_relaxed);
    invokeFilter();
    checkSyntheticReport(true);
    const std::string first = readReport();
    CHECK(Internal::exceptionFilter(nullptr) == EXCEPTION_CONTINUE_SEARCH);
    CHECK(readReport() == first);
    Crash::clearPendingReport();

    CHECK(runChild("--interrupt", directory) == 42);
    checkSyntheticReport(false);
    Crash::clearPendingReport();

    CHECK(runChild("--crash", directory) == 0xe0424242);
    const auto report = Crash::loadPendingReport();
    CHECK(report.has_value());
    CHECK(report->exceptionCode == "0xe0424242");
    CHECK(std::stoull(report->faultAddress, nullptr, 16) != 0);
    CHECK(report->stacktrace.find("  " + report->faultAddress + "\n") == 0);
    Crash::clearPendingReport();
    CHECK(RemoveDirectoryA(directory.c_str()));
    std::cout << "Windows crash report regression tests passed\n";
}
