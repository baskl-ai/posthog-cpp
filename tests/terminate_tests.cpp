// Launched in separate processes by terminate_test.cmake: a crash must not kill
// the test runner, and parsing must exercise the next-launch path.
#include <posthog/crash_handler.h>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

namespace {
std::string expectedMessage(const std::string& scenario) {
    if (scenario == "multiline") return "first line  SIGNAL: SIGSEGV";
    if (scenario == "unknown") return "Unknown exception";
    if (scenario == "explicit") return "std::terminate called";
    if (scenario == "empty") return "";
    if (scenario == "long") return std::string(1023, 'x');
    return "uncaught_boom_marker";
}

void check(bool condition, const char* description) {
    if (!condition) {
        std::cerr << description << '\n';
        std::exit(1);
    }
}
}

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const std::string mode = argv[1];
    const std::string scenario = argv[2];
    PostHog::CrashHandler::install(argv[3]);

    if (mode == "verify") {
        auto report = PostHog::CrashHandler::loadPendingReport();
        check(report.has_value(), "missing report on next launch");
        check(report->signalName == (scenario == "abort" ? "SIGABRT" : "TERMINATE"),
              "wrong signal: terminate record overwritten or direct abort suppressed");
        check(report->message == (scenario == "abort" ? "" : expectedMessage(scenario)),
              "exception message lost or malformed");
        check(report->stacktrace.find("0x") != std::string::npos, "missing native frames");
        check(report->timestamp.find_first_not_of("0123456789") == std::string::npos,
              "timestamp is not decimal");
        return 0;
    }
    if (mode != "crash") return 2;
#ifdef _MSC_VER
    // Keep intentional crashes unattended on Windows CI.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    if (scenario == "open_failure" || scenario == "write_failure") {
        // Observe the abort fallback after a real open or buffered-flush failure.
        std::signal(SIGABRT, [](int) {
            std::_Exit(PostHog::CrashHandler::Internal::g_terminateHandled.load(
                           std::memory_order_relaxed) ? 43 : 42);
        });
    }
    if (scenario == "abort") std::abort();
    if (scenario == "explicit") std::terminate();
    if (scenario == "unknown") throw 42;
    if (scenario == "multiline") throw std::runtime_error("first line\r\nSIGNAL: SIGSEGV");
    if (scenario == "long") throw std::runtime_error(std::string(8192, 'x'));
    throw std::runtime_error(expectedMessage(scenario));
}
