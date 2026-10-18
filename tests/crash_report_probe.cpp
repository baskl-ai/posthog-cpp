#include <posthog/posthog.h>
#include "../src/crash_frames.h"
#include <iostream>
#include <stdexcept>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    const std::string mode = argv[1];
    if (mode == "upload" && argc == 4) {
        PostHog::Config config;
        config.apiKey = "phc_local_test";
        config.appName = "crash_report_probe";
        config.appVersion = "test";
        config.distinctId = "local-regression-test";
        config.host = argv[3];
        PostHog::Client client(config);
        client.initialize();
        client.installCrashHandler(argv[2]);
        client.flush();
        client.shutdown();
        return 0;
    }
    if (!PostHog::CrashHandler::install(argv[2])) return 3;
    if (mode == "crash") {
#ifdef _WIN32
        SetErrorMode(SEM_NOGPFAULTERRORBOX);
#endif
#ifdef _MSC_VER
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
        throw std::runtime_error("grouping_test_marker");
    }
    if (mode != "inspect") return 2;
    const auto report = PostHog::CrashHandler::loadPendingReport();
    if (!report) return 4;
    std::cout << nlohmann::json({{"frames", PostHog::detail::crashFrames(*report, "crash_report_probe")},
        {"raw", report->stacktrace}, {"load_address", report->loadAddress},
        {"module_size", report->moduleSize}, {"message", report->message}}).dump() << '\n';
}
