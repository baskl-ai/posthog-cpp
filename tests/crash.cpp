/**
 * @file crash.cpp
 * @brief Test crash handler functionality
 *
 * Two modes:
 *   ./crash        - Crashes intentionally
 *   ./crash check  - Sends crash report from previous run
 *
 * Usage:
 *   export POSTHOG_API_KEY=phc_xxx
 *   ./crash          # First run - will crash
 *   ./crash check    # Second run - sends crash report
 */

#include <posthog/posthog.h>
#include <posthog/crash_handler.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>

// Functions that will appear in stacktrace
void innerFunction() {
    std::cout << "Crashing now..." << std::endl;
    int* ptr = nullptr;
    *ptr = 42;  // SIGSEGV
}

void outerFunction() {
    innerFunction();
}

void crashFunction() {
    outerFunction();
}

int main(int argc, char* argv[]) {
    std::cout << "=== PostHog Crash Handler Test ===" << std::endl;

    // Get API key from environment
    const char* apiKeyEnv = std::getenv("POSTHOG_API_KEY");
    std::string apiKey = apiKeyEnv ? apiKeyEnv : "";

    if (apiKey.empty()) {
        std::cerr << "Warning: POSTHOG_API_KEY not set, crash report won't be sent" << std::endl;
    } else {
        std::cout << "API Key: " << apiKey.substr(0, 8) << "..." << std::endl;
    }

    // Use platform-specific temp directory for crash reports
#ifdef _WIN32
    const char* tempEnv = std::getenv("TEMP");
    std::string crashDir = std::string(tempEnv ? tempEnv : "C:/Windows/Temp") + "/posthog_crash_test";
#else
    std::string crashDir = "/tmp/posthog_crash_test";
#endif
    std::cout << "Crash dir: " << crashDir << std::endl;

    bool checkMode = (argc > 1 && strcmp(argv[1], "check") == 0);

    if (checkMode) {
        // =====================
        // CHECK MODE
        // =====================
        std::cout << "\n[Check Mode] Looking for pending crash report..." << std::endl;

        PostHog::CrashHandler::install(crashDir);
        auto report = PostHog::CrashHandler::loadPendingReport();

        if (!report.has_value()) {
            std::cout << "No pending crash report found." << std::endl;
            std::cout << "Run './crash' first to generate a crash." << std::endl;
            return 0;
        }

        std::cout << "\nFound crash report:" << std::endl;
        std::cout << "  Signal: " << report->signalName << std::endl;
        std::cout << "  Timestamp: " << report->timestamp << std::endl;
        std::cout << "  Platform: " << report->platform << std::endl;
        std::cout << "  Load address: " << report->loadAddress << std::endl;
        std::cout << "  Exec path: " << report->execPath << std::endl;
        std::cout << "  Stacktrace:\n" << report->stacktrace << std::endl;

        if (!apiKey.empty()) {
            PostHog::Config config;
            config.apiKey = apiKey;
            config.appName = "posthog-cpp-crash-test";
            config.appVersion = "1.0.0";
            config.host = "https://eu.i.posthog.com";

            PostHog::Client client(config);
            client.initialize();
            client.installCrashHandler(crashDir);

            std::cout << "\nFlushing events..." << std::endl;
            client.flush(5000);
            client.shutdown();

            std::cout << "\n=== Crash report sent! ===" << std::endl;
            std::cout << "Check PostHog for $exception with crash_from_previous_session=true" << std::endl;
        } else {
            std::cout << "\nNo API key, clearing report..." << std::endl;
            PostHog::CrashHandler::clearPendingReport();
        }

    } else {
        // =====================
        // CRASH MODE
        // =====================
        std::cout << "\n[Crash Mode] Will crash in 2 seconds..." << std::endl;
        std::cout << "After crash, run: ./crash check" << std::endl;

        if (!apiKey.empty()) {
            PostHog::Config config;
            config.apiKey = apiKey;
            config.appName = "posthog-cpp-crash-test";
            config.appVersion = "1.0.0";

            PostHog::Client client(config);
            client.initialize();
            client.track("crash_test_started", {{"mode", "crash"}});
            client.flush(2000);
            client.installCrashHandler(crashDir);
        } else {
            PostHog::CrashHandler::install(crashDir);
        }

        std::cout << "Crash handler: " << PostHog::CrashHandler::getCrashFilePath() << std::endl;

        // Wait then crash
#ifdef _WIN32
        Sleep(2000);  // Windows Sleep in milliseconds
#else
        sleep(2);     // Unix sleep in seconds
#endif
        crashFunction();

        std::cout << "ERROR: Should not reach here!" << std::endl;
        return 1;
    }

    return 0;
}
