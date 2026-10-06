// Drive the public next-launch API into a loopback-only HTTP receiver.
#include <posthog/posthog.h>
#include <posthog/crash_handler.h>
#include <filesystem>
#include <fstream>

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const std::string dir = argv[1], mode = argv[3];
    std::filesystem::create_directories(dir);
    std::ofstream f(std::filesystem::path(dir) / "pending_crash.txt");
    f << "SIGNAL: SIGABRT\nTIME: 1700000000\nLOAD_ADDR: 0x100000000\n"
         "MODULE_SIZE: 0x1000\nEXEC_PATH: /plugins/example.plugin\n";
    if (mode == "native") f << "DEBUG_ID: 12345678-9ABC-DEF0-1234-56789ABCDEF0\n";
    if (mode == "invalid") f << "DEBUG_ID: not-a-uuid\n";
    f << "STACKTRACE:\n  0x100000080\n  0x700000010\n  0x100000100\n";
    f.close();
    PostHog::Config config;
    config.apiKey = "phc_loopback_test";
    config.host = argv[2];
    config.appName = "crash_payload_test";
    PostHog::Client client(config);
    client.initialize();
    client.installCrashHandler(dir);
    client.shutdown();
    return std::filesystem::exists(std::filesystem::path(dir) / "pending_crash.txt") ? 1 : 0;
}
