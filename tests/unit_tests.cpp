/**
 * @file unit_tests.cpp
 * @brief Unit tests that don't require network or API key
 */

#include <posthog/posthog.h>
#include <posthog/machine_id.h>
#include <posthog/stacktrace.h>
#include <posthog/crash_handler.h>
#include <iostream>
#include <cassert>

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    test_##name(); \
    std::cout << "OK" << std::endl; \
} while(0)

// Helper to check condition
#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAILED: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        exit(1); \
    } \
} while(0)

TEST(machine_id_not_empty) {
    std::string id = PostHog::MachineID::getHashedMacId();
    CHECK(!id.empty());
    CHECK(id.length() == 36);  // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
}

TEST(machine_id_algorithm) {
    // Test with known MAC value to ensure algorithm is consistent across platforms
    // Python: uuid.getnode() = 64512903190309
    // Expected: "5da68340-5f4e-b9d1-f2db-f1533b85c877"
    uint64_t testNode = 64512903190309ULL;
    std::string result = PostHog::MachineID::getHashedMacIdFromNode(testNode);
    CHECK(result == "5da68340-5f4e-b9d1-f2db-f1533b85c877");
}

TEST(stacktrace_capture) {
    std::string trace = PostHog::Stacktrace::capture(10, 0);
    CHECK(!trace.empty());
    CHECK(trace.find("#0") != std::string::npos);  // Should have frame numbers
}

TEST(stacktrace_structured) {
    auto frames = PostHog::Stacktrace::captureStructured(10, 0);
    CHECK(!frames.empty());
    CHECK(!frames[0].function.empty());
}

TEST(client_init_without_apikey) {
    PostHog::Config config;
    config.apiKey = "";  // Empty API key
    config.appName = "test";
    config.appVersion = "1.0.0";

    PostHog::Client client(config);
    bool result = client.initialize();
    CHECK(result);  // Should initialize even without API key

    // Track should not crash (just no-op)
    client.track("test_event", {{"key", "value"}});

    client.shutdown();
}

TEST(client_distinct_id) {
    PostHog::Config config;
    config.apiKey = "";
    config.appName = "test";

    PostHog::Client client(config);
    client.initialize();

    std::string id = client.getDistinctId();
    CHECK(!id.empty());

    client.shutdown();
}

TEST(client_enable_disable) {
    PostHog::Config config;
    config.apiKey = "";
    config.appName = "test";
    config.enabled = true;

    PostHog::Client client(config);
    client.initialize();

    CHECK(client.isEnabled());

    client.setEnabled(false);
    CHECK(!client.isEnabled());

    client.setEnabled(true);
    CHECK(client.isEnabled());

    client.shutdown();
}

TEST(default_crash_dir) {
    std::string dir = PostHog::Client::getDefaultCrashDir("TestApp");
    CHECK(!dir.empty());
    CHECK(dir.find("TestApp") != std::string::npos);
}

TEST(generate_machine_id) {
    std::string id = PostHog::Client::generateMachineId();
    CHECK(!id.empty());
    CHECK(id.length() == 36);  // UUID format
}

TEST(crash_filter_with_module_addresses) {
    // Crash with 2+ addresses from our module - should be reported
    PostHog::CrashHandler::Report report;
    report.loadAddress = "0x100000000";
    report.moduleSize = "0x100000";  // 1MB module (0x100000000 - 0x100100000)
    report.stacktrace = R"(
  0x100050000
  0x18bc93584
  0x100020000
  0x100030000
)";
    CHECK(PostHog::CrashHandler::hasAddressesFromOurModule(report) == true);
}

TEST(crash_filter_single_address) {
    // Crash with only 1 address from our module (crash handler) - should be filtered
    PostHog::CrashHandler::Report report;
    report.loadAddress = "0x100000000";
    report.moduleSize = "0x100000";
    report.stacktrace = R"(
  0x100050000
  0x18bc93584
  0x200000000
  0x300000000
)";
    CHECK(PostHog::CrashHandler::hasAddressesFromOurModule(report) == false);
}

TEST(crash_filter_no_module_addresses) {
    // Crash with NO addresses from our module - should be filtered
    PostHog::CrashHandler::Report report;
    report.loadAddress = "0x100000000";
    report.moduleSize = "0x100000";
    report.stacktrace = R"(
  0x18bc93584
  0x200000000
  0x300000000
  0x400000000
)";
    CHECK(PostHog::CrashHandler::hasAddressesFromOurModule(report) == false);
}

TEST(crash_filter_no_load_address) {
    // Crash without load address info - can't filter, assume ours
    PostHog::CrashHandler::Report report;
    report.stacktrace = "0x12345678";
    CHECK(PostHog::CrashHandler::hasAddressesFromOurModule(report) == true);
}

TEST(crash_filter_no_module_size) {
    // Crash with load address but no module size - can't filter, assume ours
    PostHog::CrashHandler::Report report;
    report.loadAddress = "0x100000000";
    report.stacktrace = "0x12345678";
    CHECK(PostHog::CrashHandler::hasAddressesFromOurModule(report) == true);
}

int main() {
    std::cout << "=== PostHog Unit Tests ===" << std::endl;

    RUN_TEST(machine_id_not_empty);
    RUN_TEST(machine_id_algorithm);
    RUN_TEST(stacktrace_capture);
    RUN_TEST(stacktrace_structured);
    RUN_TEST(client_init_without_apikey);
    RUN_TEST(client_distinct_id);
    RUN_TEST(client_enable_disable);
    RUN_TEST(default_crash_dir);
    RUN_TEST(generate_machine_id);
    RUN_TEST(crash_filter_with_module_addresses);
    RUN_TEST(crash_filter_single_address);
    RUN_TEST(crash_filter_no_module_addresses);
    RUN_TEST(crash_filter_no_load_address);
    RUN_TEST(crash_filter_no_module_size);

    std::cout << "\n=== All tests passed! ===" << std::endl;
    return 0;
}
