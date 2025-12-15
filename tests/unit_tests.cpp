/**
 * @file unit_tests.cpp
 * @brief Unit tests that don't require network or API key
 */

#include <posthog/posthog.h>
#include <posthog/machine_id.h>
#include <posthog/stacktrace.h>
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

    std::cout << "\n=== All tests passed! ===" << std::endl;
    return 0;
}
