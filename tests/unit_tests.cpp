/**
 * @file unit_tests.cpp
 * @brief Unit tests that don't require network or API key
 */

#include <posthog/posthog.h>
#include <posthog/machine_id.h>
#include <posthog/stacktrace.h>
#include <posthog/crash_handler.h>
#include <posthog/logging.h>
#include <iostream>
#include <cassert>
#include <fstream>
#include <cstdio>
#include <cstdlib>

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

TEST(optout_file_disables) {
    std::string homeDir;
#ifdef _WIN32
    const char* h = std::getenv("USERPROFILE");
    if (h) homeDir = h;
    std::string optOutPath = homeDir + "\\.posthog_optout";
#else
    const char* h = std::getenv("HOME");
    if (h) homeDir = h;
    std::string optOutPath = homeDir + "/.posthog_optout";
#endif

    // Create opt-out marker file
    { std::ofstream f(optOutPath); }

    PostHog::Config config;
    config.apiKey = "";
    config.appName = "test_optout";
    PostHog::Client client(config);
    client.initialize();

    CHECK(!client.isEnabled());
    client.shutdown();

    std::remove(optOutPath.c_str());
}

TEST(no_optout_file_enables) {
    std::string homeDir;
#ifdef _WIN32
    const char* h = std::getenv("USERPROFILE");
    if (h) homeDir = h;
    std::string optOutPath = homeDir + "\\.posthog_optout";
#else
    const char* h = std::getenv("HOME");
    if (h) homeDir = h;
    std::string optOutPath = homeDir + "/.posthog_optout";
#endif

    // Ensure no opt-out file
    std::remove(optOutPath.c_str());

    PostHog::Config config;
    config.apiKey = "";
    config.appName = "test_no_optout";
    PostHog::Client client(config);
    client.initialize();

    CHECK(client.isEnabled());
    client.shutdown();
}

TEST(config_enabled_false_disables) {
    PostHog::Config config;
    config.apiKey = "";
    config.appName = "test_config_disabled";
    config.enabled = false;

    PostHog::Client client(config);
    client.initialize();

    CHECK(!client.isEnabled());
    client.shutdown();
}

TEST(config_from_env) {
#ifdef _WIN32
    _putenv_s("POSTHOG_API_KEY", "phc_env");
    _putenv_s("POSTHOG_HOST", "https://us.i.posthog.com");
    _putenv_s("POSTHOG_APP_NAME", "env_app");
    _putenv_s("POSTHOG_APP_VERSION", "9.9.9");
#else
    setenv("POSTHOG_API_KEY", "phc_env", 1);
    setenv("POSTHOG_HOST", "https://us.i.posthog.com", 1);
    setenv("POSTHOG_APP_NAME", "env_app", 1);
    setenv("POSTHOG_APP_VERSION", "9.9.9", 1);
#endif

    PostHog::Config cfg = PostHog::Config::fromEnv();
    CHECK(cfg.apiKey == "phc_env");
    CHECK(cfg.host == "https://us.i.posthog.com");
    CHECK(cfg.appName == "env_app");
    CHECK(cfg.appVersion == "9.9.9");
}

TEST(log_auto_initialize) {
    PostHog::Config config;
    config.apiKey = "";
    config.appName = "auto_init_test";

    PostHog::Client client(config);
    client.logInfo("hello");
    CHECK(!client.getDistinctId().empty());
    client.shutdown();
}

TEST(log_severity_mapping) {
    using PostHog::LogLevel;
    CHECK(PostHog::toSeverityNumber(LogLevel::Trace) == 1);
    CHECK(PostHog::toSeverityNumber(LogLevel::Debug) == 5);
    CHECK(PostHog::toSeverityNumber(LogLevel::Info) == 9);
    CHECK(PostHog::toSeverityNumber(LogLevel::Warn) == 13);
    CHECK(PostHog::toSeverityNumber(LogLevel::Error) == 17);
    CHECK(PostHog::toSeverityNumber(LogLevel::Fatal) == 21);
}

TEST(log_record_json_serialization) {
    using PostHog::AnyValue;
    using PostHog::KeyValue;
    using PostHog::LogLevel;
    using PostHog::LogRecord;
    using PostHog::ResourceLogs;
    using PostHog::ScopeLogs;
    using PostHog::InstrumentationScope;
    using PostHog::ExportLogsServiceRequest;

    LogRecord record;
    record.time_unix_nano = 1234567890ULL;
    record.severity = LogLevel::Info;
    record.body = AnyValue("User clicked submit");
    record.attributes = {
        KeyValue{"button", AnyValue("submit")},
        KeyValue{"latency_ms", AnyValue(128)},
        KeyValue{"is_internal", AnyValue(true)},
    };

    ScopeLogs scope;
    scope.scope = InstrumentationScope{"posthog-cpp", POSTHOG_VERSION};
    scope.log_records.push_back(record);

    ResourceLogs res;
    res.resource_attributes = {
        KeyValue{"service.name", AnyValue("MyApp")},
        KeyValue{"service.version", AnyValue("1.0.0")},
    };
    res.scope_logs.push_back(scope);

    ExportLogsServiceRequest req;
    req.resource_logs.push_back(res);

    auto j = PostHog::toJson(req);

    CHECK(j["resourceLogs"].is_array());
    CHECK(j["resourceLogs"].size() == 1);
    CHECK(j["resourceLogs"][0]["scopeLogs"].size() == 1);
    CHECK(j["resourceLogs"][0]["scopeLogs"][0]["logRecords"].size() == 1);

    auto lr = j["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
    CHECK(lr["severityNumber"] == 9);
    CHECK(lr["severityText"] == "INFO");
    CHECK(lr["body"]["stringValue"] == "User clicked submit");
}

TEST(log_trace_context_serialization) {
    using PostHog::AnyValue;
    using PostHog::LogLevel;
    using PostHog::LogRecord;
    using PostHog::ExportLogsServiceRequest;
    using PostHog::ScopeLogs;
    using PostHog::ResourceLogs;

    LogRecord record;
    record.severity = LogLevel::Error;
    record.body = AnyValue("failure");
    record.trace_id = PostHog::TraceId::fromHex("4bf92f3577b34da6a3ce929d0e0e4736");
    record.span_id = PostHog::SpanId::fromHex("00f067aa0ba902b7");

    ScopeLogs scope;
    scope.log_records.push_back(record);

    ResourceLogs res;
    res.scope_logs.push_back(scope);

    ExportLogsServiceRequest req;
    req.resource_logs.push_back(res);

    auto j = PostHog::toJson(req);
    auto lr = j["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];

    CHECK(lr["traceId"] == "4bf92f3577b34da6a3ce929d0e0e4736");
    CHECK(lr["spanId"] == "00f067aa0ba902b7");
}

TEST(log_request_target_and_auth) {
    PostHog::Config config;
    config.apiKey = "phc_test";
    config.appName = "test";
    config.appVersion = "1.0.0";
    config.host = "https://us.i.posthog.com";

    PostHog::Client client(config);
    client.initialize();

    auto req = client.buildLogRequest(
        PostHog::LogRecord::info("hello", {{"k", PostHog::AnyValue("v")}})
    );

    CHECK(req.url == "https://us.i.posthog.com/i/v1/logs");
    CHECK(req.headers.count("Authorization") == 1);
    CHECK(req.headers.at("Authorization") == "Bearer phc_test");

    client.shutdown();
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
    RUN_TEST(optout_file_disables);
    RUN_TEST(no_optout_file_enables);
    RUN_TEST(config_enabled_false_disables);
    RUN_TEST(config_from_env);
    RUN_TEST(log_auto_initialize);
    RUN_TEST(log_severity_mapping);
    RUN_TEST(log_record_json_serialization);
    RUN_TEST(log_trace_context_serialization);
    RUN_TEST(log_request_target_and_auth);

    std::cout << "\n=== All tests passed! ===" << std::endl;
    return 0;
}
