/**
 * @file logging.cpp
 * @brief Example usage of PostHog OTLP logging
 */

#include <posthog/posthog.h>
#include <posthog/logging.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int main() {
    PostHog::Config config = PostHog::Config::fromEnv();
    if (config.apiKey.empty()) {
        std::cerr << "Set POSTHOG_API_KEY to run this example" << std::endl;
        return 1;
    }

    if (config.appName.empty()) config.appName = "posthog-cpp-logger-example";
    if (config.appVersion.empty()) config.appVersion = "1.0.0";
    if (config.host.empty()) config.host = "https://us.i.posthog.com";

    PostHog::AutoClient client(config);

    // Minimal log
    client->logInfo("Logger initialized", {
        {"env", PostHog::AnyValue("dev")},
#ifdef _WIN32
        {"pid", PostHog::AnyValue(static_cast<int64_t>(GetCurrentProcessId()))},
#else
        {"pid", PostHog::AnyValue(static_cast<int64_t>(getpid()))},
#endif
    });

    // Structured log with attributes + trace context (optional)
    PostHog::LogRecord record;
    record.severity = PostHog::LogLevel::Warn;
    record.body = PostHog::AnyValue("Cache miss");
    record.attributes = {
        {"cache_key", PostHog::AnyValue("user:42")},
        {"latency_ms", PostHog::AnyValue(12)},
        {"is_internal", PostHog::AnyValue(true)},
    };
    record.trace_id = PostHog::TraceId::fromHex("4bf92f3577b34da6a3ce929d0e0e4736");
    record.span_id = PostHog::SpanId::fromHex("00f067aa0ba902b7");

    client->log(record);

    // Logger helper (optional)
    auto sink = std::make_shared<PostHog::ClientLogSink>(client.get());
    PostHog::Logger logger(sink, PostHog::LogLevel::Info);
    logger.info("Logger helper OK", {{"status", PostHog::AnyValue("ok")}});

    client->flush(5000);
    return 0;
}
