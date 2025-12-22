/**
 * @file basic.cpp
 * @brief Basic PostHog C++ SDK usage example
 *
 * Usage:
 *   export POSTHOG_API_KEY=phc_xxx
 *   ./basic
 */

#include <posthog/posthog.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>

int main() {
    std::cout << "=== PostHog Basic Example ===" << std::endl;

    // Get API key from environment
    const char* apiKeyEnv = std::getenv("POSTHOG_API_KEY");
    if (!apiKeyEnv || strlen(apiKeyEnv) == 0) {
        std::cerr << "Error: POSTHOG_API_KEY environment variable not set" << std::endl;
        std::cerr << "Usage: export POSTHOG_API_KEY=phc_xxx && ./basic" << std::endl;
        return 1;
    }

    std::string apiKey = apiKeyEnv;
    std::cout << "API Key: " << apiKey.substr(0, 8) << "..." << std::endl;

    // Configure
    PostHog::Config config;
    config.apiKey = apiKey;
    config.appName = "posthog-cpp-example";
    config.appVersion = "1.0.0";
    config.host = "https://eu.i.posthog.com";

    // Create and initialize client
    PostHog::Client client(config);
    if (!client.initialize()) {
        std::cerr << "Failed to initialize PostHog" << std::endl;
        return 1;
    }

    std::cout << "Distinct ID: " << client.getDistinctId() << std::endl;

    // Track events
    std::cout << "\nTracking events..." << std::endl;

    client.track("example_started", {
        {"sdk", "posthog-cpp"},
        {"test_type", "basic"}
    });

    client.track("example_event", {
        {"string_prop", "hello"},
        {"number_as_string", "42"}
    });

    // Set person properties
    std::cout << "\nSetting person properties..." << std::endl;

    // $set - always updates the property
    client.setPersonProperties({
        {"example_property", "test_value"},
        {"sdk_test", "true"}
    }, false);

    // $set_once - only sets if property doesn't exist yet
    client.setPersonProperties({
        {"first_seen_sdk", "posthog-cpp"}
    }, true);

    // Track exception
    client.trackException("ExampleError", "This is a test error", "example_component", {
        {"error_code", "123"}
    });

    // Show stacktrace capture
    std::cout << "\nStacktrace capture:" << std::endl;
    std::string trace = PostHog::Client::captureStacktrace(5, 0);
    std::cout << trace << std::endl;

    // Flush and shutdown
    std::cout << "Flushing events..." << std::endl;
    client.flush(5000);
    client.shutdown();

    std::cout << "\n=== Done ===" << std::endl;
    std::cout << "Check PostHog dashboard for events from 'posthog-cpp-example'" << std::endl;

    return 0;
}
