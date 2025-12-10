/**
 * @file basic.cpp
 * @brief Basic PostHog C++ SDK usage example
 */

#include <posthog/posthog.h>
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    // Configure the client
    PostHog::Config config;
    config.apiKey = "your_posthog_api_key";  // Replace with your key
    config.appName = "MyApp";
    config.appVersion = "1.0.0";
    config.host = "https://eu.i.posthog.com";  // or https://app.posthog.com

    // Create client
    PostHog::Client client(config);

    // Initialize
    if (!client.initialize()) {
        std::cerr << "Failed to initialize PostHog" << std::endl;
        return 1;
    }

    // Install crash handler (optional but recommended)
    client.installCrashHandler();

    // Track events
    client.track("app_started", {
        {"version", "1.0.0"},
        {"platform", "desktop"}
    });

    // Simulate some work
    std::cout << "App running..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Track an error with stacktrace
    client.trackException("NetworkError", "Connection timeout", "HTTP Client", {
        {"url", "api.example.com"},
        {"timeout", "30"}
    });

    // Track completion
    client.track("app_closed", {
        {"session_duration", "60"}
    });

    // Shutdown (flushes events)
    client.shutdown();

    std::cout << "Done!" << std::endl;
    return 0;
}
