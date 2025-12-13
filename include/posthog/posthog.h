/**
 * @file posthog.h
 * @brief Lightweight PostHog C++ SDK with crash reporting
 *
 * Cross-platform analytics library for macOS and Windows.
 * Features:
 * - Event tracking with properties
 * - Automatic machine ID generation
 * - Crash handler with stack traces
 * - Async event queue with batching
 *
 * Usage:
 * @code
 * PostHog::Config config;
 * config.apiKey = "phc_xxx";
 * config.appName = "MyApp";
 * config.appVersion = "1.0.0";
 *
 * PostHog::Client client(config);
 * client.installCrashHandler();
 *
 * client.track("button_clicked", {{"button", "submit"}});
 * client.shutdown();
 * @endcode
 */

#ifndef POSTHOG_H
#define POSTHOG_H

#define POSTHOG_VERSION_MAJOR 1
#define POSTHOG_VERSION_MINOR 1
#define POSTHOG_VERSION_PATCH 1
#define POSTHOG_VERSION "1.1.1"

#include <string>
#include <map>
#include <vector>
#include <functional>
#include <memory>

namespace PostHog {

/**
 * @brief Configuration for PostHog client
 */
struct Config {
    std::string apiKey;                  ///< PostHog project API key (required)
    std::string appName;                 ///< Application name for identification
    std::string appVersion;              ///< Application version
    std::string host = "https://eu.i.posthog.com";  ///< PostHog host URL
    std::string crashReportsDir;         ///< Directory for crash reports (auto-detected if empty)
    int flushIntervalMs = 30000;         ///< Flush interval in milliseconds
    int flushBatchSize = 10;             ///< Max events per batch
    bool enabled = true;                 ///< Enable/disable analytics
};

/**
 * @brief Stack frame for structured exceptions
 */
struct StackFrame {
    std::string function;
    std::string filename;
    std::string module;
    int lineno = 0;
    int colno = 0;
    bool inApp = true;
};

/**
 * @brief Crash report from previous session
 */
struct CrashReport {
    std::string signalName;
    std::string stacktrace;
    std::string timestamp;
    std::string platform;
    std::string loadAddress;
    std::string execPath;
};

/**
 * @brief PostHog analytics client
 */
class Client {
public:
    /**
     * @brief Construct client with configuration
     * @param config Client configuration
     */
    explicit Client(const Config& config);

    /**
     * @brief Destructor - flushes pending events
     */
    ~Client();

    // Non-copyable
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    /**
     * @brief Initialize the client
     * @return true if initialization successful
     */
    bool initialize();

    /**
     * @brief Check if client is enabled and initialized
     */
    bool isEnabled() const;

    /**
     * @brief Enable or disable analytics
     */
    void setEnabled(bool enabled);

    /**
     * @brief Get anonymous distinct ID for this machine
     */
    std::string getDistinctId() const;

    /**
     * @brief Track an event
     * @param event Event name
     * @param properties Event properties
     */
    void track(const std::string& event,
               const std::map<std::string, std::string>& properties = {});

    /**
     * @brief Track an exception/error
     * @param errorType Error type (e.g., "NetworkError")
     * @param errorMessage Error message
     * @param component Component where error occurred
     * @param properties Additional properties
     */
    void trackException(const std::string& errorType,
                        const std::string& errorMessage,
                        const std::string& component = "",
                        const std::map<std::string, std::string>& properties = {});

    /**
     * @brief Install crash handler
     *
     * Installs signal handlers (SIGSEGV, SIGBUS, etc.) and checks
     * for pending crash reports from previous sessions.
     *
     * @param crashDir Custom crash directory (uses config if empty)
     */
    void installCrashHandler(const std::string& crashDir = "");

    /**
     * @brief Set metadata to include with crash reports
     *
     * Saves metadata to disk so it can be included when sending crash reports
     * from previous sessions. Call this after initialization with all relevant
     * context (build info, license info, etc.).
     *
     * @param metadata Key-value pairs to include in crash reports
     */
    void setCrashMetadata(const std::map<std::string, std::string>& metadata);

    /**
     * @brief Flush pending events
     * @param timeoutMs Maximum wait time
     */
    void flush(int timeoutMs = 5000);

    /**
     * @brief Shutdown client and flush events
     */
    void shutdown();

    /**
     * @brief Capture current stack trace
     * @param maxFrames Maximum frames to capture
     * @param skip Frames to skip from top
     * @return Stack trace as string
     */
    static std::string captureStacktrace(int maxFrames = 32, int skip = 1);

    /**
     * @brief Capture structured stack trace
     * @param maxFrames Maximum frames to capture
     * @param skip Frames to skip from top
     * @return Vector of stack frames
     */
    static std::vector<StackFrame> captureStacktraceStructured(int maxFrames = 32, int skip = 1);

    /**
     * @brief Get default crash reports directory for current platform
     * @param appName Application name for directory path
     * @return Platform-specific crash reports path
     */
    static std::string getDefaultCrashDir(const std::string& appName);

    /**
     * @brief Generate unique machine ID
     * @return Machine-specific unique identifier
     */
    static std::string generateMachineId();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace PostHog

#endif // POSTHOG_H
