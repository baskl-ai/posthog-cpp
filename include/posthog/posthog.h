/**
 * @file posthog.h
 * @brief Lightweight PostHog C++ SDK with crash reporting
 *
 * Cross-platform analytics library for macOS, Windows and Linux.
 *
 * Features:
 * - Event tracking with custom properties
 * - Exception tracking with stack traces (function names resolved at runtime)
 * - Crash reporting (SIGSEGV, SIGABRT, etc.) with signal-safe file writing
 * - Unique machine ID generation for anonymous user identification
 * - Async event queue with background worker thread
 *
 * @section usage Basic Usage
 * @code
 * PostHog::Config config;
 * config.apiKey = "phc_xxx";
 * config.appName = "MyApp";
 * config.appVersion = "1.0.0";
 * config.host = "https://us.i.posthog.com";
 *
 * PostHog::Client client(config);
 * client.initialize();
 * client.installCrashHandler();
 *
 * client.track("button_clicked", {{"button", "submit"}});
 * client.shutdown();
 * @endcode
 *
 * @section crash Crash Reporting
 * Crash handler saves stack trace to disk (network unavailable in signal handlers).
 * On next launch, installCrashHandler() sends the report to PostHog.
 * Use scripts/symbolize.py to convert addresses to function names.
 *
 * @see README.md for detailed documentation
 */

#ifndef POSTHOG_H
#define POSTHOG_H

#define POSTHOG_VERSION_MAJOR 1
#define POSTHOG_VERSION_MINOR 7
#define POSTHOG_VERSION_PATCH 0
#define POSTHOG_VERSION "1.7.0"

#include <string>
#include <map>
#include <vector>
#include <functional>
#include <memory>

namespace PostHog {

/**
 * @brief Configuration for PostHog client
 *
 * @code
 * PostHog::Config config;
 * config.apiKey = "phc_xxx";           // Required
 * config.appName = "MyApp";            // Shows as $lib in PostHog
 * config.appVersion = "1.0.0";         // Shows as $lib_version
 * config.host = "https://us.i.posthog.com";
 * @endcode
 */
struct Config {
    std::string apiKey;                  ///< PostHog project API key (required, starts with phc_)
    std::string appName;                 ///< Application name, sent as $lib property
    std::string appVersion;              ///< Application version, sent as $lib_version property
    std::string host = "https://eu.i.posthog.com";  ///< PostHog API host (us.i.posthog.com or eu.i.posthog.com)
    std::string distinctId;              ///< Custom distinct ID (auto-generated from hardware if empty)
    std::string crashReportsDir;         ///< Custom crash directory (uses platform default if empty)
    int flushIntervalMs = 30000;         ///< Background flush interval in milliseconds
    int flushBatchSize = 10;             ///< Max events per batch (not currently used)
    bool enabled = true;                 ///< If false, all tracking calls become no-ops
};

/**
 * @brief Stack frame for structured exceptions
 *
 * Used by trackException() to build PostHog's $exception_list format.
 * Function names are resolved at runtime via backtrace_symbols (Unix) or DbgHelp (Windows).
 */
struct StackFrame {
    std::string function;   ///< Function name (demangled on Unix)
    std::string filename;   ///< Source file name (if available)
    std::string module;     ///< Module/library name
    int lineno = 0;         ///< Line number (usually 0, requires debug symbols)
    int colno = 0;          ///< Column number (usually 0)
    bool inApp = true;      ///< True if frame is from application code (not system library)
};

/**
 * @brief Crash report from previous session
 *
 * Loaded by installCrashHandler() if a crash occurred in previous run.
 * Contains raw addresses that need symbolization via scripts/symbolize.py.
 */
struct CrashReport {
    std::string signalName;   ///< Signal name (SIGSEGV, SIGABRT, etc.) or EXCEPTION on Windows
    std::string exceptionCode;   ///< Windows: Exception code (0xC0000005), Unix: signal code
    std::string faultAddress;    ///< Address that caused the crash (if available)
    std::string stacktrace;   ///< Raw stack addresses (one per line, hex format)
    std::string timestamp;    ///< Unix timestamp when crash occurred
    std::string platform;     ///< Platform name (macOS, Windows, Linux)
    std::string loadAddress;  ///< Executable load address for symbolization (hex)
    std::string execPath;     ///< Full path to crashed executable
};

/**
 * @brief PostHog analytics client
 *
 * Main class for sending events to PostHog. Thread-safe - events are queued
 * and sent asynchronously by a background worker thread.
 *
 * @note Call initialize() before tracking, and shutdown() before destroying.
 */
class Client {
public:
    /**
     * @brief Construct client with configuration
     * @param config Client configuration (apiKey is required)
     */
    explicit Client(const Config& config);

    /**
     * @brief Destructor
     * @note Calls shutdown() if not already called
     */
    ~Client();

    /// @cond INTERNAL
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    /// @endcond

    /**
     * @brief Initialize the client
     *
     * Generates machine ID, detects platform info, starts background worker thread.
     * Must be called before any tracking methods.
     *
     * @return true if initialization successful
     */
    bool initialize();

    /**
     * @brief Check if client is enabled and initialized
     * @return true if tracking is active
     */
    bool isEnabled() const;

    /**
     * @brief Enable or disable analytics at runtime
     * @param enabled If false, all tracking calls become no-ops
     */
    void setEnabled(bool enabled);

    /**
     * @brief Get anonymous distinct ID for this machine
     *
     * Generated from hardware identifiers (IOPlatformUUID on macOS,
     * MachineGuid on Windows, /etc/machine-id on Linux).
     *
     * @return UUID-format string unique to this machine
     */
    std::string getDistinctId() const;

    /**
     * @brief Track a custom event
     *
     * Events are queued and sent asynchronously. Each event automatically
     * includes $lib, $lib_version, $os, and posthog_cpp_version properties.
     *
     * @param event Event name (e.g., "button_clicked", "file_opened")
     * @param properties Optional key-value properties
     *
     * @code
     * client.track("purchase_completed", {
     *     {"product_id", "abc123"},
     *     {"amount", "29.99"}
     * });
     * @endcode
     */
    void track(const std::string& event,
               const std::map<std::string, std::string>& properties = {});

    /**
     * @brief Track an exception with stack trace
     *
     * Sends $exception event with $exception_list containing stack frames.
     * Function names are resolved at runtime (no symbolization needed).
     *
     * @param errorType Exception type (e.g., "NetworkError", "ValidationError")
     * @param errorMessage Error description
     * @param component Optional component name where error occurred
     * @param properties Optional additional properties
     *
     * @code
     * try {
     *     riskyOperation();
     * } catch (const std::exception& e) {
     *     client.trackException("RuntimeError", e.what(), "DataProcessor");
     * }
     * @endcode
     */
    void trackException(const std::string& errorType,
                        const std::string& errorMessage,
                        const std::string& component = "",
                        const std::map<std::string, std::string>& properties = {});

    /**
     * @brief Set person properties using $set or $set_once
     *
     * Sets properties on the user/person in PostHog. Use $set to always update
     * the property value, or $set_once to only set if not already set.
     *
     * @param properties Properties to set, mapped to either $set or $set_once
     * @param setOnce If true, uses $set_once (only sets if property doesn't exist)
     *
     * @code
     * // Always set/update property
     * client.setPersonProperties({{"is_internal_user", "true"}}, false);
     *
     * // Only set once (won't overwrite if already exists)
     * client.setPersonProperties({{"is_internal_user", "false"}}, true);
     * @endcode
     */
    void setPersonProperties(const std::map<std::string, std::string>& properties,
                            bool setOnce = false);

    /**
     * @brief Install crash handler for unhandled signals
     *
     * Installs handlers for SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL (Unix)
     * or SetUnhandledExceptionFilter (Windows). Also checks for pending
     * crash reports from previous sessions and sends them.
     *
     * @param crashDir Custom directory for crash files.
     *        If empty, uses getDefaultCrashDir(config.appName):
     *        - Windows: %APPDATA%/{appName}/CrashReports
     *        - macOS: ~/Library/Application Support/{appName}/CrashReports
     *        - Linux: ~/.local/share/{appName}/crash_reports
     *
     * @note Directory is created if it doesn't exist (parent must exist).
     */
    void installCrashHandler(const std::string& crashDir = "");

    /**
     * @brief Set metadata to include with crash reports
     *
     * Metadata is saved to disk and included when sending crash reports
     * from previous sessions. Call after installCrashHandler().
     *
     * @param metadata Key-value pairs (e.g., build_id, license_type, last_action)
     *
     * @code
     * client.setCrashMetadata({
     *     {"build_id", "abc123"},
     *     {"license_type", "pro"},
     *     {"last_action", "importing_file"}
     * });
     * @endcode
     */
    void setCrashMetadata(const std::map<std::string, std::string>& metadata);

    /**
     * @brief Set log file path to include with crash reports
     *
     * When a crash report is sent from a previous session, the last N lines
     * from the specified log file will be included in the crash event properties.
     * Call after installCrashHandler().
     *
     * @param logFilePath Full path to the log file
     * @param maxLines Maximum number of lines to include (default: 50)
     *
     * @code
     * client.setLogFile("/path/to/plugin.log", 50);
     * @endcode
     */
    void setLogFile(const std::string& logFilePath, int maxLines = 50);

    /**
     * @brief Flush pending events synchronously
     * @param timeoutMs Maximum time to wait for flush completion
     */
    void flush(int timeoutMs = 5000);

    /**
     * @brief Shutdown client
     *
     * Stops background worker thread and flushes remaining events.
     * Call before application exit to ensure all events are sent.
     */
    void shutdown();

    /**
     * @brief Capture current stack trace as string
     * @param maxFrames Maximum number of frames to capture
     * @param skip Number of frames to skip from top (to exclude this function)
     * @return Multi-line string with one frame per line
     */
    static std::string captureStacktrace(int maxFrames = 32, int skip = 1);

    /**
     * @brief Capture current stack trace as structured frames
     * @param maxFrames Maximum number of frames to capture
     * @param skip Number of frames to skip from top
     * @return Vector of StackFrame with function names (resolved at runtime)
     */
    static std::vector<StackFrame> captureStacktraceStructured(int maxFrames = 32, int skip = 1);

    /**
     * @brief Get default crash directory for platform
     * @param appName Application name for path
     * @return Platform-specific user-writable directory path
     */
    static std::string getDefaultCrashDir(const std::string& appName);

    /**
     * @brief Generate unique machine identifier
     *
     * Generates deterministic ID from network adapter MAC address using SHA256.
     * Compatible with Python's uuid.getnode() algorithm.
     *
     * @return UUID-format string unique to this machine
     */
    static std::string generateMachineId();

    /**
     * @brief Generate machine ID with file fallback
     *
     * If fallbackPath exists, reads ID from file (for persistence across MAC changes).
     * Otherwise generates new ID and saves to file.
     *
     * @param fallbackPath Path to store/read ID
     * @return UUID-format string
     */
    static std::string generateMachineId(const std::string& fallbackPath);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace PostHog

#endif // POSTHOG_H
