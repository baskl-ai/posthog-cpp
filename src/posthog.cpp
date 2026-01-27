/**
 * @file posthog.cpp
 * @brief PostHog C++ SDK implementation
 */

#include "posthog/posthog.h"
#include "posthog/machine_id.h"
#include "posthog/stacktrace.h"
#include "posthog/crash_handler.h"

// Skip version check to avoid warnings when parent project uses different nlohmann/json version
#define JSON_SKIP_LIBRARY_VERSION_CHECK
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#ifdef POSTHOG_USE_CURL
#include <curl/curl.h>
#endif

using json = nlohmann::json;

namespace PostHog {

/**
 * @brief Internal implementation
 */
class Client::Impl {
public:
    Config config;
    std::string distinctId;
    std::string osInfo;  // Combined "$os" field: "Mac OS X arm64 15.5"

    std::atomic<bool> enabled{true};
    std::atomic<bool> initialized{false};
    std::atomic<bool> shutdownRequested{false};

    std::queue<std::string> eventQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::thread workerThread;

    Impl(const Config& cfg) : config(cfg) {}

    ~Impl() {
        shutdown();
    }

    bool initialize() {
        if (initialized) return true;

        // Use custom distinct ID if provided, otherwise generate from MAC address
        if (!config.distinctId.empty()) {
            distinctId = config.distinctId;
        } else {
            distinctId = MachineID::getHashedMacId();
            if (distinctId.empty()) {
                distinctId = "unknown-" + std::to_string(std::time(nullptr));
            }
        }

        // Detect platform
        detectPlatform();

        // Start worker thread
        workerThread = std::thread(&Impl::workerLoop, this);

        initialized = true;
        std::cout << "[PostHog] Initialized, distinct_id: " << distinctId.substr(0, 8) << "..." << std::endl;
        return true;
    }

    /**
     * @brief Detects platform info and stores in platformName as "$os" field
     *
     * Format: "OS arch version" (e.g., "Mac OS X arm64 15.5", "Windows x64 10.0.22631")
     */
    void detectPlatform() {
        std::string os;
        std::string arch;
        std::string version;

#ifdef _WIN32
        os = "Windows";
    #if defined(_M_ARM64)
        arch = "arm64";
    #elif defined(_M_X64) || defined(_WIN64)
        arch = "x64";
    #else
        arch = "x86";
    #endif
        OSVERSIONINFOEX osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        #pragma warning(suppress: 4996)
        if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
            std::ostringstream ss;
            ss << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "." << osvi.dwBuildNumber;
            version = ss.str();
        }
#elif defined(__APPLE__)
        os = "Mac OS X";
    #if defined(__arm64__)
        arch = "arm64";
    #else
        arch = "x86_64";
    #endif
        FILE* pipe = popen("sw_vers -productVersion 2>/dev/null", "r");
        if (pipe) {
            char buffer[64];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                version = buffer;
                if (!version.empty() && version.back() == '\n') {
                    version.pop_back();
                }
            }
            pclose(pipe);
        }
#else
        os = "Linux";
        struct utsname uts;
        if (uname(&uts) == 0) {
            arch = uts.machine;  // x86_64, aarch64, etc.
            version = uts.release;
        }
#endif
        // Combine into single string: "Mac OS X arm64 15.5"
        osInfo = os + " " + arch + " " + version;
    }

    void track(const std::string& event, const std::map<std::string, std::string>& properties) {
        if (!enabled || !initialized) return;

        json j;
        j["api_key"] = config.apiKey;
        j["event"] = event;
        j["distinct_id"] = distinctId;

        json props;
        props["$lib"] = config.appName;
        props["$lib_version"] = config.appVersion;
        props["$os"] = osInfo;
        props["posthog_cpp_version"] = POSTHOG_VERSION;

        for (const auto& [key, value] : properties) {
            props[key] = value;
        }

        j["properties"] = props;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            eventQueue.push(j.dump());
        }
        queueCondition.notify_one();

        std::cout << "[PostHog] Queued event: " << event << std::endl;
    }

    void trackException(const std::string& errorType,
                        const std::string& errorMessage,
                        const std::string& component,
                        const std::map<std::string, std::string>& additionalProps) {
        if (!enabled || !initialized) return;

        auto frames = Stacktrace::captureStructured(15, 2, config.appName);

        json j;
        j["api_key"] = config.apiKey;
        j["event"] = "$exception";
        j["distinct_id"] = distinctId;

        json props;
        props["$lib"] = config.appName;
        props["$lib_version"] = config.appVersion;
        props["$os"] = osInfo;
        props["posthog_cpp_version"] = POSTHOG_VERSION;
        if (!component.empty()) {
            props["component"] = component;
        }

        for (const auto& [key, value] : additionalProps) {
            props[key] = value;
        }

        // Build $exception_list
        json exceptionList = json::array();
        json exception;
        exception["type"] = errorType;
        exception["value"] = errorMessage.substr(0, 500);
        exception["mechanism"]["handled"] = true;
        exception["mechanism"]["synthetic"] = false;

        json stacktrace;
        stacktrace["type"] = "raw";
        json framesList = json::array();

        for (const auto& frame : frames) {
            json f;
            f["platform"] = "custom";
            f["lang"] = "cpp";
            f["function"] = frame.function;
            if (!frame.filename.empty()) f["filename"] = frame.filename;
            if (frame.lineno > 0) f["lineno"] = frame.lineno;
            if (!frame.module.empty()) f["module"] = frame.module;
            f["in_app"] = frame.inApp;
            f["resolved"] = true;
            framesList.push_back(f);
        }

        stacktrace["frames"] = framesList;
        exception["stacktrace"] = stacktrace;
        exceptionList.push_back(exception);

        props["$exception_list"] = exceptionList;
        j["properties"] = props;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            eventQueue.push(j.dump());
        }
        queueCondition.notify_one();

        std::cout << "[PostHog] Queued exception: " << errorType << std::endl;
    }

    void setPersonProperties(const std::map<std::string, std::string>& properties, bool setOnce) {
        if (!enabled || !initialized) return;
        if (properties.empty()) return;

        json j;
        j["api_key"] = config.apiKey;
        j["event"] = "$set";
        j["distinct_id"] = distinctId;

        json props;
        props["$lib"] = config.appName;
        props["$lib_version"] = config.appVersion;
        props["$os"] = osInfo;
        props["posthog_cpp_version"] = POSTHOG_VERSION;

        // Add properties to either $set or $set_once
        json propsToSet;
        for (const auto& [key, value] : properties) {
            propsToSet[key] = value;
        }

        if (setOnce) {
            props["$set_once"] = propsToSet;
        } else {
            props["$set"] = propsToSet;
        }

        j["properties"] = props;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            eventQueue.push(j.dump());
        }
        queueCondition.notify_one();

        std::cout << "[PostHog] Queued person properties ("
                  << (setOnce ? "$set_once" : "$set") << ")" << std::endl;
    }

    /**
     * @brief Generate detailed crash description from crash report
     * @param report Crash report with signal name, code, and fault address
     * @return Human-readable crash description
     */
    std::string generateCrashDescription(const CrashHandler::Report& report) {
        std::string description;

        // Windows exception codes
        if (!report.exceptionCode.empty() && report.signalName == "EXCEPTION") {
            std::string code = report.exceptionCode;
            if (code == "0xC0000005" || code == "0xc0000005") {
                description = "Access Violation";
                if (!report.faultAddress.empty()) {
                    description += " at address " + report.faultAddress;
                }
            } else if (code == "0xC0000094" || code == "0xc0000094") {
                description = "Integer Division by Zero";
            } else if (code == "0xC000008C" || code == "0xc000008c") {
                description = "Array Bounds Exceeded";
            } else if (code == "0x80000003" || code == "0x80000003") {
                description = "Breakpoint Exception";
            } else if (code == "0xC00000FD" || code == "0xc00000fd") {
                description = "Stack Overflow";
            } else {
                description = "Exception " + code;
                if (!report.faultAddress.empty()) {
                    description += " at " + report.faultAddress;
                }
            }
        }
        // Unix signal codes
        else if (report.signalName == "SIGSEGV") {
            description = "Segmentation Fault";
            if (!report.faultAddress.empty()) {
                description += " at address " + report.faultAddress;
            }
            // Signal codes for SIGSEGV
            if (!report.exceptionCode.empty()) {
                int code = std::atoi(report.exceptionCode.c_str());
                if (code == 1) {
                    description += " (address not mapped to object)";
                } else if (code == 2) {
                    description += " (invalid permissions for mapped object)";
                }
            }
        } else if (report.signalName == "SIGABRT") {
            description = "Aborted";
        } else if (report.signalName == "SIGBUS") {
            description = "Bus Error";
            if (!report.faultAddress.empty()) {
                description += " at address " + report.faultAddress;
            }
        } else if (report.signalName == "SIGFPE") {
            description = "Floating Point Exception";
        } else if (report.signalName == "SIGILL") {
            description = "Illegal Instruction";
            if (!report.faultAddress.empty()) {
                description += " at address " + report.faultAddress;
            }
        } else {
            description = report.signalName;
            if (!report.faultAddress.empty()) {
                description += " at " + report.faultAddress;
            }
        }

        return description.empty() ? "Application crashed (from previous session)" : description;
    }

    void trackCrashReport(const CrashHandler::Report& report) {
        if (!enabled || !initialized) return;

        // Convert unix timestamp to ISO 8601
        std::string isoTimestamp;
        try {
            time_t crashTime = std::stol(report.timestamp);
            struct tm* timeInfo = gmtime(&crashTime);
            char buffer[32];
            strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", timeInfo);
            isoTimestamp = buffer;
        } catch (...) {
            isoTimestamp = report.timestamp;
        }

        json j;
        j["api_key"] = config.apiKey;
        j["event"] = "$exception";
        j["distinct_id"] = distinctId;

        json props;
        props["$lib"] = config.appName;
        props["$lib_version"] = config.appVersion;
        props["$os"] = osInfo;
        props["posthog_cpp_version"] = POSTHOG_VERSION;
        props["crash_from_previous_session"] = true;
        props["crash_timestamp"] = isoTimestamp;

        if (!report.loadAddress.empty()) {
            props["load_address"] = report.loadAddress;
        }
        if (!report.execPath.empty()) {
            props["exec_path"] = report.execPath;
        }

        // Load and add custom metadata from previous session
        auto metadata = CrashHandler::loadMetadata();
        for (const auto& [key, value] : metadata.properties) {
            props[key] = value;
        }

        // Load and add log file contents from previous session
        auto logConfig = CrashHandler::loadLogFileConfig();
        if (!logConfig.path.empty()) {
            std::string logs = CrashHandler::readLastLines(logConfig.path, logConfig.maxLines);
            if (!logs.empty()) {
                props["recent_logs"] = logs;
                std::cout << "[PostHog] Attached " << logConfig.maxLines << " lines from log file" << std::endl;
            }
        }

        // Build $exception_list
        json exceptionList = json::array();
        json exception;
        exception["type"] = report.signalName;
        exception["value"] = generateCrashDescription(report);
        exception["mechanism"]["handled"] = false;
        exception["mechanism"]["synthetic"] = false;

        json stacktrace;
        stacktrace["type"] = "raw";
        json framesList = json::array();

        std::istringstream ss(report.stacktrace);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("0x") != std::string::npos) {
                json f;
                f["platform"] = "custom";
                f["lang"] = "cpp";
                f["function"] = line;
                f["in_app"] = true;
                f["resolved"] = false;
                framesList.push_back(f);
            }
        }

        stacktrace["frames"] = framesList;
        exception["stacktrace"] = stacktrace;
        exceptionList.push_back(exception);

        props["$exception_list"] = exceptionList;
        j["properties"] = props;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            eventQueue.push(j.dump());
        }
        queueCondition.notify_one();

        std::cout << "[PostHog] Queued crash report: " << report.signalName << std::endl;
    }

    void flush(int timeoutMs) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

        while (true) {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (eventQueue.empty()) break;
            }

            if (std::chrono::steady_clock::now() >= deadline) {
                std::cerr << "[PostHog] Flush timeout" << std::endl;
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void shutdown() {
        if (!initialized) return;

        shutdownRequested = true;
        queueCondition.notify_one();

        if (workerThread.joinable()) {
            workerThread.join();
        }

        initialized = false;
        std::cout << "[PostHog] Shutdown complete" << std::endl;
    }

    void workerLoop() {
        while (!shutdownRequested) {
            std::string eventJson;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCondition.wait_for(lock, std::chrono::milliseconds(config.flushIntervalMs), [this] {
                    return !eventQueue.empty() || shutdownRequested;
                });

                if (eventQueue.empty()) {
                    if (shutdownRequested) break;
                    continue;
                }

                eventJson = eventQueue.front();
                eventQueue.pop();
            }

            sendEvent(eventJson);
        }

        // Flush remaining events on shutdown
        while (true) {
            std::string eventJson;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (eventQueue.empty()) break;
                eventJson = eventQueue.front();
                eventQueue.pop();
            }
            sendEvent(eventJson);
        }
    }

    void sendEvent(const std::string& eventJson) {
#ifdef POSTHOG_USE_CURL
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "[PostHog] Failed to init curl" << std::endl;
            return;
        }

        std::string url = config.host + "/i/v0/e/";

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, eventJson.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, eventJson.length());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "[PostHog] Send failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
#else
        std::cout << "[PostHog] Would send: " << eventJson.substr(0, 100) << "..." << std::endl;
#endif
    }
};

// Client implementation

Client::Client(const Config& config) : m_impl(std::make_unique<Impl>(config)) {}

Client::~Client() = default;

bool Client::initialize() {
    return m_impl->initialize();
}

bool Client::isEnabled() const {
    return m_impl->enabled && m_impl->initialized;
}

void Client::setEnabled(bool enabled) {
    m_impl->enabled = enabled;
}

std::string Client::getDistinctId() const {
    return m_impl->distinctId;
}

void Client::track(const std::string& event, const std::map<std::string, std::string>& properties) {
    m_impl->track(event, properties);
}

void Client::trackException(const std::string& errorType,
                            const std::string& errorMessage,
                            const std::string& component,
                            const std::map<std::string, std::string>& properties) {
    m_impl->trackException(errorType, errorMessage, component, properties);
}

void Client::setPersonProperties(const std::map<std::string, std::string>& properties, bool setOnce) {
    m_impl->setPersonProperties(properties, setOnce);
}

void Client::installCrashHandler(const std::string& crashDir) {
    std::string dir = crashDir.empty()
        ? CrashHandler::getDefaultCrashDir(m_impl->config.appName)
        : crashDir;

    if (!CrashHandler::install(dir)) {
        std::cerr << "[PostHog] Failed to install crash handler" << std::endl;
        return;
    }

    std::cout << "[PostHog] Crash handler installed: " << CrashHandler::getCrashFilePath() << std::endl;

    // Check for pending crash report
    auto report = CrashHandler::loadPendingReport();
    if (report.has_value()) {
        // Filter out crashes that don't involve our module
        // This prevents reporting crashes from other plugins or host app
        if (CrashHandler::hasAddressesFromOurModule(*report)) {
            std::cout << "[PostHog] Found crash report from our module: " << report->signalName << std::endl;
            m_impl->trackCrashReport(*report);
        } else {
            std::cout << "[PostHog] Ignoring crash report (not from our module): " << report->signalName << std::endl;
        }
        CrashHandler::clearPendingReport();
        CrashHandler::clearMetadata();
        CrashHandler::clearLogFileConfig();
    }
}

void Client::setCrashMetadata(const std::map<std::string, std::string>& metadata) {
    if (!CrashHandler::isInstalled()) {
        std::cerr << "[PostHog] Warning: setCrashMetadata called before installCrashHandler" << std::endl;
        return;
    }

    CrashHandler::Metadata md;
    md.properties = metadata;
    if (CrashHandler::saveMetadata(md)) {
        std::cout << "[PostHog] Crash metadata saved (" << metadata.size() << " properties)" << std::endl;
    } else {
        std::cerr << "[PostHog] Failed to save crash metadata" << std::endl;
    }
}

void Client::setLogFile(const std::string& logFilePath, int maxLines) {
    // Check if crash handler is installed by verifying crash file path exists
    std::string crashPath = CrashHandler::getCrashFilePath();
    if (crashPath.empty()) {
        std::cerr << "[PostHog] Warning: setLogFile called before installCrashHandler" << std::endl;
        return;
    }

    CrashHandler::LogFileConfig config;
    config.path = logFilePath;
    config.maxLines = maxLines;
    if (CrashHandler::saveLogFileConfig(config)) {
        std::cout << "[PostHog] Log file configured: " << logFilePath << " (max " << maxLines << " lines)" << std::endl;
    } else {
        std::cerr << "[PostHog] Failed to save log file config" << std::endl;
    }
}

void Client::flush(int timeoutMs) {
    m_impl->flush(timeoutMs);
}

void Client::shutdown() {
    m_impl->shutdown();
}

std::string Client::captureStacktrace(int maxFrames, int skip) {
    return Stacktrace::capture(maxFrames, skip + 1);
}

std::vector<StackFrame> Client::captureStacktraceStructured(int maxFrames, int skip) {
    auto frames = Stacktrace::captureStructured(maxFrames, skip + 1);
    std::vector<StackFrame> result;
    result.reserve(frames.size());
    for (const auto& f : frames) {
        StackFrame sf;
        sf.function = f.function;
        sf.filename = f.filename;
        sf.module = f.module;
        sf.lineno = f.lineno;
        sf.colno = f.colno;
        sf.inApp = f.inApp;
        result.push_back(sf);
    }
    return result;
}

std::string Client::getDefaultCrashDir(const std::string& appName) {
    return CrashHandler::getDefaultCrashDir(appName);
}

std::string Client::generateMachineId() {
    return MachineID::getHashedMacId();
}

std::string Client::generateMachineId(const std::string& fallbackPath) {
    return MachineID::getHashedMacIdWithFallback(fallbackPath);
}

} // namespace PostHog
