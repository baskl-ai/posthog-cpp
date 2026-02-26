/**
 * @file logging.h
 * @brief OTLP logging data structures and helpers
 */

#ifndef POSTHOG_LOGGING_H
#define POSTHOG_LOGGING_H

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <initializer_list>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace PostHog {

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal
};

inline int toSeverityNumber(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return 1;
        case LogLevel::Debug: return 5;
        case LogLevel::Info: return 9;
        case LogLevel::Warn: return 13;
        case LogLevel::Error: return 17;
        case LogLevel::Fatal: return 21;
    }
    return 9;
}

inline std::string toSeverityText(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
    }
    return "INFO";
}

struct TraceId {
    std::string hex;
    static TraceId fromHex(const std::string& value) { return TraceId{value}; }
};

struct SpanId {
    std::string hex;
    static SpanId fromHex(const std::string& value) { return SpanId{value}; }
};

struct AnyValue;
struct LogRecord;

class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void emit(const LogRecord& record) = 0;
};

struct KeyValue {
    std::string key;
    std::shared_ptr<AnyValue> value;

    KeyValue() = default;
    KeyValue(const std::string& k, const AnyValue& v);
    KeyValue(const char* k, const AnyValue& v);
};

struct AnyValue {
    using Array = std::vector<AnyValue>;
    using KvList = std::vector<KeyValue>;

    std::variant<std::string, bool, int64_t, double, Array, KvList> value;

    AnyValue() : value(std::string()) {}
    AnyValue(const std::string& v) : value(v) {}
    AnyValue(const char* v) : value(std::string(v)) {}
    AnyValue(bool v) : value(v) {}
    AnyValue(int64_t v) : value(v) {}
    AnyValue(int v) : value(static_cast<int64_t>(v)) {}
    AnyValue(double v) : value(v) {}
    AnyValue(const Array& v) : value(v) {}
    AnyValue(const KvList& v) : value(v) {}
};

inline KeyValue::KeyValue(const std::string& k, const AnyValue& v)
    : key(k), value(std::make_shared<AnyValue>(v)) {}
inline KeyValue::KeyValue(const char* k, const AnyValue& v)
    : key(k), value(std::make_shared<AnyValue>(v)) {}

struct LogRecord {
    std::optional<uint64_t> time_unix_nano;
    LogLevel severity = LogLevel::Info;
    std::optional<std::string> severity_text;
    AnyValue body;
    std::vector<KeyValue> attributes;
    std::optional<TraceId> trace_id;
    std::optional<SpanId> span_id;
    std::optional<uint8_t> trace_flags;

    static LogRecord info(const std::string& message,
                          const std::vector<KeyValue>& attrs = {}) {
        LogRecord r;
        r.severity = LogLevel::Info;
        r.body = AnyValue(message);
        r.attributes = attrs;
        return r;
    }

    static LogRecord info(const std::string& message,
                          std::initializer_list<KeyValue> attrs) {
        return info(message, std::vector<KeyValue>(attrs));
    }

    static LogRecord withLevel(LogLevel level,
                               const std::string& message,
                               const std::vector<KeyValue>& attrs = {}) {
        LogRecord r;
        r.severity = level;
        r.body = AnyValue(message);
        r.attributes = attrs;
        return r;
    }
};

struct InstrumentationScope {
    std::string name;
    std::string version;
};

struct ScopeLogs {
    InstrumentationScope scope;
    std::vector<LogRecord> log_records;
};

struct ResourceLogs {
    std::vector<KeyValue> resource_attributes;
    std::vector<ScopeLogs> scope_logs;
};

struct ExportLogsServiceRequest {
    std::vector<ResourceLogs> resource_logs;
};

struct LogRequest {
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

inline KeyValue kv(const std::string& key, const AnyValue& value) {
    return KeyValue(key, value);
}

inline bool isAtLeast(LogLevel level, LogLevel minLevel) {
    return toSeverityNumber(level) >= toSeverityNumber(minLevel);
}

class Logger {
public:
    Logger(std::shared_ptr<LogSink> sink, LogLevel minLevel = LogLevel::Info)
        : m_sink(std::move(sink)), m_minLevel(minLevel) {}

    void log(LogLevel level,
             const std::string& message,
             const std::vector<KeyValue>& attributes = {}) {
        if (!m_sink || !isAtLeast(level, m_minLevel)) return;
        m_sink->emit(LogRecord::withLevel(level, message, attributes));
    }

    void trace(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Trace, message, attributes);
    }
    void debug(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Debug, message, attributes);
    }
    void info(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Info, message, attributes);
    }
    void warn(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Warn, message, attributes);
    }
    void error(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Error, message, attributes);
    }
    void fatal(const std::string& message, const std::vector<KeyValue>& attributes = {}) {
        log(LogLevel::Fatal, message, attributes);
    }

private:
    std::shared_ptr<LogSink> m_sink;
    LogLevel m_minLevel;
};

inline nlohmann::json toJson(const AnyValue& value);
inline nlohmann::json toJson(const KeyValue& kv);
inline nlohmann::json toJson(const LogRecord& record);
inline nlohmann::json toJson(const ScopeLogs& scope);
inline nlohmann::json toJson(const ResourceLogs& resource);
inline nlohmann::json toJson(const ExportLogsServiceRequest& req);

inline nlohmann::json toJson(const AnyValue& value) {
    nlohmann::json j;
    if (std::holds_alternative<std::string>(value.value)) {
        j["stringValue"] = std::get<std::string>(value.value);
    } else if (std::holds_alternative<bool>(value.value)) {
        j["boolValue"] = std::get<bool>(value.value);
    } else if (std::holds_alternative<int64_t>(value.value)) {
        j["intValue"] = std::to_string(std::get<int64_t>(value.value));
    } else if (std::holds_alternative<double>(value.value)) {
        j["doubleValue"] = std::get<double>(value.value);
    } else if (std::holds_alternative<AnyValue::Array>(value.value)) {
        nlohmann::json values = nlohmann::json::array();
        for (const auto& v : std::get<AnyValue::Array>(value.value)) {
            values.push_back(toJson(v));
        }
        j["arrayValue"] = {{"values", values}};
    } else if (std::holds_alternative<AnyValue::KvList>(value.value)) {
        nlohmann::json values = nlohmann::json::array();
        for (const auto& kv : std::get<AnyValue::KvList>(value.value)) {
            values.push_back(toJson(kv));
        }
        j["kvlistValue"] = {{"values", values}};
    }
    return j;
}

inline nlohmann::json toJson(const KeyValue& kv) {
    nlohmann::json j;
    j["key"] = kv.key;
    if (kv.value) {
        j["value"] = toJson(*kv.value);
    } else {
        j["value"] = nlohmann::json::object();
    }
    return j;
}

inline nlohmann::json toJson(const LogRecord& record) {
    nlohmann::json j;
    if (record.time_unix_nano.has_value()) {
        j["timeUnixNano"] = std::to_string(record.time_unix_nano.value());
    }
    j["severityNumber"] = toSeverityNumber(record.severity);
    j["severityText"] = record.severity_text.value_or(toSeverityText(record.severity));
    j["body"] = toJson(record.body);
    if (!record.attributes.empty()) {
        nlohmann::json attrs = nlohmann::json::array();
        for (const auto& kv : record.attributes) {
            attrs.push_back(toJson(kv));
        }
        j["attributes"] = attrs;
    }
    if (record.trace_id.has_value()) {
        j["traceId"] = record.trace_id->hex;
    }
    if (record.span_id.has_value()) {
        j["spanId"] = record.span_id->hex;
    }
    if (record.trace_flags.has_value()) {
        j["traceFlags"] = record.trace_flags.value();
    }
    return j;
}

inline nlohmann::json toJson(const ScopeLogs& scope) {
    nlohmann::json j;
    nlohmann::json scopeObj;
    scopeObj["name"] = scope.scope.name;
    if (!scope.scope.version.empty()) {
        scopeObj["version"] = scope.scope.version;
    }
    j["scope"] = scopeObj;

    nlohmann::json records = nlohmann::json::array();
    for (const auto& r : scope.log_records) {
        records.push_back(toJson(r));
    }
    j["logRecords"] = records;
    return j;
}

inline nlohmann::json toJson(const ResourceLogs& resource) {
    nlohmann::json j;

    if (!resource.resource_attributes.empty()) {
        nlohmann::json attrs = nlohmann::json::array();
        for (const auto& kv : resource.resource_attributes) {
            attrs.push_back(toJson(kv));
        }
        j["resource"] = {{"attributes", attrs}};
    }

    nlohmann::json scopes = nlohmann::json::array();
    for (const auto& s : resource.scope_logs) {
        scopes.push_back(toJson(s));
    }
    j["scopeLogs"] = scopes;

    return j;
}

inline nlohmann::json toJson(const ExportLogsServiceRequest& req) {
    nlohmann::json j;
    nlohmann::json resources = nlohmann::json::array();
    for (const auto& r : req.resource_logs) {
        resources.push_back(toJson(r));
    }
    j["resourceLogs"] = resources;
    return j;
}

} // namespace PostHog

#endif // POSTHOG_LOGGING_H
