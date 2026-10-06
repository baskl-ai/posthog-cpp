#ifndef POSTHOG_EXCEPTION_FRAMES_H
#define POSTHOG_EXCEPTION_FRAMES_H

#include <posthog/stacktrace.h>
#include <nlohmann/json.hpp>

namespace PostHog {
namespace detail {
// Shared with the regression probe so tests check the actual wire fields.
inline nlohmann::json exceptionFrames(const std::vector<Stacktrace::Frame>& frames) {
    auto result = nlohmann::json::array();
    for (const auto& frame : frames) {
        nlohmann::json f = {{"platform", "custom"}, {"lang", "cpp"},
            {"function", frame.function}, {"in_app", frame.inApp},
            {"resolved", frame.resolved}};
        if (!frame.filename.empty()) f["filename"] = frame.filename;
        if (frame.lineno > 0) f["lineno"] = frame.lineno;
        if (!frame.module.empty()) f["module"] = frame.module;
        result.push_back(std::move(f));
    }
    return result;
}
} // namespace detail
} // namespace PostHog
#endif
