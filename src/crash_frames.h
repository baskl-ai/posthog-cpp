#ifndef POSTHOG_CRASH_FRAMES_H
#define POSTHOG_CRASH_FRAMES_H

#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <limits>

namespace PostHog {
namespace detail {

inline bool crashHexAddress(const std::string& text, std::uint64_t& value) {
    if (text.size() <= 2 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    for (size_t i = 2; i < text.size(); ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(text[i]))) return false;
    }
    try {
        value = std::stoull(text, nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

inline bool crashDebugId(const std::string& text) {
    if (text.size() != 36) return false;
    bool nonzero = false;
    for (size_t i = 0; i < text.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i] != '-') return false;
        } else {
            // Match the uploader's uppercase, dash-separated UUID exactly.
            if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'A' && text[i] <= 'F'))) return false;
            nonzero |= text[i] != '0';
        }
    }
    return nonzero;
}

// Shared by the actual crash sender and regressions; contains only event properties.
inline nlohmann::json crashFrameProperties(const CrashHandler::Report& report) {
    using json = nlohmann::json;
    std::uint64_t base = 0, size = 0;
    const bool native = report.platform == "macOS" && crashDebugId(report.debugId)
        && crashHexAddress(report.loadAddress, base) && base > 0
        && crashHexAddress(report.moduleSize, size) && size > 0
        && size <= (std::numeric_limits<std::uint64_t>::max)() - base;
    json frames = json::array();
    std::istringstream lines(report.stacktrace);
    std::string line;
    bool haveNativeFrame = false;
    while (std::getline(lines, line)) {
        size_t start = line.find("0x");
        if (start == std::string::npos) start = line.find("0X");
        if (start == std::string::npos) continue;
        size_t end = start + 2;
        while (end < line.size() && std::isxdigit(static_cast<unsigned char>(line[end]))) ++end;
        const std::string address = line.substr(start, end - start);
        std::uint64_t pc = 0;
        if (!crashHexAddress(address, pc)) continue;
        const bool ours = native && pc >= base && pc - base < size;
        json frame = {{"platform", ours ? "native" : "custom"}, {"lang", "cpp"},
                      {"function", line}, {"in_app", native ? ours : true}, {"resolved", false}};
        if (ours) {
            frame["instruction_addr"] = address;
            frame["image_addr"] = report.loadAddress;
            haveNativeFrame = true;
        }
        frames.push_back(std::move(frame));
    }
    // backtrace() writes innermost first; native stacks use PostHog's bottom-up order.
    if (native) std::reverse(frames.begin(), frames.end());
    json props = {{"frames", std::move(frames)}};
    if (haveNativeFrame) {
        json image = {{"debug_id", report.debugId}, {"image_addr", report.loadAddress},
                      {"image_size", size}, {"type", "macho"}};
        if (!report.execPath.empty()) image["code_file"] = report.execPath;
        props["$debug_images"] = json::array({std::move(image)});
    }
    return props;
}

} // namespace detail
} // namespace PostHog
#endif
