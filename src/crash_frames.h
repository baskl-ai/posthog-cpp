#ifndef POSTHOG_CRASH_FRAMES_H
#define POSTHOG_CRASH_FRAMES_H

#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <limits>
#include <sstream>

namespace PostHog {
namespace detail {

// Reports are parsed on the next launch, never in the signal handler. Require
// the complete token: stoull alone accepts signs, whitespace and trailing junk.
inline bool crashHex(const std::string& text, std::uint64_t& value) {
    std::size_t i = 0;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) i = 2;
    if (i == text.size()) return false;
    value = 0;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        const unsigned digit = c >= '0' && c <= '9' ? c - '0' :
            c >= 'a' && c <= 'f' ? c - 'a' + 10 :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 : 16;
        if (digit == 16 || value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 16)
            return false;
        value = value * 16 + digit;
    }
    return true;
}

inline nlohmann::json crashFrames(const CrashHandler::Report& report, const std::string& appName = "") {
    std::uint64_t base = 0, size = 0;
    const bool haveRange = crashHex(report.loadAddress, base) && base != 0 &&
        crashHex(report.moduleSize, size) && size != 0 &&
        size <= (std::numeric_limits<std::uint64_t>::max)() - base;
    auto frames = nlohmann::json::array();
    std::istringstream trace(report.stacktrace);
    std::string line;
    while (std::getline(trace, line)) {
        if (line.find("0x") == std::string::npos && line.find("0X") == std::string::npos) continue;
        // The writer emits one address per line. Do not normalize an arbitrary
        // hex substring of malformed or legacy symbol-rich text.
        const auto first = line.find_first_not_of(" \t\r");
        const auto last = line.find_last_not_of(" \t\r");
        std::uint64_t address = 0;
        const bool parsed = first != std::string::npos &&
            crashHex(line.substr(first, last - first + 1), address);
        const bool inModule = haveRange && parsed && address >= base && address - base < size;
        nlohmann::json frame = {{"platform", "custom"}, {"lang", "cpp"},
            {"function", line}, {"in_app", haveRange ? inModule : true}, {"resolved", false}};
        if (inModule) {
            std::ostringstream offset;
            offset << "<module>+0x" << std::hex << (address - base);
            frame["function"] = offset.str();
            if (!appName.empty()) frame["module"] = appName;
        }
        frames.push_back(std::move(frame));
    }
    return frames;
}
} // namespace detail
} // namespace PostHog
#endif
