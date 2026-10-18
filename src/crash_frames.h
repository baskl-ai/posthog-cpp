#ifndef POSTHOG_CRASH_FRAMES_H
#define POSTHOG_CRASH_FRAMES_H

#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <limits>
#include <vector>

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

// Shared by the sender and tests. Addresses always come from the saved session,
// never from the possibly updated/rebased binary running on the next launch.
inline nlohmann::json crashFrameProperties(const CrashHandler::Report& report, const std::string& appName = "") {
    using json = nlohmann::json;
    std::uint64_t base = 0, size = 0, instruction = 0;
    const bool native = report.platform == "macOS" && crashDebugId(report.debugId)
        && crashHex(report.loadAddress, base) && base > 0
        && crashHex(report.moduleSize, size) && size > 0
        && size <= (std::numeric_limits<std::uint64_t>::max)() - base;
    const bool haveInstruction = (report.instructionAddress.rfind("0x", 0) == 0 ||
                                  report.instructionAddress.rfind("0X", 0) == 0) &&
        crashHex(report.instructionAddress, instruction) && instruction != 0;
    const auto legacyFrames = crashFrames(report, appName);
    if (!native) {
        json props = {{"frames", legacyFrames}};
        if (haveInstruction) props["crash_instruction_addr"] = report.instructionAddress;
        return props;
    }
    const auto inModule = [&](std::uint64_t pc) { return native && pc >= base && pc - base < size; };
    struct CapturedFrame { json fallback; std::string address; std::uint64_t pc; };
    std::vector<CapturedFrame> captured;
    std::istringstream lines(report.stacktrace);
    std::string line;
    size_t index = 0;
    while (std::getline(lines, line)) {
        if (line.find("0x") == std::string::npos && line.find("0X") == std::string::npos) continue;
        const auto fallback = legacyFrames[index++];
        const auto first = line.find_first_not_of(" \t\r");
        const auto last = line.find_last_not_of(" \t\r");
        const auto address = line.substr(first, last - first + 1);
        std::uint64_t pc = 0;
        // Legacy symbol-rich lines remain custom; never borrow a hex substring.
        if (crashHex(address, pc)) captured.push_back({fallback, address, pc});
        else captured.push_back({fallback, "", 0});
    }
    if (native && haveInstruction) {
        // If unwinding crossed the signal trampoline, discard the handler prefix.
        // If it did not, retain the best-effort stack and add the interrupted PC.
        const auto interrupted = std::find_if(captured.begin(), captured.end(),
            [&](const auto& f) { return f.pc == instruction; });
        if (interrupted != captured.end()) captured.erase(captured.begin(), interrupted);
    }
    json frames = json::array();
    bool haveNativeFrame = false;
    const auto append = [&](json frame, const std::string& address, std::uint64_t pc) {
        const bool ours = inModule(pc);
        if (ours) {
            frame["platform"] = "native";
            frame["instruction_addr"] = address;
            frame["image_addr"] = report.loadAddress;
            haveNativeFrame = true;
        }
        frames.push_back(std::move(frame));
    };
    for (const auto& frame : captured) append(frame.fallback, frame.address, frame.pc);
    // backtrace() writes innermost first; PostHog expects native stacks bottom-up.
    if (native) std::reverse(frames.begin(), frames.end());
    if (native && haveInstruction && (captured.empty() || captured.front().pc != instruction)) {
        auto fault = report;
        fault.stacktrace = report.instructionAddress;
        append(crashFrames(fault, appName)[0], report.instructionAddress, instruction);
    }
    json props = {{"frames", std::move(frames)}};
    if (haveInstruction) props["crash_instruction_addr"] = report.instructionAddress;
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
