#ifndef POSTHOG_CRASH_FRAMES_H
#define POSTHOG_CRASH_FRAMES_H

#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <limits>
#include <vector>

namespace PostHog {
namespace detail {

inline bool crashHexAddress(const std::string& text, std::uint64_t& value) {
    if (text.size() <= 2 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    const auto parsed = std::from_chars(text.data() + 2, text.data() + text.size(), value, 16);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
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
inline nlohmann::json crashFrameProperties(const CrashHandler::Report& report) {
    using json = nlohmann::json;
    std::uint64_t base = 0, size = 0, instruction = 0;
    const bool native = report.platform == "macOS" && crashDebugId(report.debugId)
        && crashHexAddress(report.loadAddress, base) && base > 0
        && crashHexAddress(report.moduleSize, size) && size > 0
        && size <= (std::numeric_limits<std::uint64_t>::max)() - base;
    const bool haveInstruction = crashHexAddress(report.instructionAddress, instruction) && instruction != 0;
    const auto inModule = [&](std::uint64_t pc) { return native && pc >= base && pc - base < size; };
    struct CapturedFrame { std::string raw, address; std::uint64_t pc; };
    std::vector<CapturedFrame> captured;
    std::istringstream lines(report.stacktrace);
    std::string line;
    while (std::getline(lines, line)) {
        auto start = line.find("0x");
        if (start == std::string::npos) start = line.find("0X");
        if (start == std::string::npos) continue;
        const auto end = line.find_first_of(" \t\r])", start);
        const auto address = line.substr(start, end == std::string::npos ? end : end - start);
        std::uint64_t pc = 0;
        if (crashHexAddress(address, pc)) captured.push_back({line, address, pc});
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
    const auto append = [&](const std::string& raw, const std::string& address, std::uint64_t pc) {
        const bool ours = inModule(pc);
        json frame = {{"platform", ours ? "native" : "custom"}, {"lang", "cpp"},
                      {"function", raw}, {"in_app", native ? ours : true}, {"resolved", false}};
        if (ours) {
            frame["instruction_addr"] = address;
            frame["image_addr"] = report.loadAddress;
            haveNativeFrame = true;
        }
        frames.push_back(std::move(frame));
    };
    for (const auto& frame : captured) append(frame.raw, frame.address, frame.pc);
    // backtrace() writes innermost first; PostHog expects native stacks bottom-up.
    if (native) std::reverse(frames.begin(), frames.end());
    if (native && haveInstruction && (captured.empty() || captured.front().pc != instruction)) {
        append("fault instruction " + report.instructionAddress, report.instructionAddress, instruction);
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
