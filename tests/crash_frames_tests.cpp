#include "../src/crash_frames.h"
#include <iostream>
#include <stdexcept>

using PostHog::CrashHandler::Report;
using PostHog::detail::crashFrames;

static void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

int main() {
    Report a;
    a.loadAddress = "0x100000000";
    a.moduleSize = "0x1000";
    a.stacktrace = "  0x100000000\n  0x100000123\n  0x100000fff\n  0x100001000\n  0xfffffff\n";
    auto frames = crashFrames(a);
    check(frames.size() == 5, "frame count changed");
    check(frames[0]["function"] == "<module>+0x0", "base must be inclusive");
    check(frames[1]["function"] == "<module>+0x123", "wrong offset");
    check(frames[2]["function"] == "<module>+0xfff", "last byte is in module");
    check(frames[3]["function"] == "  0x100001000", "end must be exclusive");
    check(frames[4]["function"] == "  0xfffffff", "address below base rewritten");
    check(!frames[3]["in_app"].get<bool>() && !frames[4]["in_app"].get<bool>(),
          "external frames marked in app");
    for (const auto& f : frames) {
        check(f["platform"] == "custom" && !f["resolved"].get<bool>(),
              "offsets must not claim native symbolication");
    }

    Report b = a;
    b.loadAddress = "0x700000000";
    b.stacktrace = "0x700000000\n0x700000123\n0x700000fff\n";
    const auto relocated = crashFrames(b);
    for (int i = 0; i < 3; ++i) check(relocated[i] == frames[i], "ASLR changes module frame identity");
    check(crashFrames(a, "plugin_a")[1]["module"] == "plugin_a", "logical module name missing");
    check(crashFrames(a, "plugin_a")[1] != crashFrames(a, "plugin_b")[1],
          "different application modules have identical frame inputs");
    b.stacktrace = "0x700000124\n";
    check(crashFrames(b)[0] != frames[1], "different instruction offsets collapsed");

    for (const auto& bad : {"", "0", "0x0", "-1000", "+1000", " 1000", "0x", "1000junk",
                            "10000000000000000", "ffffffffffffffff"}) {
        auto invalid = a;
        invalid.moduleSize = bad;
        check(crashFrames(invalid)[1]["function"] == "  0x100000123",
              "invalid or overflowing size normalized frames");
    }
    for (const auto& bad : {"", "0", "-1", "+1", " 1000", "1000junk", "0x", "10000000000000000"}) {
        auto invalid = a;
        invalid.loadAddress = bad;
        check(crashFrames(invalid)[1]["function"] == "  0x100000123", "invalid base normalized frames");
    }
    b = a;
    b.stacktrace = "text 0x100000123\n0x100000123 0x100000124\n0x100000123garbage\n0X100000ABC\n\t0x100000123\r\n";
    const auto legacy = crashFrames(b);
    check(legacy[0]["function"] == "text 0x100000123", "rewrote legacy symbol-rich text");
    check(legacy[1]["function"] == "0x100000123 0x100000124", "rewrote multiple hex tokens");
    check(legacy[2]["function"] == "0x100000123garbage", "accepted trailing junk");
    check(legacy[3]["function"] == "<module>+0xabc", "uppercase address rejected");
    check(legacy[4]["function"] == "<module>+0x123", "CRLF frame rejected");
    b = a;
    b.stacktrace = "no frames\n";
    check(crashFrames(b).empty(), "invented a frame");
    std::cout << "crash frame payload checks passed\n";
}
