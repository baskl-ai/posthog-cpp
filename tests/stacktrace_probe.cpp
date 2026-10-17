#include "../src/exception_frames.h"
#include <iostream>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

using Frames = std::vector<PostHog::Stacktrace::Frame>;
static volatile int visited = 0;

static NOINLINE Frames leaf() {
    auto frames = PostHog::Stacktrace::captureStructured(32, 0, "stacktrace_probe");
    ++visited; // Keep optimized builds from tail-calling away our fixture stack.
    return frames;
}
static NOINLINE Frames callerA() {
    auto frames = leaf();
    visited += 2;
    return frames;
}
static NOINLINE Frames callerB() {
    auto frames = leaf();
    visited += 3;
    return frames;
}
static NOINLINE Frames outer(bool alternate) {
    auto frames = alternate ? callerB() : callerA();
    ++visited;
    return frames;
}
int main(int argc, char**) {
    const auto frames = outer(argc > 1);
    std::cout << nlohmann::json({
        {"frames", PostHog::detail::exceptionFrames(frames)},
        {"probe_address", reinterpret_cast<uintptr_t>(&leaf)}
    }).dump() << '\n';
}
