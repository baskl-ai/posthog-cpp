#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <stdexcept>

extern "C" __attribute__((visibility("default"))) const char* posthog_test_metadata(const char* dir) {
    namespace internal = PostHog::CrashHandler::Internal;
    PostHog::CrashHandler::install(dir);
    static std::string result;
    result = nlohmann::json{{"debug_id", internal::g_debugId},
                           {"image_size", internal::g_moduleSize},
                           {"code_file", internal::g_execPath}}.dump();
    return result.c_str();
}

// Real optimized fault/terminate sites, shared by the executable and plugin fixture.
// Reading a volatile target prevents optimization into a different trap instruction.
__attribute__((noinline)) void posthog_test_fault_marker() {
    volatile std::uintptr_t target = 1;
    *reinterpret_cast<volatile int*>(target) = 42;
}

__attribute__((noinline)) void posthog_test_terminate_marker() {
    throw std::runtime_error("native_fixture_uncaught");
}

extern "C" __attribute__((visibility("default"))) void posthog_test_crash(
    const char* dir, const char* mode) {
    PostHog::CrashHandler::install(dir);
    if (std::strcmp(mode, "signal") == 0) posthog_test_fault_marker();
    else posthog_test_terminate_marker();
}
