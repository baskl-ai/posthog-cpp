#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>

extern "C" __attribute__((visibility("default"))) const char* posthog_test_metadata(const char* dir) {
    namespace internal = PostHog::CrashHandler::Internal;
    PostHog::CrashHandler::install(dir);
    static std::string result;
    result = nlohmann::json{{"debug_id", internal::g_debugId},
                           {"image_size", internal::g_moduleSize},
                           {"code_file", internal::g_execPath}}.dump();
    return result.c_str();
}
