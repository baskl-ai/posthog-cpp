#include <posthog/crash_handler.h>
#include <nlohmann/json.hpp>
#include <dlfcn.h>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) return 2;
    if (argc == 3) {
        void* module = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (!module) { std::cerr << dlerror(); return 1; }
        auto query = reinterpret_cast<const char* (*)(const char*)>(dlsym(module, "posthog_test_metadata"));
        if (!query) return 1;
        std::cout << query(argv[1]) << '\n';
        // The module owns registered handlers. Keep it loaded until process exit.
    } else {
        namespace internal = PostHog::CrashHandler::Internal;
        PostHog::CrashHandler::install(argv[1]);
        std::cout << nlohmann::json{{"debug_id", internal::g_debugId},
                                  {"image_size", internal::g_moduleSize},
                                  {"code_file", internal::g_execPath}}.dump() << '\n';
    }
}
