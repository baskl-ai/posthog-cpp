#include <posthog/crash_handler.h>

LONG callFilterFromOtherTranslationUnit() {
    return PostHog::CrashHandler::Internal::exceptionFilter(nullptr);
}

std::uintptr_t moduleAddressFromOtherTranslationUnit() {
    return PostHog::CrashHandler::Internal::g_loadAddress;
}
