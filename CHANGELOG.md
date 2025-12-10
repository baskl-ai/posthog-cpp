# Changelog

## [1.0.0] - 2024-12-10

### Added
- `PostHog::Client` for event tracking
- Cross-platform crash handler (SIGSEGV, SIGABRT, etc.)
- Cross-platform stacktrace capture with `$exception_list` format
- Cross-platform machine ID generation
- Bundled nlohmann/json 3.12.0 (optional via `POSTHOG_USE_BUNDLED_JSON`)
- Async event queue with background worker thread
- Optional libcurl support (`POSTHOG_USE_CURL`)
