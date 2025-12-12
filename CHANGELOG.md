# Changelog

## [1.1.0] - 2024-12-12

### Added
- `setCrashMetadata()` method to include custom properties in crash reports
- `CrashHandler::saveMetadata()` / `loadMetadata()` for persistent crash context
- Crash reports now include metadata from previous session (build info, license, etc.)

## [1.0.1] - 2024-12-10

### Added
- Windows DbgHelp symbolization for crash reports (function names and line numbers)
- Comprehensive testing documentation with symbolization guides
- Platform-specific temp directory handling (%TEMP% on Windows, /tmp on Unix)

### Changed
- Renamed examples/ → tests/ for clarity
- CMake option: POSTHOG_BUILD_EXAMPLES → POSTHOG_BUILD_TESTS
- Improved curl detection: check FetchContent target before system curl
- Fetch curl only for tests if parent project doesn't provide it

### Fixed
- Windows stacktrace now captures full call stack (CaptureStackBackTrace)
- Curl integration works when posthog-cpp is used via FetchContent

## [1.0.0] - 2024-12-10

### Added
- `PostHog::Client` for event tracking
- Cross-platform crash handler (SIGSEGV, SIGABRT, etc.)
- Cross-platform stacktrace capture with `$exception_list` format
- Cross-platform machine ID generation
- Bundled nlohmann/json 3.12.0 (optional via `POSTHOG_USE_BUNDLED_JSON`)
- Async event queue with background worker thread
- Optional libcurl support (`POSTHOG_USE_CURL`)
