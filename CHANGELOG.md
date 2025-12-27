# Changelog

## [1.4.1] - 2025-12-27

### Fixed
- Actually use `hasAddressesFromOurModule()` filter in `installCrashHandler()` to prevent reporting crashes from other plugins/host app
- Add `MODULE_SIZE` to `std::set_terminate` handler (was missing, causing filter to fail for terminate crashes)

## [1.4.0] - 2025-12-22

### Added
- `setPersonProperties()` method for setting person properties with `$set` or `$set_once`
- Support for setting user properties to enable analytics filtering by internal/external users

## [1.3.0] - 2025-12-19

### Added
- `hasAddressesFromOurModule()` function to filter out host app crashes
- `MODULE_SIZE` field in crash reports for address range filtering
- Module size tracking on macOS (mach-o header parsing) and Windows (MODULEINFO)

### Changed
- Crash filtering requires 2+ frames from our module (1 is always crash handler itself)

## [1.2.0] - 2025-12-15

### Changed
- `generateMachineId()` now uses MAC address + SHA256 hash (Python uuid.getnode() compatible)
- Added `generateMachineId(fallbackPath)` overload for file-based ID persistence
- Added bundled picosha2.h for SHA256 hashing
- CI now compares C++ and Python ID generation to ensure compatibility

### Removed
- Old hardware-based ID generation (IOPlatformUUID, MachineGuid, /etc/machine-id)

## [1.1.2] - 2025-12-15

### Added
- `posthog_cpp_version` property in all events (SDK version tracking)
- README.md with documentation
- GitHub Actions CI (build matrix: Windows, macOS, Linux)
- Unit tests without network (MachineID, Stacktrace, Client init)

### Changed
- Combined platform info into single `$os` field (e.g., "Mac OS X arm64 15.5", "Windows x64 10.0.22631")
- Removed separate `platform` and `os_version` fields
- Default crash directory now uses user-writable paths instead of system paths:
  - Windows: `%APPDATA%/{appName}/CrashReports`
  - macOS: `~/Library/Application Support/{appName}/CrashReports`
  - Linux: `~/.local/share/{appName}/crash_reports`

### Removed
- `POSTHOG_USE_BUNDLED_JSON` CMake option (was non-functional, nlohmann/json is always bundled)
- Added `JSON_SKIP_LIBRARY_VERSION_CHECK` to avoid warnings when parent project uses different nlohmann/json version

## [1.1.1] - 2025-12-13

### Fixed
- Windows crash in `PostHog::Client::Impl::workerLoop()` by adding `_DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR` define for MSVC builds

## [1.1.0] - 2024-12-12

### Added
- `setCrashMetadata()` method to include custom properties in crash reports
- `CrashHandler::saveMetadata()` / `loadMetadata()` for persistent crash context
- Crash reports now include metadata from previous session (build info, license, etc.)
- `scripts/symbolize.py` - cross-platform crash stacktrace symbolizer (atos, llvm-symbolizer, addr2line)

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
