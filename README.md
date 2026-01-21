# posthog-cpp

Lightweight C++ SDK for [PostHog](https://posthog.com) analytics with crash reporting.

Cross-platform: **macOS** (arm64, x86_64), **Windows** (x64, x86, arm64), **Linux** (x86_64, aarch64)

## Quick Start

### CMake Integration

```cmake
include(FetchContent)

FetchContent_Declare(
    posthog
    GIT_REPOSITORY https://github.com/bskl-xyz/posthog-cpp.git
    GIT_TAG main
)

# Disable bundled curl if your project already provides it
set(POSTHOG_USE_CURL OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(posthog)

target_link_libraries(your_app PRIVATE posthog)
```

### Basic Usage

```cpp
#include <posthog/posthog.h>

int main() {
    PostHog::Config config;
    config.apiKey = "phc_xxx";
    config.appName = "MyApp";
    config.appVersion = "1.0.0";
    config.host = "https://us.i.posthog.com";  // or https://eu.i.posthog.com

    PostHog::Client client(config);
    client.initialize();

    // Track events
    client.track("app_started", {
        {"feature", "analytics"}
    });

    // Track exceptions (captures stack trace with function names)
    try {
        riskyOperation();
    } catch (const std::exception& e) {
        client.trackException("RuntimeError", e.what(), "component_name");
    }

    client.shutdown();
    return 0;
}
```

## Features

- **Event tracking** — custom events with properties
- **Exception tracking** — captures stack traces at runtime (function names resolved)
- **Crash reporting** — intercepts SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL (signal-safe)
- **Machine ID** — unique anonymous identifier per device
- **Async queue** — non-blocking event dispatch with background thread
- **Bundled dependencies** — nlohmann/json included, libcurl optional

## Crash Reporting

Crash handler saves stack trace to disk during crash (network unavailable in signal handlers). On next app launch, the report is sent to PostHog.

### Setup

```cpp
PostHog::Client client(config);
client.initialize();

// Install crash handler (uses default directory based on config.appName)
client.installCrashHandler();

// Or specify custom directory (must exist or parent must exist)
client.installCrashHandler("/path/to/crash/dir");

// Optional: add metadata for crash reports
client.setCrashMetadata({
    {"build_id", "abc123"},
    {"license_type", "pro"},
    {"last_action", "importing_file"}
});
```

### Default Crash Directories

Based on `config.appName`:

| Platform | Path |
|----------|------|
| **Windows** | `%APPDATA%\{appName}\CrashReports` |
| **macOS** | `~/Library/Application Support/{appName}/CrashReports` |
| **Linux** | `~/.local/share/{appName}/crash_reports` |

### How It Works

1. **Crash occurs** → signal handler saves raw addresses to `pending_crash.txt`
2. **Next launch** → `installCrashHandler()` detects the file and sends `$exception` event
3. **PostHog** → shows crash in Error Tracking

### Symbolization

Crash stack traces contain only memory addresses. To get function names and line numbers:

```bash
python scripts/symbolize.py \
    --executable /path/to/MyApp \
    --load-address 0x104504000 \
    --addresses 0x104507698 0x104505bf4 0x104506a10
```

**Requirements:**
- Original executable (same build that crashed)
- Debug symbols: `.dSYM` (macOS), `.pdb` (Windows), or debug build (Linux)
- Load address from crash report (`load_address` property in PostHog)

**Output:**
```
0x104507698 -> main (main.cpp:42)
0x104505bf4 -> processData (processor.cpp:128)
```

### Runtime Exceptions vs Crashes

|                      | `trackException()`  | Crash Handler              |
|----------------------|---------------------|----------------------------|
| **When**             | Runtime (try/catch) | Signal (SIGSEGV, etc.)     |
| **Function names**   | ✅ Resolved         | ❌ Addresses only           |
| **Line numbers**     | ❌ No               | ❌ No (needs symbolization) |
| **Sent immediately** | ✅ Yes              | ❌ Next launch              |

## Known Issues

### Windows: VS2022 17.10+ mutex crash

Visual Studio 2022 v17.10 introduced a breaking change with `std::mutex`. The library includes a workaround, but it may not work in all scenarios (including GitHub Actions).

**Workaround:** Add to your project:
```cmake
target_compile_definitions(your_app PRIVATE _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR)
```

### CURL conflicts

If your project already uses libcurl, disable bundled curl:

```cmake
set(POSTHOG_USE_CURL OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(posthog)
```

The library will use whichever curl target is available (`libcurl_static` or `CURL::libcurl`).

## API Reference

See [include/posthog/posthog.h](include/posthog/posthog.h) for full API (Doxygen comments).

**Main classes:**
- `PostHog::Config` — client configuration
- `PostHog::Client` — analytics client

**Header-only utilities:**
- `posthog/machine_id.h` — cross-platform machine ID
- `posthog/stacktrace.h` — stack trace capture
- `posthog/crash_handler.h` — signal handler

## License

See [LICENSE](LICENSE)

## Support our work
If you appreciate this free software and would like to leave a donation, [you can do so here](https://donate.stripe.com/14AcN65uL9J2g6h8UObsc01) (adjust the quantity to change the $ amount)!