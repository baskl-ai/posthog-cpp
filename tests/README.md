# PostHog C++ Tests

## Building Tests

```bash
cmake -B build -S . -DPOSTHOG_BUILD_TESTS=ON
cmake --build build --config Release
```

## Running Tests

### Basic Test
Tests basic PostHog functionality (events, properties):
```bash
cd build/tests/Release
POSTHOG_API_KEY=phc_xxx ./basic
```

### Crash Handler Test
Tests crash handler and stacktrace capture:

**Step 1: Trigger crash**
```bash
cd build/tests/Release
POSTHOG_API_KEY=phc_xxx ./crash
```

**Step 2: Send crash report**
```bash
POSTHOG_API_KEY=phc_xxx ./crash check
```

The crash report will include:
- Signal/exception type
- Timestamp
- Platform info
- **Full stacktrace** (Windows: CaptureStackBackTrace, Unix: backtrace)
- Executable path and load address

Check PostHog dashboard for `$exception` event with `crash_from_previous_session=true`.

## Windows Notes

On Windows:
- Use `set POSTHOG_API_KEY=phc_xxx` instead of `export`
- Or run directly: `crash.exe` (without POSTHOG_API_KEY it will still save crash locally)
- Crash files are saved to: `%TEMP%\posthog_crash_test\`

### Symbolizing Windows Crash Reports

Crash reports on Windows automatically include:
- **System function names** (Windows DLLs like ntdll.dll, kernel32.dll) - always available
- **User function names and line numbers** - requires PDB files

To get full symbolization with file names and line numbers for your code:
1. Build with debug info: `/Zi` (MSVC) or `-g` (MinGW/GCC)
2. Keep PDB files next to the executable
3. The crash handler will automatically symbolize using DbgHelp API

If symbols are not available at crash time, you can symbolize manually:

**Method 1: Using addr2line (if built with MinGW/GCC)**
```bash
addr2line -e crash.exe -f -C 0x00007FF79FA46988
```

**Method 2: Using Windows Debugger (WinDbg)**
1. Open WinDbg
2. File → Open Executable → `crash.exe`
3. Load symbols: `.sympath+ build\tests\Release`
4. Use `ln` command with addresses from crash report:
   ```
   ln 0x00007FF79FA46988
   ```

**Method 3: Using Visual Studio Developer Command Prompt**
```cmd
dumpbin /disasm crash.exe | findstr "00007FF79FA46988"
```

**Method 4: Automated symbolization script** (Python example)
```python
import subprocess
import re

# Read crash report
with open('pending_crash.txt', 'r') as f:
    crash_data = f.read()

# Extract addresses
load_addr = int(re.search(r'LOAD_ADDR: 0x([0-9a-fA-F]+)', crash_data).group(1), 16)
addresses = re.findall(r'0x([0-9a-fA-F]+)', crash_data)

# Symbolize each address
for addr_str in addresses:
    addr = int(addr_str, 16)
    offset = addr - load_addr  # Calculate offset from module base
    # Use addr2line, llvm-symbolizer, or Windows DbgHelp API
    print(f"Address: {addr_str} -> Offset: {hex(offset)}")
```

The crash report includes `LOAD_ADDR` (module base address) which you need to calculate offsets for symbolization.

## macOS/Linux Notes

### Symbolizing macOS/Linux Crash Reports

**Method 1: Using llvm-symbolizer (recommended)**
```bash
# Install if needed
brew install llvm  # macOS
apt-get install llvm  # Linux

# Symbolize addresses
llvm-symbolizer -e ./crash 0x104507698
```

**Method 2: Using atos (macOS only)**
```bash
# Read crash report to get load address and stack addresses
atos -o ./crash -l 0x104504000 0x10450769c 0x104505bf4
```

**Method 3: Using addr2line (Linux/macOS with GCC)**
```bash
addr2line -e ./crash -f -C -p 0x10450769c
```

**Method 4: Automated script for macOS**
```bash
#!/bin/bash
# symbolize_crash.sh
CRASH_FILE="$1"
EXECUTABLE="$2"

LOAD_ADDR=$(grep "Load address:" "$CRASH_FILE" | awk '{print $3}')
ADDRESSES=$(grep "^  0x" "$CRASH_FILE" | awk '{print $1}')

echo "Symbolizing crash from $CRASH_FILE"
echo "Load address: $LOAD_ADDR"
echo ""

for addr in $ADDRESSES; do
    echo "Address: $addr"
    atos -o "$EXECUTABLE" -l "$LOAD_ADDR" "$addr"
    echo ""
done
```

Usage:
```bash
chmod +x symbolize_crash.sh
./symbolize_crash.sh /tmp/posthog_crash_test/pending_crash.txt ./crash
```

The stacktrace on macOS/Linux includes raw addresses that need to be symbolized using the executable and DWARF debug info (compile with `-g` flag).
