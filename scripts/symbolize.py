#!/usr/bin/env python3
"""
Symbolize crash stacktraces from PostHog exception events.

Usage:
    # From PostHog JSON (copy $exception_list from event properties)
    python3 symbolize.py --json exception_list.json --binary ./MyApp.plugin

    # From pending_crash.txt file
    python3 symbolize.py --crash /Library/Application\ Support/BSKL/AI\ MACHINE/CrashReports/pending_crash.txt --binary ./MyPlugin.plugin

    # Symbolize single address
    python3 symbolize.py --addr 0x104507698 --load-addr 0x104504000 --binary ./crash

Requirements:
    - macOS: atos (built-in) or llvm-symbolizer (brew install llvm)
    - Linux: addr2line or llvm-symbolizer
    - Windows: llvm-symbolizer or addr2line (from MinGW/MSYS2)

Note: Binary must be built with debug symbols (-g flag) for full symbolization.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def find_symbolizer():
    """Find available symbolizer tool."""
    system = platform.system()

    if system == "Darwin":
        # macOS: prefer atos, fallback to llvm-symbolizer
        if shutil.which("atos"):
            return "atos"
        if shutil.which("llvm-symbolizer"):
            return "llvm-symbolizer"
        # Try Homebrew LLVM path
        llvm_path = "/opt/homebrew/opt/llvm/bin/llvm-symbolizer"
        if os.path.exists(llvm_path):
            return llvm_path
        llvm_path = "/usr/local/opt/llvm/bin/llvm-symbolizer"
        if os.path.exists(llvm_path):
            return llvm_path
    elif system == "Linux":
        if shutil.which("llvm-symbolizer"):
            return "llvm-symbolizer"
        if shutil.which("addr2line"):
            return "addr2line"
    elif system == "Windows":
        if shutil.which("llvm-symbolizer"):
            return "llvm-symbolizer"
        if shutil.which("addr2line"):
            return "addr2line"

    return None


def symbolize_address_atos(binary: str, load_addr: str, address: str) -> str:
    """Symbolize address using macOS atos."""
    try:
        result = subprocess.run(
            ["atos", "-o", binary, "-l", load_addr, address],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout.strip()
        if output and not output.startswith("0x"):
            return output
    except Exception as e:
        print(f"  atos error: {e}", file=sys.stderr)
    return None


def symbolize_address_llvm(binary: str, address: str) -> str:
    """Symbolize address using llvm-symbolizer."""
    symbolizer = find_symbolizer()
    if not symbolizer or "llvm-symbolizer" not in symbolizer:
        return None

    try:
        result = subprocess.run(
            [symbolizer, "-e", binary, "-f", "-C", address],
            capture_output=True,
            text=True,
            timeout=5
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 2 and lines[0] != "??":
            return f"{lines[0]} at {lines[1]}"
        elif len(lines) >= 1 and lines[0] != "??":
            return lines[0]
    except Exception as e:
        print(f"  llvm-symbolizer error: {e}", file=sys.stderr)
    return None


def symbolize_address_addr2line(binary: str, address: str) -> str:
    """Symbolize address using addr2line."""
    try:
        result = subprocess.run(
            ["addr2line", "-e", binary, "-f", "-C", "-p", address],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout.strip()
        if output and "??" not in output:
            return output
    except Exception as e:
        print(f"  addr2line error: {e}", file=sys.stderr)
    return None


def symbolize_address(binary: str, load_addr: str, address: str) -> str:
    """Symbolize a single address using available tools."""
    system = platform.system()

    # Try atos first on macOS (best results)
    if system == "Darwin" and load_addr:
        result = symbolize_address_atos(binary, load_addr, address)
        if result:
            return result

    # Calculate offset for other tools
    if load_addr:
        try:
            addr_int = int(address, 16)
            load_int = int(load_addr, 16)
            offset = addr_int - load_int
            offset_addr = hex(offset)
        except ValueError:
            offset_addr = address
    else:
        offset_addr = address

    # Try llvm-symbolizer
    result = symbolize_address_llvm(binary, offset_addr)
    if result:
        return result

    # Try addr2line
    result = symbolize_address_addr2line(binary, offset_addr)
    if result:
        return result

    return None


def parse_crash_file(crash_path: str) -> dict:
    """Parse pending_crash.txt file."""
    with open(crash_path, 'r') as f:
        content = f.read()

    result = {
        "signal": None,
        "timestamp": None,
        "load_address": None,
        "exec_path": None,
        "addresses": []
    }

    for line in content.split('\n'):
        if line.startswith("SIGNAL: "):
            result["signal"] = line[8:]
        elif line.startswith("TIME: "):
            result["timestamp"] = line[6:]
        elif line.startswith("LOAD_ADDR: "):
            result["load_address"] = line[11:]
        elif line.startswith("EXEC_PATH: "):
            result["exec_path"] = line[11:]
        elif line.strip().startswith("0x"):
            result["addresses"].append(line.strip())

    return result


def parse_exception_list_data(data) -> dict:
    """Parse PostHog $exception_list JSON data."""

    # Handle both array and single object
    if isinstance(data, list):
        exception = data[0] if data else {}
    else:
        exception = data

    result = {
        "signal": exception.get("type", "Unknown"),
        "load_address": None,
        "addresses": []
    }

    # Extract addresses from stacktrace frames
    stacktrace = exception.get("stacktrace", {})
    frames = stacktrace.get("frames", [])

    for frame in frames:
        # Try mangled_name first (PostHog format), then function
        func = frame.get("mangled_name", "") or frame.get("function", "")
        # Extract address from function field (format: "  0x12345678" or "0x12345678")
        match = re.search(r'0x[0-9a-fA-F]+', func)
        if match:
            result["addresses"].append(match.group(0))

    return result


def parse_exception_list(json_path: str) -> dict:
    """Parse PostHog $exception_list JSON from file."""
    with open(json_path, 'r') as f:
        data = json.load(f)
    return parse_exception_list_data(data)


def parse_exception_list_stdin() -> dict:
    """Parse PostHog $exception_list JSON from stdin."""
    data = json.load(sys.stdin)
    return parse_exception_list_data(data)


def parse_exception_list_clipboard() -> dict:
    """Parse PostHog $exception_list JSON from clipboard (macOS)."""
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=5
        )
        data = json.loads(result.stdout)
        return parse_exception_list_data(data)
    except FileNotFoundError:
        print("Error: pbpaste not found (macOS only)", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in clipboard: {e}", file=sys.stderr)
        sys.exit(1)


def symbolize_crash(crash_data: dict, binary: str, load_addr_override: str = None):
    """Symbolize all addresses in crash data."""
    load_addr = load_addr_override or crash_data.get("load_address")

    print(f"Signal: {crash_data.get('signal', 'Unknown')}")
    if crash_data.get("timestamp"):
        print(f"Time: {crash_data['timestamp']}")
    print(f"Load Address: {load_addr or 'Unknown'}")
    print(f"Binary: {binary}")
    print()
    print("Symbolized Stacktrace:")
    print("-" * 60)

    for i, addr in enumerate(crash_data.get("addresses", [])):
        symbol = symbolize_address(binary, load_addr, addr)
        if symbol:
            print(f"  #{i}: {addr}")
            print(f"       {symbol}")
        else:
            print(f"  #{i}: {addr} (no symbol)")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Symbolize crash stacktraces from PostHog events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--json", "-j",
        help="Path to $exception_list JSON file (use '-' for stdin)"
    )
    input_group.add_argument(
        "--crash", "-c",
        help="Path to pending_crash.txt file"
    )
    input_group.add_argument(
        "--addr", "-a",
        help="Single address to symbolize"
    )
    input_group.add_argument(
        "--paste", "-p",
        action="store_true",
        help="Read JSON from clipboard (macOS only)"
    )

    parser.add_argument(
        "--binary", "-b",
        required=True,
        help="Path to executable/plugin binary (with debug symbols)"
    )
    parser.add_argument(
        "--load-addr", "-l",
        help="Override load address (hex, e.g., 0x104504000)"
    )

    args = parser.parse_args()

    # Check binary exists
    if not os.path.exists(args.binary):
        print(f"Error: Binary not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    # Check symbolizer available
    symbolizer = find_symbolizer()
    if not symbolizer:
        print("Error: No symbolizer found.", file=sys.stderr)
        print("Please install one of:", file=sys.stderr)
        print("  - macOS: atos (built-in) or llvm-symbolizer (brew install llvm)", file=sys.stderr)
        print("  - Linux: llvm-symbolizer or addr2line", file=sys.stderr)
        print("  - Windows: llvm-symbolizer or addr2line (from MSYS2)", file=sys.stderr)
        sys.exit(1)

    print(f"Using symbolizer: {symbolizer}")
    print()

    if args.addr:
        # Single address mode
        symbol = symbolize_address(args.binary, args.load_addr, args.addr)
        print(f"Address: {args.addr}")
        print(f"Symbol: {symbol or '(no symbol)'}")

    elif args.paste:
        # Clipboard mode (macOS)
        print("Reading JSON from clipboard...")
        crash_data = parse_exception_list_clipboard()
        symbolize_crash(crash_data, args.binary, args.load_addr)

    elif args.json:
        if args.json == '-':
            # Stdin mode
            print("Reading JSON from stdin...")
            crash_data = parse_exception_list_stdin()
        else:
            # File mode
            crash_data = parse_exception_list(args.json)
        symbolize_crash(crash_data, args.binary, args.load_addr)

    elif args.crash:
        # Crash file mode
        crash_data = parse_crash_file(args.crash)
        symbolize_crash(crash_data, args.binary, args.load_addr)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
