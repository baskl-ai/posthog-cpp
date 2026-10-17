"""Exercise optimized, symbol-free capture and its actual JSON wire fields."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def capture(binary, alternate=False):
    result = json.loads(subprocess.check_output(
        [str(binary)] + (["alternate"] if alternate else []), text=True))
    frames = result["frames"]
    assert frames, "capture returned no frames"
    assert all(not f["function"].startswith("0x") for f in frames), frames
    app = [f for f in frames if "stacktrace_probe" in f.get("module", "")]
    assert len(app) >= 3, f"optimized unwind stopped early: {app}"
    offsets = [f for f in app if f["function"].startswith("<module>+0x")]
    assert len(offsets) >= 3, f"fixture did not exercise symbol-free frames: {app}"
    assert all(not f["resolved"] for f in offsets), offsets
    assert all(f["in_app"] for f in app), app
    assert all("/" not in f.get("filename", "") and "\\" not in f.get("filename", "")
               for f in offsets), offsets
    return app, result["probe_address"]


binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="posthog-stacktrace-") as temp:
    copies = []
    for name in ("installation-a", "installation-b"):
        destination = Path(temp) / name / binary.name
        destination.parent.mkdir()
        shutil.copy2(binary, destination)  # Intentionally do not copy debug symbols.
        copies.append(destination)
    baseline, _ = capture(copies[0])
    addresses = set()
    for copied in copies:
        for _ in range(3):
            frames, address = capture(copied)
            assert frames == baseline, "frame identity changed across process/path relocation"
            addresses.add(address)
        different, _ = capture(copied, alternate=True)
        assert different != baseline, "different call sites collapsed into one identity"
    print("stable wire frames across 6 launches and 2 installation paths; "
          f"observed ASLR relocation: {len(addresses) > 1}")
