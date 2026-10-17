"""Real optimized/stripped plugin crash -> next-launch HTTP event -> matching dSYM.

No production events or uploads. atos verifies the captured address, not just a
UUID-shaped string or a fabricated report. Server-side PostHog resolution remains
a separate deployment check.
"""
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading


class Receiver(http.server.BaseHTTPRequestHandler):
    events = []

    def do_POST(self):
        event = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if event.get("event") == "$exception":
            self.events.append(event["properties"])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


probe, module, sender = (Path(p).resolve() for p in sys.argv[1:])
with tempfile.TemporaryDirectory(prefix="posthog-real-crash-") as temp:
    root = Path(temp).resolve()
    symbols = {}
    for binary in (probe, module):
        dsym = root / (binary.name + ".dSYM")
        subprocess.run(["dsymutil", str(binary), "-o", str(dsym)], check=True)
        uuids = subprocess.check_output(["dwarfdump", "--uuid", str(dsym)], text=True)
        dwarf = next((dsym / "Contents/Resources/DWARF").iterdir())
        symbols[binary.name] = (re.findall(r"UUID: ([0-9A-Fa-f-]{36})", uuids), dwarf)
        shipped = root / binary.name
        shutil.copy2(binary, shipped)
        subprocess.run(["strip", "-x", str(shipped)], check=True)
        subprocess.run(["codesign", "--force", "--sign", "-", str(shipped)], check=True)
    shipped_probe, shipped_module = root / probe.name, root / module.name
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ, HOME=temp, USERPROFILE=temp, NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    try:
        for binary in (probe, module):
            for scenario in ("signal", "terminate"):
                Receiver.events.clear()
                directory = root / (binary.name + "-" + scenario)
                directory.mkdir()
                command = [str(shipped_probe), "crash", str(directory), scenario]
                if binary == module:
                    command.append(str(shipped_module))
                child = subprocess.run(command, env=env, capture_output=True, timeout=20)
                assert child.returncode in (-signal.SIGSEGV, -signal.SIGBUS, -signal.SIGABRT), child
                saved = json.loads(subprocess.check_output(
                    [str(shipped_probe), "inspect", str(directory)], env=env, text=True, timeout=10))
                expected_ids, dwarf = symbols[binary.name]
                assert saved["debug_id"] in [u.upper() for u in expected_ids], saved
                assert Path(saved["module"]).resolve() == root / binary.name, saved
                subprocess.run([str(sender), str(directory), f"http://127.0.0.1:{server.server_port}",
                                "pending"], check=True, env=env, capture_output=True, timeout=30)
                assert len(Receiver.events) == 1, Receiver.events
                props = Receiver.events[0]
                image = props["$debug_images"][0]
                assert image["debug_id"] == saved["debug_id"]
                assert image["image_addr"] == saved["base"]
                assert image["code_file"] == saved["module"]
                frames = props["$exception_list"][0]["stacktrace"]["frames"]
                native = [f for f in frames if f["platform"] == "native"]
                assert native, props
                if scenario == "signal":
                    assert props["crash_instruction_addr"] == saved["instruction"]
                    assert frames[-1]["instruction_addr"] == saved["instruction"], frames
                    candidates = [frames[-1]]
                    marker = "posthog_test_fault_marker"
                else:
                    assert saved["message"] == "native_fixture_uncaught"
                    candidates = native
                    marker = "posthog_test_terminate_marker"
                resolved = [subprocess.check_output(
                    ["atos", "-arch", platform.machine(), "-o", str(dwarf), "-l", image["image_addr"],
                     (frame["instruction_addr"] if scenario == "signal" else
                      hex(int(frame["instruction_addr"], 16) - 1))], text=True) for frame in candidates]
                assert any(marker in value and re.search(r"\.cpp:\d+", value) for value in resolved), resolved
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
print("real stripped executable/plugin signal and terminate reports resolve to fixture source via matching dSYMs")
