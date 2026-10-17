"""Crash/next-launch relocation checks, plus real loopback HTTP when CURL is on."""
import http.server
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading


binary = str(Path(sys.argv[1]).resolve())
use_http = len(sys.argv) > 2 and sys.argv[2] == "http"


def run(*args, crash=False):
    child = subprocess.run([binary, *args], capture_output=True, text=True, timeout=20)
    if crash:
        assert child.returncode != 0, "crash fixture did not crash"
    else:
        assert child.returncode == 0, child.stdout + child.stderr
    return child.stdout


with tempfile.TemporaryDirectory(prefix="posthog-crash-") as temp:
    root = Path(temp)
    # Every HTTP request targets a local capture server, never production.
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    baseline = None
    for i in range(2):
        directory = root / str(i)
        run("crash", str(directory), crash=True)
        captured = json.loads(run("inspect", str(directory)))
        assert captured["message"] == "grouping_test_marker"
        size = int(captured["module_size"], 16)
        assert 0 < size < 256 * 1024 * 1024, "image span missing or includes preferred base/__PAGEZERO"
        app = [f for f in captured["frames"] if f["in_app"]]
        assert len(app) >= 2, "module range missed our real stack"
        assert all(f["function"].startswith("<module>+0x") for f in app), app
        assert all(not f["resolved"] and f["platform"] == "custom" for f in app)
        if baseline is not None:
            assert app == baseline, "same binary/call path changed across launches"
        baseline = app

    if use_http:
        requests = queue.Queue()

        class Capture(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                requests.put(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Capture) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                # Real persisted terminate report through the public SDK API.
                run("upload", str(directory), f"http://127.0.0.1:{server.server_port}")
                event = requests.get(timeout=5)
                props = event["properties"]
                assert event["event"] == "$exception"
                assert props["crash_stacktrace"] == captured["raw"]
                assert props["load_address"] == captured["load_address"]
                exception = props["$exception_list"][0]
                assert exception["value"] == "grouping_test_marker"
                assert exception["mechanism"]["handled"] is False
                assert exception["stacktrace"]["frames"] == captured["frames"]
                assert "$exception_fingerprint" not in props, "SDK must preserve server grouping rules"
                assert not (directory / "pending_crash.txt").exists()
            finally:
                server.shutdown()
                worker.join(timeout=5)

print("real crash/next-launch frame identity passed" + ("; loopback HTTP payload passed" if use_http else ""))
