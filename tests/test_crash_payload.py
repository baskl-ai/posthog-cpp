"""Check complete events through the real install/parse/filter/queue/HTTP path."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


class Receiver(http.server.BaseHTTPRequestHandler):
    events = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.events.append((self.path, json.loads(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


with tempfile.TemporaryDirectory(prefix="posthog-crash-payload-") as temp:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Isolate opt-out checks and all saved SDK state from the user's home.
        env = dict(os.environ, HOME=temp, USERPROFILE=temp, NO_PROXY="127.0.0.1")
        for mode in ("native", "legacy", "invalid"):
            Receiver.events.clear()
            subprocess.run([sys.argv[1], str(Path(temp) / mode),
                            f"http://127.0.0.1:{server.server_port}", mode],
                           check=True, env=env, timeout=20, capture_output=True)
            events = [(path, e) for path, e in Receiver.events if e.get("event") == "$exception"]
            assert len(events) == 1, events
            path, event = events[0]
            assert path == "/i/v0/e/"
            props = event["properties"]
            assert props["crash_from_previous_session"] is True
            exception = props["$exception_list"][0]
            assert exception["type"] == "SIGABRT"
            frames = exception["stacktrace"]["frames"]
            assert len(frames) == 3
            if mode == "native" and sys.platform == "darwin":
                image = props["$debug_images"][0]
                assert image["debug_id"] == "12345678-9ABC-DEF0-1234-56789ABCDEF0"
                assert image["image_addr"] == "0x100000000"
                assert image["image_size"] == 4096
                assert image["code_file"] == "/plugins/example.plugin"
                assert image["type"] == "macho"
                assert frames[0]["instruction_addr"] == "0x100000100"
                assert frames[2]["instruction_addr"] == "0x100000080"
                assert frames[1]["platform"] == "custom"
                assert "image_addr" not in frames[1]
                assert frames[1]["in_app"] is False
            else:
                assert "$debug_images" not in props
                assert all(f["platform"] == "custom" for f in frames)
                assert frames[0]["function"] == "  0x100000080"
                assert all("instruction_addr" not in f for f in frames)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
print("real crash events: native/legacy/invalid metadata checked via loopback HTTP")
