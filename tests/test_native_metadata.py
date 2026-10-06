"""Compare installed UUIDs against the same dwarfdump source used by the CLI."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

probe, module = map(lambda p: Path(p).resolve(), sys.argv[1:])
with tempfile.TemporaryDirectory(prefix="posthog-native-metadata-") as temp:
    for binary in (probe, module):
        args = [str(probe), temp] + ([str(module)] if binary == module else [])
        metadata = json.loads(subprocess.check_output(args, text=True))
        # Exercise a real dSYM, not just UUID formatting against a stubbed header.
        dsym = str(Path(temp) / (binary.name + ".dSYM"))
        subprocess.run(["dsymutil", str(binary), "-o", dsym], check=True)
        uuids = subprocess.check_output(["dwarfdump", "--uuid", dsym], text=True)
        expected = re.findall(r"UUID: ([0-9A-Fa-f-]{36})", uuids)
        assert metadata["debug_id"] in [u.upper() for u in expected], (metadata, uuids)
        assert Path(metadata["code_file"]).resolve() == binary, metadata
        assert 0 < metadata["image_size"] < 1024 * 1024 * 1024, metadata
print("executable and plugin module UUIDs match their dSYMs; module paths/ranges valid")
