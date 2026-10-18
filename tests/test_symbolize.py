import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch, call

spec = importlib.util.spec_from_file_location("symbolize", Path(__file__).parents[1] / "scripts" / "symbolize.py")
symbolize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(symbolize)


class SymbolizeTests(unittest.TestCase):
    def setUp(self):
        self.exception = {"type": "SIGSEGV", "stacktrace": {"frames": [
            {"function": "<module>+0x123"}, {"mangled_name": "  0x700000abc"},
        ]}}

    def test_full_event_keeps_raw_addresses_and_load_address(self):
        props = {"crash_stacktrace": "  0x100000123\n  0x700000abc\n",
                 "load_address": "0x100000000", "$exception_list": [self.exception]}
        for data in (props, {"properties": props}):
            parsed = symbolize.parse_exception_list_data(data)
            self.assertEqual(parsed["addresses"], ["0x100000123", "0x700000abc"])
            self.assertEqual(parsed["load_address"], "0x100000000")

    def test_mixed_frames_are_converted_individually(self):
        parsed = symbolize.parse_exception_list_data([self.exception])
        with patch.object(symbolize, "symbolize_address", return_value="test") as lookup:
            with contextlib.redirect_stdout(io.StringIO()):
                symbolize.symbolize_crash(parsed, "binary", "0x100000000")
            # Reconstruct the original runtime address before atos receives it;
            # system-library addresses must never receive the module base again.
            self.assertEqual(lookup.call_args_list, [
                call("binary", "0x100000000", "0x100000123"),
                call("binary", "0x100000000", "0x700000abc"),
            ])

    def test_no_load_address_does_not_guess_macho_preferred_base(self):
        with patch.object(symbolize, "symbolize_address") as lookup:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                symbolize.symbolize_crash(symbolize.parse_exception_list_data(self.exception), "binary")
            self.assertIn("needs --load-addr", output.getvalue())
            lookup.assert_called_once_with("binary", None, "0x700000abc")

    def test_legacy_raw_list_and_empty_input(self):
        legacy = [{"type": "SIGABRT", "stacktrace": {"frames": [{"function": "  0x1234"}]}}]
        self.assertEqual(symbolize.parse_exception_list_data(legacy)["addresses"], ["0x1234"])
        self.assertEqual(symbolize.parse_exception_list_data([])["addresses"], [])


if __name__ == "__main__":
    unittest.main()
