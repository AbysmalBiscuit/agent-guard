#!/usr/bin/env python3
"""Importing the package starts nothing. Run directly: python3 <this file>."""

import json
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent / "plugin"

# A fresh interpreter, so this file's imports are not the package under test.
_PROBE = textwrap.dedent(
    """
    import atexit
    import gc
    import json
    import sys
    import threading

    plugin_root = sys.argv[1]
    sys.path.insert(0, plugin_root)
    sys.argv = ["python3", "--codex", "--grok"]

    def handler_modules():
        # atexit stores (func, args, kwargs). The list is private and has no
        # public reader, so the probe walks the module's referents.
        modules = []
        for referent in gc.get_referents(atexit):
            if not isinstance(referent, list):
                continue
            for entry in referent:
                if isinstance(entry, tuple) and entry and callable(entry[0]):
                    modules.append(getattr(entry[0], "__module__", "") or "")
        return modules

    def snapshot():
        return {
            "timers": sorted(
                type(item).__name__
                for item in threading.enumerate()
                if isinstance(item, threading.Timer)
            ),
            "handlers": sorted(handler_modules()),
            "callbacks": atexit._ncallbacks(),
        }

    before = snapshot()
    read = {"argv": False}
    real = sys.argv

    class Argv:
        def __iter__(self):
            read["argv"] = True
            return iter(real)

        def __getitem__(self, item):
            read["argv"] = True
            return real[item]

        def __len__(self):
            read["argv"] = True
            return len(real)

    sys.argv = Argv()
    import agent_guard
    import agent_guard._state
    import agent_guard.contract
    import agent_guard.dispatch
    import agent_guard.file_checks
    import agent_guard.changeset
    after = snapshot()
    new_handlers = sorted(set(after["handlers"]) - set(before["handlers"]))
    print(json.dumps({
        "timers": after["timers"],
        "new_exit_handlers": new_handlers,
        "callback_delta": after["callbacks"] - before["callbacks"],
        "read_argv": read["argv"],
    }))
    """
)


class ImportSideEffectTests(unittest.TestCase):
    def test_importing_the_package_starts_no_watchdog_registers_no_exit_handler_and_reads_no_argv(
        self,
    ):
        child = subprocess.run(
            [sys.executable, "-c", _PROBE, str(PLUGIN_ROOT)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        report = json.loads(child.stdout)
        self.assertEqual(report["timers"], [])
        self.assertEqual(report["new_exit_handlers"], [])
        self.assertEqual(report["callback_delta"], 0)
        self.assertFalse(report["read_argv"])


if __name__ == "__main__":
    unittest.main()
