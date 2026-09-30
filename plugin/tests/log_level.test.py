#!/usr/bin/env python3
"""Cases for where the log level comes from. Run directly: python3 <this file>.

Each case drives the hook end to end with a Stop payload, which logs its one
invoke line and then exits because no root asked for the changeset layer.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "agent_guard.py"


class LogLevelTests(unittest.TestCase):
    def test_config_alone_turns_logging_on(self):
        self.assertIn('hook="Stop"', self.run_hook("log = 1\n"))

    def test_config_zero_stays_silent(self):
        self.assertEqual(self.run_hook("log = 0\n"), "")

    def test_no_setting_stays_silent(self):
        self.assertEqual(self.run_hook(""), "")

    def test_env_overrides_the_config(self):
        self.assertEqual(self.run_hook("log = 3\n", AGENT_GUARD_LOG="0"), "")
        self.assertIn('hook="Stop"', self.run_hook("log = 0\n", AGENT_GUARD_LOG="1"))

    def test_checkout_overrides_the_global(self):
        self.assertEqual(self.run_hook("log = 1\n", checkout="log = 0\n"), "")
        self.assertIn('hook="Stop"', self.run_hook("log = 0\n", checkout="log = 1\n"))

    def test_checkout_naming_no_level_keeps_the_global(self):
        self.assertIn('hook="Stop"', self.run_hook("log = 1\n", checkout="block = true\n"))

    def run_hook(self, config, checkout=None, **env_extra):
        """The hook's log after one Stop call under this config, or "" if it
        wrote none. A checkout's own config.toml layers over the global one when
        given. HOME is moved so the case reads its own file rather than the
        machine's."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            home = root / "home"
            config_dir = root / "config"
            home.mkdir()
            config_dir.mkdir()
            (config_dir / "config.toml").write_text(config, encoding="utf-8")
            if checkout is not None:
                nearer = root / ".agents" / "plugins" / "agent-guard"
                nearer.mkdir(parents=True)
                (nearer / "config.toml").write_text(checkout, encoding="utf-8")

            env = os.environ.copy()
            env.pop("AGENT_GUARD_LOG", None)
            env.update(
                HOME=str(home),
                AGENT_GUARD_CONFIG_DIR=str(config_dir),
                XDG_STATE_HOME=str(root / "state"),
                **env_extra,
            )
            payload = {
                "session_id": "test-session",
                "cwd": str(root),
                "hook_event_name": "Stop",
            }
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                cwd=root,
                env=env,
                timeout=15,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            written = home / "agent-guard.log"
            return written.read_text(encoding="utf-8") if written.is_file() else ""


if __name__ == "__main__":
    unittest.main()
