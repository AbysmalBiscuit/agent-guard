#!/usr/bin/env python3
"""install.sh and the session-start bootstrap refuse a mise older than the
`min_version` of plugin/mise.toml, and say how to update it."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hook_support import PLUGIN_ROOT

REQUIRED = "2026.9.16"
OLDER = "2026.9.15"


def copy_plugin(destination):
    for relative in (
        "scripts/install.sh",
        "hooks/bootstrap-tools",
        ".claude-plugin/plugin.json",
        "mise.toml",
    ):
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PLUGIN_ROOT / relative, destination / relative)


def stub_mise(directory, version):
    """A `mise` that reports `version` and fails every other command, as an
    older mise does under the `min_version` of plugin/mise.toml."""
    directory.mkdir(parents=True, exist_ok=True)
    mise = directory / "mise"
    mise.write_text(
        f'#!/bin/sh\n[ "$1" = --version ] && echo "{version} linux-x64 (2026-09-27)" && exit 0\n'
        "exit 1\n",
        encoding="utf-8",
    )
    mise.chmod(0o755)


class MiseVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plugin = self.root / "plugin"
        copy_plugin(self.plugin)
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("MISE_", "AGENT_GUARD_"))
        }
        self.env.update(HOME=str(self.root / "home"), XDG_STATE_HOME=str(self.root / "state"))

    def run_with_mise(self, version, script):
        stub_mise(self.root / "bin", version)
        self.env["PATH"] = f"{self.root / 'bin'}:{self.env['PATH']}"
        return subprocess.run(
            ["bash", str(self.plugin / script)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
        )

    def assert_names_the_update(self, stderr):
        self.assertIn(f"mise {REQUIRED} or newer", stderr)
        self.assertIn(f"found {OLDER}", stderr)
        self.assertIn("mise self-update", stderr)

    def test_install_refuses_an_older_mise_and_names_the_update(self):
        result = self.run_with_mise(OLDER, "scripts/install.sh")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assert_names_the_update(result.stderr)

    def test_install_accepts_the_required_mise(self):
        result = self.run_with_mise(REQUIRED, "scripts/install.sh")
        self.assertIn("mise lists no tools", result.stderr)
        self.assertNotIn("mise self-update", result.stderr)

    def test_bootstrap_reports_an_older_mise_and_names_the_update(self):
        result = self.run_with_mise(OLDER, "hooks/bootstrap-tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_names_the_update(result.stderr)


if __name__ == "__main__":
    unittest.main()
