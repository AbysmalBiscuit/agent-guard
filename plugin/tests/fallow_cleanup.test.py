#!/usr/bin/env python3
"""Exercise SessionEnd cleanup with real fallow audit caches."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "agent_guard.py"


@unittest.skipUnless(shutil.which("fallow"), "requires fallow with audit-cache remove")
class FallowCleanupTests(unittest.TestCase):
    def test_session_end_removes_only_its_projects_cache(self):
        for codex in (False, True):
            with self.subTest(codex=codex), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scratch = root / "tmp"
                scratch.mkdir()
                config = root / "config"
                config.mkdir()
                (config / "config.toml").write_text("always = []\n", encoding="utf-8")
                env = {
                    **os.environ,
                    "TMPDIR": str(scratch),
                    "TMP": str(scratch),
                    "TEMP": str(scratch),
                    "AGENT_GUARD_CONFIG_DIR": str(config),
                    "AGENT_GUARD_LOG": "0",
                }
                projects = [root / "project", root / "other"]
                caches = []
                for project in projects:
                    project.mkdir()
                    self.run_command(["git", "init", "--quiet", str(project)], env)
                    source = project / "index.js"
                    source.write_text("console.log('before');\n", encoding="utf-8")
                    self.run_command(["git", "-C", str(project), "add", "."], env)
                    self.run_command(
                        [
                            "git",
                            "-C",
                            str(project),
                            "-c",
                            "user.name=Test",
                            "-c",
                            "user.email=test@example.com",
                            "-c",
                            "commit.gpgSign=false",
                            "commit",
                            "-qm",
                            "seed",
                        ],
                        env,
                    )
                    source.write_text("console.log('after');\n", encoding="utf-8")
                    before = set(scratch.glob("fallow-audit-base-cache-*"))
                    self.run_command(
                        [
                            "fallow",
                            "audit",
                            "--root",
                            str(project),
                            "--base",
                            "HEAD",
                            "--format",
                            "json",
                        ],
                        env,
                    )
                    created = [
                        path
                        for path in scratch.glob("fallow-audit-base-cache-*")
                        if path.is_dir() and path not in before
                    ]
                    assert len(created) == 1, "audit must create a real cache"
                    caches.extend(created)

                for _ in range(2):
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), *(["--codex"] if codex else [])],
                        input=json.dumps(
                            {
                                "hook_event_name": "SessionEnd",
                                "session_id": "cleanup-test",
                                "cwd": str(projects[0]),
                            }
                        ),
                        capture_output=True,
                        text=True,
                        env=env,
                        cwd=projects[1],
                        timeout=15,
                        check=False,
                    )
                    assert result.returncode == 0, result.stderr
                    assert result.stdout == ""
                    assert not caches[0].exists(), "session cache was left in tmp"
                    assert caches[1].is_dir(), "another project's cache was removed"

    def run_command(self, command, env):
        result = subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=30, check=False
        )
        assert result.returncode == 0, result.stderr
        return result


if __name__ == "__main__":
    unittest.main()
