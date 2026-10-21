#!/usr/bin/env python3
"""Stop and doctor cases for the mise-pinned tools."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import run_hook, stub_mise, tool_version

PIN = tool_version("fallow")
PINNED = f"PINNED-{PIN}"


def hook_env(root, extra_env):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    env.update(extra_env)
    return env


def stop_hook(root, extra_env):
    payload = {
        "session_id": "pinned",
        "cwd": str(root),
        "hook_event_name": "Stop",
    }
    return run_hook(
        json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=root,
        env=hook_env(root, extra_env),
        timeout=30,
    )


def doctor_hook(root, extra_env):
    return run_hook(
        None,
        args=("doctor",),
        capture_output=True,
        text=True,
        cwd=root,
        env=hook_env(root, extra_env),
        timeout=20,
    )


def init_repo(root):
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "agent-guard@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Agent Guard Test"], cwd=root, check=True)
    (root / "src.ts").write_text("export const value = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "src.ts"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Agent Guard Test",
            "-c",
            "user.email=agent-guard@example.com",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "base",
        ],
        cwd=root,
        check=True,
    )
    (root / "src.ts").write_text("export const value = 2\n", encoding="utf-8")


def opt_in(root):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True)
    (nearer / "config.toml").write_text("fallow = true\nlog = 0\n", encoding="utf-8")


def write_fallow(directory, marker):
    path = pathlib.Path(directory) / "fallow"
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        f'  printf "%s\\n" "{marker}"\n'
        "  exit 0\n"
        "fi\n"
        'printf "%s\\n" "$0" > "${FALLOW_WHICH_LOG}"\n'
        'printf "%s\\n" "{}"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


class MissingToolTests(unittest.TestCase):
    def test_a_missing_mise_leaves_the_audit_silent_and_doctor_names_it(self):
        """No mise on PATH leaves Stop silent. doctor names the missing mise
        and the fallow pin it cannot resolve."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            project = root / "project"
            project.mkdir()
            init_repo(project)
            opt_in(project)
            empty = root / "empty-path"
            empty.mkdir()
            env = {"PATH": str(empty)}

            hook = stop_hook(project, env)
            doctor = doctor_hook(project, env)

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn("mise       : not installed", doctor.stdout)
        self.assertIn("mise missing", doctor.stdout)
        self.assertIn("fallow missing", doctor.stdout)


class MissingPinTests(unittest.TestCase):
    def test_a_missing_pin_leaves_that_tool_silent_and_doctor_names_it(self):
        """A pin mise cannot resolve leaves that tool silent. doctor names the
        missing pin. An older fallow earlier on PATH does not fill in."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            project = root / "project"
            project.mkdir()
            init_repo(project)
            opt_in(project)
            older = root / "older"
            older.mkdir()
            write_fallow(older, "OLD-3.22.0")
            log = root / "which.txt"
            mise = stub_mise(root / "mise")
            env = {
                "PATH": os.pathsep.join([mise, str(older), os.environ.get("PATH", "")]),
                "FALLOW_WHICH_LOG": str(log),
            }

            hook = stop_hook(project, env)
            doctor = doctor_hook(project, env)

        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(hook.stdout, "")
        self.assertFalse(log.exists())
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn(f"fallow     : not installed  pin {PIN}", doctor.stdout)
        self.assertIn("fallow missing", doctor.stdout)


class PinnedFallowTests(unittest.TestCase):
    def test_stop_audit_runs_the_mise_pinned_fallow_ahead_of_path(self):
        """An older fallow earlier on PATH does not win. Stop runs the binary
        mise pins for this plugin."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            project = root / "project"
            project.mkdir()
            init_repo(project)
            opt_in(project)
            older = root / "older"
            older.mkdir()
            write_fallow(older, "OLD-3.22.0")
            pinned = root / "pinned"
            pinned.mkdir()
            pinned_bin = write_fallow(pinned, PINNED)
            log = root / "which.txt"
            mise = stub_mise(root / "mise", {"fallow": pinned_bin})
            env = {
                "PATH": os.pathsep.join([str(older), mise, os.environ.get("PATH", "")]),
                "FALLOW_WHICH_LOG": str(log),
            }

            result = stop_hook(project, env)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(log.is_file(), result.stderr + result.stdout)
            self.assertEqual(log.read_text(encoding="utf-8").strip(), str(pinned_bin))


if __name__ == "__main__":
    unittest.main()
