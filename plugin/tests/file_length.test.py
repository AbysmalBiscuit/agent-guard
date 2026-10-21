#!/usr/bin/env python3
"""Stop-hook cases for the file-length changeset check."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from hook_support import PLUGIN_ROOT as PLUGIN
from hook_support import run_hook

WARN_MESSAGE = "Split this file by responsibility, and move tests into focused files."
BLOCK_MESSAGE = "Split this file by responsibility, and move tests into focused files."


def commit_all(root, message):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
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
            message,
        ],
        cwd=root,
        check=True,
    )


def init_repo(root):
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "agent-guard@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Agent Guard Test"], cwd=root, check=True)


def doctor_hook(root):
    """Stdout of `agent_guard doctor` in this tree."""
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    result = run_hook(
        None,
        args=("doctor",),
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        timeout=30,
    )
    return result


def stop_hook(root, session="test-session", extra_env=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AGENT_GUARD_"):
            env.pop(key)
    env["HOME"] = str(root / "home")
    env["AGENT_GUARD_CONFIG_DIR"] = str(PLUGIN)
    env["AGENT_GUARD_LOG"] = "0"
    env["XDG_STATE_HOME"] = str(root / "state")
    if extra_env:
        env.update(extra_env)
    payload = {
        "session_id": session,
        "cwd": str(root),
        "hook_event_name": "Stop",
    }
    return run_hook(
        json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        timeout=30,
    )


def enable(root, body):
    nearer = root / ".agents" / "plugins" / "agent-guard"
    nearer.mkdir(parents=True, exist_ok=True)
    (nearer / "config.toml").write_text(body, encoding="utf-8")


def write_lines(path, count):
    path.write_text("".join(f"line {number}\n" for number in range(1, count + 1)), encoding="utf-8")


def length_config(warn_message="", block_message="", extra=""):
    messages = ""
    if warn_message:
        messages += f'warn_message = "{warn_message}"\n'
    if block_message:
        messages += f'block_message = "{block_message}"\n'
    return f"""\
fallow = false
block = true

[file_length]
enabled = true
{messages}
[[file_length.limits]]
extensions = '\\.py$'
warn = 4
block_lines = 8
{extra}"""


ON = length_config()

OFF_UNSET = """\
fallow = false
block = true

[file_length]
[[file_length.limits]]
extensions = '\\.py$'
warn = 4
block_lines = 8
"""

OFF_FALSE = OFF_UNSET.replace("[file_length]\n", "[file_length]\nenabled = false\n", 1)

ALT = """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
extensions = '\\.(rs|go)$'
warn = 4
block_lines = 8
"""


def _skip_fingerprints(root):
    """How many distinct Stop skip fingerprints this tree has written."""
    return len(
        {
            path.read_text(encoding="utf-8")
            for path in (root / "state").rglob("last-diff")
        }
    )


def context_of(result):
    payload = json.loads(result.stdout)
    return payload["hookSpecificOutput"]["additionalContext"]


class FileLengthTests(unittest.TestCase):
    def test_a_long_changed_file_stays_silent_when_the_check_is_off(self):
        """The check is off until a tree turns it on. A limit with enabled
        unset, and one with enabled false, both stay silent on a long file, a
        blank file, a path of only spaces, and an untracked notes.txt."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "short.py", 2)
            commit_all(root, "base")
            write_lines(root / "long.py", 1200)
            (root / "blank.py").write_text("   \n", encoding="utf-8")
            (root / "   ").write_text("x\n", encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(root, OFF_UNSET)

            unset = stop_hook(root, session="off-unset")

            enable(root, OFF_FALSE)
            disabled = stop_hook(root, session="off-false")

        self.assertEqual(unset.returncode, 0, unset.stderr)
        self.assertEqual(unset.stdout, "")
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertEqual(disabled.stdout, "")

    def test_a_file_past_warn_warns_and_one_past_block_blocks(self):
        """A changed file above the warn limit warns, and one above the block
        limit blocks. Both use the default messages. A file at the warn limit
        stays quiet, and a file the branch did not change stays quiet."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "old.py", 20)
            commit_all(root, "base")
            write_lines(root / "at_warn.py", 4)
            write_lines(root / "warn.py", 5)
            write_lines(root / "block.py", 9)
            enable(root, ON)

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        specific = output["hookSpecificOutput"]
        self.assertEqual(specific["permissionDecision"], "deny")
        report = specific["additionalContext"]
        self.assertIn("warn.py", report)
        self.assertIn("5 lines", report)
        self.assertIn(WARN_MESSAGE, report)
        self.assertIn("block.py", report)
        self.assertIn("9 lines", report)
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("at_warn.py", report)
        self.assertNotIn("old.py", report)
        self.assertIn(BLOCK_MESSAGE, specific["permissionDecisionReason"])

    def test_an_alternation_regex_warns_and_blocks_a_non_python_file(self):
        """An extension regex with alternation still selects its types. A
        9-line Rust file blocks, a 5-line Go file warns, and both use the
        default messages. A file at the warn limit stays quiet."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.rs", 1)
            commit_all(root, "base")
            write_lines(root / "at_warn.rs", 4)
            write_lines(root / "warn.go", 5)
            write_lines(root / "b.rs", 9)
            enable(root, ALT)

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        specific = output["hookSpecificOutput"]
        self.assertEqual(specific["permissionDecision"], "deny")
        report = specific["additionalContext"]
        self.assertIn("warn.go", report)
        self.assertIn("5 lines", report)
        self.assertIn(WARN_MESSAGE, report)
        self.assertIn("b.rs", report)
        self.assertIn("9 lines", report)
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("at_warn.rs", report)
        self.assertIn(BLOCK_MESSAGE, specific["permissionDecisionReason"])

    def test_a_project_message_replaces_the_default(self):
        """A tree's warn and block messages replace the defaults on both the
        report and the refusal."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "warn.py", 5)
            write_lines(root / "block.py", 9)
            enable(
                root,
                length_config(
                    "move the extra helpers out",
                    "this file is past the block line",
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("move the extra helpers out", report)
        self.assertIn("this file is past the block line", report)
        self.assertNotIn(WARN_MESSAGE, report)
        self.assertNotIn(BLOCK_MESSAGE, report)
        self.assertIn("this file is past the block line", specific["permissionDecisionReason"])
        self.assertNotIn(BLOCK_MESSAGE, specific["permissionDecisionReason"])

    def test_a_path_limit_applies_and_an_accepted_file_fails_only_when_it_grows(self):
        """A path limit and a glob limit replace the type limit for those files.
        A nested glob matches a file under it, and a path does not match the
        same suffix under vendor/. An accepted file stays quiet at its recorded
        size and blocks once it grows past that size. A blank path stays quiet."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            src = root / "src"
            src.mkdir()
            write_lines(src / "app.py", 6)
            write_lines(src / "kept.py", 6)
            write_lines(src / "grown.py", 7)
            nested = src / "a" / "b"
            nested.mkdir(parents=True)
            write_lines(nested / "c.py", 7)
            vendor = root / "vendor" / "src"
            vendor.mkdir(parents=True)
            write_lines(vendor / "app.py", 9)
            write_lines(root / "plain.py", 6)
            (root / "   .py").write_text("x\n", encoding="utf-8")
            enable(
                root,
                length_config(
                    extra="""\
[[file_length.limits]]
pattern = "src/app.py"
warn = 10
block_lines = 20

[[file_length.limits]]
pattern = "src/*.py"
accept = true
lines = 6

[[file_length.limits]]
pattern = "src/**/*.py"
accept = true
lines = 6
"""
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  plain.py  ", report)
        self.assertIn("  vendor/src/app.py  ", report)
        self.assertIn("  src/grown.py  ", report)
        self.assertIn("  src/a/b/c.py  ", report)
        self.assertIn("accepted at 6", report)
        self.assertNotIn("  src/app.py  ", report)
        self.assertNotIn("kept.py", report)
        self.assertNotIn("   .py", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_an_accept_row_without_lines_is_ignored(self):
        """An accept row with no lines, or with lines at zero, does not accept
        the file. The file stays quiet, and doctor names the row as a config
        error. A blank path and an untracked notes.txt stay quiet beside it."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "open.py", 40)
            write_lines(root / "zero.py", 40)
            (root / "   ").write_text("x\n" * 40, encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(
                root,
                """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
pattern = "open.py"
accept = true

[[file_length.limits]]
pattern = "zero.py"
accept = true
lines = 0
""",
            )

            result = stop_hook(root)
            reported = doctor_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(reported.returncode, 0, reported.stderr)
        self.assertIn("config error", reported.stdout)
        self.assertIn("open.py", reported.stdout)
        self.assertIn("zero.py", reported.stdout)

    def test_block_false_reports_the_block_level_without_refusing(self):
        """The block level still names the file when the global block setting
        is off. Stop finishes, and the report keeps the default block message."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "block.py", 9)
            (root / "blank.py").write_text("\n", encoding="utf-8")
            enable(root, ON.replace("block = true\n", "block = false\n", 1))

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", specific)
        report = specific["additionalContext"]
        self.assertIn("block.py", report)
        self.assertIn("9 lines", report)
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("blank.py", report)

    def test_a_nearer_table_keeps_farther_keys_and_replaces_limits(self):
        """A nearer [file_length] merges per key. It omits enabled, so the
        farther enabled stays on, and its own limits list replaces the farther
        list. A file past the farther warn limit stays quiet under the nearer
        limit."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "warn.py", 5)
            write_lines(root / "other.py", 9)
            wider = root / "wider"
            wider.mkdir()
            (wider / "config.toml").write_text(
                """\
[file_length]
enabled = true
warn_message = "farther warn"
block_message = "farther block"
[[file_length.limits]]
extensions = '\\.py$'
warn = 4
block_lines = 8
""",
                encoding="utf-8",
            )
            enable(
                root,
                """\
[file_length]
warn_message = "nearer warn"
[[file_length.limits]]
extensions = '\\.py$'
warn = 20
block_lines = 40
""",
            )

            result = stop_hook(root, extra_env={"AGENT_GUARD_CONFIG_DIR": str(wider)})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_blank_message_keeps_the_default(self):
        """A blank override is not a message. The default stays, and an
        untracked notes.txt stays silent beside a file the check does report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "block.py", 9)
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(
                root,
                length_config(extra="").replace(
                    "enabled = true\n",
                    "enabled = true\nwarn_message = ''\nblock_message = '   '\n",
                    1,
                ),
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn(BLOCK_MESSAGE, report)
        self.assertNotIn("notes.txt", report)

    def test_edge_inputs_stay_quiet_beside_a_real_finding(self):
        """A blank extension, a blank pattern, a repeated-space file name, and
        a file the ignore pattern covers stay quiet. The worktree's own
        untracked notes stay quiet beside a file the check does report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "block.py", 9)
            (root / "   ").write_text("x\n" * 9, encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            generated = root / "pkg" / "generated"
            generated.mkdir(parents=True)
            write_lines(generated / "long.py", 20)
            enable(
                root,
                ON
                + """
[[file_length.limits]]
extensions = ""
warn = 1
block_lines = 2

[[file_length.limits]]
pattern = "   "
warn = 1
block_lines = 2
""",
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("  block.py  ", report)
        self.assertNotIn("notes.txt", report)
        self.assertNotIn("generated/long.py", report)
        self.assertNotIn("   ", report)

    def test_a_leading_double_star_matches_a_root_file(self):
        """`**/app.rs` matches `app.rs` at the root and `src/app.rs`. It does
        not match `app.rs.bak`."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            write_lines(root / "app.rs", 9)
            src = root / "src"
            src.mkdir()
            write_lines(src / "app.rs", 9)
            write_lines(root / "app.rs.bak", 9)
            enable(
                root,
                """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
pattern = "**/app.rs"
warn = 4
block_lines = 8
""",
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  app.rs  ", report)
        self.assertIn("  src/app.rs  ", report)
        self.assertNotIn("app.rs.bak", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_an_inner_double_star_keeps_the_separator(self):
        """`src/**/x.rs` matches `src/x.rs` and `src/a/x.rs`. It does not match
        `srcfoo/x.rs`."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            src = root / "src"
            src.mkdir()
            write_lines(src / "x.rs", 9)
            nested = src / "a"
            nested.mkdir()
            write_lines(nested / "x.rs", 9)
            decoy = root / "srcfoo"
            decoy.mkdir()
            write_lines(decoy / "x.rs", 9)
            enable(
                root,
                """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
pattern = "src/**/x.rs"
warn = 4
block_lines = 8
""",
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  src/x.rs  ", report)
        self.assertIn("  src/a/x.rs  ", report)
        self.assertNotIn("srcfoo/x.rs", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_a_trailing_double_star_stays_inside_its_directory(self):
        """`vendor/**` matches `vendor/a.py` and `vendor/sub/a.py`. It does not
        match `vendorX/a.py`."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            vendor = root / "vendor"
            vendor.mkdir()
            write_lines(vendor / "a.py", 9)
            nested = vendor / "sub"
            nested.mkdir()
            write_lines(nested / "a.py", 9)
            decoy = root / "vendorX"
            decoy.mkdir()
            write_lines(decoy / "a.py", 9)
            enable(
                root,
                """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
pattern = "vendor/**"
warn = 4
block_lines = 8
""",
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  vendor/a.py  ", report)
        self.assertIn("  vendor/sub/a.py  ", report)
        self.assertNotIn("vendorX/a.py", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_a_trailing_double_star_does_not_match_a_hyphen_sibling(self):
        """`src/**` matches `src/a.py`. It does not match `src-old/a.py`."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            src = root / "src"
            src.mkdir()
            write_lines(src / "a.py", 9)
            decoy = root / "src-old"
            decoy.mkdir()
            write_lines(decoy / "a.py", 9)
            enable(
                root,
                """\
fallow = false
block = true

[file_length]
enabled = true
[[file_length.limits]]
pattern = "src/**"
warn = 4
block_lines = 8
""",
            )

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  src/a.py  ", report)
        self.assertNotIn("src-old/a.py", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_a_covered_file_past_the_listing_cap_still_blocks(self):
        """The length check reads a covered file that sorts after the first
        200 changed paths. An uncovered file in that prefix does not hide it."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            write_lines(root / "seed.py", 1)
            commit_all(root, "base")
            for number in range(201):
                write_lines(root / f"noise-{number:03d}.txt", 1)
            write_lines(root / "zzz.py", 9)
            enable(root, ON)

            result = stop_hook(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        specific = json.loads(result.stdout)["hookSpecificOutput"]
        report = specific["additionalContext"]
        self.assertIn("  zzz.py  ", report)
        self.assertIn("9 lines", report)
        self.assertEqual(specific["permissionDecision"], "deny")

    def test_a_non_source_edit_does_not_move_the_skip_when_the_check_is_off(self):
        """With the check off, a README edit is not a length change. Stop
        writes the same skip fingerprint before and after that edit, and the
        second Stop stays silent. A later source edit moves the fingerprint."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "home").mkdir()
            init_repo(root)
            (root / "seed.ts").write_text("export const seed = 1\n", encoding="utf-8")
            (root / "README.md").write_text("base\n", encoding="utf-8")
            commit_all(root, "base")
            (root / "touched.ts").write_text("export const touched = 1\n", encoding="utf-8")
            (root / "notes.txt").write_text("untracked\n", encoding="utf-8")
            enable(root, OFF_UNSET)

            first = stop_hook(root, session="skip-off")
            saved = _skip_fingerprints(root)
            (root / "README.md").write_text("base\nnon-source edit\n", encoding="utf-8")
            (root / "config.toml").write_text("unrelated = true\n", encoding="utf-8")
            second = stop_hook(root, session="skip-off-again")
            after = _skip_fingerprints(root)
            (root / "grown.ts").write_text("export const grown = 1\n", encoding="utf-8")
            moved = stop_hook(root, session="skip-moved")
            later = _skip_fingerprints(root)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, "")
        self.assertEqual(saved, 1)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout, "")
        self.assertEqual(after, saved)
        self.assertEqual(moved.returncode, 0, moved.stderr)
        self.assertEqual(moved.stdout, "")
        self.assertEqual(later, 2)


if __name__ == "__main__":
    unittest.main()
