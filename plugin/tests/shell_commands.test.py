#!/usr/bin/env python3
"""The shell-command reader returns each command with its name and arguments."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_guard.shell_commands import read_commands


def names(command, **options):
    return [(item.name, item.args) for item in read_commands(command, **options)]


class ReadCommandsTests(unittest.TestCase):
    def test_each_shape_returns_the_commands_it_runs(self):
        cases = {
            # Wrappers and their operands.
            "sudo rg -n foo": [("rg", ("-n", "foo"))],
            "sudo -u root timeout 5 rg -n foo": [("rg", ("-n", "foo"))],
            "nice -n 5 env -u HOME rg -n foo": [("rg", ("-n", "foo"))],
            "if true; then rg -n foo; fi": [
                ("true", ()),
                ("rg", ("-n", "foo")),
                ("fi", ()),
            ],
            # Assignments.
            "FOO=1 BAR=2 rg -n foo": [("rg", ("-n", "foo"))],
            # Redirects and the file descriptor in front of them.
            "rg -n foo > /tmp/out": [("rg", ("-n", "foo"))],
            "rg -n foo 2>&1 | head": [("rg", ("-n", "foo")), ("head", ())],
            "rg -n foo &> out; ls": [("rg", ("-n", "foo")), ("ls", ())],
            "diff <(rg -n foo) b": [("diff", ()), ("rg", ("-n", "foo")), ("b", ())],
            # Shells.
            "bash -c 'rg -n foo'": [("bash", ("-c", "rg -n foo")), ("rg", ("-n", "foo"))],
            "bash -lc 'rg -n foo | head'": [
                ("bash", ("-lc", "rg -n foo | head")),
                ("rg", ("-n", "foo")),
                ("head", ()),
            ],
            "bash <<< 'rg -n foo'": [("bash", ()), ("rg", ("-n", "foo"))],
            "bash script.sh": [("bash", ("script.sh",))],
            "echo $(rg -n foo)": [("echo", ("$",)), ("rg", ("-n", "foo"))],
            # xargs runs its utility.
            "xargs -I {} grep -r foo .": [
                ("xargs", ("-I", "{}", "grep", "-r", "foo", ".")),
                ("grep", ("-r", "foo", ".")),
            ],
            "fd . | xargs -0 sudo grep -r foo .": [
                ("fd", (".",)),
                ("xargs", ("-0", "sudo", "grep", "-r", "foo", ".")),
                ("grep", ("-r", "foo", ".")),
            ],
            "xargs -n 1": [("xargs", ("-n", "1"))],
            # `.exe`, directories and case.
            "rg.exe -n foo": [("rg", ("-n", "foo"))],
            "RG.EXE -n foo": [("rg", ("-n", "foo"))],
            "/usr/bin/rg -n foo": [("rg", ("-n", "foo"))],
            "C:/tools/rg.exe -n foo": [("rg", ("-n", "foo"))],
            # Newlines end a command, outside quotes and after a comment.
            "rg -n foo\nhead file": [("rg", ("-n", "foo")), ("head", ("file",))],
            "rg -n foo # note\nhead file": [("rg", ("-n", "foo")), ("head", ("file",))],
            'git commit -m "a\n\nrg -rn b"': [("git", ("commit", "-m", "a\n\nrg -rn b"))],
            # Quoted operators are text.
            'rg -n "a|b" file': [("rg", ("-n", "a|b", "file"))],
            "rg -n 'a; b && c > d' file": [("rg", ("-n", "a; b && c > d", "file"))],
            "{ rg -n foo; }": [("rg", ("-n", "foo"))],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(names(command), expected)

    def test_an_unclosed_quote_keeps_what_came_before_it_unless_asked(self):
        command = 'rg -n foo; grep -r "unterminated'
        self.assertEqual(names(command), [("rg", ("-n", "foo")), ("grep", ("-r",))])
        self.assertEqual(names(command, partial=False), [])

    def test_blank_input_returns_nothing(self):
        for command in ("", "   ", "   \n  "):
            with self.subTest(command=command):
                self.assertEqual(read_commands(command), [])
        self.assertEqual(names("rg   -n    foo"), [("rg", ("-n", "foo"))])

    def test_a_windows_path_keeps_its_backslashes_when_asked(self):
        command = r"C:\tools\rg.exe -n foo C:\src\file.rs"
        self.assertEqual(
            names(command, keep_backslashes=True),
            [("rg", ("-n", "foo", r"C:\src\file.rs"))],
        )
        self.assertEqual(names(command)[0][1][-1], "C:srcfile.rs")


if __name__ == "__main__":
    unittest.main()
