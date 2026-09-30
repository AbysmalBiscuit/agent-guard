#!/usr/bin/env python3
"""Cases for mandatory/secret_decrypt.py. Run directly: python3 <this file>.

Held here rather than beside the check, because mandatory/ globs every *.py
in it and would run this file as a check on each Bash call."""

import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
    "hook", pathlib.Path(__file__).parent.parent / "mandatory" / "secret_decrypt.py"
)
assert spec is not None
assert spec.loader is not None
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

MUST_BLOCK = [
    "age -d secrets.age",
    "/usr/bin/age --decrypt f",
    "rage -d f",
    'sh -c "age -d f"',
    "C:/tools/age.exe -d f",
    "sops -d file.yaml",
    "age-keygen -o key.txt",
    "sudo age -d f",
    "env AGE=1 age -d f",
    "FOO=1 rage -d f",
    "xargs -I{} age -d {}",
    "ls && age -d f",
    "chezmoi apply",
    "chezmoi apply --dry-run",
    "chezmoi update",
    "chezmoi init --apply",
    "chezmoi diff",
    "chezmoi dump",
    "chezmoi archive",
    "chezmoi verify",
    "chezmoi cat ~/.bashrc",
    "chezmoi cat-config",
    "chezmoi data",
    "chezmoi execute-template '{{ decrypt .x }}'",
    "chezmoi secret keyring get",
    "cat ~/.config/chezmoi/key.txt",
    "cp ~/.config/age/keys.txt /tmp/x",
    "head -1 /c/Users/Lev/.config/chezmoi/encryption-key.txt",
    "cat ~/.age/identity.txt",
]

MUST_PASS = [
    "chezmoi status",
    "chezmoi managed",
    "chezmoi source-path",
    "chezmoi doctor",
    "git status",
    "ls ~/.config/chezmoi/",
    "echo hello",
    "npm run manage",
    "cat package.json",
    "du -sh storage/",
    "rg 'age' src/",
    "cargo build --package agent",
    "grep -r 'sops' .",
    "echo 'age' >> notes.txt",
    "xargs rg age",
]

failures = 0

for command in MUST_BLOCK:
    if hook.find_violation(command) is None:
        print(f"MISS (should block): {command}")
        failures += 1

for command in MUST_PASS:
    reason = hook.find_violation(command)
    if reason is not None:
        print(f"FALSE POSITIVE: {command} -> {reason}")
        failures += 1

total = len(MUST_BLOCK) + len(MUST_PASS)
print("%d/%d passed" % (total - failures, total))
sys.exit(1 if failures else 0)
