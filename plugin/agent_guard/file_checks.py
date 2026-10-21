"""Per-file rules, per-file check scripts, and tool-call checks."""

import json
import os
import re
import signal
import sys
from contextlib import contextmanager
from pathlib import Path

from . import _state
from .checks import FILE_CHECKS, MANDATORY_CHECKS, TOOL_CHECKS
from .config import sgconfig_for
from .contract import (
    ASK_EXIT,
    FINDING_LINE,
    SHELL_TOOLS,
    SILENT,
    Decision,
    advised,
    asked,
    changed_lines,
    denied,
    finding_line,
    git_base,
)
from .process import have, run, run_full

# A check that outruns its bound is silence. The agent cannot wait, and a
# check the agent cannot wait for should not become a refusal.
CHECK_TIMEOUT = 5


@contextmanager
def _bounded(seconds):
    """Raise TimeoutError once `seconds` pass, where the platform allows it.

    Windows has no SIGALRM. There the process watchdog is the only backstop,
    and a wedged check takes the run down with it instead of being skipped.
    """
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def fire(*_):
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_checks(path, roots, cwd):
    """Package file checks, then a root's checks/ scripts.

    A script prints `  <file>:<line>  [<rule-id>] <message>` and runs in its own
    interpreter, because the executable bit does not survive a clone."""
    out = []
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    for check in FILE_CHECKS:
        name = check.__module__.rsplit(".", 1)[-1]
        try:
            with _bounded(CHECK_TIMEOUT):
                lines = check(source, path)
        except TimeoutError:
            _state.log(2, "check", script=name, verdict="silent", reason="timeout")
            continue
        except Exception:
            _state.log(2, "check", script=name, verdict="silent", reason="raised")
            continue
        if lines:
            out.append("\n".join(lines))
    for root in roots:
        checks = root / "checks"
        if not checks.is_dir():
            continue
        for script in sorted(checks.glob("*.py")):
            # Only newlines: the leading two spaces are part of the finding format.
            text = run([sys.executable, str(script), str(path)], timeout=10, cwd=cwd).strip("\r\n")
            if text:
                out.append(text)
    return "\n".join(out)


def run_changeset_checks(base, roots, cwd):
    """Conventions only a diff can show. A root's changeset_checks/ holds Python
    scripts, each given the base revision as its argument and printing a finished
    section on stdout when it has something to say; silence means nothing found.

    The per-call layers cannot stand in for this. A PreToolUse check sees one
    call and a PostToolUse check sees one file, so whatever reaches the branch by
    a route neither covers arrives unexamined. The diff is where that shows up.

    A script runs in its own interpreter, for the reason run_checks gives."""
    out = []
    for root in roots:
        directory = root / "changeset_checks"
        if not directory.is_dir():
            continue
        for script in sorted(directory.glob("*.py")):
            text = run([sys.executable, str(script), base], timeout=20, cwd=cwd).strip()
            if text:
                out.append(text)
    return "\n\n".join(out)


def _failed(name):
    """The text a raised check leaves when it printed nothing."""
    return (
        f"agent-guard: the check {name} failed to run, so the call it protects "
        "is refused. Fix the check; Edit and Write are not gated by this hook."
    )


def _merge(named):
    """One decision from named check results. A denial outranks an ask."""
    advice, asks, denials = [], [], []
    for name, decision in named:
        text = (decision.context or "").strip()
        verdict = "silent"
        if decision.permission == "deny":
            verdict = "deny"
        elif decision.permission == "ask":
            verdict = "ask"
        elif text:
            verdict = "advise"
        _state.log(
            2,
            "check",
            script=name,
            verdict=verdict,
            reason=text.splitlines()[0] if text else None,
        )
        if verdict == "deny":
            denials.append(text or _failed(name))
        elif verdict == "ask":
            asks.append(text)
        elif text:
            advice.append(text)
    if denials:
        return denied("\n\n".join(denials + asks + advice), "\n\n".join(denials))
    if asks:
        return asked("\n\n".join(asks + advice), "\n\n".join(asks))
    if advice:
        return advised("\n\n".join(advice))
    return SILENT


def run_mandatory(payload):
    """Shell-tool checks no config can switch off.

    A raised check is a denial naming it. Silence would hide a broken security
    check, and file tools stay ungated so the check can still be edited."""
    if (payload.get("tool_name") or "") not in SHELL_TOOLS:
        return SILENT
    named = []
    for check in MANDATORY_CHECKS:
        name = check.__module__.rsplit(".", 1)[-1]
        try:
            with _bounded(CHECK_TIMEOUT):
                named.append((name, check(payload)))
        except TimeoutError:
            _state.log(2, "check", script=name, verdict="silent", reason="timeout")
        except Exception:
            named.append((name, denied(_failed(name), _failed(name))))
    merged = _merge(named)
    if merged.permission != "allow" or merged.context:
        _state.log(
            1,
            "decision",
            tool=payload.get("tool_name") or "",
            outcome=merged.permission,
        )
    return merged


def script_verdict(out, code):
    """The decision a project script's stdout and exit code stand for.

    Empty stdout is silence, whatever the exit code. Stdout with exit 0 advises.
    Stdout with the ask exit code hands the call to the human. Any other
    non-zero exit denies."""
    text = out.strip()
    if not text:
        return Decision()
    if code == 0:
        return advised(text)
    if code == ASK_EXIT:
        return asked(text, text)
    return denied(text, text)


def check_tool(payload, roots, settings, cwd):
    """Package tool checks, then a root's tool_checks/ scripts.

    A script gets the tool name as its argument and the payload on stdin.
    Empty stdout is silence, exit 0 advises, the ask exit hands the call to
    the human, and any other non-zero exit denies."""
    if not settings.tool_checks:
        return SILENT
    raw = json.dumps(payload, separators=(",", ":"))
    tool = payload.get("tool_name") or ""
    named = []
    for check in TOOL_CHECKS:
        name = check.__module__.rsplit(".", 1)[-1]
        try:
            with _bounded(CHECK_TIMEOUT):
                named.append((name, check(payload)))
        except TimeoutError:
            _state.log(2, "check", script=name, verdict="silent", reason="timeout")
        except Exception:
            # A broken built-in degrades to silence rather than denying work.
            _state.log(2, "check", script=name, verdict="silent", reason="raised")
    for root in roots:
        checks = root / "tool_checks"
        if not checks.is_dir():
            continue
        for script in sorted(checks.glob("*.py")):
            out, code = run_full(
                [sys.executable, str(script), tool],
                timeout=CHECK_TIMEOUT,
                cwd=cwd,
                stdin=raw,
            )
            named.append((script.name, script_verdict(out, code)))

    merged = _merge(named)
    _state.log(
        1,
        "decision",
        tool=tool,
        outcome=merged.permission if merged.context or merged.permission != "allow" else "allow",
    )
    return merged


_INFO_FINDING = re.compile(r"  \[info:")
_ERROR_FINDING = re.compile(r"  \[error:")
_FINDING_RULE = re.compile(r"  \[([^\]]+)\]")
_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update) File: (.+)$", re.MULTILINE)
_PATCH_MOVE = re.compile(r"^\*\*\* Move to: (.+)$", re.MULTILINE)


def _rules(findings):
    return {match.group(1) for line in findings if (match := _FINDING_RULE.search(line))}


def _severity(finding):
    """0 for the loudest tier. A check grades its own findings through a prefix on
    the rule id, so the runner ranks them without knowing which check spoke."""
    if _ERROR_FINDING.search(finding):
        return 0
    return 2 if _INFO_FINDING.search(finding) else 1


def edited_paths(payload, cwd):
    tool_input = payload.get("tool_input") or {}
    direct = tool_input.get("file_path") or ""
    candidates = [direct] if direct else []
    if payload.get("tool_name") == "apply_patch":
        command = tool_input.get("command") or ""
        candidates.extend(_PATCH_FILE.findall(command))
        candidates.extend(_PATCH_MOVE.findall(command))

    paths = []
    seen = set()
    for candidate in candidates:
        path = Path(candidate.strip())
        if not path.is_absolute():
            path = cwd / path
        try:
            path = path.resolve()
        except OSError:
            continue
        key = os.path.normcase(str(path))
        if key not in seen and path.is_file():
            seen.add(key)
            paths.append(str(path))
    return paths


# ast-grep's own severity mapped onto the prefix a Python check would have
# written, so a rule states its tier in the file that defines it. A rule that
# declares nothing reports "hint", which is indistinguishable from asking for
# one, so hint lands in the default tier; `severity: info` is how a rule asks
# for the note tier.
_SG_SEVERITY = {"error": "error:", "warning": "warn:", "info": "info:", "hint": "warn:"}


def scan_file(path, roots, cwd, layers):
    findings = []
    if "rules" in layers and have("ast-grep"):
        # One scan per root rather than one merged config: each root's sgconfig
        # resolves its own ruleDirs and custom-language libraryPath relative to
        # itself.
        for root in roots:
            config = sgconfig_for(root)
            if config is None:
                continue
            raw = run(
                ["ast-grep", "scan", "-c", str(config), "--json=compact", path],
                timeout=15,
                cwd=cwd,
            )
            try:
                hits = json.loads(raw) if raw.strip() else []
            except ValueError:
                continue
            for hit in hits or []:
                rule = re.sub(r"-(typescript|tsx)$", "", hit.get("ruleId", ""))
                line = hit.get("range", {}).get("start", {}).get("line", 0) + 1
                findings.append(
                    finding_line(
                        hit.get("file", path),
                        line,
                        f"{_SG_SEVERITY.get(hit.get('severity'), 'warn:')}{rule}",
                        hit.get("message", ""),
                    )
                )
    extra = run_checks(path, roots, cwd) if "checks" in layers else ""
    if extra:
        findings.extend(extra.splitlines())
    return [f for f in findings if f.strip()]


def check_file(payload, roots, settings, cwd, layers):
    """Per-file syntactic rules. Must stay in the low milliseconds: this fires on
    every edit from every agent and subagent, so its cost multiplies. Git is
    consulted only once a rule has fired, so a clean file costs no subprocess."""
    paths = edited_paths(payload, cwd)
    findings = []
    base = None
    for path in paths:
        if not settings.ext_re.search(path) or settings.ignore_re.search(path):
            continue
        path_findings = scan_file(path, roots, cwd, layers)
        if settings.scope == "diff" and path_findings:
            if base is None:
                base = git_base(settings, cwd)
            added = changed_lines(path, base, cwd)
            if added is not None:
                path_findings = [
                    line
                    for line in path_findings
                    if (match := FINDING_LINE.search(line)) and int(match.group(1)) in added
                ]
        findings.extend(path_findings)

    # Each tier gets its own heading, so a note cannot dilute a violation and a
    # violation well past the line does not read as one merely over it. The
    # budget goes to the loudest tier first. Everything with no severity prefix,
    # the ast-grep rules included, is an ordinary violation.
    errors, warnings, notes = (
        [line for line in findings if _severity(line) == rank] for rank in (0, 1, 2)
    )
    errors = errors[: settings.max_findings]
    warnings = warnings[: max(settings.max_findings - len(errors), 0)]
    notes = notes[: max(settings.max_findings - len(errors) - len(warnings), 0)]
    # Which rules fire and how often is the only way to tell a rule earning its
    # noise from one agents have learned to skim. Rule ids and suffixes carry no
    # file content, so this sits at the level a session can leave on.
    _state.log(
        1,
        "findings",
        tool=payload.get("tool_name"),
        suffix=",".join(sorted({os.path.splitext(p)[1] for p in paths})) or None,
        errors=len(errors),
        warnings=len(warnings),
        notes=len(notes),
        rules=",".join(sorted(_rules(errors + warnings + notes))) or None,
    )
    if not (errors or warnings or notes):
        return SILENT

    context = ""
    if errors or warnings:
        context = "agent-guard found convention violations in the file you just wrote. "
        if errors:
            context += "Start with these, which are well past the line:\n\n" + "\n".join(errors)
            if warnings:
                context += "\n\nThen these:\n\n" + "\n".join(warnings)
        else:
            context += "Fix them now rather than leaving them for review:\n\n" + "\n".join(warnings)
        context += (
            "\n\nThese come from this project's documented conventions. If a finding "
            "is genuinely wrong, say why instead of silently ignoring it."
        )
    if notes:
        context += (
            "\n\nWorth a second look, though none of these is a violation:\n\n"
            if errors or warnings
            else "agent-guard noticed something in the file you just wrote. Improve it "
            "if you agree; it is not a violation:\n\n"
        ) + "\n".join(notes)

    return advised(context)
