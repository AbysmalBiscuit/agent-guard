"""Per-file rules, per-file check scripts, and tool-call checks."""

import json
import os
import re
import sys
from pathlib import Path

from . import _state
from .config import sgconfig_for
from .contract import (
    ASK_EXIT,
    SHELL_TOOLS,
    changed_lines,
    emit,
    emit_silent,
    git_base,
)
from .paths import MANDATORY_DIR, MANDATORY_TIMEOUT
from .process import have, run, run_full, run_script


def run_checks(path, roots, cwd):
    """Conventions ast-grep cannot reach. Tree-sitter discards whitespace, so
    nothing about blank lines or vertical spacing is expressible as a rule; those
    live here instead. A root's checks/ holds Python scripts, each given one file
    path as its argument and printing findings on stdout in the shape the
    ast-grep scan produces:

      <2 spaces><file>:<line><2 spaces>[<rule-id>] <message>

    A check decides for itself which files it has anything to say about, because
    the extensions setting is one regex for the whole layer.

    Run through this interpreter rather than their shebang: the executable bit
    does not survive a clone onto Windows, and an interpreter the hook is already
    running under is the one thing every machine is guaranteed to have."""
    out = []
    for root in roots:
        checks = root / "checks"
        if not checks.is_dir():
            continue
        for script in sorted(checks.glob("*.py")):
            # Only newlines: the leading two spaces are part of the finding format.
            result = run_script(script, str(path), "", cwd, 10)
            text = (
                result[0]
                if result
                else run([sys.executable, str(script), str(path)], timeout=10, cwd=cwd)
            ).strip("\r\n")
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

    Run through this interpreter rather than their shebang, for the reason
    run_checks gives."""
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


def run_mandatory(payload, cwd):
    """PreToolUse scripts no config can switch off, for rules whose whole value
    is that an agent cannot negotiate past them. Same contract as tool_checks/,
    so a script changes tier by changing directory.

    A script that exits non-zero without saying why has crashed rather than
    denied, and that is reported as a denial naming the file. The alternative is
    silence, and a security check that vanishes when it breaks is worse than one
    that is loudly in the way.

    Shell tools only, which is what keeps that trade survivable: the tier exists
    because a shell command reaches secrets that the Read and Edit permission
    rules already gate, and leaving the file tools out of it means a broken
    script can still be edited back into shape. Scope by tool, not a setting:
    nothing here is negotiable for the calls it does cover."""
    if not MANDATORY_DIR.is_dir():
        return
    if (payload.get("tool_name") or "") not in SHELL_TOOLS:
        return
    raw = json.dumps(payload, separators=(",", ":"))
    tool = payload.get("tool_name") or ""

    advice, denials = [], []
    for script in sorted(MANDATORY_DIR.glob("*.py")):
        out, code = run_script(script, tool, raw, cwd, MANDATORY_TIMEOUT) or run_full(
            [sys.executable, str(script), tool],
            timeout=MANDATORY_TIMEOUT,
            cwd=cwd,
            stdin=raw,
        )
        out = out.strip()
        _state.log(
            2,
            "mandatory",
            script=script.name,
            verdict="deny" if code else "advise" if out else "silent",
            reason=out.splitlines()[0] if out else None,
        )
        if code:
            denials.append(
                out
                or f"agent-guard: the mandatory check {script.name} failed to run, "
                "so the call it protects is refused. Fix the script; Edit and "
                "Write are not gated by this hook."
            )
        elif out:
            advice.append(out)

    if denials:
        emit("PreToolUse", "\n\n".join(denials + advice), "\n\n".join(denials))
    if advice:
        emit("PreToolUse", "\n\n".join(advice))


def check_tool(payload, roots, settings, cwd):
    """The call the agent is about to make, before it makes it. A root's
    tool_checks/ holds Python scripts, each given the tool name as its argument
    and the whole hook payload on stdin, and answering in three ways:

      empty stdout            the call is fine, say nothing
      stdout, exit 0          advisory: the call proceeds, the text is context
      stdout, exit 2          ask: the human decides, the text is the question
      stdout, other non-zero  deny: the call never runs, the text is the reason

    The ask tier is for a convention that holds until a human says otherwise.
    Advice an agent may talk itself past is not the same rule, and a refusal a
    human cannot lift is a different one; asking is how a check says the call is
    theirs to allow. A crashing check exits 1, so it can only ever deny.

    A denial is read by the model, not by a person, so a script's text earns its
    keep by naming what to do instead. Scripts run through this interpreter
    rather than their shebang, because the executable bit does not survive a
    clone onto Windows."""
    if not settings.tool_checks:
        emit_silent()
    raw = json.dumps(payload, separators=(",", ":"))
    tool = payload.get("tool_name") or ""

    advice, asks, denials = [], [], []
    for root in roots:
        checks = root / "tool_checks"
        if not checks.is_dir():
            continue
        for script in sorted(checks.glob("*.py")):
            out, code = run_script(script, tool, raw, cwd, 5) or run_full(
                [sys.executable, str(script), tool],
                timeout=5,
                cwd=cwd,
                stdin=raw,
            )
            out = out.strip()
            verdict = "silent"
            if out:
                verdict = "ask" if code == ASK_EXIT else "deny" if code else "advise"
            _state.log(
                2,
                "tool-check",
                script=script.name,
                verdict=verdict,
                reason=out.splitlines()[0] if out else None,
            )
            if not out:
                continue
            {"ask": asks, "deny": denials, "advise": advice}[verdict].append(out)

    if denials:
        _state.log(1, "decision", tool=tool, outcome="deny", checks=len(denials))
        emit(
            "PreToolUse",
            "\n\n".join(denials + asks + advice),
            deny="\n\n".join(denials),
        )
    if asks:
        _state.log(1, "decision", tool=tool, outcome="ask", checks=len(asks))
        emit("PreToolUse", "\n\n".join(asks + advice), ask="\n\n".join(asks))
    if advice:
        _state.log(1, "decision", tool=tool, outcome="advise", checks=len(advice))
        emit("PreToolUse", "\n\n".join(advice))
    _state.log(1, "decision", tool=tool, outcome="allow")
    emit_silent()


_FINDING_LINE = re.compile(r":(\d+)  \[")
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
                    "  {}:{}  [{}{}] {}".format(
                        hit.get("file", path),
                        line,
                        _SG_SEVERITY.get(hit.get("severity"), "warn:"),
                        rule,
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
                    if (match := _FINDING_LINE.search(line)) and int(match.group(1)) in added
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
        emit_silent()

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

    emit("PostToolUse", context)
