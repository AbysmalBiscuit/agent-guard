"""The Stop-time changeset audit."""

import ast
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import JSCPD_MAX_SIZE, JSCPD_MIN_LINES, JSCPD_MIN_TOKENS, _int
from .contract import SILENT, advised, denied, git_base
from .external import EXTERNAL_TOOLS, run_external, tool_argv
from .file_checks import run_changeset_checks
from .paths import BARREL_OR_TEST, STATE_DIR, TEST_PATH
from .process import (
    clear_python_problem,
    have,
    python_tool_problem,
    record_python_problem,
    run,
    succeeds,
)


def find_duplication(changeset):
    """Duplication introduced by the changeset. Generated code is excluded: it is
    duplicated by design, and flagging it teaches agents to ignore the hook."""
    settings = changeset.settings
    cwd = changeset.cwd
    if not settings.use_fallow or not have("fallow"):
        return ""
    raw = run(
        ["fallow", "audit", "--base", changeset.base, "--format", "json"],
        timeout=settings.fallow_timeout,
        cwd=cwd,
    )
    if not raw.strip():
        return ""
    try:
        data = json.loads(raw)
    except ValueError:
        return ""

    groups = []
    for group in (data.get("duplication") or {}).get("clone_groups") or []:
        if not group.get("introduced"):
            continue
        instances = group.get("instances") or []
        if any(settings.ignore_re.search(i.get("file", "")) for i in instances):
            continue
        groups.append(group)
    return format_fresh_groups(groups, changeset.seen_file, settings)


def format_fresh_groups(groups, seen_file, settings):
    """The clone-report shape, shared by fallow and the Python analysis.

    A fingerprint already written this session stays out, so each clone group
    is reported once."""
    if not groups or seen_file is None:
        return ""
    try:
        seen = set(seen_file.read_text(encoding="utf-8").split())
    except OSError:
        seen = set()
    fresh = [g for g in groups if g.get("fingerprint") not in seen]
    if not fresh:
        return ""
    try:
        with seen_file.open("a", encoding="utf-8") as fh:
            for g in fresh:
                fh.write(f"{g.get('fingerprint')}\n")
    except OSError:
        pass

    lines = []
    for group in fresh[: settings.max_findings]:
        instances = group.get("instances") or []
        head = "  {} duplicated lines across {} sites ({}):".format(
            group.get("line_count"), len(instances), group.get("fingerprint")
        )
        body = [f"    {i.get('file')}:{i.get('start_line')}" for i in instances[:4]]
        if len(instances) > 4:
            body.append(f"    ... and {len(instances) - 4} more")
        lines.append("\n".join([head, *body]))
    return "\n".join(lines)


def find_over_extraction(changeset):
    """Helpers extracted past the point of usefulness. Two shapes are reported,
    each behind its own switch: an export whose only consumer is its own test,
    and an export with exactly one real caller. Barrel re-exports do not count as
    consumers. Reference counting is name-based, so it is a heuristic, which is
    why this stays advisory: a same-named symbol elsewhere reads as a consumer."""
    settings = changeset.settings
    cwd = changeset.cwd
    seen_file = changeset.seen_file
    roots = changeset.roots
    if not (settings.test_only or settings.single_caller) or not have("ast-grep"):
        return ""
    try:
        seen = set(seen_file.read_text(encoding="utf-8").split())
    except OSError:
        seen = set()

    out = []
    checked = 0
    for rel in changeset.changed:
        if checked >= settings.max_symbols:
            break
        path = cwd / rel
        if not path.is_file() or settings.ignore_re.search(rel) or TEST_PATH.search(rel):
            continue
        if rel.endswith(".tsx"):
            lang = "tsx"
        elif rel.endswith(".ts"):
            lang = "typescript"
        else:
            continue

        # Last root wins, so a repo can replace the global query with its own.
        query = None
        for root in reversed(roots):
            candidate = root / "queries" / f"exported-symbols-{lang}.yml"
            if candidate.is_file():
                query = candidate
                break
        if query is None:
            continue

        raw = run(
            ["ast-grep", "scan", "-r", str(query), "--json=compact", rel],
            timeout=15,
            cwd=cwd,
        )
        try:
            hits = json.loads(raw) if raw.strip() else []
        except ValueError:
            continue
        found = set()
        for hit in hits or []:
            single = (hit.get("metaVariables") or {}).get("single") or {}
            text = (single.get("NAME") or {}).get("text")
            if text:
                found.add(text)
        names = sorted(found)

        for name in names:
            if checked >= settings.max_symbols:
                break
            checked += 1
            if f"{rel}:{name}" in seen:
                continue
            refs = [
                r.lstrip("./")
                for r in run(
                    ["rg", "-l", "--type", "ts", "--", rf"\b{re.escape(name)}\b", "."],
                    timeout=15,
                    cwd=cwd,
                ).splitlines()
                if r.strip()
            ]
            refs = [r for r in refs if r != rel]
            testrefs = sum(1 for r in refs if TEST_PATH.search(r))
            otherrefs = sum(1 for r in refs if not BARREL_OR_TEST.search(r))

            if settings.test_only and otherrefs == 0 and testrefs > 0:
                mark = (
                    f"  {rel}:{name} is exported but consumed only by its test. "
                    "Inline it, or drop the export and the test with it."
                )
            elif settings.single_caller and otherrefs == 1:
                mark = (
                    f"  {rel}:{name} has exactly one caller. Inline it there "
                    "unless the split earns its keep."
                )
            else:
                continue
            try:
                with seen_file.open("a", encoding="utf-8") as fh:
                    fh.write(f"{rel}:{name}\n")
            except OSError:
                pass
            out.append(mark)
    return "\n".join(out)


_SOURCE_RE = re.compile(r"\.(ts|tsx|js|jsx)$")

_VULTURE_HIT = re.compile(
    r"^(.*?):(\d+): unused (\w+) '([^']+)' \((\d+)% confidence\)", re.MULTILINE
)
_LIZARD_WARN = re.compile(
    r"^(.*?):(\d+): warning: (\S+) has .*?(\d+) CCN, .*?(\d+) PARAM, (\d+) length",
    re.MULTILINE,
)


def _rel(path, cwd):
    text = str(path)
    prefix = str(cwd) + os.sep
    return text[len(prefix) :] if text.startswith(prefix) else text


def _python_spans(cwd, rel):
    """Half-open [start, end) line span of each function, keyed by the name
    complexipy prints: Class::method, or the bare name for a module function."""
    try:
        source = (cwd / rel).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError, ValueError):
        return {}
    spans = {}

    def walk(node, qual):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{qual}::{child.name}" if qual else child.name
                end = child.end_lineno if child.end_lineno is not None else child.lineno
                spans[name] = (child.lineno, end + 1)
                walk(child, name)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{qual}::{child.name}" if qual else child.name)

    walk(tree, "")
    return spans


_HUNK = re.compile(r"^@@ \S+ \+(\d+)(?:,(\d+))?")


def _added_lines(diff_text):
    """Line numbers one file's patch added. None means the file is untracked.

    A context line in the hunk is not an added line. Counting the hunk range
    would treat the line above an insertion as the branch's."""
    if diff_text is None:
        return None
    added = set()
    new_line = None
    for line in diff_text.splitlines():
        match = _HUNK.match(line)
        if match:
            new_line = int(match.group(1))
            continue
        if new_line is None or line.startswith("\\"):
            continue
        if line.startswith("+"):
            added.add(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        else:
            new_line += 1
    return added


def _touched(span, added):
    """A function the changeset touched overlaps a line the branch added."""
    if added is None:
        return True
    start, end = span
    return any(line in added for line in range(start, end))


def _baselined_complexipy(cwd, analysis, rel, name):
    path = cwd / analysis.baseline
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    for entry in data if isinstance(data, list) else []:
        entry_path = str(entry.get("path") or "").replace("\\", "/")
        if Path(entry_path).as_posix() != Path(rel).as_posix():
            continue
        for function in entry.get("functions") or []:
            if function.get("name") == name:
                return True
    return False


def _selected(changed, analysis, settings, cwd):
    """Changed files this analysis reads, minus generated and vendored paths."""
    selected = []
    for rel in changed:
        if not analysis.ext_re.search(rel) or settings.ignore_re.search(rel):
            continue
        if (cwd / rel).is_file():
            selected.append(rel)
    return selected


def find_complexipy(changeset):
    """Cognitive complexity the changeset introduced, above the tree's threshold."""
    analysis = changeset.analysis
    settings = changeset.settings
    cwd = changeset.cwd
    timeout = changeset.slot
    files = _selected(changeset.changed, analysis, settings, cwd)
    if not files:
        return ""
    cmd = tool_argv("complexipy", cwd)
    if cmd is None:
        return ""
    try:
        out_dir = tempfile.TemporaryDirectory(prefix="complexipy-")
    except OSError:
        return ""
    with out_dir:
        run_external(
            "complexipy",
            [
                *cmd,
                *files,
                "--max-complexity-allowed",
                str(analysis.max_complexity),
                "--failed",
                "--output-format",
                "json",
                "--output",
                out_dir.name,
                "--color",
                "no",
                "--snapshot-ignore",
                "--cache-dir",
                str(STATE_DIR / "complexipy-cache"),
            ],
            timeout,
            cwd,
        )
        report = Path(out_dir.name) / "complexipy-results.json"
        # complexipy writes the report to a file and may print nothing, so an
        # empty stdout is not the failure. A missing report is.
        if not report.is_file() and not python_tool_problem(cwd):
            record_python_problem("complexipy wrote no report, so the analysis stayed silent", cwd)
        try:
            rows = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else []
        except (OSError, ValueError):
            rows = []
    lines = []
    for row in rows:
        rel = _rel(row.get("path") or "", cwd)
        name = row.get("function_name") or ""
        score = row.get("complexity")
        if not name or rel not in files or not isinstance(score, int):
            continue
        if score < analysis.max_complexity:
            continue
        if _baselined_complexipy(cwd, analysis, rel, name):
            continue
        span = _python_spans(cwd, rel).get(name)
        added = _added_lines(changeset.diff_for(rel))
        if span is None or not _touched(span, added):
            continue
        lines.append(
            f"  {rel}:{span[0]}  {name} has cognitive complexity {score}, "
            f"above {analysis.max_complexity}. Split it."
        )
    return "\n".join(lines[: settings.max_findings])


def find_lizard(changeset):
    """Cyclomatic complexity, length, or parameter count the changeset introduced."""
    analysis = changeset.analysis
    settings = changeset.settings
    cwd = changeset.cwd
    timeout = changeset.slot
    files = _selected(changeset.changed, analysis, settings, cwd)
    if not files:
        return ""
    cmd = tool_argv("lizard", cwd)
    if cmd is None:
        return ""
    # A missing whitelist file makes lizard print nothing, so pass one only when it exists.
    whitelist = cwd / analysis.baseline
    baseline_args = ["-W", str(whitelist)] if whitelist.is_file() else []
    raw = run_external(
        "lizard",
        [
            *cmd,
            "-C",
            str(analysis.ccn),
            "-L",
            str(analysis.length),
            "-a",
            str(analysis.arguments),
            "-w",
            *baseline_args,
            *files,
        ],
        timeout,
        cwd,
    )
    lines = []
    for match in _LIZARD_WARN.finditer(raw):
        rel = _rel(match.group(1), cwd)
        name = match.group(3)
        ccn, params, length = (int(match.group(i)) for i in (4, 5, 6))
        start = int(match.group(2))
        # lizard prints a bare name. The report uses the qualified name when
        # the file has one, so a method does not collide with another.
        qualified = name
        if rel.endswith((".py", ".pyi")):
            for candidate, span in _python_spans(cwd, rel).items():
                if span[0] == start and candidate.split("::")[-1] == name:
                    qualified = candidate
                    break
        # lizard prints the function's start line and its length. The span is
        # those lines; a name lookup would collide on same-named methods.
        span = (start, start + length)
        added = _added_lines(changeset.diff_for(rel))
        if not _touched(span, added):
            continue
        reasons = []
        if ccn > analysis.ccn:
            reasons.append(f"cyclomatic complexity {ccn}")
        if length > analysis.length:
            reasons.append(f"length {length}")
        if params > analysis.arguments:
            reasons.append(f"{params} parameters")
        if not reasons:
            continue
        lines.append(f"  {rel}:{start}  {qualified} has {', '.join(reasons)}. Split it.")
    return "\n".join(lines[: settings.max_findings])


def find_vulture(changeset):
    """Dead code on a line the branch added."""
    analysis = changeset.analysis
    settings = changeset.settings
    cwd = changeset.cwd
    timeout = changeset.slot
    files = _selected(changeset.changed, analysis, settings, cwd)
    if not files:
        return ""
    cmd = tool_argv("vulture", cwd)
    if cmd is None:
        return ""
    whitelist = cwd / analysis.baseline
    paths = [*files, str(whitelist)] if whitelist.is_file() else files
    raw = run_external(
        "vulture",
        [*cmd, *paths, "--min-confidence", str(analysis.min_confidence)],
        timeout,
        cwd,
    )
    # An import outranks a function, which outranks a name the file does use.
    rank = {"import": 0, "function": 1, "class": 1, "method": 1, "variable": 2, "attribute": 3}
    hits = []
    for match in _VULTURE_HIT.finditer(raw):
        rel = _rel(match.group(1), cwd)
        number = int(match.group(2))
        kind = match.group(3)
        name = match.group(4)
        confidence = int(match.group(5))
        if rel not in files:
            continue
        added = _added_lines(changeset.diff_for(rel))
        if added is not None and number not in added:
            continue
        hits.append((rank.get(kind, 4), -confidence, number, rel, name))
    hits.sort()
    lines = [
        f"  {rel}:{number}  dead code: {name} is unused. Delete it or use it."
        for _kind, _confidence, number, rel, name in hits
    ]
    return "\n".join(lines[: settings.max_findings])


def _rel_of(name, cwd):
    """A tool path as a path relative to the analysis root."""
    try:
        return str(Path(name).resolve().relative_to(cwd))
    except (OSError, ValueError):
        text = str(name)
        prefix = str(cwd) + os.sep
        return text[len(prefix) :] if text.startswith(prefix) else text


def _on_added_line(instance, line_count, added):
    """True when the branch added a line inside this instance. None means git
    has never tracked the file, so every line of it is the branch's."""
    lines = added.get(instance["file"])
    if lines is None and instance["file"] in added:
        return True
    if not lines:
        return False
    start = instance["start_line"] or 1
    return any(line in lines for line in range(start, start + (line_count or 1)))


def python_clone_groups(data, cwd, added):
    """jscpd's pair list, grouped the way fallow groups a clone.

    Sites are collected by fragment first. A group stays only when one of its
    instances sits on a line the branch added."""
    groups = {}
    for pair in data.get("duplicates") or []:
        fragment = pair.get("fragment") or ""
        fingerprint = hashlib.sha1(fragment.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
        instances = []
        for side in ("firstFile", "secondFile"):
            loc = pair.get(side) or {}
            start = (loc.get("startLoc") or {}).get("line") or loc.get("start")
            instances.append({"file": _rel_of(loc.get("name") or "", cwd), "start_line": start})
        line_count = pair.get("lines")
        group = groups.setdefault(
            fingerprint,
            {"fingerprint": fingerprint, "line_count": line_count, "instances": []},
        )
        for instance in instances:
            if instance not in group["instances"]:
                group["instances"].append(instance)
    kept = []
    for group in groups.values():
        instances = group["instances"]
        if any(_on_added_line(instance, group["line_count"], added) for instance in instances):
            kept.append(group)
    return kept


def render_clone_groups(groups, seen_file, settings):
    """One block per fresh fingerprint, remembered so a second Stop stays quiet."""
    kept = []
    for group in groups:
        instances = group.get("instances") or []
        if any(settings.ignore_re.search(i.get("file", "")) for i in instances):
            continue
        kept.append(group)
    return format_fresh_groups(kept, seen_file, settings)


def jscpd_pattern(suffixes):
    """jscpd --pattern for the suffixes the extension regex selects.

    One suffix is `**/*.<suffix>`. Several are `**/*.{<suffixes>}`. A suffix
    outside jscpd's format table still scans: the pattern names the file."""
    if not suffixes:
        return ""
    if len(suffixes) == 1:
        return f"**/*.{suffixes[0]}"
    return "**/*.{" + ",".join(suffixes) + "}"


def jscpd_cross_formats(suffixes):
    """Formats jscpd must compare with each other for this selection.

    `.ts` and `.tsx` are different formats, so a clone across them is invisible
    unless they share a cross-format group. Same-format clones need no group."""
    present = {suffix for suffix in suffixes if suffix in {"ts", "tsx", "js", "jsx"}}
    if len(present) < 2:
        return ""
    return "js-ts"


def jscpd_scan_files(changed, ext_re, cwd):
    """Worktree paths the extension regex selects, including unchanged files."""
    paths = set(changed)
    for line in run(["git", "ls-files", "-z"], cwd=cwd).split("\0"):
        rel = line.strip()
        if rel:
            paths.add(rel)
    return [rel for rel in paths if ext_re.search(rel)]


def jscpd_scan_suffixes(paths):
    """The suffix list, computed once, for the pattern and the cross-format group."""
    suffixes = list(dict.fromkeys(Path(rel).suffix.lstrip(".") for rel in paths))
    return [suffix for suffix in suffixes if suffix.isascii() and suffix.isalnum()]


def find_jscpd(changeset):
    """Clone groups among the file types this analysis reads, when one
    instance sits on an added line."""
    analysis = changeset.analysis
    settings = changeset.settings
    cwd = changeset.cwd
    timeout = changeset.slot
    seen_file = changeset.seen_file
    changed = changeset.changed
    selected = [rel for rel in changed if analysis.ext_re.search(rel)]
    if not selected:
        return ""
    cmd = tool_argv("jscpd", cwd)
    if cmd is None:
        return ""
    added = {rel: _added_lines(changeset.diff_for(rel)) for rel in selected}
    suffixes = jscpd_scan_suffixes(jscpd_scan_files(changed, analysis.ext_re, cwd))
    pattern = jscpd_pattern(suffixes)
    if not pattern:
        return ""
    cross = jscpd_cross_formats(suffixes)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        out_dir = Path(tempfile.mkdtemp(prefix="jscpd-", dir=STATE_DIR))
    except OSError:
        return ""
    report = out_dir / "jscpd-report.json"
    argv = [
        *cmd,
        "--pattern",
        pattern,
        "--min-lines",
        JSCPD_MIN_LINES,
        "--min-tokens",
        JSCPD_MIN_TOKENS,
        "--max-size",
        JSCPD_MAX_SIZE,
        "--reporters",
        "json",
        "--output",
        str(out_dir),
        "--absolute",
        "--silent",
        "--no-gitignore",
    ]
    if cross:
        argv.extend(["--cross-formats", cross])
    argv.append(".")
    # The tree root keeps an unchanged original visible to a clone of a new file.
    run_external("jscpd", argv, timeout, cwd)
    try:
        data = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
    except (OSError, ValueError):
        data = None
    shutil.rmtree(out_dir, ignore_errors=True)
    if not data:
        return ""
    return render_clone_groups(python_clone_groups(data, cwd, added), seen_file, settings)


def _module_in_root(module, root):
    """A pyscn module as a path relative to the analysis root.

    pyscn dots every parent directory into the module name, so a copy under
    the state directory carries those segments. file_path does not."""
    file_path = str(module.get("file_path") or "")
    if file_path:
        try:
            rel = Path(file_path).resolve().relative_to(Path(root).resolve())
        except ValueError:
            return ""
        return str(rel.with_suffix("")).replace(os.sep, ".").removesuffix(".__init__")
    return str(module.get("module_name") or "")


def cycle_keys(raw, root):
    """One stable key per cycle, modules relative to the analysis root."""
    if not raw or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    analysis = (data.get("system") or {}).get("dependency_analysis") or {}
    metrics = analysis.get("module_metrics") or {}
    cycles = (analysis.get("circular_dependencies") or {}).get("circular_dependencies") or []
    keys = set()
    for cycle in cycles:
        modules = []
        for name in cycle.get("modules") or []:
            metric = metrics.get(name) or {}
            rel = _module_in_root({"file_path": metric.get("file_path"), "module_name": name}, root)
            if rel:
                modules.append(rel)
        if modules:
            keys.add(" ".join(sorted(modules)))
    return keys


def _extract_base(base, cwd, dest, deadline):
    """Python files at the base revision, under dest, inside the shared deadline.

    One git archive feeds tar, so the copy is one subprocess, bounded by the
    time still left."""
    left = deadline - time.monotonic()
    if left <= 0:
        return False
    archive = None
    try:
        archive = subprocess.Popen(
            ["git", "archive", "--format=tar", base],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        tar = subprocess.run(
            ["tar", "-x", "-C", str(dest)],
            stdin=archive.stdout,
            timeout=left,
            check=False,
        )
        if archive.stdout:
            archive.stdout.close()
        archive.wait(timeout=left)
    except (OSError, subprocess.TimeoutExpired):
        if archive is not None:
            with contextlib.suppress(OSError):
                archive.kill()
        return False
    if tar.returncode != 0 or archive.returncode != 0:
        return False
    # pyscn reads Python. Other files from the archive are not modules.
    for path in Path(dest).rglob("*"):
        if path.is_file() and path.suffix not in (".py", ".pyi"):
            path.unlink(missing_ok=True)
    return True


def find_pyscn(changeset):
    """Import cycles the working tree has and the base revision did not."""
    analysis = changeset.analysis
    cwd = changeset.cwd
    timeout = changeset.slot
    changed = changeset.changed
    if not any(analysis.ext_re.search(rel) for rel in changed):
        return ""
    cmd = tool_argv("pyscn", cwd)
    if cmd is None:
        return ""
    started = time.monotonic()
    current_raw = run_external(
        "pyscn",
        [*cmd, "analyze", "--select", "deps", "--json", "--output", "-", "."],
        timeout,
        cwd,
    )
    current = cycle_keys(current_raw, cwd)
    if not current:
        return ""
    left = timeout - (time.monotonic() - started)
    if left <= 0:
        record_python_problem(
            "pyscn: no time left under the hook deadline, so the analysis stayed silent", cwd
        )
        return ""
    try:
        parent = Path(tempfile.mkdtemp(prefix="pyscn-base-", dir=STATE_DIR))
    except OSError:
        return ""
    # pyscn names a module from the directory it scans, so the copy sits in a
    # directory with the tree's own name. The same cycle then has the same key.
    dest = parent / cwd.name
    deadline = time.monotonic() + left
    try:
        dest.mkdir()
        source = changeset.shared_base(deadline)
        if not source or not _extract_base_from(source, dest):
            record_python_problem(
                "pyscn: the base revision copy did not finish, so the analysis stayed silent",
                cwd,
            )
            return ""
        base_raw = run_external(
            "pyscn",
            [*cmd, "analyze", "--select", "deps", "--json", "--output", "-", "."],
            max(deadline - time.monotonic(), 1),
            dest,
        )
    finally:
        shutil.rmtree(parent, ignore_errors=True)
    base_keys = cycle_keys(base_raw, dest)
    if base_keys is None:
        return ""
    fresh = sorted(current - base_keys)
    if not fresh:
        return ""
    lines = ["  import cycles the base revision did not have:"]
    lines.extend(f"    {key}" for key in fresh[: changeset.settings.max_findings])
    return "\n".join(lines)


def find_file_length_analysis(changeset):
    """Changed files past a warn or block limit, from the shared file list."""
    text, blocks = find_file_length(changeset.length_changed, changeset.settings, changeset.cwd)
    changeset.length_blocks = blocks
    return text


# One signature. A new analysis is another row, not another call shape.
ANALYSES = (
    ("duplication", find_duplication),
    ("over-extraction", find_over_extraction),
    ("complexipy", find_complexipy),
    ("lizard", find_lizard),
    ("vulture", find_vulture),
    ("jscpd", find_jscpd),
    ("pyscn", find_pyscn),
    ("file-length", find_file_length_analysis),
)

_PYTHON = frozenset(tool.name for tool in EXTERNAL_TOOLS)


def run_analyses(changeset):
    """Every analysis, each given the same changeset. A tool with no time left
    is recorded and skipped. The changeset owns that record."""
    findings = {}
    for name, analyze in ANALYSES:
        if name in _PYTHON:
            analysis = changeset.settings.python[name]
            if not analysis.enabled:
                continue
            left = changeset.budget - (time.monotonic() - changeset.budget_started)
            if left <= 0:
                record_python_problem(
                    f"{name}: no time left under the hook deadline, so the analysis stayed silent",
                    changeset.cwd,
                )
                continue
            changeset.analysis = analysis
            changeset.slot = min(analysis.timeout, left)
        elif name == "file-length" and not changeset.length_changed:
            continue
        text = analyze(changeset)
        if text:
            findings[name] = text
    return findings


def render_findings(who, findings, violations):
    """One report from every analysis's text. The wording is the contract the
    existing Stop tests read."""
    sections = []
    if violations:
        sections.append(violations)
    dupes = findings.get("duplication")
    if dupes:
        sections.append(
            f"{who} introduced duplicated code rather than reusing what already "
            f"exists:\n\n{dupes}\n\nConsolidate against the existing "
            "implementation, or explain why a separate one is warranted. Run "
            "'fallow dupes --trace <fingerprint>' for the full clone group.\n"
        )
    extraction = findings.get("over-extraction")
    if extraction:
        sections.append(
            f"{who} added helpers that carry their own abstraction cost without "
            f"earning it:\n\n{extraction}\nAn indirection worth keeping has more "
            "than one caller, or a name that explains something the inlined code "
            "would not."
        )
    python = "\n".join(
        findings[name] for name, _analyze in ANALYSES if name in _PYTHON and findings.get(name)
    )
    if python:
        sections.append(
            f"{who} introduced findings the tree asked this audit to report:\n\n{python}\n"
        )
    length_text = findings.get("file-length")
    if length_text:
        sections.append(
            f"{who} changed files past a length limit this tree set:\n\n{length_text}\n"
        )
    return sections


def _watched_diff(diff_text, watched):
    """The one patch, reduced to the files the skip watches."""
    if not watched:
        return ""
    keep = set(watched)
    parts = []
    for rel, text in _split_diff(diff_text).items():
        if rel in keep:
            parts.append(text)
    return "".join(parts)


def _fingerprint_files(changed, settings):
    """Files a repeat Stop compares. With the length check off, a non-source
    edit is not a change the skip watches."""
    if settings.file_length.enabled:
        return changed
    patterns = [_SOURCE_RE]
    patterns.extend(analysis.ext_re for analysis in settings.python.values() if analysis.enabled)
    return [rel for rel in changed if any(pattern.search(rel) for pattern in patterns)]


def _line_count(path):
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def find_file_length(changed, settings, cwd):
    """Changed files past a warn or block limit this tree named."""
    length = settings.file_length
    if not length.enabled or not length.limits:
        return "", False
    lines = []
    blocks = False
    for rel in changed:
        if not rel.strip() or settings.ignore_re.search(rel):
            continue
        limit = _length_limit(rel, length.limits)
        if limit is None:
            continue
        count = _line_count(cwd / rel)
        if limit.accept:
            if limit.lines and count > limit.lines:
                blocks = True
                lines.append(
                    f"  {rel}  {count} lines, accepted at {limit.lines}. {length.block_message}"
                )
            continue
        if limit.block_lines and count > limit.block_lines:
            blocks = True
            lines.append(
                f"  {rel}  {count} lines, past the block limit of {limit.block_lines}. "
                f"{length.block_message}"
            )
        elif limit.warn_lines and count > limit.warn_lines:
            lines.append(
                f"  {rel}  {count} lines, past the warn limit of {limit.warn_lines}. "
                f"{length.warn_message}"
            )
    return "\n".join(lines[: settings.max_findings]), blocks


def _length_pattern_match(rel, pattern):
    """A git pathspec over the whole relative path. `**` crosses segments."""
    parts = pattern.replace("\\", "/").split("/")
    expr = r"\A"
    last = len(parts) - 1
    for index, part in enumerate(parts):
        if part == "**":
            if index == 0 and last > 0:
                expr += r"(?:.*/)?"
            elif index == last and index > 0:
                expr += r"/.*"
            elif index == 0:
                expr += r".*"
            else:
                expr += r"/(?:.*/)?"
            continue
        if index and parts[index - 1] != "**":
            expr += r"/"
        expr += _length_segment(part)
    return re.fullmatch(expr, rel.replace("\\", "/")) is not None


def _length_segment(part):
    out = []
    for char in part:
        if char == "*":
            out.append(r"[^/]*")
        elif char == "?":
            out.append(r"[^/]")
        else:
            out.append(re.escape(char))
    return "".join(out)


def _length_files(changed, settings):
    """Changed files the length check reads, from the one changed-file list.

    The 200-file cap applies after the length filter, so a covered file that
    sorts after 200 uncovered paths still reaches the check."""
    if not settings.file_length.enabled:
        return []
    limits = settings.file_length.limits
    selected = [rel for rel in changed if rel.strip() and _length_limit(rel, limits) is not None]
    return selected[:200]


def _usable_limits(limits):
    """Rows the check can apply. An accept row needs a recorded size."""
    return [limit for limit in limits if not _accept_without_lines(limit)]


def _accept_without_lines(limit):
    return limit.accept and limit.lines <= 0


def _length_limit(rel, limits):
    """A named path or glob outranks an extension regex.

    The first matching path wins, then the first matching extension. A path
    limit listed after a broad extension still applies to that path."""
    usable = _usable_limits(limits)
    named = [limit for limit in usable if limit.pattern]
    typed = [limit for limit in usable if limit.ext_re is not None]
    for limit in named:
        if _length_pattern_match(rel, limit.pattern):
            return limit
    for limit in typed:
        if limit.ext_re.search(rel):
            return limit
    return None


class Changeset:
    """One Stop's diff, file list, and base copy, shared by every analysis.

    `diff_text` is the one `git diff` against the base. `base_copy` is filled
    the first time an analysis asks for the base revision."""

    def __init__(self, base, diff_text, changed, cwd, settings, roots, seen_file):
        self.base = base
        self.diff_text = diff_text
        self.changed = changed
        self.cwd = cwd
        self.settings = settings
        self.roots = roots
        self.seen_file = seen_file
        self.length_changed = []
        self.length_blocks = False
        self.analysis = None
        self.slot = None
        self.budget_started = None
        self.budget = None
        self._files = {}
        self._base_copy = None
        self._base_miss = False
        for rel, text in _split_diff(diff_text).items():
            self._files[rel] = text

    def diff_for(self, rel):
        """This file's patch. None means the file is untracked."""
        if rel in self._files:
            return self._files[rel]
        if rel in self.changed and not succeeds(
            ["git", "ls-files", "--error-unmatch", "--", rel], cwd=self.cwd
        ):
            return None
        return ""

    def shared_base(self, deadline):
        """Directory of the one base extraction, or "" when it did not finish."""
        if self._base_miss:
            return ""
        if self._base_copy is None:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            self._base_copy = Path(tempfile.mkdtemp(prefix="changeset-base-", dir=STATE_DIR))
            if not _extract_base(self.base, self.cwd, self._base_copy, deadline):
                self._base_miss = True
                shutil.rmtree(self._base_copy, ignore_errors=True)
                self._base_copy = None
                return ""
        return str(self._base_copy)

    def close(self):
        if self._base_copy is not None:
            shutil.rmtree(self._base_copy, ignore_errors=True)
            self._base_copy = None


def _split_diff(diff_text):
    """One patch body per path in a combined `git diff`."""
    files = {}
    current = None
    body = []

    def finish():
        if current is not None:
            files[current] = "\n".join(body) + ("\n" if body else "")

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            finish()
            body = [line]
            current = None
            parts = line.split(" ")
            if len(parts) >= 4 and parts[-1].startswith("b/"):
                current = parts[-1][2:]
            continue
        if current is None:
            continue
        body.append(line)
    finish()
    return files


def _extract_base_from(source, dest):
    """Copy the shared base extraction into the directory an analysis scans."""
    try:
        for path in Path(source).rglob("*"):
            rel = path.relative_to(source)
            target = Path(dest) / rel
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    except OSError:
        return False
    return True


def read_changeset(base, cwd):
    """The diff once, plus untracked names. A new file is absent from the diff."""
    diff_text = run(["git", "diff", base], cwd=cwd)
    changed = _names_from_diff(diff_text)
    seen = set(changed)
    for line in run(["git", "ls-files", "--others", "--exclude-standard"], cwd=cwd).splitlines():
        rel = line.strip()
        if rel and rel not in seen:
            seen.add(rel)
            changed.append(rel)
    return diff_text, changed


def _names_from_diff(diff_text):
    """Paths the one patch touches, including deletions."""
    names = []
    seen = set()
    for line in diff_text.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split(" ")
        if len(parts) < 4 or not parts[-1].startswith("b/"):
            continue
        rel = parts[-1][2:]
        if not rel or rel in seen:
            continue
        seen.add(rel)
        names.append(rel)
    return names


def changeset_fingerprint(diff_text, changed, cwd):
    """Everything a report would be derived from, hashed. The diff alone cannot
    stand in for it: an untracked file's content is absent from the diff, so a
    second new file after a first report would read as no change at all and the
    report would be skipped. The diff still goes in, because a deletion moves it
    while leaving nothing on disk to read."""
    digest = hashlib.sha256()
    digest.update(diff_text.encode("utf-8", "replace"))
    digest.update("\0".join(changed).encode("utf-8", "replace"))
    for rel in changed:
        digest.update(rel.encode("utf-8", "replace"))
        path = cwd / rel
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def check_changeset(session, agent_type, roots, settings, cwd):
    """Cross-file analysis on the changeset. Only findings the changeset
    introduced are reported; inherited debt is not this agent's to answer for."""
    if not have("git") or not succeeds(["git", "rev-parse", "--git-dir"], cwd=cwd):
        return SILENT

    base = git_base(settings, cwd)
    diff_text, changed = read_changeset(base, cwd)
    # Before the source-glob gate: the duplication audit reads TS and JS, but a
    # changeset-check speaks for whatever files its own rule covers, and a
    # branch that touched only markdown or shell still has to answer for them.
    wants_base = settings.python["pyscn"].enabled or any(
        (root / "changeset_checks").is_dir() for root in roots
    )
    held = Changeset(base, diff_text, changed, cwd, settings, roots, None)
    base_copy = held.shared_base(time.monotonic() + 20) if wants_base else ""
    violations = run_changeset_checks(base, roots, cwd, base_copy)
    if not changed and not violations:
        # Nothing for the tools to read. Drop a note from an earlier Stop.
        clear_python_problem(cwd)
        return SILENT

    sdir = STATE_DIR / session
    try:
        sdir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return SILENT
    seen_file = sdir / "seen-fingerprints"
    if not seen_file.exists():
        with contextlib.suppress(OSError):
            seen_file.touch()

    # Skip re-running when the changeset has not moved since the last report.
    # Python tools run after this skip: a repeat of the same diff must not pay
    # for them again.
    fingerprint = (
        changeset_fingerprint(
            _watched_diff(diff_text, _fingerprint_files(changed, settings)),
            _fingerprint_files(changed, settings),
            cwd,
        )
        + hashlib.sha1(violations.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()
    )
    last = sdir / "last-diff"
    try:
        if last.is_file() and last.read_text(encoding="utf-8").strip() == fingerprint:
            return SILENT
        last.write_text(fingerprint, encoding="utf-8")
    except OSError:
        pass

    changeset = held
    changeset.seen_file = seen_file
    changeset.length_changed = _length_files(changed, settings)
    who = f"Subagent '{agent_type}'" if agent_type else "This agent"
    # fallow and the Python tools share one deadline under the hook's 60s.
    # Each Python tool gets only the time still left.
    changeset.budget = 55
    changeset.budget_started = time.monotonic()
    clear_python_problem(cwd)
    try:
        findings = run_analyses(changeset)
    finally:
        changeset.close()
    sections = render_findings(who, findings, violations)
    if not sections:
        return SILENT
    context = "\n".join(sections)
    dupes = findings.get("duplication") or ""
    length_blocks = changeset.length_blocks

    blocks_file = sdir / "blocks"
    blocks = _int(blocks_file.read_text(encoding="utf-8") if blocks_file.is_file() else "0", 0)
    if settings.block and (violations or dupes or length_blocks) and blocks < settings.max_blocks:
        with contextlib.suppress(OSError):
            blocks_file.write_text(str(blocks + 1), encoding="utf-8")
        if length_blocks:
            reason = f"agent-guard: {settings.file_length.block_message}"
        elif violations:
            reason = "agent-guard: this changeset violates a rule of the tree it is in"
        else:
            reason = "agent-guard: duplication introduced by this changeset is unresolved"
        return denied(context, reason)
    return advised(context)
