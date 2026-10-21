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
from .contract import SILENT, advised, changed_lines, denied, git_base
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


def find_duplication(base, seen_file, settings, cwd):
    """Duplication introduced by the changeset. Generated code is excluded: it is
    duplicated by design, and flagging it teaches agents to ignore the hook."""
    if not settings.use_fallow or not have("fallow"):
        return ""
    raw = run(
        ["fallow", "audit", "--base", base, "--format", "json"],
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
    return format_fresh_groups(groups, seen_file, settings)


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


def find_over_extraction(changed, seen_file, roots, settings, cwd):
    """Helpers extracted past the point of usefulness. Two shapes are reported,
    each behind its own switch: an export whose only consumer is its own test,
    and an export with exactly one real caller. Barrel re-exports do not count as
    consumers. Reference counting is name-based, so it is a heuristic, which is
    why this stays advisory: a same-named symbol elsewhere reads as a consumer."""
    if not (settings.test_only or settings.single_caller) or not have("ast-grep"):
        return ""
    try:
        seen = set(seen_file.read_text(encoding="utf-8").split())
    except OSError:
        seen = set()

    out = []
    checked = 0
    for rel in changed:
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


SOURCE_GLOBS = ("*.ts", "*.tsx", "*.js", "*.jsx")
PYTHON_GLOBS = ("*.py", "*.pyi")

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


def find_complexipy(changed, analysis, settings, cwd, base, timeout, _seen_file):
    """Cognitive complexity the changeset introduced, above the tree's threshold."""
    files = _selected(changed, analysis, settings, cwd)
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
        added = changed_lines(str(cwd / rel), base, cwd)
        if span is None or not _touched(span, added):
            continue
        lines.append(
            f"  {rel}:{span[0]}  {name} has cognitive complexity {score}, "
            f"above {analysis.max_complexity}. Split it."
        )
    return "\n".join(lines[: settings.max_findings])


def find_lizard(changed, analysis, settings, cwd, base, timeout, _seen_file):
    """Cyclomatic complexity, length, or parameter count the changeset introduced."""
    files = _selected(changed, analysis, settings, cwd)
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
        added = changed_lines(str(cwd / rel), base, cwd)
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


def find_vulture(changed, analysis, settings, cwd, base, timeout, _seen_file):
    """Dead code on a line the branch added."""
    files = _selected(changed, analysis, settings, cwd)
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
        added = changed_lines(str(cwd / rel), base, cwd)
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


def jscpd_pattern(selected):
    """jscpd --pattern for the suffixes of the selected files.

    One suffix is `**/*.<suffix>`. Several are `**/*.{<suffixes>}`. A suffix
    outside jscpd's format table still scans: the pattern names the file."""
    suffixes = list(dict.fromkeys(Path(rel).suffix.lstrip(".") for rel in selected))
    suffixes = [suffix for suffix in suffixes if suffix.isascii() and suffix.isalnum()]
    if not suffixes:
        return ""
    if len(suffixes) == 1:
        return f"**/*.{suffixes[0]}"
    return "**/*.{" + ",".join(suffixes) + "}"


def jscpd_suffixes(ext_re):
    """Suffixes the extensions regex writes, so the changeset lists them."""
    written = []
    for bare, grouped in re.findall(r"\\\.(?:([A-Za-z0-9]+)|(\([^)]*\)))", ext_re.pattern):
        pieces = [bare] if bare else grouped[1:-1].split("|")
        written.extend(piece for piece in pieces if piece.isascii() and piece.isalnum())
    return list(dict.fromkeys(written))


def find_jscpd(changed, analysis, settings, cwd, base, timeout, seen_file):
    """Clone groups among the file types this analysis reads, when one
    instance sits on an added line."""
    selected = [rel for rel in changed if analysis.ext_re.search(rel)]
    if not selected:
        return ""
    cmd = tool_argv("jscpd", cwd)
    if cmd is None:
        return ""
    added = {rel: changed_lines(str(cwd / rel), base, cwd) for rel in selected}
    pattern = jscpd_pattern(selected)
    if not pattern:
        return ""
    try:
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
        ".",
    ]
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


def find_pyscn(changed, analysis, settings, cwd, base, timeout, _seen_file):
    """Import cycles the working tree has and the base revision did not."""
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
        if not _extract_base(base, cwd, dest, deadline):
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
    lines.extend(f"    {key}" for key in fresh[: settings.max_findings])
    return "\n".join(lines)


def find_python(changed, settings, cwd, base, budget, seen_file=None):
    """Findings from the analyses this tree turned on.

    `budget` is seconds left under the Stop hook's own deadline. Each tool gets
    only what remains, and a tool with none left is skipped and recorded."""
    readers = {
        "complexipy": find_complexipy,
        "lizard": find_lizard,
        "vulture": find_vulture,
        "jscpd": find_jscpd,
        "pyscn": find_pyscn,
    }
    missing = [tool.name for tool in EXTERNAL_TOOLS if tool.name not in readers]
    if missing:
        raise RuntimeError(f"no reader for {', '.join(missing)}")
    clear_python_problem(cwd)
    sections = []
    started = time.monotonic()
    for tool in EXTERNAL_TOOLS:
        name = tool.name
        analysis = settings.python[name]
        if not analysis.enabled:
            continue
        left = budget - (time.monotonic() - started)
        if left <= 0:
            record_python_problem(
                f"{name}: no time left under the hook deadline, so the analysis stayed silent",
                cwd,
            )
            continue
        slot = min(analysis.timeout, left)
        text = readers[name](changed, analysis, settings, cwd, base, slot, seen_file)
        if text:
            sections.append(text)
    return "\n".join(sections)


def source_globs(settings):
    """File types the changeset listing reads. Python globs join only when a
    tree turned a Python analysis on, so an opted-out tree keeps its old list.
    jscpd also reads the suffixes its extensions regex matches."""
    globs = list(SOURCE_GLOBS)
    if any(analysis.enabled for analysis in settings.python.values()):
        globs.extend(PYTHON_GLOBS)
    jscpd = settings.python["jscpd"]
    if jscpd.enabled:
        globs.extend(f"*.{suffix}" for suffix in jscpd_suffixes(jscpd.ext_re))
    return tuple(dict.fromkeys(globs))


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


def _length_files(base, cwd, settings):
    """Changed files the length check reads, before the listing cap."""
    if not settings.file_length.enabled:
        return []
    limits = settings.file_length.limits
    return changed_files(
        base,
        cwd,
        (),
        keep=lambda rel: bool(rel.strip()) and _length_limit(rel, limits) is not None,
    )


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


def changed_files(base, cwd, globs, keep=None):
    """What the branch touched, including what git does not track yet. A file an
    agent wrote and has not committed never appears in `git diff`, and it is the
    likeliest place for a copy of something that already exists: written from
    scratch by someone who did not find the original. --exclude-standard keeps
    ignored trees such as node_modules out. `keep` drops a path before the
    200-file cap."""
    listings = (
        ["git", "diff", "--name-only", base, "--", *globs],
        ["git", "ls-files", "--others", "--exclude-standard", "--", *globs],
    )
    out, seen = [], set()
    for cmd in listings:
        for line in run(cmd, cwd=cwd).splitlines():
            rel = line.strip()
            if not rel or rel in seen or (keep is not None and not keep(rel)):
                continue
            seen.add(rel)
            out.append(rel)
            if len(out) == 200:
                return out
    return out


def changeset_fingerprint(base, changed, cwd, globs):
    """Everything a report would be derived from, hashed. The diff alone cannot
    stand in for it: an untracked file's content is absent from the diff, so a
    second new file after a first report would read as no change at all and the
    report would be skipped. The diff still goes in, because a deletion moves it
    while leaving nothing on disk to read."""
    digest = hashlib.sha256()
    digest.update(run(["git", "diff", base, "--", *globs], cwd=cwd).encode("utf-8", "replace"))
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
    globs = source_globs(settings)
    changed = changed_files(base, cwd, globs)
    length_changed = _length_files(base, cwd, settings)
    changed = list(dict.fromkeys([*changed, *length_changed]))
    # Before the source-glob gate: the duplication audit reads TS and JS, but a
    # changeset-check speaks for whatever files its own rule covers, and a
    # branch that touched only markdown or shell still has to answer for them.
    violations = run_changeset_checks(base, roots, cwd)
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
        changeset_fingerprint(base, changed, cwd, globs)
        + hashlib.sha1(violations.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()
    )
    last = sdir / "last-diff"
    try:
        if last.is_file() and last.read_text(encoding="utf-8").strip() == fingerprint:
            return SILENT
        last.write_text(fingerprint, encoding="utf-8")
    except OSError:
        pass

    who = f"Subagent '{agent_type}'" if agent_type else "This agent"
    # fallow and the Python tools share one deadline under the hook's 60s.
    # Each Python tool gets only the time still left.
    audit_deadline = time.monotonic() + 55
    dupes = find_duplication(base, seen_file, settings, cwd)
    extraction = find_over_extraction(changed, seen_file, roots, settings, cwd)
    sections = []
    if violations:
        sections.append(violations)
    if dupes:
        sections.append(
            f"{who} introduced duplicated code rather than reusing what already "
            f"exists:\n\n{dupes}\n\nConsolidate against the existing "
            "implementation, or explain why a separate one is warranted. Run "
            "'fallow dupes --trace <fingerprint>' for the full clone group.\n"
        )
    if extraction:
        sections.append(
            f"{who} added helpers that carry their own abstraction cost without "
            f"earning it:\n\n{extraction}\nAn indirection worth keeping has more "
            "than one caller, or a name that explains something the inlined code "
            "would not."
        )
    python = find_python(changed, settings, cwd, base, audit_deadline - time.monotonic(), seen_file)
    if python:
        sections.append(
            f"{who} introduced findings the tree asked this audit to report:\n\n{python}\n"
        )
    length_text, length_blocks = find_file_length(length_changed, settings, cwd)
    if length_text:
        sections.append(
            f"{who} changed files past a length limit this tree set:\n\n{length_text}\n"
        )
    if not sections:
        return SILENT
    context = "\n".join(sections)

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
