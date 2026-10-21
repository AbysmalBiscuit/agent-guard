"""Layered config and the settings a run reads."""

import os
import re
import tomllib

from .paths import _ENV_PREFIX, CONFIG_DIR, CONFIG_NAME, ROOT_NAMES, STATE_DIR


def is_root(path):
    """A config.toml alone is enough: a tree that wants only the global rules
    under its own settings still opts in by carrying the directory."""
    return path.is_dir() and (
        (path / "rules").is_dir()
        or (path / "checks").is_dir()
        or (path / "tool_checks").is_dir()
        or (path / "changeset_checks").is_dir()
        or (path / "sgconfig.yml").is_file()
        or (path / CONFIG_NAME).is_file()
    )


def discover_roots(cwd):
    """Every ancestor of the working directory, outermost first, so a nearer tree
    layers over a wider one: a checkout over the directory that holds every
    checkout of that project, over the global install. Deliberately not keyed on
    the git toplevel, because worktrees of one repository share settings that
    belong in the directory above them rather than in its own history."""
    roots = [CONFIG_DIR]
    for ancestor in reversed([cwd, *list(cwd.parents)]):
        for name in ROOT_NAMES:
            candidate = ancestor / name
            if candidate != CONFIG_DIR and is_root(candidate):
                roots.append(candidate)
    return roots


def load_config(roots):
    """Every root's config.toml, nearest last.

    Unknown keys are ignored. An unparsable file is skipped.
    AGENT_GUARD_<KEY> overrides a file. A [python] table lands on python_<key>."""
    cfg = {}
    origins = {}
    for root in roots:
        f = root / CONFIG_NAME
        if not f.is_file():
            continue
        try:
            with f.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        label = str(root)
        flat = {k: v for k, v in data.items() if not isinstance(v, dict)}
        python = data.get("python")
        if isinstance(python, dict):
            flat.update({f"python_{k}": v for k, v in python.items() if not isinstance(v, dict)})
        for key in flat:
            origins[key] = label
        cfg.update(flat)
    for key, value in os.environ.items():
        if key.startswith(_ENV_PREFIX):
            name = key[len(_ENV_PREFIX) :].lower()
            cfg[name] = value
            origins[name] = key
    cfg["__origins"] = origins
    return cfg


def _compile(pattern):
    try:
        return re.compile(pattern)
    except re.error:
        # A broken pattern fails closed to "matches nothing" rather than
        # widening to everything.
        return re.compile(r"(?!x)x")


class Settings:
    """Values come from TOML, so they arrive already typed. They also come from
    the environment as strings, so every read coerces."""

    def __init__(self, cfg):
        g = cfg.get
        # Blocking is opt-in. A gate that is wrong once teaches every agent to
        # route around it, so a rule earns the right to block only after it
        # proves quiet.
        self.block = _bool(g("block"), False)
        # There is no built-in loop protection on Stop hooks, so cap how often
        # one session may be refused before this downgrades itself to advisory.
        self.max_blocks = _int(g("max_blocks"), 2)
        # tool_checks/ can refuse a call outright, so it needs a kill switch a
        # denied agent's operator can reach without editing a script:
        # AGENT_GUARD_TOOL_CHECKS=0 for one run.
        self.tool_checks = _bool(g("tool_checks"), True)
        self.use_fallow = _bool(g("fallow"), True)
        self.fallow_timeout = _float(g("fallow_timeout"), 45.0)
        # Findings shown per report, so feedback stays inside working memory.
        self.max_findings = _int(g("max_findings"), 8)
        # Bound on symbols reference-counted per changeset, so a wide diff stays
        # cheap.
        self.max_symbols = _int(g("max_symbols"), 40)
        # A function with one caller is often a fine module boundary, so that
        # half is opt-in.
        self.single_caller = _bool(g("single_caller"), False)
        # Exports whose only consumer is their own test. A tree mid-migration,
        # where a parity test is deliberately the sole caller of the new path,
        # turns this off.
        self.test_only = _bool(g("test_only"), True)
        # Which lines of an edited file the per-file findings are reported on.
        # 'diff' keeps only the lines the branch introduced; 'file' reports the
        # whole file. Inherited debt is not the editing agent's to answer for,
        # and a report mostly made of it is one an agent learns to skim past.
        self.scope = _str(g("scope"), "diff")
        # Which files the per-file rules run on. A repo adding rules for another
        # language widens this in its own config.toml.
        self.ext_src = _str(g("extensions"), r"\.(ts|tsx|mts|cts)$")
        self.ext_re = _compile(self.ext_src)
        # Paths this hook has nothing useful to say about: code that is
        # generated rather than written, and vendored code the tree does not own.
        # Flagging either trains agents to ignore the hook. Only the language-wide
        # shapes are listed here, and a project names its own directories through
        # the additive knob. Separators are matched both ways, because a hook
        # payload carries whatever form the platform uses.
        ignore = _str(
            g("ignore"),
            r"\.gen\.|[/\\](generated|__generated__|node_modules)[/\\]|\.d\.ts$",
        )
        extra = _str(g("ignore_extra"), "")
        # Appended rather than assigned, so a layer adds paths without restating
        # the defaults. Restating them by hand invites a stray leading '|', whose
        # empty alternation matches every path and silently disables the check.
        self.ignore_src = f"{ignore}|{extra}" if extra else ignore
        self.ignore_re = _compile(self.ignore_src)
        self.base_override = _str(g("base"), "")
        # Layers that still run where no tree has opted in. rules/ and checks/
        # describe a project's conventions and wait to be asked for; a global
        # tool_checks/ describes the machine, which is the same one in every
        # directory. Empty by default, so behaviour changes only for a config
        # that asks for it.
        self.always = _layers(g("always"))
        # Which file wrote each setting, for doctor. Absent on a hand-built cfg.
        self.origins = g("__origins") if isinstance(g("__origins"), dict) else {}
        # Python changeset analyses. Off until a tree turns one on: each one
        # assumes that tree's thresholds and baseline, so firing unasked is noise.
        self.python = {name: PythonAnalysis(name, g, self.origins) for name in PYTHON_ANALYSES}


def _bool(value, fallback):
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _int(value, fallback):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return fallback


def _float(value, fallback):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return fallback


def _str(value, fallback):
    return fallback if value is None else str(value)


LAYERS = ("rules", "checks", "tool_checks", "changeset")

# jscpd's default min-tokens treats a short file list as empty.
JSCPD_MIN_LINES = "5"
JSCPD_MIN_TOKENS = "5"
# jscpd's default file-size bound skips a large Python file. No line bound:
# a line bound hides the same files.
JSCPD_MAX_SIZE = "100m"

# extensions is the file types a tree asks this analysis to run on.
PYTHON_ANALYSES = ("complexipy", "lizard", "vulture", "jscpd", "pyscn")
PYTHON_DEFAULT_EXTENSIONS = {
    "complexipy": r"\.py$",
    "lizard": r"\.(py|ts|tsx)$",
    "vulture": r"\.py$",
    "jscpd": r"\.py$",
    "pyscn": r"\.py$",
}
PYTHON_DEFAULT_BASELINE = {
    "complexipy": "complexipy-snapshot.json",
    "lizard": "whitelizard.txt",
    "vulture": "vulture-whitelist.py",
    "jscpd": "",
    "pyscn": "",
}


class PythonAnalysis:
    """One opt-in changeset analysis, read from the [python] table."""

    def __init__(self, name, get, origins):
        self.name = name
        self.enabled = _bool(get(f"python_{name}"), False)
        raw_extensions = get(f"python_{name}_extensions")
        # An empty value is a tree asking for no file types, not the default.
        self.extensions = (
            PYTHON_DEFAULT_EXTENSIONS[name] if raw_extensions is None else str(raw_extensions)
        )
        # An empty pattern matches every path, so a blank value matches none.
        self.ext_re = _compile(self.extensions) if self.extensions else _compile(r"(?!x)x")
        self.baseline = _str(get(f"python_{name}_baseline"), PYTHON_DEFAULT_BASELINE[name])
        self.timeout = _float(get("python_timeout"), 20.0)
        self.max_complexity = _int(get("python_complexipy_max"), 15)
        self.ccn = _int(get("python_lizard_ccn"), 15)
        self.length = _int(get("python_lizard_length"), 1000)
        # High until a tree names its own limit, so an ordinary signature stays quiet.
        self.arguments = _int(get("python_lizard_arguments"), 100)
        self.min_confidence = _int(get("python_vulture_min_confidence"), 60)
        self.origin = origins.get(f"python_{name}", "")


def _layers(value):
    """A TOML list, or the comma-separated string an environment override
    arrives as. Unknown names are dropped rather than widening anything."""
    if value is None:
        return frozenset()
    names = value if isinstance(value, list) else str(value).split(",")
    return frozenset(str(n).strip() for n in names) & frozenset(LAYERS)


def sgconfig_for(root):
    """A root ships either a full sgconfig.yml, required for custom languages
    whose libraryPath resolves relative to it, or just a rules/ directory.
    Synthesise a config for the latter, cached and refreshed when rules change."""
    own = root / "sgconfig.yml"
    if own.is_file():
        return own
    rules = root / "rules"
    if not rules.is_dir():
        return None
    key = re.sub(r"[^A-Za-z0-9]", "_", str(root))
    generated = STATE_DIR / "generated" / f"{key}.yml"
    try:
        generated.parent.mkdir(parents=True, exist_ok=True)
        if not generated.is_file() or generated.stat().st_mtime <= rules.stat().st_mtime:
            generated.write_text(f"ruleDirs:\n  - {rules}\n", encoding="utf-8")
    except OSError:
        return None
    return generated
