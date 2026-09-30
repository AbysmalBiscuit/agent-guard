#!/usr/bin/env python3
"""Course-corrects coding agents in-flight by feeding convention violations back
to the model. Dispatches on the hook event name in the payload on stdin, so a
single entry point works for every hook it is registered under.

  PreToolUse                          tool_checks/ scripts on the call about to
                                      run, advisory or denying
  PostToolUse (edits or apply_patch)  fast per-file ast-grep rules and checks/
                                      scripts, advisory, on the lines the branch
                                      introduced
  Stop | SubagentStop                 fallow audit on the changeset, gating

Always exits 0 and speaks through the hookSpecificOutput JSON contract, so a
broken check degrades to silence rather than wedging the session.
"""

import atexit
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import tomllib
from datetime import datetime
from pathlib import Path

_watchdog = None
CODEX = "--codex" in sys.argv[1:]


def _env_setting(key):
    """What the environment says one setting is, empty when it says nothing."""
    return (os.environ.get("AGENT_GUARD_" + key.upper()) or "").strip().lower()


def _global_setting(key):
    """What the install's own config.toml says, for a run that ends before a
    checkout's can be read. Reading a checkout's this early would put a repo
    file between the mandatory tier and the call it refuses."""
    try:
        with (CONFIG_DIR / CONFIG_NAME).open("rb") as handle:
            return str(tomllib.load(handle).get(key, "")).strip().lower()
    except (OSError, tomllib.TOMLDecodeError):
        return ""


# How much to write to ~/agent-guard.log. Nothing, "0" or "off" writes nothing,
# so the hook costs nothing when nobody is watching.
_LEVELS = {
    "0": 0,
    "off": 0,
    "false": 0,
    "1": 1,
    "on": 1,
    "true": 1,
    "info": 1,
    "2": 2,
    "debug": 2,
    "3": 3,
    "trace": 3,
}
LOG_PATH = Path.home() / "agent-guard.log"
_level = _LEVELS.get(_env_setting("log"))
_held = []


def set_log_level(cfg):
    """Settle the level from the layered config, then release what was held.

    The lines a run opens with come before any root has been read, because the
    mandatory tier answers ahead of discovery so that no repo file stands
    between it and the call it refuses. Holding them is what lets a checkout's
    own config.toml still decide whether they are written.
    """
    global _level
    if _level is None:
        _level = _LEVELS.get(str(cfg.get("log", "")).strip().lower(), 0)
    release_log()


def release_log():
    """Write the held lines the settled level allows, once.

    A run that exits before discovery, a mandatory refusal above all, settles
    for the global level instead: a checkout that never got read cannot be the
    one to silence it.
    """
    global _held
    held, _held = _held, []
    level = _level if _level is not None else _LEVELS.get(_global_setting("log"), 0)
    for line_level, line in held:
        if line_level <= level:
            write_log(line)


def log(level, event, **fields):
    """Hold or append one line, by the level in force.

    Logging is a debugging aid and never a reason to fail, so a line that cannot
    be written is dropped rather than reported. Levels are 1 for the decision a
    call reached, 2 for each check's verdict, and 3 for the command text itself,
    which is held back until then because a command line can carry a secret.
    """
    if _level is not None and level > _level:
        return
    stamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
    rest = " ".join(
        f"{key}={value if isinstance(value, int) else json.dumps(str(value))}"
        for key, value in fields.items()
        if value is not None
    )
    line = f"{stamp} [{level}] {event} {rest}".rstrip() + "\n"
    if _level is None:
        _held.append((level, line))
        return
    write_log(line)


def write_log(line):
    with contextlib.suppress(BaseException), LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line)


# Every exit short of the watchdog's runs this, so a refusal that ends the run
# before discovery still reaches the log.
atexit.register(release_log)


def arm_watchdog(seconds):
    """The harness timeout kills the process it spawned, which stops helping the
    moment this one outlives the session that spawned it. Owning the deadline
    here bounds an orphan too."""
    global _watchdog
    if _watchdog is not None:
        _watchdog.cancel()
    _watchdog = threading.Timer(seconds, lambda: os._exit(0))
    _watchdog.daemon = True
    _watchdog.start()


def deadline(fallback):
    """Seconds before the watchdog fires. AGENT_GUARD_DEADLINE may lengthen this
    but not shorten it past the floor: a deadline short enough to kill the
    process before the mandatory tier has answered would be a way to switch that
    tier off, and that tier exists to have no off switch."""
    try:
        requested = float(os.environ.get("AGENT_GUARD_DEADLINE") or fallback)
    except ValueError:
        requested = fallback
    return max(requested, 6.0)


arm_watchdog(deadline(55))

# Everything this hook needs lives beside it, so the whole directory relocates as
# one unit. Resolved through any symlink, so the plugin directory can itself be
# a link without the roots below it moving.
SELF = Path(__file__).resolve()
CONFIG_DIR = Path(os.environ.get("AGENT_GUARD_CONFIG_DIR") or SELF.parent.parent)
STATE_DIR = (
    Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "agent-guard"
)

# The tier no setting reaches. Resolved from this file's own directory rather
# than CONFIG_DIR, so the environment override that repoints the install cannot
# move it, and read from the global install alone, so a checkout can neither add
# a script that runs on every call nor drop one that must.
MANDATORY_DIR = SELF.parent.parent / "mandatory"
MANDATORY_TIMEOUT = 5
# AGENT_GUARD_IN_PROCESS=0 puts every check back in its own subprocess, for
# bisecting a check that misbehaves only when it shares this interpreter.
IN_PROCESS = (os.environ.get("AGENT_GUARD_IN_PROCESS") or "1").strip() not in ("0", "off")

CONFIG_NAME = "config.toml"
_ENV_PREFIX = "AGENT_GUARD_"

# Rules come in layers, each named by its directory in a tree: the tracked one
# first, then a machine-local overlay beside it that outranks it. Later roots add
# rules and tighten settings, and a tree opts in by creating one of these
# directories; nothing in the global install changes.
ROOT_NAMES = (".agents/plugins/agent-guard", ".agents/plugins/agent-guard.local")

TEST_PATH = re.compile(r"(test|spec)\.|/tests?/|__tests__")
BARREL_OR_TEST = re.compile(r"(test|spec)\.|/tests?/|__tests__|/index\.tsx?$")


def have(tool):
    return shutil.which(tool) is not None


def run(cmd, timeout=20, cwd=None, stdin=None, env=None):
    """Stdout, or an empty string for any failure. Every external call is bounded
    so a wedged tool cannot outlive the hook."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            input=stdin,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return ""
    return p.stdout or ""


def run_full(cmd, timeout=20, cwd=None, stdin=None, env=None):
    """Stdout and exit code together, for callers whose contract reads both. A
    failure to spawn at all reports code 0, so a missing interpreter stays
    silent rather than denying every call."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            input=stdin,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return "", 0
    return p.stdout or "", p.returncode


@contextlib.contextmanager
def alarm(seconds):
    """Raise inside the block once `seconds` pass, where the platform allows it.

    Windows has no SIGALRM, and there the process watchdog is the only backstop:
    a wedged check takes the run down with it instead of being skipped. Both
    outcomes are silence, which is the direction a broken check should fail."""
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def fire(*_):
        raise TimeoutError(f"check ran longer than {seconds}s")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_script(path, argument, stdin, cwd, timeout):
    """One check's stdout and exit code, run in this interpreter.

    Spawning a Python per check costs more than every check does put together,
    and the checks are small pure-stdlib scripts, so they run here instead. The
    source is executed with `__name__` set to "__main__" so the script's own
    guard runs exactly as it would in a subprocess and its exit code arrives as
    SystemExit; nothing about the contract changes.

    Returns None when the script cannot be run this way, so the caller falls
    back to a subprocess rather than skipping a check for a reason that has
    nothing to do with what the check is for."""
    if not IN_PROCESS:
        return None
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return None

    captured = io.StringIO()
    namespace = {"__name__": "__main__", "__file__": str(path), "__doc__": None}
    argv, stdin_stream, directory = sys.argv, sys.stdin, os.getcwd()
    search, loaded = list(sys.path), set(sys.modules)
    home = str(path.parent)
    code = 0
    try:
        sys.argv = [str(path), argument]
        sys.stdin = io.StringIO(stdin)
        # An interpreter running a script puts its directory first, and a check
        # that imports a helper beside it depends on that.
        sys.path.insert(0, home)
        with contextlib.suppress(OSError):
            os.chdir(cwd)
        with (
            alarm(timeout),
            contextlib.redirect_stdout(captured),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            exec(compile(source, str(path), "exec"), namespace)  # noqa: S102
    except SystemExit as stop:
        # An interpreter exits 0 for `sys.exit(None)` and 1 for `sys.exit(str)`,
        # after printing the string to stderr. A check that denies that way
        # denies here too.
        code = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
    except TimeoutError:
        # A subprocess that outran its timeout was reported as silence, and a
        # check the agent cannot wait for should not become a refusal.
        return "", 0
    except BaseException:
        # A check's own guard turns its crashes into silence, so reaching here
        # means the guard itself never ran: a syntax error, or an import that
        # failed. The interpreter would have exited 1, and the mandatory tier
        # reads that as a denial on purpose. Report it the same way, keeping
        # whatever the check managed to print: a subprocess that died mid-run
        # still delivered the stdout it had already written.
        return captured.getvalue(), 1
    finally:
        sys.argv, sys.stdin, sys.path[:] = argv, stdin_stream, search
        # Helpers a check imported are dropped again, so two roots shipping a
        # module of the same name do not serve each other's copy. Anything from
        # outside the check's own directory, the standard library above all,
        # stays cached: re-importing it per check is what this call is avoiding.
        for name in set(sys.modules) - loaded:
            origin = getattr(sys.modules.get(name), "__file__", None) or ""
            if origin.startswith(home + os.sep):
                del sys.modules[name]
        with contextlib.suppress(OSError):
            os.chdir(directory)
    return captured.getvalue(), code


def succeeds(cmd, timeout=20, cwd=None):
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, check=False)
    except Exception:
        return False
    return done.returncode == 0


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
    """Every root's config.toml, in order, so a nearer tree tunes extensions,
    ignore patterns and which checks run without editing the global install.
    Keys are flat; unknown ones are ignored, and a file that will not parse is
    skipped rather than taken as empty. An AGENT_GUARD_<KEY> environment variable
    overrides the files for a single run."""
    cfg = {}
    for root in roots:
        f = root / CONFIG_NAME
        if not f.is_file():
            continue
        try:
            with f.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        cfg.update({k: v for k, v in data.items() if not isinstance(v, dict)})
    for key, value in os.environ.items():
        if key.startswith(_ENV_PREFIX):
            cfg[key[len(_ENV_PREFIX) :].lower()] = value
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


# A tool-check's exit code for the ask tier: stdout with this hands the call to
# the human, where any other non-zero refuses it outright.
ASK_EXIT = 2


# Tools that run a shell command, across the harnesses this hook is registered
# under. The mandatory tier is scoped to these.
SHELL_TOOLS = frozenset({"Bash", "PowerShell", "exec_command", "shell_command", "shell"})


def emit_silent():
    sys.exit(0)


def emit(event, context, deny="", ask=""):
    """`deny` refuses the call, `ask` hands it to the human, and a call carrying
    both is refused: a check that says no outranks one that says maybe.

    The reason is repeated in `additionalContext` by the caller, so a harness
    that does not implement the ask decision still tells the model why the call
    was questioned rather than dropping the finding on the floor."""
    if CODEX and event in ("Stop", "SubagentStop"):
        out = {"decision": "block", "reason": context} if deny else {"systemMessage": context}
        sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        sys.exit(0)

    out = {"hookEventName": event}
    if deny:
        out["permissionDecision"] = "deny"
        out["permissionDecisionReason"] = deny
    elif ask:
        out["permissionDecision"] = "ask"
        out["permissionDecisionReason"] = ask
    out["additionalContext"] = context
    sys.stdout.write(json.dumps({"hookSpecificOutput": out}, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(0)


def git_base(settings, cwd):
    """The merge-base with the upstream branch, matching the changeset audit.
    With no upstream it falls back to HEAD, so the scope degrades to the
    uncommitted working tree rather than back to the whole file."""
    if settings.base_override:
        return settings.base_override
    upstream = run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd=cwd
    ).strip()
    base = run(["git", "merge-base", "HEAD", upstream or "origin/HEAD"], cwd=cwd).strip()
    return base or run(["git", "rev-parse", "HEAD"], cwd=cwd).strip()


_HUNK = re.compile(r"^@@ \S+ \+(\d+)(?:,(\d+))?")


def changed_lines(path, base, cwd):
    """Line numbers one file gained since the branch's base. An empty set is a
    real answer meaning the branch added no lines to it; None means git cannot
    answer at all (no repository, or a file it has never tracked), which the
    caller reads as "every line is the agent's"."""
    if not have("git") or not succeeds(["git", "rev-parse", "--git-dir"], cwd=cwd):
        return None
    if not succeeds(["git", "ls-files", "--error-unmatch", "--", path], cwd=cwd):
        return None
    if not base:
        return None
    added = set()
    diff = run(["git", "diff", "--unified=0", base, "--", path], cwd=cwd)
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if not m:
            continue
        start = int(m.group(1))
        count = 1 if m.group(2) is None else int(m.group(2))
        added.update(range(start, start + count))
    return added


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
        log(
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
            log(
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
        log(1, "decision", tool=tool, outcome="deny", checks=len(denials))
        emit(
            "PreToolUse",
            "\n\n".join(denials + asks + advice),
            deny="\n\n".join(denials),
        )
    if asks:
        log(1, "decision", tool=tool, outcome="ask", checks=len(asks))
        emit("PreToolUse", "\n\n".join(asks + advice), ask="\n\n".join(asks))
    if advice:
        log(1, "decision", tool=tool, outcome="advise", checks=len(advice))
        emit("PreToolUse", "\n\n".join(advice))
    log(1, "decision", tool=tool, outcome="allow")
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
    log(
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
    if not groups:
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


def changed_files(base, cwd):
    """What the branch touched, including what git does not track yet. A file an
    agent wrote and has not committed never appears in `git diff`, and it is the
    likeliest place for a copy of something that already exists: written from
    scratch by someone who did not find the original. --exclude-standard keeps
    ignored trees such as node_modules out."""
    listings = (
        ["git", "diff", "--name-only", base, "--", *SOURCE_GLOBS],
        ["git", "ls-files", "--others", "--exclude-standard", "--", *SOURCE_GLOBS],
    )
    out, seen = [], set()
    for cmd in listings:
        for line in run(cmd, cwd=cwd).splitlines():
            rel = line.strip()
            if rel and rel not in seen:
                seen.add(rel)
                out.append(rel)
    return out[:200]


def changeset_fingerprint(base, changed, cwd):
    """Everything a report would be derived from, hashed. The diff alone cannot
    stand in for it: an untracked file's content is absent from the diff, so a
    second new file after a first report would read as no change at all and the
    report would be skipped. The diff still goes in, because a deletion moves it
    while leaving nothing on disk to read."""
    digest = hashlib.sha256()
    digest.update(
        run(["git", "diff", base, "--", *SOURCE_GLOBS], cwd=cwd).encode("utf-8", "replace")
    )
    for rel in changed:
        digest.update(rel.encode("utf-8", "replace"))
        path = cwd / rel
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def check_changeset(event, session, agent_type, roots, settings, cwd):
    """Cross-file analysis on the changeset. Only findings the changeset
    introduced are reported; inherited debt is not this agent's to answer for."""
    if not have("git") or not succeeds(["git", "rev-parse", "--git-dir"], cwd=cwd):
        emit_silent()

    base = git_base(settings, cwd)
    changed = changed_files(base, cwd)
    # Before the source-glob gate: the duplication audit reads TS and JS, but a
    # changeset-check speaks for whatever files its own rule covers, and a
    # branch that touched only markdown or shell still has to answer for them.
    violations = run_changeset_checks(base, roots, cwd)
    if not changed and not violations:
        emit_silent()

    sdir = STATE_DIR / session
    try:
        sdir.mkdir(parents=True, exist_ok=True)
    except OSError:
        emit_silent()
    seen_file = sdir / "seen-fingerprints"
    if not seen_file.exists():
        with contextlib.suppress(OSError):
            seen_file.touch()

    # Skip re-running when the changeset has not moved since the last report.
    fingerprint = (
        changeset_fingerprint(base, changed, cwd)
        + hashlib.sha1(violations.encode("utf-8", "replace"), usedforsecurity=False).hexdigest()
    )
    last = sdir / "last-diff"
    try:
        if last.is_file() and last.read_text(encoding="utf-8").strip() == fingerprint:
            emit_silent()
        last.write_text(fingerprint, encoding="utf-8")
    except OSError:
        pass

    who = f"Subagent '{agent_type}'" if agent_type else "This agent"
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
    if not sections:
        emit_silent()
    context = "\n".join(sections)

    blocks_file = sdir / "blocks"
    blocks = _int(blocks_file.read_text(encoding="utf-8") if blocks_file.is_file() else "0", 0)
    if settings.block and (violations or dupes) and blocks < settings.max_blocks:
        with contextlib.suppress(OSError):
            blocks_file.write_text(str(blocks + 1), encoding="utf-8")
        reason = (
            "agent-guard: this changeset violates a rule of the tree it is in"
            if violations
            else "agent-guard: duplication introduced by this changeset is unresolved"
        )
        emit(event, context, reason)
    emit(event, context)


def doctor(cwd):
    """A hook that is silent when healthy is indistinguishable from one that is
    silently broken, so make the difference inspectable."""
    roots = discover_roots(cwd)
    cfg = load_config(roots)
    set_log_level(cfg)
    settings = Settings(cfg)
    print("agent-guard doctor")
    print(f"  cwd        : {cwd}")
    print(f"  config     : {CONFIG_NAME}")
    print(f"  scope      : {settings.scope}")
    print(f"  extensions : {settings.ext_src}")
    print(f"  ignore     : {settings.ignore_src}")
    print(f"  always     : {', '.join(sorted(settings.always)) or 'nothing'}")
    log_from = "AGENT_GUARD_LOG" if _env_setting("log") else "config.toml"
    print(f"  log        : {_level} from {log_from}, writing {LOG_PATH}")
    print("  roots      :")
    for root in roots:
        config = sgconfig_for(root)
        rules = len(list((root / "rules").glob("*.yml"))) if (root / "rules").is_dir() else 0
        checks = len(list((root / "checks").glob("*.py"))) if (root / "checks").is_dir() else 0
        tool_checks = (
            len(list((root / "tool_checks").glob("*.py"))) if (root / "tool_checks").is_dir() else 0
        )
        diff_checks = (
            len(list((root / "changeset_checks").glob("*.py")))
            if (root / "changeset_checks").is_dir()
            else 0
        )
        print(f"    {root}")
        print(f"      config     : {config if config else 'NONE'}")
        print(f"      rules(own) : {rules}")
        print(f"      checks     : {checks}")
        print(f"      tool_checks: {tool_checks}")
        print(f"      changeset_checks: {diff_checks}")
    mandatory = len(list(MANDATORY_DIR.glob("*.py"))) if MANDATORY_DIR.is_dir() else 0
    print(f"  mandatory  : {mandatory} ({MANDATORY_DIR})")
    for tool in ("ast-grep", "fallow", "git", "rg"):
        print(f"  {tool:<10} : {shutil.which(tool) or 'not installed'}")
    print()
    print(f"  tool_checks      : {'on' if settings.tool_checks else 'off'}")
    print("  mandatory/       : always on; no config key or root reaches it")
    print("  ast-grep missing -> per-file rules skipped (checks/ still run)")
    print("  fallow missing   -> changeset duplication check skipped")
    print("  rg missing       -> over-extraction check skipped")
    print("  scope=diff       -> per-file findings limited to lines the branch")
    print("                      added; findings older than it stay quiet")
    print("  only the global root listed -> nothing here opted in, so only the")
    print("                      layers named by `always` run")
    sys.exit(0)


def main():
    args = [arg for arg in sys.argv[1:] if arg != "--codex"]
    argv_event = args[0] if args else ""
    if argv_event == "doctor":
        doctor(Path.cwd())

    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)
    try:
        payload = json.loads(raw)
    except ValueError:
        sys.exit(0)

    event = argv_event or payload.get("hook_event_name") or ""
    session = payload.get("session_id") or "nosession"
    agent_type = payload.get("agent_type") or ""

    cwd = Path.cwd()
    declared = payload.get("cwd") or ""
    if declared and Path(declared).is_dir():
        cwd = Path(declared).resolve()

    tool_input = payload.get("tool_input") or {}
    log(
        1,
        "invoke",
        hook=event,
        tool=payload.get("tool_name"),
        agent=agent_type or None,
        session=session[:8],
        cwd=str(cwd),
    )
    log(3, "input", command=tool_input.get("command"), path=tool_input.get("file_path"))

    if event == "SessionEnd":
        run(
            [sys.executable, str(SELF.parent / "fallow_cleanup.py")],
            stdin=json.dumps({**payload, "hook_event_name": event}),
            cwd=cwd,
            timeout=12,
        )
        sys.exit(0)

    # Ahead of discovery and the config, so no root and no setting is between
    # this tier and the call it refuses. A config.toml that will not even parse
    # cannot take it out either.
    if event == "PreToolUse":
        arm_watchdog(deadline(6))
        run_mandatory(payload, cwd)

    roots = discover_roots(cwd)
    cfg = load_config(roots)
    set_log_level(cfg)
    settings = Settings(cfg)

    # Registered in user settings, so it is reachable from every project on the
    # machine. Carrying an agent-guard directory somewhere above the working
    # directory is the whole opt-in, and a tree that has opted in runs every
    # layer. Everywhere else only the layers named in `always` run, so a rule
    # about the machine reaches every directory while a project's conventions
    # still wait to be asked for.
    scoped = len(roots) > 1
    allowed = frozenset(LAYERS) if scoped else settings.always
    if not allowed:
        sys.exit(0)

    if event == "PreToolUse":
        # The watchdog is already armed by the mandatory tier above. A check that
        # has not answered by then has nothing worth waiting for.
        if "tool_checks" not in allowed:
            sys.exit(0)
        check_tool(payload, roots, settings, cwd)
    elif event == "PostToolUse":
        # One event drives two layers, so it carries the permitted set down
        # rather than deciding here.
        layers = allowed & frozenset(("rules", "checks"))
        if not layers:
            sys.exit(0)
        arm_watchdog(deadline(9))
        check_file(payload, roots, settings, cwd, layers)
    elif event in ("Stop", "SubagentStop"):
        if "changeset" not in allowed:
            sys.exit(0)
        check_changeset(event, session, agent_type, roots, settings, cwd)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        # A broken check degrades to silence rather than wedging the session.
        sys.exit(0)
