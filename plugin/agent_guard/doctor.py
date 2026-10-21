"""Inspect what a checkout resolves to."""

import shutil

from . import _state
from .config import Settings, discover_roots, load_config, sgconfig_for
from .external import missing_launcher_note
from .paths import CONFIG_NAME, MANDATORY_DIR
from .process import have, python_tool_problem


def doctor(cwd):
    """A hook that is silent when healthy is indistinguishable from one that is
    silently broken, so make the difference inspectable."""
    roots = discover_roots(cwd)
    cfg = load_config(roots)
    _state.set_log_level(cfg)
    settings = Settings(cfg)
    print("agent-guard doctor")
    print(f"  cwd        : {cwd}")
    print(f"  config     : {CONFIG_NAME}")
    print(f"  scope      : {settings.scope}")
    print(f"  extensions : {settings.ext_src}")
    print(f"  ignore     : {settings.ignore_src}")
    print(f"  always     : {', '.join(sorted(settings.always)) or 'nothing'}")
    log_from = "AGENT_GUARD_LOG" if _state._env_setting("log") else "config.toml"
    print(f"  log        : {_state._level} from {log_from}, writing {_state.LOG_PATH}")
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
    if not have("ast-grep"):
        print("  ast-grep missing -> per-file rules skipped (checks/ still run)")
    if not have("fallow"):
        print("  fallow missing   -> changeset duplication check skipped")
    if not have("rg"):
        print("  rg missing       -> over-extraction check skipped")
    print("  python analyses:")
    for name, analysis in settings.python.items():
        state = "on" if analysis.enabled else "off"
        origin = analysis.origin or "default"
        print(f"    {name:<12} {state}  from {origin}")
        for label, key, value in (
            ("extensions", f"python_{name}_extensions", analysis.extensions),
            ("baseline", f"python_{name}_baseline", analysis.baseline),
            ("timeout", "python_timeout", analysis.timeout),
        ):
            where = settings.origins.get(key, "default")
            print(f"      {label:<11}: {value}  from {where}")
        if name == "complexipy":
            where = settings.origins.get("python_complexipy_max", "default")
            print(f"      max        : {analysis.max_complexity}  from {where}")
        elif name == "lizard":
            for label, key, value in (
                ("ccn", "python_lizard_ccn", analysis.ccn),
                ("length", "python_lizard_length", analysis.length),
                ("arguments", "python_lizard_arguments", analysis.arguments),
            ):
                print(f"      {label:<11}: {value}  from {settings.origins.get(key, 'default')}")
        elif name == "vulture":
            print(
                "      confidence : "
                f"{analysis.min_confidence}  from "
                f"{settings.origins.get('python_vulture_min_confidence', 'default')}"
            )
    problem = python_tool_problem(cwd)
    if problem:
        print(f"  python tools : {problem}")
    else:
        enabled = {name for name, analysis in settings.python.items() if analysis.enabled}
        for note in missing_launcher_note(enabled, cwd):
            print(f"  python tools : {note}")
    if settings.scope == "diff":
        print("  scope=diff       -> per-file findings limited to lines the branch")
        print("                      added; findings older than it stay quiet")
    if len(roots) == 1:
        print("  only the global root listed -> nothing here opted in, so only the")
        print("                      layers named by `always` run")
