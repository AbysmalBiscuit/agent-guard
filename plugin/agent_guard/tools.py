"""The binaries the audit runs, resolved from the plugin's mise config."""

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

from .paths import PLUGIN_ROOT

MISE_CONFIG = PLUGIN_ROOT / "mise.toml"

# Registry name to the mise tool id that pins it. The version lives in the
# config, so a second copy here would drift.
TOOL_IDS = {
    "fallow": "github:fallow-rs/fallow",
    "ast-grep": "ast-grep",
    "uv": "uv",
    "complexipy": "pipx:complexipy",
    "lizard": "pipx:lizard",
    "vulture": "pipx:vulture",
    "jscpd": "npm:jscpd",
    "pyscn": "pipx:pyscn",
}


def tool_version(name):
    """The version `mise.toml` pins for one registry tool, or an empty string."""
    tool_id = TOOL_IDS.get(name)
    if tool_id is None:
        return ""
    try:
        data = tomllib.loads(MISE_CONFIG.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    tools = data.get("tools") or {}
    value = tools.get(tool_id, "")
    if isinstance(value, dict):
        value = value.get("version", "")
    return str(value) if value else ""


def pinned_binary(name):
    """The mise-pinned binary for `name`, or None when mise cannot name one."""
    override = os.environ.get(f"MISE_{name.upper().replace('-', '_')}")
    if override is not None:
        path = Path(override)
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    mise = shutil.which("mise")
    if mise is None or not MISE_CONFIG.is_file():
        return None
    return _mise_which(mise, name)


def _mise_which(mise, name):
    try:
        done = subprocess.run(
            [mise, "-C", str(PLUGIN_ROOT), "which", name],
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    path = (done.stdout or "").strip()
    if done.returncode != 0 or not path:
        return None
    binary = Path(path)
    if binary.is_file() and os.access(binary, os.X_OK):
        return str(binary)
    return None
