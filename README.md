# agent-guard

A Claude Code and Codex plugin that checks what a coding agent does against local rules and feeds violations back to the model while it works.

One hook script, `plugin/scripts/agent_guard.py`, dispatches on the hook event:

| Event | What runs |
|---|---|
| `PreToolUse` | `tool_checks/` scripts on the shell command or edit about to run, plus the `mandatory/` tier on shell tools. A check can advise, ask the human, or deny. |
| `PostToolUse` (edits) | ast-grep `rules/` and per-file `checks/` scripts on the lines the branch introduced. Advisory. |
| `Stop`, `SubagentStop` | A fallow audit of the changeset for duplication and over-extraction. Advisory unless `block = true`. |
| `SessionEnd` | Removes the fallow audit cache of the session's project. |

The hook always exits 0 and reports through the hook JSON contract, so a broken check degrades to silence instead of wedging the session.

## Install

Claude Code:

```sh
claude plugin marketplace add AbysmalBiscuit/agent-guard
claude plugin install agent-guard@agent-guard
```

Codex:

```sh
codex plugin marketplace add AbysmalBiscuit/agent-guard
```

Then install Agent Guard from the Plugins Directory. Codex skips plugin hooks until you review and trust them.

### Requirements

- `python3` 3.11 or newer on `PATH`. The hooks use only the standard library.
- Optional: `ast-grep` for `rules/`, `fallow` for the changeset audit, `git` for diff scoping. Each feature stays silent when its tool is missing.

`plugin/scripts/install.sh` installs uv and fallow on Linux and macOS, skipping whichever is already on `PATH`. fallow comes from its latest GitHub release into `$XDG_BIN_HOME` (default `~/.local/bin`), after its Ed25519 signature is checked with OpenSSL 3.

```sh
bash plugin/scripts/install.sh
```

## Configuration

`plugin/config.toml` is the global layer and documents every setting. On top of it, the hook discovers roots by walking up from the working directory: any directory holding `.agents/plugins/agent-guard/` (tracked) or `.agents/plugins/agent-guard.local/` (machine-local). Each root can carry `rules/`, `checks/`, `tool_checks/`, and a `config.toml` that tightens the settings below it. An `AGENT_GUARD_<KEY>` environment variable outranks every file for one run.

The plugin directory is replaced on every update, so keep personal settings out of it: put them in `~/.agents/plugins/agent-guard.local/config.toml`, which applies to every working directory under your home, or point `AGENT_GUARD_CONFIG_DIR` at a directory of your own.

To see which roots, rules, and tools a directory resolves to:

```sh
python3 <plugin root>/scripts/agent_guard.py doctor
```

`mandatory/` holds checks no configuration can disable or move. They load only from the installed plugin.

## Layout

```text
.claude-plugin/marketplace.json   Claude Code marketplace
.agents/plugins/marketplace.json  Codex marketplace
plugin/
  .claude-plugin/plugin.json      Claude Code manifest
  .codex-plugin/plugin.json       Codex manifest
  hooks/hooks.json                Claude Code hooks
  hooks/hooks-codex.json          Codex hooks
  scripts/                        hook entry point and helpers
  tool_checks/ checks/ mandatory/ check scripts
  rules/ queries/ sgconfig.yml    ast-grep rules
  tests/                          test suite
```

## Development

```sh
uv sync
uv run ruff check
uv run ruff format --check
uv run pyrefly check
uv run python plugin/tests/run.py
claude plugin validate plugin
```

## License

[GPL-3.0-or-later](LICENSE)
