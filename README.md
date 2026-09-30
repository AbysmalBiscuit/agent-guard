# agent-guard

A Claude Code and Codex plugin that checks what a coding agent does against local rules and feeds violations back to the model while it works.

One hook script, `plugin/scripts/agent_guard.py`, handles every hook event:

| Event | What runs |
|---|---|
| `SessionStart` | `hooks/bootstrap-tools`, which installs ast-grep and fallow when missing. |
| `PreToolUse` | `tool_checks/` scripts on the shell command or edit about to run, plus the `mandatory/` tier on shell tools. A check can advise, ask the human, or deny. |
| `PostToolUse` (edits) | ast-grep `rules/` and `checks/` scripts on each edited file, reporting only the lines the branch introduced. Advisory. |
| `Stop`, `SubagentStop` | A fallow audit of the changeset for duplication and over-extraction, plus `changeset_checks/` scripts. Advisory unless `block = true`. |
| `SessionEnd` | Removes the fallow audit cache of the session's project. |

The hook always exits 0 and reports through the hook JSON contract, so a broken check goes quiet instead of wedging the session.

## Install

Claude Code:

```sh
claude plugin marketplace add AbysmalBiscuit/agent-guard
claude plugin install agent-guard@agent-guard
```

Codex:

```sh
codex plugin marketplace add AbysmalBiscuit/agent-guard
codex plugin add agent-guard@agent-guard
```

Codex skips plugin hooks until you review and trust them, so open a session and approve them before expecting any output.

### Requirements

The hooks need `python3` 3.11 or newer on `PATH`, and use only the standard library. Codex on Windows calls `python` instead.

Three tools are optional. Each feature stays silent when its tool is missing:

| Tool | Used for |
|---|---|
| `ast-grep` | the `rules/` layer |
| `fallow` | the Stop-time changeset audit |
| `git` | limiting findings to the lines the branch introduced |

At session start, `hooks/bootstrap-tools` installs ast-grep and fallow when either is missing by running `plugin/scripts/install.sh`. You can also run that script yourself on Linux, macOS, or Git Bash on Windows:

```sh
bash plugin/scripts/install.sh
```

It installs uv, then ast-grep with `uv tool install ast-grep-cli`, then fallow from its latest GitHub release after checking the release's Ed25519 signature with OpenSSL 3. Everything lands in `$XDG_BIN_HOME` (default `~/.local/bin`), which must be on `PATH` for the hooks to find it. Tools already on `PATH` are left alone.

The session start hook differs from a manual run in three ways:

- It stops the uv installer from editing your shell profiles, so you add `~/.local/bin` to `PATH` yourself. It reminds you at each session start until you do.
- It records a failed install in `$XDG_STATE_HOME/agent-guard/bootstrap-failed` and skips retries until the plugin version changes. Delete that file to retry sooner.
- `AGENT_GUARD_NO_BOOTSTRAP=1` turns it off.

## Turn it on for a project

Out of the box, only `tool_checks/` and `checks/` run everywhere. The `rules/` layer and the changeset audit run only in a tree that opts in, because they assume a project shape. A tree opts in with a root directory at its top:

- `.agents/plugins/agent-guard/`, committed, for rules the whole team shares.
- `.agents/plugins/agent-guard.local/`, kept out of version control, for one machine.

A root counts once it holds a `config.toml`, an `sgconfig.yml`, or one of the check directories under [Writing checks](#writing-checks). An empty `config.toml` is enough to turn on every layer with the global settings:

```sh
mkdir -p .agents/plugins/agent-guard
touch .agents/plugins/agent-guard/config.toml
```

Then check what the hook resolves from inside the tree:

```sh
python3 <plugin root>/scripts/agent_guard.py doctor
```

`<plugin root>` is the installed copy, `~/.claude/plugins/cache/agent-guard/agent-guard/<version>/` for Claude Code or `~/.codex/plugins/cache/agent-guard/agent-guard/<version>/` for Codex. `doctor` lists the roots it found, the rules and checks each one holds, the effective settings, and which optional tools are on `PATH`.

## Configuration

Settings layer from widest to nearest, and a nearer layer tightens any setting below it:

1. `plugin/config.toml`, the global layer. It documents every setting, so read it before changing one.
2. Every root found by walking up from the working directory, outermost first. A root is a directory holding `.agents/plugins/agent-guard/` or `.agents/plugins/agent-guard.local/`, and its `config.toml` applies to everything under it.
3. `AGENT_GUARD_<KEY>` environment variables, which outrank every file, for example `AGENT_GUARD_BLOCK=true`.

The plugin directory is replaced on every update, so put personal settings in `~/.agents/plugins/agent-guard.local/config.toml`, which applies to every working directory under your home. `AGENT_GUARD_CONFIG_DIR` replaces the global layer with a directory of your own.

The settings you are most likely to change:

| Setting | Default | Effect |
|---|---|---|
| `always` | `["tool_checks", "checks"]` | layers that run in trees that have not opted in |
| `block` | `false` | `true` lets Stop and SubagentStop refuse to finish on findings |
| `tool_checks` | `true` | `false` is the kill switch when a PreToolUse check starts refusing real work |
| `fallow` | `true` | `false` keeps the Stop hook to per-file checks |
| `scope` | `"diff"` | `"file"` reports findings on whole files, not only the branch's lines |
| `extensions` | most source, config, and markdown files | regex of files the per-file layers check |
| `ignore_extra` | unset | regex of paths to skip, added to the built-in generated and vendored paths |
| `log` | `1` | how much each run appends to `~/agent-guard.log`, from `0` (nothing) to `3` (command text too) |

`mandatory/` holds checks no setting, root, or environment variable can disable or move. They load only from the installed plugin and run on shell tools.

## Writing checks

A root holds any of these directories. The hook runs every `*.py` script in them with its own Python interpreter, so the executable bit and shebang do not matter.

| Directory | Runs on | Input | Output |
|---|---|---|---|
| `tool_checks/` | PreToolUse | tool name as the argument, hook payload JSON on stdin | empty stdout is silence; stdout with exit 0 advises; exit 2 asks the human; any other non-zero exit denies |
| `checks/` | PostToolUse | one file path as the argument | one finding per line, `  <file>:<line>  [<rule-id>] <message>`, with two leading spaces |
| `rules/` | PostToolUse | ast-grep YAML rules | ast-grep findings |
| `changeset_checks/` | Stop, SubagentStop | the base revision as the argument | a finished report section, or nothing |

The model reads every message, so a message should name what to do instead, not only what went wrong. `checks/` scripts decide for themselves which files they have anything to say about. A root needs its own `sgconfig.yml` only to register a custom ast-grep language.

Each bundled script's docstring explains what it enforces and why, so read one as a template before writing your own.

## Troubleshooting

- Run `doctor` from the directory in question to see which roots, rules, and tools apply there.
- Raise `log` to `2` to record every check's verdict in `~/agent-guard.log`, or to `3` to include the command text.
- Set `AGENT_GUARD_TOOL_CHECKS=false` for one session when a PreToolUse check blocks work it should allow, then fix the check.

## Layout

```text
.claude-plugin/marketplace.json   Claude Code marketplace
.agents/plugins/marketplace.json  Codex marketplace
plugin/
  .claude-plugin/plugin.json      Claude Code manifest
  .codex-plugin/plugin.json       Codex manifest
  hooks/hooks.json                Claude Code hooks
  hooks/hooks-codex.json          Codex hooks
  hooks/bootstrap-tools           SessionStart tool installer
  hooks/run-hook.cmd              cross-platform launcher for bash hooks
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
claude plugin validate .
```

`devrun task verify` runs all of these in sequence. CI also runs `shellcheck` on the bash scripts.

## License

[GPL-3.0-or-later](LICENSE)
