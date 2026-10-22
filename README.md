# agent-guard

A Claude Code, Codex, and Grok Build plugin that checks what a coding agent does against local rules and feeds violations back to the model while it works.

One hook package, `plugin/agent_guard`, handles every hook event:

| Event | What runs |
|---|---|
| `SessionStart` | `hooks/bootstrap-tools`, which installs the pinned tools through mise. |
| `PreToolUse` | Built-in tool checks, plus `tool_checks/` scripts, on the shell command or edit about to run, plus the `mandatory/` tier on shell tools. A check can advise, ask the human, or deny. |
| `PostToolUse` (edits) | ast-grep `rules/`, built-in file checks and `checks/` scripts on each edited file, reporting only the lines the branch introduced. Advisory. |
| `Stop`, `SubagentStop` | A fallow audit of the changeset for duplication and over-extraction, plus `changeset_checks/` scripts. A tree can also turn on Python complexity and dead-code analyses, and a file-length check. Advisory unless `block = true`. |
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

Grok Build:

```sh
grok plugin marketplace add AbysmalBiscuit/agent-guard
grok plugin install agent-guard --trust
grok plugin enable agent-guard
```

Grok Build reads `.grok-plugin/` ahead of `.claude-plugin/`, so it installs its own manifest and `hooks/hooks-grok.json` and never loads the Claude Code hooks. Those hooks pass `--grok`, which renames Grok's `run_terminal_command`, `search_replace`, and `write` to `Bash`, `Edit`, and `Write` before any check runs, so checks only ever see Claude's names. Edits through `hashline_edit` get the per-file checks but skip the `tool_checks/` that read the edit's text.

### Requirements

The hooks need `python3` 3.11 or newer on `PATH`, and use only the standard library. Codex on Windows calls `python` instead.

These tools are optional. Each feature stays silent when its tool is missing:

| Tool | Used for |
|---|---|
| `mise` 2026.9.16 or newer | installs every pinned tool, and is what the audit runs them through |
| `ast-grep` | the `rules/` layer |
| `fallow` | the Stop-time changeset audit for TypeScript and JavaScript |
| `git` | limiting findings to the lines the branch introduced |

`plugin/mise.toml` pins each tool and its version. That file is the only place you change a version. fallow comes from the `github:` backend, which serves the prebuilt release. The Python audit tools and jscpd come from mise too.

`plugin/mise.lock` records the URL and the checksum of each download, and the provenance of a download that has one. `plugin/.mise/locks/` holds the npm and Python dependency locks. `install.sh` sets the mise settings in its environment, so they win over the machine's mise settings. Some lock entries record `provenance = "github-attestations"`. For each of these downloads, each install verifies the GitHub attestation again, and an install with no attestation fails. A test fails when a `github:` or `aqua:` lock entry has no `provenance`, unless the test lists its tool as one that publishes no attestations. Thus a lock that `mise lock` writes after a wrong "no attestations" answer fails CI. An install of a tool with no lock entry also fails. After a version change, run this command from the repository root for the changed tool, then commit the files that mise writes:

```sh
MISE_TRUSTED_CONFIG_PATHS="$PWD/plugin" mise -C plugin lock <tool>
```

`plugin/mise.toml` has a `[settings]` table, so mise loads it only when it trusts the file. `MISE_TRUSTED_CONFIG_PATHS` gives that trust, as in `install.sh`.

Install mise, then install the pins:

```sh
bash plugin/scripts/install.sh
```

The script runs `mise install` for each tool in `plugin/mise.toml`, and for no tool of another mise config, such as the global one. A copy already on `PATH` does not win: mise installs the pin anyway. When mise is missing, the script says so and stops.

The script needs mise 2026.9.16 or newer, the `min_version` in `plugin/mise.toml`. An older mise cannot read `plugin/mise.lock`. With an older mise, the script names the required version and stops. Run `mise self-update`, then run the script again.

At session start, `hooks/bootstrap-tools` runs that script. The session start hook differs from a manual run in two ways:

- It records a failed install in `$XDG_STATE_HOME/agent-guard/bootstrap-failed` and skips retries until the plugin version changes. Delete that file to retry sooner.
- `AGENT_GUARD_NO_BOOTSTRAP=1` turns it off.

Machine provisioning installs mise, then runs `install.sh`. The Stop audit runs the binary `mise which` names for that config, not the first copy on `PATH`. `doctor` reports each pin, the binary the audit runs, and a missing mise or tool.

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
python3 <plugin root>/agent_guard doctor
python3 <plugin root>/agent_guard audit [--base REF] [PATH]
```

`<plugin root>` is the installed copy, `~/.claude/plugins/cache/agent-guard/agent-guard/<version>/` for Claude Code or `~/.codex/plugins/cache/agent-guard/agent-guard/<version>/` for Codex. For Grok Build, `grok plugin details agent-guard` prints where it is installed. `doctor` lists the roots it found, the rules and checks each one holds, the effective settings, and which optional tools are on `PATH`.

`audit` runs the same changeset audit as Stop. `PATH` is the checkout, and the default is the current directory. `--base` names the revision to compare with, and the default is the base Stop uses. The command uses no session state, so a second run prints the same findings. It prints findings as plain text. It exits 0 when there are none, 1 when a finding would warn, and 2 when a finding would block. A usage or checkout error exits 3. Each tool keeps its own timeout.

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

Python analyses live under `[python]` in a tree's `config.toml`. Each one is off until that tree turns it on. A tree picks the file types with `<analysis>_extensions`. The baseline file holds offenders that stay silent. The plugin's `config.toml` ends with a commented `# [python]` header and the keys below it. A key above that header is ignored, so uncomment the header with the keys.

```toml
[python]
complexipy = true
complexipy_extensions = '\.py$'
complexipy_baseline = "complexipy-snapshot.json"
complexipy_max = 15

lizard = true
lizard_extensions = '\.(py|ts|tsx)$'
lizard_baseline = "whitelizard.txt"
lizard_ccn = 15
lizard_length = 1000
lizard_arguments = 100

vulture = true
vulture_extensions = '\.py$'
vulture_baseline = "vulture-whitelist.py"
vulture_min_confidence = 60

jscpd = true
jscpd_extensions = '\.py$'

pyscn = true
pyscn_extensions = '\.py$'

timeout = 20
```

| Setting | Default | Effect |
|---|---|---|
| `complexipy` | `false` | cognitive complexity, through complexipy |
| `complexipy_extensions` | `\.py$` | file types complexipy reads |
| `complexipy_baseline` | `complexipy-snapshot.json` | snapshot of functions that stay silent |
| `complexipy_max` | `15` | cognitive complexity a function may reach |
| `lizard` | `false` | cyclomatic complexity, length, and parameter count |
| `lizard_extensions` | `\.(py\|ts\|tsx)$` | file types lizard reads. Add or drop TypeScript here |
| `lizard_baseline` | `whitelizard.txt` | function names that stay silent |
| `lizard_ccn` | `15` | cyclomatic complexity a function may reach |
| `lizard_length` | `1000` | function length a function may reach |
| `lizard_arguments` | `100` | parameter count a function may reach |
| `vulture` | `false` | dead code, through vulture |
| `vulture_extensions` | `\.py$` | file types vulture reads |
| `vulture_baseline` | `vulture-whitelist.py` | names that stay silent |
| `vulture_min_confidence` | `60` | lowest confidence vulture reports |
| `jscpd` | `false` | duplicated code, through jscpd |
| `jscpd_extensions` | `\.py$` | file types jscpd reads |
| `pyscn` | `false` | import cycles, through pyscn |
| `pyscn_extensions` | `\.py$` | file types pyscn reads |
| `timeout` | `20` | seconds one analysis may run |

File length lives under `[file_length]`. It is off until a tree sets `enabled`. With the check on and no `limits` list, Python files (`\.py$`) warn above 500 lines and block above 1000. A project `limits` list replaces that row. `limits = []` drops it. Each `[[file_length.limits]]` row is one file type, selected by an extension regex, or one path or glob. A path row outranks a type row. A nearer `limits` list replaces a farther one. A file above `warn_lines` warns. A file above `block_lines` blocks when the global `block` setting is on, and still reports when that setting is off. `accept` records a file at `lines`: the check fails only when that file grows past the recorded size.

```toml
[file_length]
enabled = true
warn_message = "Split this file by responsibility, and move tests into focused files."
block_message = "Split this file by responsibility, and move tests into focused files."

[[file_length.limits]]
extensions = '\.py$'
warn_lines = 500
block_lines = 1000

[[file_length.limits]]
pattern = "src/app.rs"
accept = true
lines = 4000
```

| Setting | Default | Effect |
|---|---|---|
| `enabled` | `false` | `true` compares each changed file with its limit |
| `warn_message` | Split this file by responsibility, and move tests into focused files. | message for a file above `warn_lines` |
| `block_message` | Split this file by responsibility, and move tests into focused files. | message for a file above `block_lines`, and for an accepted file that grew |
| `limits` | Python files warn above 500 and block above 1000 when the check is on | rows that name a file type, a path, or a glob. A list replaces the default row. An empty list drops it |
| `extensions` | unset | extension regex that selects the files a type row covers |
| `pattern` | unset | path or glob a row covers. A path row outranks a type row |
| `warn_lines` | unset | line count above which a file warns |
| `block_lines` | unset | line count above which a file blocks |
| `accept` | `false` | `true` accepts the file at `lines` and fails only when it grows |
| `lines` | unset | recorded size of an accepted file. An accept row without `lines`, or with `lines` at zero or below, is ignored, and `doctor` reports it as a config error |

complexipy, lizard, vulture, pyscn and jscpd run at the versions in `plugin/mise.toml`. The audit runs the binary mise pins. A tree's own `.venv` supplies a tool ahead of the mise pin when it has one. Nothing is installed into the project. A missing mise, a missing pin, or a timeout leaves that tool silent. `doctor` lists which analyses are on, where each setting came from, each pin, and that silence.

A clone group is reported when one of its instances sits on a line the branch added, and each fingerprint once per session. A cycle is reported when the base revision did not have it.

The mandatory tier holds checks no setting, root, or environment variable can disable or move. It loads only from the installed package and runs on shell tools.

## Writing checks

A root holds any of these directories. The hook runs every `*.py` script in them with its own Python interpreter, so the executable bit and shebang do not matter. Built-in checks are package functions and do not use this contract.

| Directory | Runs on | Input | Output |
|---|---|---|---|
| `tool_checks/` | PreToolUse | tool name as the argument, hook payload JSON on stdin | empty stdout is silence; stdout with exit 0 advises; exit 2 asks the human; any other non-zero exit denies |
| `checks/` | PostToolUse | one file path as the argument | one finding per line, `  <file>:<line>  [<rule-id>] <message>`, with two leading spaces |
| `rules/` | PostToolUse | ast-grep YAML rules | ast-grep findings |
| `changeset_checks/` | Stop, SubagentStop | argv[1] is the base revision. argv[2] is the shared base copy, or empty when there is no base. A script treats that copy as read-only. A script that reads only argv[1] works unchanged | a finished report section, or nothing |

The model reads every message, so a message should name what to do instead, not only what went wrong. `checks/` scripts decide for themselves which files they have anything to say about. A root needs its own `sgconfig.yml` only to register a custom ast-grep language.

Each bundled script's docstring explains what it enforces and why, so read one as a template before writing your own.

## Troubleshooting

- Run `doctor` from the directory in question to see which roots, rules, and tools apply there.
- Run `audit` from that directory to print the Stop findings for the current branch.
- Raise `log` to `2` to record every check's verdict in `~/agent-guard.log`, or to `3` to include the command text.
- Set `AGENT_GUARD_TOOL_CHECKS=false` for one session when a PreToolUse check blocks work it should allow, then fix the check.

## Layout

```text
.claude-plugin/marketplace.json   Claude Code marketplace
.agents/plugins/marketplace.json  Codex marketplace
.grok-plugin/marketplace.json     Grok Build marketplace
plugin/
  .claude-plugin/plugin.json      Claude Code manifest
  .codex-plugin/plugin.json       Codex manifest
  .grok-plugin/plugin.json        Grok Build manifest
  hooks/hooks.json                Claude Code hooks
  hooks/hooks-codex.json          Codex hooks
  hooks/hooks-grok.json           Grok Build hooks
  hooks/bootstrap-tools           SessionStart tool installer
  hooks/run-hook.cmd              cross-platform launcher for bash hooks
  agent_guard/                    hook package
  scripts/                        helpers
  agent_guard/checks/             built-in checks
  rules/ queries/ sgconfig.yml    ast-grep rules
tests/                            test suite
```

## Development

```sh
uv sync
uv run ruff check
uv run ruff format --check
uv run pyrefly check
uv run python tests/run.py
claude plugin validate plugin
claude plugin validate .
```

`devrun task verify` runs all of these in sequence. CI also runs `shellcheck` on the bash scripts.

## License

[GPL-3.0-or-later](LICENSE)
