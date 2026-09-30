#!/usr/bin/env python3
"""PreToolUse guard: text the house style keeps out of what agents write.

A rule maps the text to catch, pasted as itself, to what to write instead, and
"" to delete it. Wrap the value in Explain when a swap cannot carry the advice.
The dict a rule sits in is its severity, and matching ignores case. Only what a
call adds is read, and an agent editing these rules is refused, so they stay
the human's to change.
"""

# ruff: noqa: RUF001

import json
import sys
import unicodedata


class Explain(str):
    """Advice the agent reads as written, where a plain value is a swap."""

    __slots__ = ()


INFLATED = Explain("Significance inflation. Cut the puffery and state what happened.")
PROMOTIONAL = Explain("Promotional language. Describe it in neutral words.")
UNSOURCED = Explain("A vague attribution. Name the source, or delete the claim.")
CHATBOT = Explain("Chatbot filler. Delete it and respond directly.")
UNSPECIFIC = Explain("Replace it with the specific fact, plan or number.")
PARALLELISM = Explain("A negative parallelism. State the point directly.")

# Denied outright: the call never runs.
REFUSE: dict[str, str] = {
    "—": Explain(
        "Use periods or commas only (no parentheses, no en dashes, no "
        "hyphen-as-dash substitutes). If a thought needs separation, end the "
        "sentence or use a comma."
    ),
    "–": Explain("Write a range as `3 to 5`, and a hyphen only where a hyphen is meant."),
    "…": "...",
    "→": "->",
    "←": "<-",
    "↔": "<->",
    "⇒": "=>",
    "⇐": "<=",
    "⇔": "<=>",
    "↑": "up",
    "↓": "down",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
}

# Handed to the human, who allows the call or not.
ASK: dict[str, str] = {}

# Allowed, with the advice passed to the agent as context.
WARN: dict[str, str] = {
    "·": Explain(
        "Use a comma, a slash or a hyphen instead of an interpunct, unless the human asked for one."
    ),
    # Significance inflation and promotion
    "pivotal": INFLATED,
    "testament to": INFLATED,
    "evolving landscape": INFLATED,
    "setting the stage for": INFLATED,
    "indelible mark": INFLATED,
    "deeply rooted": INFLATED,
    "nestled": PROMOTIONAL,
    "vibrant": PROMOTIONAL,
    "breathtaking": PROMOTIONAL,
    "groundbreaking": PROMOTIONAL,
    "renowned": PROMOTIONAL,
    "stunning": PROMOTIONAL,
    "must-visit": PROMOTIONAL,
    # Vague attributions and formulaic challenges
    "experts believe": UNSOURCED,
    "industry reports suggest": UNSOURCED,
    "some critics argue": UNSOURCED,
    "despite challenges": UNSPECIFIC,
    "continues to thrive": UNSPECIFIC,
    "the future looks bright": UNSPECIFIC,
    # AI vocabulary
    "additionally": "also",
    "crucial": "important",
    "delve": "look at",
    "delving": "looking at",
    "enduring": "lasting",
    "foster": "encourage",
    "garner": "get",
    "interplay": "interaction",
    "intricate": "complex",
    "showcase": "show",
    "showcasing": "showing",
    "tapestry": UNSPECIFIC,
    # Copula avoidance and negative parallelism
    "serves as": "is",
    "stands as": "is",
    "boasts": "has",
    "it's not just": PARALLELISM,
    "it's not only": PARALLELISM,
    # Chatbot and sycophancy
    "i hope this helps": CHATBOT,
    "let me know if": CHATBOT,
    "of course!": CHATBOT,
    "certainly!": CHATBOT,
    "smoking gun": CHATBOT,
    "great question": CHATBOT,
    "you're absolutely right": CHATBOT,
    "excellent point": CHATBOT,
    "good catch": CHATBOT,
    "while specific details are limited": UNSOURCED,
    # Filler and hedging
    "in order to": "to",
    "due to the fact that": "because",
    "it is important to note that": "",
    "in the event that": "if",
    "could potentially": "could",
    # Jargon and fancy words
    "gold-plating": "more than the job needs",
    "wedge in": "add",
    "utilize": "use",
    "leverage": "use",
    "facilitate": "help",
    "numerous": "many",
}

SWAP = "Write `{good}` instead."
DELETE = "Delete it."

FINDING = """\
{label} in: {excerpt}
  {advice}"""

REFUSE_MESSAGE = """\
agent-guard: unslop refuses this text.

{findings}"""

ASK_MESSAGE = """\
agent-guard: unslop asks the human about this text.

{findings}"""

WARN_MESSAGE = """\
agent-guard: the call runs, but unslop flags this text. Reword it where the advice fits.

{findings}"""

# stdout with this exit code asks; any other non-zero denies.
ASK_EXIT = 2

# Loudest first: a call tripping several tiers is judged by the first it trips.
TIERS = (
    (REFUSE, 1, REFUSE_MESSAGE),
    (ASK, ASK_EXIT, ASK_MESSAGE),
    (WARN, 0, WARN_MESSAGE),
)

SHELL_TOOLS = {"Bash", "PowerShell", "exec_command", "shell_command", "shell"}


def added_lines(patch):
    """The `+` side of an apply_patch envelope, which is the only side written."""
    return "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+"))


def text_field(source, *keys):
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def written_text(tool, tool_input):
    """What this call would add, empty for a call that adds nothing."""
    if tool == "apply_patch":
        return added_lines(text_field(tool_input, "command", "cmd"))
    if tool in SHELL_TOOLS:
        return text_field(tool_input, "command", "cmd")
    if tool == "Write":
        return text_field(tool_input, "content")
    if tool == "Edit":
        return text_field(tool_input, "new_string")
    if tool == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list):
            return ""
        return "\n".join(text_field(edit, "new_string") for edit in edits if isinstance(edit, dict))
    if tool == "NotebookEdit":
        return text_field(tool_input, "new_source")
    return ""


def excerpt(text, index, length, width=56):
    """The first occurrence in one line of context, so the agent can find it."""
    start, end = max(0, index - width // 2), min(len(text), index + length + width // 2)
    body = " ".join(text[start:end].split())
    return ("..." if start else "") + body + ("..." if end < len(text) else "")


def label(key):
    """A character by its Unicode name and codepoint; longer text quoted."""
    if len(key) != 1:
        return f'"{key}"'
    name = unicodedata.name(key, "unnamed character").lower()
    return f"{name} (U+{ord(key):04X})"


def advice(good):
    if isinstance(good, Explain):
        return good
    return SWAP.format(good=good) if good else DELETE


def report(text, rules):
    """A line about each rule `text` trips, empty when it trips none."""
    folded = text.lower()
    findings = []
    for key, good in rules.items():
        index = folded.find(key.lower()) if key else -1
        if index >= 0:
            findings.append(
                FINDING.format(
                    label=label(key),
                    excerpt=excerpt(text, index, len(key)),
                    advice=advice(good),
                )
            )
    return "\n".join(findings)


def judge(text):
    """The message and exit code of the loudest tier `text` trips."""
    for rules, code, message in TIERS:
        findings = report(text, rules)
        if findings:
            return message.format(findings=findings), code
    return "", 0


def main():
    tool = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    tool_input = payload.get("tool_input")
    text = written_text(tool, tool_input if isinstance(tool_input, dict) else {})
    if not text:
        return 0
    message, code = judge(text)
    if message:
        print(message)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        # A broken check degrades to silence rather than denying real work.
        sys.exit(0)
