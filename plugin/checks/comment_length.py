#!/usr/bin/env python3
"""Comments longer than the conventions allow, in every language a tree holds.

AGENTS.md: if you need a paragraph-long comment to justify why the workaround is
OK, the code is wrong. A paragraph is a multi-sentence unit, so sentences are
what this counts, with a line ceiling behind them and a character ceiling for
the single sentence that rambles. Counting lines alone measures the file's wrap
width: in a real tree the median three-line comment is one sentence that did not
fit, and half of them are `====` section banners.

An ast-grep rule cannot reach any of this. Tree-sitter gives each `//` line a
comment node of its own, so a rule over one node's text never sees the run.

Doc comments keep a far looser budget. `/** */`, `///` and `//!` are written for
a caller who never opens the file, not narration of the code beside them. A
Python docstring is a string literal rather than a comment, so it arrives from
the parser instead of the scanner and answers to the same budget.

Line numbers are what the runner filters on when scope is "diff", so a span is
reported on its last line: a comment an agent grows by appending has its old
first line and its new last one.
"""

import ast
import io
import os
import re
import sys
import tokenize
from typing import NamedTuple

# One id per thing measured, and a severity prefix for how far past the line it
# went. The runner heads each tier separately and spends its budget on the
# loudest first; the message carries the count that tripped it, so the id has no
# business also grading the finding. Every tier says its severity, including the
# middle one: an unprefixed `comment-length` would read as a finding that
# asserts nothing, since every comment has a length.
RULE = "warn:comment-length"
HARD_RULE = "error:comment-length"
INFO_RULE = "info:comment-length"
DOC_INFO_RULE = "info:doc-comment-length"
DOC_RULE = "warn:doc-comment-length"
HARD_DOC_RULE = "error:doc-comment-length"

SENTENCES_MESSAGE = (
    "comment runs {sentences} sentences over {lines} lines; if the code needs a "
    "paragraph to justify it, fix the code"
)
LINES_MESSAGE = (
    "comment runs {lines} lines; if the code needs a paragraph to justify it, fix the code"
)
CHARS_MESSAGE = (
    "comment runs {chars} characters in {sentences} sentence; the same point fits in fewer"
)
DOC_MESSAGE = "doc comment runs {lines} lines; trim it to what a caller needs"
DOC_INFO_MESSAGE = "doc comment runs {lines} lines; a caller reads the first line and stops"
HARD_SENTENCES_MESSAGE = (
    "comment runs {sentences} sentences over {lines} lines; keep the one that says "
    "why and delete the rest"
)
HARD_LINES_MESSAGE = "comment runs {lines} lines; keep the line that says why and delete the rest"
HARD_DOC_MESSAGE = (
    "doc comment runs {lines} lines; keep the summary and the parameters, and move "
    "the prose into a document"
)

# Each is the count that trips the rule, so a span firing at four lines says 4.
# A HARD_ threshold is where a comment stopped being a note on the code and
# became a document living inside it, which is a different thing to tell an
# agent than that its comment ran long.
FLAG_SENTENCES = 3
HARD_SENTENCES = 5
FLAG_LINES = 4
HARD_LINES = 8
FLAG_CHARS = 200
FLAG_DOC_LINES = 10
HARD_DOC_LINES = 25
FLAG_DOC_INFO_LINES = 5


# `spanning` is the quotes that survive a newline; the rest end at one, so an
# unbalanced quote costs a line rather than the rest of the file.
class Syntax(NamedTuple):
    line: tuple[str, ...]
    block: tuple[str, str] | None
    quotes: tuple[str, ...]
    spanning: tuple[str, ...]
    doc: tuple[str, ...]


C = Syntax(("//",), ("/*", "*/"), ('"', "'", "`"), ("`",), ("///", "//!", "/**"))
# Lifetimes read as an unterminated char literal, and `'` opens nothing a
# comment can hide behind that `"` does not.
RUST = C._replace(quotes=('"',))
HASH = Syntax(("#",), None, ('"', "'"), (), ())
SQL = Syntax(("--",), ("/*", "*/"), ("'", '"'), (), ())
CSS = Syntax((), ("/*", "*/"), ('"', "'"), (), ())

SYNTAX = {}
for _suffixes, _syntax in (
    (
        (
            ".ts .tsx .mts .cts .js .jsx .mjs .cjs .java .kt .kts .swift .scala .dart"
            " .c .h .cc .cpp .hpp .cs .go .proto .php"
        ),
        C,
    ),
    (".rs", RUST),
    (".sh .bash .zsh .toml .rb .pl .ini .cfg .conf .mk .tf", HASH),
    (".sql", SQL),
    (".css .scss .less", CSS),
):
    SYNTAX.update(dict.fromkeys(_suffixes.split(), _syntax))

YAML_SUFFIXES = (".yml", ".yaml")
PYTHON_SUFFIXES = (".py", ".pyi")
SUFFIXES = tuple(SYNTAX) + YAML_SUFFIXES + PYTHON_SUFFIXES

MARKER = re.compile(r"^\s*(?:/\*+|\*+/|\*(?!/)|//+|#+|--+)\s?")
TRAILER = re.compile(r"\s*\*+/\s*$")
# A drawn separator, whether it is the whole line or the wings around a title.
BANNER_LINE = re.compile(r"^[-=*_~+]{4,}$")
BANNER_RUN = re.compile(r"[-=*_~+]{6,}")
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\[\"`])")


# start and end are 1-indexed and inclusive; alone is False for a comment with
# code before it on its line, which no run may join.
class Comment(NamedTuple):
    start: int
    end: int
    alone: bool
    block: bool
    text: str


def limit(name, fallback):
    """A threshold the environment may move for one run, the way every other
    agent-guard setting can be."""
    try:
        value = int(os.environ.get(name, "").strip())
    except ValueError:
        return fallback
    return value if value > 0 else fallback


def opener(source, index, openers):
    for token in openers:
        if source.startswith(token, index):
            return token
    return None


def skip_string(source, index, line, syntax):
    """Past the string opening at index, as (index, line). A quote that cannot
    span lines gives the newline back rather than swallowing it."""
    quote = source[index]
    spans = quote in syntax.spanning
    end = len(source)
    cursor = index + 1
    while cursor < end:
        char = source[cursor]
        if char == "\\":
            if source[cursor + 1 : cursor + 2] == "\n":
                line += 1
            cursor += 2
            continue
        if char == quote:
            return cursor + 1, line
        if char == "\n":
            if not spans:
                return cursor, line
            line += 1
        cursor += 1
    return end, line


def comments(source, syntax):
    """Every comment in source, in order."""
    found = []
    index, line, end = 0, 1, len(source)
    alone = True
    while index < end:
        char = source[index]
        if char == "\n":
            index, line, alone = index + 1, line + 1, True
            continue
        token = opener(source, index, syntax.line)
        if token:
            stop = source.find("\n", index)
            stop = end if stop < 0 else stop
            found.append(Comment(line, line, alone, False, source[index:stop]))
            index = stop
            continue
        if syntax.block and source.startswith(syntax.block[0], index):
            close = source.find(syntax.block[1], index + len(syntax.block[0]))
            stop = end if close < 0 else close + len(syntax.block[1])
            text = source[index:stop]
            found.append(Comment(line, line + text.count("\n"), alone, True, text))
            index, line, alone = stop, line + text.count("\n"), False
            continue
        if char in syntax.quotes:
            index, line = skip_string(source, index, line, syntax)
            alone = False
            continue
        if not char.isspace():
            alone = False
        index += 1
    return found


def python_comments(source):
    """Comments a tokenizer found, so a `#` inside a string stays a string.

    A file mid-edit stops the tokenizer partway; what it read before that is
    still true, and reporting on it beats guessing at the rest."""
    lines = source.splitlines()
    found = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                row = token.start[0]
                alone = lines[row - 1].lstrip().startswith("#")
                found.append(Comment(row, row, alone, False, token.string))
    except (SyntaxError, tokenize.TokenError, IndentationError, ValueError):
        pass
    return found


def python_docstrings(source):
    """Docstring spans as (start, end, True), so they answer to the doc budget.

    A docstring is a string literal rather than a comment, so no comment scanner
    reaches one. Every other language this checks writes its doc comments in
    comment syntax, which is why only Python needs a parser."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        first = (node.body or [None])[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            out.append((first.lineno, first.end_lineno, True))
    return out


def yaml_comments(source):
    """A block scalar carries whatever it likes, and a CI job's `run: |` body is
    usually a shell script whose `#` lines are the script's, not the YAML's."""
    lines = source.splitlines()
    opaque = set()
    index = 0
    while index < len(lines):
        text = lines[index].split("#", 1)[0].rstrip()
        chomped = text[-2:-1] in ("|", ">") and text[-1:] in ("+", "-")
        if text.endswith(("|", ">")) or chomped:
            indent = len(lines[index]) - len(lines[index].lstrip())
            index += 1
            while index < len(lines):
                body = lines[index]
                if body.strip() and len(body) - len(body.lstrip()) <= indent:
                    break
                opaque.add(index + 1)
                index += 1
            continue
        index += 1
    return [c for c in comments(source, HASH) if c.start not in opaque]


def spans(found, syntax):
    """Comment spans as (start, end, doc), consecutive whole-line comments
    merged into the one run a reader sees."""
    out = []
    run = None
    for comment in found:
        doc = comment.text.startswith(syntax.doc) if syntax.doc else False
        if run and not (
            not comment.block and comment.alone and comment.start == run[1] + 1 and doc == run[2]
        ):
            out.append(tuple(run))
            run = None
        if not comment.block and comment.alone:
            if run:
                run[1] = comment.end
            else:
                run = [comment.start, comment.end, doc]
            continue
        if comment.alone or comment.end > comment.start:
            out.append((comment.start, comment.end, doc))
    if run:
        out.append(tuple(run))
    return out


def measure(lines, start, end):
    """A span as (lines, sentences, characters), reading only its prose.

    A drawn separator is decoration rather than something written, so it counts
    toward none of the three. Half the three-line runs in a real tree are a
    title between two rules, and telling an agent to fix the code under one is
    how a check earns being skimmed past."""
    prose = []
    for number in range(start, end + 1):
        text = TRAILER.sub("", MARKER.sub("", lines[number - 1])).strip()
        if BANNER_LINE.match(text):
            continue
        prose.append(BANNER_RUN.sub(" ", text).strip())
    body = " ".join(t for t in prose if t).strip()
    if len(body) < 3:
        return 0, 0, 0
    sentences = [s for s in SENTENCE_BREAK.split(body) if s.strip()]
    return len(prose), max(len(sentences), 1), len(body)


def findings(path, source):
    lower = path.lower()
    if lower.endswith(PYTHON_SUFFIXES):
        found, syntax = python_comments(source), HASH
    elif lower.endswith(YAML_SUFFIXES):
        found, syntax = yaml_comments(source), HASH
    else:
        syntax = SYNTAX[lower[lower.rindex(".") :]]
        found = comments(source, syntax)
    # A shebang is how the file is run, not something written about it, and it
    # sits directly above the header comment it would otherwise lengthen.
    found = [c for c in found if not (c.start == 1 and c.text.startswith("#!"))]
    flag_sentences = limit("AGENT_GUARD_COMMENT_SENTENCES", FLAG_SENTENCES)
    hard_sentences = limit("AGENT_GUARD_COMMENT_HARD_SENTENCES", HARD_SENTENCES)
    flag_lines = limit("AGENT_GUARD_COMMENT_LINES", FLAG_LINES)
    hard_lines = limit("AGENT_GUARD_COMMENT_HARD_LINES", HARD_LINES)
    flag_chars = limit("AGENT_GUARD_COMMENT_CHARS", FLAG_CHARS)
    flag_doc = limit("AGENT_GUARD_DOC_LINES", FLAG_DOC_LINES)
    hard_doc = limit("AGENT_GUARD_DOC_HARD_LINES", HARD_DOC_LINES)
    flag_doc_info = limit("AGENT_GUARD_DOC_INFO_LINES", FLAG_DOC_INFO_LINES)
    lines = source.splitlines()
    docs = python_docstrings(source) if lower.endswith(PYTHON_SUFFIXES) else []
    out = []
    for start, end, doc in sorted(spans(found, syntax) + docs):
        count, sentences, chars = measure(lines, start, end)
        if not count:
            continue
        if doc:
            if count >= hard_doc:
                out.append(report(path, end, HARD_DOC_RULE, HARD_DOC_MESSAGE, lines=count))
            elif count >= flag_doc:
                out.append(report(path, end, DOC_RULE, DOC_MESSAGE, lines=count))
            elif count >= flag_doc_info:
                out.append(report(path, end, DOC_INFO_RULE, DOC_INFO_MESSAGE, lines=count))
            continue
        if sentences >= hard_sentences:
            message = HARD_SENTENCES_MESSAGE.format(sentences=sentences, lines=count)
            out.append(report(path, end, HARD_RULE, message))
        elif count >= hard_lines:
            out.append(report(path, end, HARD_RULE, HARD_LINES_MESSAGE, lines=count))
        elif sentences >= flag_sentences:
            message = SENTENCES_MESSAGE.format(sentences=sentences, lines=count)
            out.append(report(path, end, RULE, message))
        elif count >= flag_lines:
            out.append(report(path, end, RULE, LINES_MESSAGE, lines=count))
        elif chars >= flag_chars:
            message = CHARS_MESSAGE.format(chars=chars, sentences=sentences)
            out.append(report(path, end, INFO_RULE, message))
    return out


def report(path, line, rule, message, **fields):
    return f"  {path}:{line}  [{rule}] {message.format(**fields)}"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else ""
    # The extensions setting is one regex for the whole checks/ layer, so each
    # check narrows to the files it has anything to say about.
    if not path.lower().endswith(SUFFIXES):
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            source = handle.read()
    except OSError:
        return
    try:
        out = findings(path, source)
    except Exception:
        # A file this cannot read is a file it has nothing to say about, and an
        # agent stopped by the guard's own crash learns to distrust it.
        return
    for finding in out:
        print(finding)


if __name__ == "__main__":
    main()
