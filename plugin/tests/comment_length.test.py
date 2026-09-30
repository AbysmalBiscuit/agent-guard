#!/usr/bin/env python3
"""Cases for checks/comment_length.py. Run directly: python3 <this file>.

The cases that matter separate a paragraph from a single sentence that wrapped,
since a check firing on the second teaches agents to skim past the first. Two
of them drive the real hook end to end, one asserting a violation reaches the
agent and one that a note arrives under a heading that does not call it one.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types

CHECK = pathlib.Path(__file__).parent.parent / "checks" / "comment_length.py"
GUARD = pathlib.Path(__file__).parent.parent / "scripts" / "agent_guard.py"

for _key in [k for k in os.environ if k.startswith("AGENT_GUARD_")]:
    del os.environ[_key]


def load():
    module = types.ModuleType("check_under_test")
    module.__file__ = str(CHECK)
    exec(compile(CHECK.read_text(encoding="utf-8"), str(CHECK), "exec"), module.__dict__)
    return module


CHECKER = load()
LONG_SENTENCE = (
    "// The scheduler reads the stored value synchronously on the first render "
    "rather than waiting for an effect, because an effect would paint the empty "
    "state first and the resulting flash is visible on every navigation into the "
    "calendar, which the design review rejected twice.\n"
)


def report(name, source):
    return CHECKER.findings(name, source)


def hook(target, base):
    payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target)},
            "cwd": base,
        }
    )
    done = subprocess.run(
        [sys.executable, str(GUARD)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=base,
    )
    return done.stdout


def test_a_run_of_stacked_line_comments_is_one_span():
    found = report("a.ts", "const a = 1;\n" + "// narration\n" * 15)
    assert len(found) == 1, found
    assert "a.ts:16" in found[0] and "15 lines" in found[0], found


def test_a_wrapped_sentence_passes_at_the_width_that_wrapped_it():
    source = (
        "// Area overlaps register a frame after the collision event, so query the\n"
        "// target directly here instead of waiting for the overlap callback.\n"
        "for (const target of hitbox.overlaps()) {}\n"
    )
    assert report("a.ts", source) == []
    assert report("a.ts", "// one\n// two\n// three\nconst a = 1;\n") == []


def test_a_third_sentence_is_a_violation_at_any_width():
    source = "// First fact. Second fact. Third fact.\nconst a = 1;\n"
    found = report("a.ts", source)
    assert len(found) == 1, found
    assert "3 sentences" in found[0], found


def test_a_fourth_line_is_a_violation():
    found = report("a.ts", "// one\n// two\n// three\n// four\nconst a = 1;\n")
    assert len(found) == 1 and "4 lines" in found[0], found


def test_an_eighth_line_grades_harder_than_a_fourth():
    assert "[warn:comment-length]" in report("a.ts", "// narration\n" * 7)[0]
    found = report("a.ts", "// narration\n" * 8)
    assert len(found) == 1 and "[error:comment-length]" in found[0], found
    assert "8 lines" in found[0], found


def test_a_fifth_sentence_grades_harder_than_a_third():
    source = "// One fact. Two fact. Three fact. Four fact. Five fact.\nconst a = 1;\n"
    found = report("a.ts", source)
    assert len(found) == 1 and "[error:comment-length]" in found[0], found
    assert "5 sentences" in found[0], found


def test_one_long_sentence_inside_the_bounds_is_a_note():
    found = report("a.ts", LONG_SENTENCE + "const a = 1;\n")
    assert len(found) == 1, found
    assert "[info:comment-length]" in found[0], found


def test_a_drawn_banner_is_decoration_rather_than_prose():
    source = "// " + "=" * 40 + "\n// HPLC-SEC run completion\n// " + "=" * 40 + "\nconst a = 1;\n"
    assert report("a.ts", source) == []


def test_a_block_comment_counts_its_own_lines():
    found = report("a.ts", "/*\n a\n b\n c\n d\n*/\nconst a = 1;\n")
    assert len(found) == 1, found


def test_a_comment_after_code_joins_nothing():
    assert report("a.ts", "const a = 1; // x\nconst b = 2; // y\nconst c = 3; // z\n") == []


def test_a_blank_line_ends_a_run():
    source = "// one\n// two\n\n// three\n// four\nconst a = 1;\n"
    assert report("a.ts", source) == []


def test_a_template_literal_holds_no_comments():
    source = "const s = `\n// no\n// still no\n// no\n// nor this\n`;\nconst b = 2;\n"
    assert report("a.ts", source) == []


def test_a_python_string_holds_no_comments():
    """The docstring itself is long enough to be a note; what it must never be
    is a run of the four comments written inside it."""
    source = '"""Doc.\n\n# no\n# still no\n# no\n# nor this\n"""\nx = 1\n'
    assert [f for f in report("a.py", source) if "[warn:comment-length]" in f] == []


def test_a_yaml_block_scalar_holds_no_comments():
    source = "jobs:\n  x:\n    steps:\n      - run: |\n" + "          # step\n" * 30
    assert report("a.yml", source) == []


def test_a_lifetime_is_not_a_string_that_hides_a_run():
    source = "pub fn f<'a>(x: &'a str) {}\n" + "// narration\n" * 4
    assert len(report("a.rs", source)) == 1, report("a.rs", source)


def test_a_doc_comment_is_a_note_at_five_lines_and_a_violation_at_ten():
    def doc(body):
        return report("a.ts", "/**\n" + " * doc\n" * body + " */\nexport const a = 1;\n")

    assert doc(2) == []
    note = doc(3)
    assert len(note) == 1 and "[info:doc-comment-length]" in note[0], note
    assert "5 lines" in note[0], note
    assert "[info:doc-comment-length]" in doc(7)[0], doc(7)
    breach = doc(8)
    assert len(breach) == 1 and "[warn:doc-comment-length]" in breach[0], breach
    assert "10 lines" in breach[0], breach


def test_a_doc_comment_past_twenty_five_lines_grades_harder():
    def doc(body):
        return report("a.ts", "/**\n" + " * doc\n" * body + " */\nexport const a = 1;\n")

    assert "[warn:doc-comment-length]" in doc(20)[0], doc(20)
    breach = doc(23)
    assert len(breach) == 1 and "[error:doc-comment-length]" in breach[0], breach
    assert "25 lines" in breach[0], breach


def test_a_rust_doc_run_answers_to_the_doc_budget():
    assert report("a.rs", "/// doc\n" * 4 + "pub fn f() {}\n") == []
    note = report("a.rs", "/// doc\n" * 5 + "pub fn f() {}\n")
    assert len(note) == 1 and "[info:doc-comment-length]" in note[0], note


def test_a_python_docstring_answers_to_the_doc_budget():
    short = 'def f():\n    """Does a thing.\n\n    With a note.\n    """\n    return 1\n'
    assert report("a.py", short) == []
    long = 'def f():\n    """Doc.\n' + "    line\n" * 10 + '    """\n    return 1\n'
    found = report("a.py", long)
    assert len(found) == 1 and "[warn:doc-comment-length]" in found[0], found


def test_a_python_docstring_is_not_read_as_a_comment_run():
    source = 'def f():\n    """One. Two. Three. Four."""\n    return 1\n'
    assert report("a.py", source) == []


def test_config_files_answer_to_the_same_rule():
    assert report("a.toml", "# one\n# two\n# three\n# four\nkey = 1\n") != []


def test_a_shebang_is_not_part_of_the_header():
    found = report("a.sh", "#!/usr/bin/env bash\n# one\n# two\n# three\n# four\necho hi\n")
    assert len(found) == 1 and "4 lines" in found[0], found


def test_every_finding_reaches_the_agent():
    """Truncating in file order would drop the comment the agent just wrote,
    because the runner's diff filter keeps only the newest lines."""
    source = "".join(f"// one\n// two\n// three\n// four\nconst a{i} = 1;\n" for i in range(5))
    assert len(report("a.ts", source)) == 5


def test_an_environment_override_moves_a_threshold():
    os.environ["AGENT_GUARD_COMMENT_SENTENCES"] = "5"
    try:
        assert report("a.ts", "// One. Two. Three.\nconst a = 1;\n") == []
    finally:
        del os.environ["AGENT_GUARD_COMMENT_SENTENCES"]


def test_the_hook_reports_the_run_it_used_to_miss():
    with tempfile.TemporaryDirectory() as base:
        target = pathlib.Path(base, "stacked.ts")
        target.write_text("const a = 1;\n" + "// narration\n" * 15, encoding="utf-8")
        out = hook(target, base)
        assert "error:comment-length" in out, out
        assert "stacked.ts:16" in out, out
        assert "well past the line" in out, out


def test_the_hook_asks_for_a_fix_at_the_lower_tier():
    with tempfile.TemporaryDirectory() as base:
        target = pathlib.Path(base, "short.ts")
        target.write_text("// narration\n" * 4 + "const a = 1;\n", encoding="utf-8")
        out = hook(target, base)
        assert "[warn:comment-length]" in out, out
        assert "Fix them now" in out, out
        assert "well past the line" not in out, out


def test_the_hook_shows_a_note_without_calling_it_a_violation():
    with tempfile.TemporaryDirectory() as base:
        target = pathlib.Path(base, "verbose.ts")
        target.write_text(LONG_SENTENCE + "const a = 1;\n", encoding="utf-8")
        out = hook(target, base)
        assert "info:comment-length" in out, out
        assert "it is not a violation" in out, out
        assert "convention violations" not in out, out


if __name__ == "__main__":
    failures = 0
    for name, case in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            case()
            print(f"ok   {name}")
        except AssertionError as bad:
            failures += 1
            print(f"FAIL {name}: {bad}")
        except Exception as bad:
            failures += 1
            print(f"FAIL {name}: {type(bad).__name__}: {bad}")
    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)
