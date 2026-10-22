#!/usr/bin/env python3
"""Run every *.test.py beside this file, each in its own interpreter."""

import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def main() -> int:
    failed: list[str] = []
    for test in sorted(TESTS.glob("*.test.py")):
        print(f"== {test.name}", flush=True)
        if subprocess.run([sys.executable, str(test)], check=False).returncode:
            failed.append(test.name)

    print(f"\n{len(failed)} failed" + (f": {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
