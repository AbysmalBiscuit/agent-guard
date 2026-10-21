"""The hook core.

The harnesses run this package with plain `python3` on the package directory.
Importing it starts nothing. `decide` takes one event and returns a decision.
"""

from .contract import Decision
from .dispatch import decide

__all__ = ["Decision", "decide"]
