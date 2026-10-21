"""Built-in checks as package functions.

A tool check takes the hook payload and returns a decision. A file check takes
the file text and its path and returns finding lines. A project root still
ships scripts; those stay on the stdin contract and are not imported here.
"""

from . import (
    cd_relative_path,
    comment_length,
    markdown_hard_wrap,
    prune_temp_dir,
    rg_replace_footgun,
    secret_decrypt,
    shell_conventions,
    text_quality,
)

MANDATORY_CHECKS = (secret_decrypt.check,)

TOOL_CHECKS = (
    rg_replace_footgun.check,
    shell_conventions.check,
    cd_relative_path.check,
    text_quality.check,
    prune_temp_dir.check,
)

FILE_CHECKS = (
    comment_length.check,
    markdown_hard_wrap.check,
)

__all__ = ["FILE_CHECKS", "MANDATORY_CHECKS", "TOOL_CHECKS"]
