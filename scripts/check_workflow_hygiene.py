#!/usr/bin/env python3
"""Fail when the Marketplace CodeQL opt-in contract regresses."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CODEQL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "codeql.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"workflow hygiene failed: {message}")


def main() -> None:
    content = CODEQL_WORKFLOW.read_text(encoding="utf-8")
    directives = "\n".join(
        line for line in content.splitlines() if not line.lstrip().startswith("#")
    )

    require(
        "permissions:\n  actions: read\n  contents: read\n  security-events: write"
        in directives,
        "CodeQL must retain minimal upload permissions",
    )
    require(
        directives.count("if: ${{ vars.CODEQL_ENABLED == 'true' }}") == 1,
        "CodeQL must have exactly one explicit CODEQL_ENABLED opt-in job gate",
    )
    require(
        "\n  pull_request:\n" in directives
        and "pull_request_target:" not in directives,
        "CodeQL must use the unprivileged pull_request event",
    )

    codeql_steps = re.findall(
        r"github/codeql-action/[a-z-]+@v\d+", directives
    )
    require(
        codeql_steps
        == [
            "github/codeql-action/init@v4",
            "github/codeql-action/analyze@v4",
        ],
        "CodeQL must initialize and analyze with v4 exactly once per matrix entry",
    )
    require(
        re.search(r"- language: rust\n\s+build-mode: none", directives) is not None,
        "the matrix must use build-mode none for Rust source analysis",
    )
    require(
        re.search(r"- language: actions\n\s+build-mode: none", directives) is not None,
        "the matrix must use build-mode none for Actions workflow analysis",
    )
    require(
        directives.count("- language:") == 2,
        "the CodeQL matrix must contain only Rust and Actions",
    )
    require(
        "languages: ${{ matrix.language }}" in directives
        and "build-mode: ${{ matrix.build-mode }}" in directives
        and "category: /language:${{ matrix.language }}" in directives,
        "CodeQL init and result categories must follow the language matrix",
    )
    require(
        re.search(r"\bcpp\b", directives, flags=re.IGNORECASE) is None,
        "Marketplace is Rust; C/C++ analysis must not return",
    )

    print("CodeQL workflow hygiene checks passed")


if __name__ == "__main__":
    main()
