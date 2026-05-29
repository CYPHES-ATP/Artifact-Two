#!/usr/bin/env python3
"""Repo-local wrapper for the Artifact Two ATP bundle verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from artifact_two.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
