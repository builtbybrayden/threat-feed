"""Shared test fixtures. No test touches the network (CLAUDE.md)."""

import sys
from pathlib import Path

import pytest

# Make the project importable without installing it.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.util import load_config, load_watchlist  # noqa: E402


@pytest.fixture
def config():
    return load_config(ROOT / "config.yaml")


@pytest.fixture
def watchlist():
    return load_watchlist(ROOT / "watchlist.yaml")
