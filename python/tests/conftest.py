"""Shared fixtures for VI tests."""

from __future__ import annotations

import pytest

from helpers import get_agent_keys


@pytest.fixture
def agent_keys():
    return get_agent_keys()
