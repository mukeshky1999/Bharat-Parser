"""
Bharat Forensic Suite — E2E Test Suite Pytest Fixtures
"""

import os
import shutil
import pytest
from pathlib import Path

# Initialize environment
import tests.e2e.env_setup as env_setup


@pytest.fixture(scope="function")
def isolated_e2e_env():
    """Provides an isolated scratch directory under .workspace_tmp/e2e_scratch."""
    sandbox = env_setup.create_isolated_sandbox(prefix="pytest_e2e_")
    yield sandbox
    env_setup.cleanup_isolated_sandbox(sandbox)


@pytest.fixture(scope="session")
def test_evidence_dir():
    """Returns path to authentic test evidence directory."""
    return env_setup.TEST_EVIDENCE_DIR
