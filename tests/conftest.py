"""Pytest configuration for hub tests."""

import pytest
import os

# Configure test environment - MUST be set before importing any app modules
os.environ["ASEOKA_HUB_DB_PATH"] = ":memory:"
os.environ["ASEOKA_HUB_JWT_SECRET"] = "test_secret_key_for_testing"
os.environ["ASEOKA_HUB_REQUIRE_AUTH"] = "false"
# Disable rate limiting for tests
os.environ["ASEOKA_RATE_LIMIT_LOGIN"] = "1000/minute"
os.environ["ASEOKA_RATE_LIMIT_BOOTSTRAP"] = "1000/minute"
os.environ["ASEOKA_RATE_LIMIT_DEFAULT"] = "1000/minute"


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


def pytest_configure(config):
    """Configure pytest-asyncio."""
    config.addinivalue_line("markers", "asyncio: mark test as async")
