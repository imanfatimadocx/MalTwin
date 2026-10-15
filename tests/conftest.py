"""
conftest.py
===========
Shared pytest configuration and fixtures for MalTwin test suite.
"""

import json
import os

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: tests that require the Malimg dataset at data/malimg/"
    )
    config.addinivalue_line(
        "markers",
        "rtm(test_id, *requirement_ids): Requirement Traceability Matrix link — "
        "automated test case ID followed by the SRS requirement IDs it verifies",
    )


# ── RTM collection ────────────────────────────────────────────────────────────
# When MALTWIN_RTM_OUT is set (scripts/generate_rtm.py does this), every test
# carrying @pytest.mark.rtm is recorded with its outcome and written to JSON.
_RTM_ROWS: list[dict] = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    marker = item.get_closest_marker("rtm")
    if marker is None or not os.environ.get("MALTWIN_RTM_OUT"):
        return
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        test_id, *reqs = marker.args
        _RTM_ROWS.append({
            "test_id": test_id, "requirements": reqs, "nodeid": item.nodeid,
            "outcome": "skipped" if rep.skipped else rep.outcome,
            "doc": (item.function.__doc__ or "").strip().splitlines()[0] if item.function.__doc__ else "",
        })


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("MALTWIN_RTM_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(_RTM_ROWS, f, indent=2)


@pytest.fixture(scope="session")
def device():
    """Return 'cpu' — all unit tests run on CPU regardless of host GPU."""
    return "cpu"


@pytest.fixture(scope="session")
def num_classes():
    return 25


@pytest.fixture(scope="session")
def img_size():
    return 128
