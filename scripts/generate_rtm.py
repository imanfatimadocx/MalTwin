#!/usr/bin/env python3
"""
Run the automated test suite and produce the Requirement Traceability Matrix.

Every automated test case ID (AT-xx-nn) comes from an @pytest.mark.rtm marker on
a real test function, so the RTM can never drift from the code: if a test is
renamed or removed, its row disappears; if it fails, the RTM says FAIL.

Usage:
    python scripts/generate_rtm.py            # runs tests, writes docs/RTM.md + docs/rtm.csv
    python scripts/generate_rtm.py --no-run   # rebuild tables from the last run

Outputs:
    docs/RTM.md      requirement → automated tests → result, plus test → requirement table
    docs/rtm.csv     same data for spreadsheets
"""
import argparse
import csv
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "docs" / "rtm_results.json"

# Requirement catalogue: docs/requirements.json is the single source for the
# functional and non-functional requirements. The SDS (Chapter 2) is generated
# from the same file, so the document and this matrix cannot disagree.
CATALOGUE = ROOT / "docs" / "requirements.json"


def load_reqs() -> list[tuple[str, str, str, str]]:
    """(id, text, status, verification) for every FR and NFR."""
    cat = json.loads(CATALOGUE.read_text())
    reqs = [(r["id"], r["text"], r["status"], "Deferred" if r["status"].startswith("Deferred") else "Test")
            for r in cat["functional"]]
    reqs += [(r["id"], r["text"], r["status"], r["verification"]) for r in cat["nonfunctional"]]
    return reqs


REQS = load_reqs()


def run_tests() -> int:
    env = dict(os.environ, MALTWIN_RTM_OUT=str(RESULTS))
    RESULTS.parent.mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "pytest", "tests", "-m", "not integration", "-q", "-p", "no:warnings", "-p", "no:cacheprovider"]
    print("$ " + " ".join(cmd[2:]))
    return subprocess.call(cmd, cwd=ROOT, env=env)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-run", action="store_true")
    a = ap.parse_args()
    if not a.no_run:
        run_tests()
    rows = json.loads(RESULTS.read_text())

    # collapse parametrised cases (same test ID) into one row
    by_tc: dict[str, dict] = {}
    for r in rows:
        t = by_tc.setdefault(r["test_id"], {"reqs": r["requirements"], "nodeid": r["nodeid"].split("[")[0],
                                            "cases": 0, "failed": 0, "skipped": 0})
        t["cases"] += 1
        t["failed"] += r["outcome"] == "failed"
        t["skipped"] += r["outcome"] == "skipped"
    result = lambda t: "FAIL" if t["failed"] else ("SKIP" if t["skipped"] == t["cases"] else "PASS")  # noqa: E731

    req_tests = defaultdict(list)
    for tc, t in by_tc.items():
        for rq in t["reqs"]:
            req_tests[rq].append(tc)
    unknown = sorted(set(req_tests) - {r[0] for r in REQS})

    lines = [
        "# Requirement Traceability Matrix — MalTwin",
        "",
        f"Generated {datetime.now():%Y-%m-%d %H:%M} by `scripts/generate_rtm.py` from a live test run. "
        "Each automated test case ID is an `@pytest.mark.rtm` marker on a real test in `tests/`.",
        "",
        "## Requirements → automated tests",
        "",
        "| Requirement | Description | Status | Verification | Automated test cases | Result |",
        "|---|---|---|---|---|---|",
    ]
    covered = 0
    for rid, desc, status, verif in REQS:
        tcs = sorted(req_tests.get(rid, []))
        if tcs:
            covered += 1
            res = "FAIL" if any(result(by_tc[t]) == "FAIL" for t in tcs) else \
                  ("PASS" if any(result(by_tc[t]) == "PASS" for t in tcs) else "SKIP")
        else:
            res = "—"
        lines.append(f"| {rid} | {desc} | {status} | {verif} | {', '.join(tcs) or '—'} | {res} |")

    lines += ["", "## Automated test cases → code", "",
              "| Test ID | Requirements | Test function | Cases | Result |", "|---|---|---|---|---|"]
    for tc in sorted(by_tc, key=lambda x: (x.split("-")[1], int(x.split("-")[2]))):
        t = by_tc[tc]
        lines.append(f"| {tc} | {', '.join(t['reqs'])} | `{t['nodeid']}` | {t['cases']} | {result(t)} |")

    implemented = [r for r in REQS if r[3] == "Test"]
    n_pass = sum(result(t) == "PASS" for t in by_tc.values())
    n_fail = sum(result(t) == "FAIL" for t in by_tc.values())
    lines += ["", "## Summary", "",
              f"- Automated test cases in RTM: **{len(by_tc)}** ({sum(t['cases'] for t in by_tc.values())} executions incl. parameters)",
              f"- Passed: **{n_pass}**, failed: **{n_fail}**, skipped: **{len(by_tc) - n_pass - n_fail}**",
              f"- Requirements verified by test that are covered by at least one automated test: **{sum(1 for r in implemented if r[0] in req_tests)} / {len(implemented)}**",
              f"- Deferred requirements (Digital Twin): {', '.join(r[0] for r in REQS if r[2].startswith('Deferred'))}",
              f"- Verified by benchmark / inspection / user trial: {', '.join(r[0] for r in REQS if r[3] not in ('Test', 'Deferred'))}"]
    if unknown:
        lines.append(f"- WARNING: tests reference unknown requirement IDs: {unknown}")
    (ROOT / "docs" / "RTM.md").write_text("\n".join(lines) + "\n")

    with open(ROOT / "docs" / "rtm.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["requirement", "description", "status", "verification", "test_ids", "result"])
        for rid, desc, status, verif in REQS:
            tcs = sorted(req_tests.get(rid, []))
            res = ("FAIL" if any(result(by_tc[t]) == "FAIL" for t in tcs) else "PASS") if tcs else ""
            w.writerow([rid, desc, status, verif, " ".join(tcs), res])

    print("\n".join(lines[-6:]))
    print(f"\nWrote docs/RTM.md and docs/rtm.csv")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
