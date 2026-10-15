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

# Requirement catalogue (SRS v1.0 + Evaluation 3 additions). Status reflects the
# implementation; DEFERRED requirements are listed so the matrix is complete.
REQS = [
    ("FR1.1", "Dashboard shows operational status of all modules", "Implemented"),
    ("FR1.2", "Cumulative detection statistics (analysed / malware / benign)", "Implemented"),
    ("FR1.3", "Persistent sidebar navigation between all screens", "Implemented"),
    ("FR1.4", "Feed of the most recent detection events", "Implemented"),
    ("FR2.1", "Start/stop Digital Twin simulation", "Deferred (final evaluation)"),
    ("FR2.2", "Live Digital Twin traffic log", "Deferred (final evaluation)"),
    ("FR2.3", "Digital Twin node status panel", "Deferred (final evaluation)"),
    ("FR2.4", "Protocol traffic pie chart", "Deferred (final evaluation)"),
    ("FR3.1", "Upload PE/ELF binary (max 50 MB, magic-byte validation)", "Implemented"),
    ("FR3.2", "Convert binary to grayscale image", "Implemented"),
    ("FR3.3", "Show metadata incl. SHA-256", "Implemented"),
    ("FR3.4", "Pixel intensity histogram (256 bins)", "Implemented"),
    ("FR5.1", "Run detection model on uploaded binary", "Implemented"),
    ("FR5.2", "Top-1 label with colour-coded confidence", "Implemented"),
    ("FR5.3", "Per-class probability chart", "Implemented"),
    ("FR5.4", "Grad-CAM heatmap on request", "Implemented"),
    ("FR5.5", "MITRE ATT&CK for ICS mapping", "Implemented"),
    ("FR5.6", "PDF / JSON forensic report download", "Implemented"),
    ("FR-B1", "Backend: validate, read bytes, build 2-D image", "Implemented"),
    ("FR-B2", "Backend: load model, preprocess, forward pass", "Implemented"),
    ("FR-B3", "Backend: log detection event to SQLite", "Implemented"),
    ("FR-B4", "Backend: compile report with MITRE data", "Implemented"),
    ("FR-B5", "Backend: start Digital Twin", "Deferred (final evaluation)"),
    ("FR-B6", "Backend: Grad-CAM hooks on last conv layer", "Implemented"),
    ("REL-1", "Identical results for identical input", "Implemented"),
    ("REL-2", "Corrupt/malformed files handled without crash", "Implemented"),
    ("REL-4", "No detection records lost (WAL)", "Implemented"),
    ("SEC-3", "Database file permission 600", "Implemented"),
    ("SEC-4", "SHA-256 computed locally", "Implemented"),
    ("USE-3", "Errors state what, cause and action", "Implemented"),
    ("M3-FE2", "Label encoding", "Implemented"),
    ("M3-FE3", "Stratified train/val/test split", "Implemented"),
    ("M3-FE4", "Dataset integrity validation", "Implemented"),
    ("M4-FE1", "Augmentation (rotation, flip, brightness)", "Implemented"),
    ("M4-FE2", "Gaussian noise injection", "Implemented"),
    ("M4-FE3", "Class-aware oversampling", "Implemented"),
    ("M5-FE2", "Configurable CNN training", "Implemented"),
    ("M5-FE3", "Evaluation metrics incl. ROC-AUC, FPR, unseen-family", "Implemented"),
    ("M5-FE5", "Model serialisation", "Implemented"),
    ("M5-BEN", "Benign class and benign false-positive evaluation", "Implemented"),
    ("M9-1", "Parse Zeek / IoT-23 conn.log", "Implemented"),
    ("M9-2", "IP-free behavioural flow features", "Implemented"),
    ("M9-3", "Behaviour classification model", "Implemented"),
    ("M9-4", "Capture-level verdict", "Implemented"),
    ("M9-5", "Feature-importance explanation", "Implemented"),
    ("M9-6", "MITRE ATT&CK for ICS per behaviour", "Implemented"),
    ("M9-7", "Dynamic Analysis dashboard page", "Implemented"),
    ("M10-1", "Decision-level fusion with agreement categories", "Implemented"),
    ("M10-2", "Combined MITRE mapping tagged by source", "Implemented"),
    ("M10-3", "Hybrid Verdict page and what-if simulator", "Implemented"),
    ("M1-DESIGN", "Digital Twin design page and prerequisite checks", "Implemented (design only)"),
]


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
        "| Requirement | Description | Status | Automated test cases | Result |",
        "|---|---|---|---|---|",
    ]
    covered = 0
    for rid, desc, status in REQS:
        tcs = sorted(req_tests.get(rid, []))
        if tcs:
            covered += 1
            res = "FAIL" if any(result(by_tc[t]) == "FAIL" for t in tcs) else \
                  ("PASS" if any(result(by_tc[t]) == "PASS" for t in tcs) else "SKIP")
        else:
            res = "—"
        lines.append(f"| {rid} | {desc} | {status} | {', '.join(tcs) or '—'} | {res} |")

    lines += ["", "## Automated test cases → code", "",
              "| Test ID | Requirements | Test function | Cases | Result |", "|---|---|---|---|---|"]
    for tc in sorted(by_tc, key=lambda x: (x.split("-")[1], int(x.split("-")[2]))):
        t = by_tc[tc]
        lines.append(f"| {tc} | {', '.join(t['reqs'])} | `{t['nodeid']}` | {t['cases']} | {result(t)} |")

    implemented = [r for r in REQS if not r[2].startswith("Deferred")]
    n_pass = sum(result(t) == "PASS" for t in by_tc.values())
    n_fail = sum(result(t) == "FAIL" for t in by_tc.values())
    lines += ["", "## Summary", "",
              f"- Automated test cases in RTM: **{len(by_tc)}** ({sum(t['cases'] for t in by_tc.values())} executions incl. parameters)",
              f"- Passed: **{n_pass}**, failed: **{n_fail}**, skipped: **{len(by_tc) - n_pass - n_fail}**",
              f"- Implemented requirements covered by at least one automated test: **{sum(1 for r in implemented if r[0] in req_tests)} / {len(implemented)}**",
              f"- Deferred requirements (Digital Twin): {', '.join(r[0] for r in REQS if r[2].startswith('Deferred'))}"]
    if unknown:
        lines.append(f"- WARNING: tests reference unknown requirement IDs: {unknown}")
    (ROOT / "docs" / "RTM.md").write_text("\n".join(lines) + "\n")

    with open(ROOT / "docs" / "rtm.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["requirement", "description", "status", "test_ids", "result"])
        for rid, desc, status in REQS:
            tcs = sorted(req_tests.get(rid, []))
            res = ("FAIL" if any(result(by_tc[t]) == "FAIL" for t in tcs) else "PASS") if tcs else ""
            w.writerow([rid, desc, status, " ".join(tcs), res])

    print("\n".join(lines[-6:]))
    print(f"\nWrote docs/RTM.md and docs/rtm.csv")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
