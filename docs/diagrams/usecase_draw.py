"""UML use case diagrams for MalTwin (standard notation).

Stick-figure actors, ellipse use cases with IDs, a rectangle system boundary,
solid association lines (actor–use case only), hollow-triangle generalisation
between actors, and dashed open-arrow «include» / «extend» dependencies.
Use cases are never chained to each other by plain lines.
"""
import math
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, Rectangle, FancyArrowPatch, Polygon

NAVY, FILL, ADD, PLAN = "#1F3864", "#EEF2F8", "#FFF2CC", "#F2F2F2"
EW, EH = 2.6, 0.7
LINE = "#333333"


def actor(ax, x, y, name):
    ax.add_patch(plt.Circle((x, y + 0.55), 0.13, fill=False, lw=1.6, color=NAVY))
    ax.plot([x, x], [y + 0.42, y + 0.05], color=NAVY, lw=1.6)
    ax.plot([x - 0.25, x + 0.25], [y + 0.32, y + 0.32], color=NAVY, lw=1.6)
    ax.plot([x, x - 0.2], [y + 0.05, y - 0.25], color=NAVY, lw=1.6)
    ax.plot([x, x + 0.2], [y + 0.05, y - 0.25], color=NAVY, lw=1.6)
    ax.text(x, y - 0.36, name, ha="center", va="top", fontsize=10.5)
    return (x, y + 0.2)


def usecase(ax, c, label, kind="normal"):
    fc = {"normal": FILL, "addendum": ADD, "planned": PLAN}[kind]
    ls = "--" if kind == "planned" else "-"
    ax.add_patch(Ellipse(c, EW, EH, facecolor=fc, edgecolor=NAVY, lw=1.4, ls=ls, zorder=3))
    ax.text(c[0], c[1], label, ha="center", va="center", fontsize=9.4, zorder=4)


def edge(c, toward):
    dx, dy = toward[0] - c[0], toward[1] - c[1]
    t = 1 / math.sqrt((dx / (EW / 2)) ** 2 + (dy / (EH / 2)) ** 2)
    return (c[0] + dx * t, c[1] + dy * t)


def assoc(ax, a, c):
    p = (c[0] - EW / 2, c[1]) if a[0] < c[0] else (c[0] + EW / 2, c[1])   # attach at the near tip
    ax.plot([a[0], p[0]], [a[1], p[1]], color=LINE, lw=1.0, zorder=1)


def dep(ax, src, dst, label, lpos=None, ha="center"):
    """Dashed dependency src -> dst with an open arrowhead and a stereotype label."""
    s, d = edge(src, dst), edge(dst, src)
    ax.add_patch(FancyArrowPatch(s, d, arrowstyle="->,head_length=7,head_width=4.5",
                                 linestyle=(0, (4, 3)), color=LINE, lw=1.0, zorder=2))
    lx, ly = lpos or ((s[0] + d[0]) / 2, (s[1] + d[1]) / 2)
    ax.text(lx, ly, f"«{label}»", fontsize=8.6, ha=ha, va="center", zorder=5,
            bbox=dict(facecolor="white", edgecolor="none", pad=0.5))


def generalise(ax, child, parent):
    """Solid line with a hollow triangle at the parent (UML generalisation)."""
    (x1, y1), (x2, y2) = child, parent
    ax.plot([x1, x2], [y1, y2 - 0.22], color=LINE, lw=1.0)
    ax.add_patch(Polygon([[x2, y2], [x2 - 0.13, y2 - 0.24], [x2 + 0.13, y2 - 0.24]],
                         closed=True, facecolor="white", edgecolor=LINE, lw=1.0, zorder=3))


def legend(ax, x, y, items):
    for i, (kind, text) in enumerate(items):
        yy = y - i * 0.42
        fc = {"normal": FILL, "addendum": ADD, "planned": PLAN}[kind]
        ax.add_patch(Ellipse((x, yy), 0.55, 0.26, facecolor=fc, edgecolor=NAVY, lw=1.0,
                             ls="--" if kind == "planned" else "-"))
        ax.text(x + 0.4, yy, text, va="center", fontsize=8.6)


def diagram_a(out):
    fig, ax = plt.subplots(figsize=(11.2, 9.6))
    ax.set_xlim(0, 11.2); ax.set_ylim(0.8, 10.6); ax.axis("off")
    ax.add_patch(Rectangle((2.75, 2.25), 6.35, 8.15, fill=False, edgecolor=NAVY, lw=1.6))
    ax.text(5.92, 10.1, "MalTwin — Analysis and Reporting", ha="center", fontsize=11.5, weight="bold")
    L, R = 4.35, 7.55
    U = {
        "01": ((L, 9.4), "Upload Binary File\nUC-01", "normal"),
        "02": ((L, 8.4), "View File Analysis\nUC-02", "normal"),
        "03": ((L, 7.4), "Run Malware Detection\nUC-03", "normal"),
        "07": ((L, 6.2), "Analyse Network Capture\nUC-07", "addendum"),
        "08": ((L, 5.1), "View Hybrid Verdict\nUC-08", "addendum"),
        "06": ((L, 4.0), "Generate Forensic Report\nUC-06", "normal"),
        "09": ((L, 2.9), "View Dashboard and\nDetection History  UC-09", "normal"),
        "05": ((R, 8.6), "View Grad-CAM\nExplanation  UC-05", "normal"),
        "04": ((R, 6.2), "Map to MITRE\nATT&CK for ICS  UC-04", "normal"),
    }
    P = {k: v[0] for k, v in U.items()}
    an = actor(ax, 1.05, 6.4, "Security\nAnalyst")
    actor(ax, 1.05, 2.6, "Security\nResearcher")
    generalise(ax, (1.05, 3.32), (an[0], an[1] - 0.95))
    ev = actor(ax, 10.3, 3.25, "Academic\nEvaluator")
    for k in ["01", "02", "03", "07", "08", "06", "09"]:
        assoc(ax, an, P[k])
    for k in ["06", "09"]:
        assoc(ax, ev, P[k])
    for k, (c, label, kind) in U.items():
        usecase(ax, c, label, kind)
    dep(ax, P["05"], P["03"], "extend", lpos=(6.05, 8.15))
    dep(ax, P["03"], P["04"], "include", lpos=(6.05, 6.95))
    dep(ax, P["07"], P["04"], "include", lpos=(5.95, 6.2))
    dep(ax, P["06"], P["04"], "include")
    legend(ax, 3.2, 1.75, [("normal", "SRS use case"), ("addendum", "SRS addendum (Modules 9 and 10)")])
    fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


def diagram_b(out):
    fig, ax = plt.subplots(figsize=(11.2, 7.4))
    ax.set_xlim(0, 11.2); ax.set_ylim(0.0, 8.3); ax.axis("off")
    ax.add_patch(Rectangle((2.75, 1.2), 6.35, 6.95, fill=False, edgecolor=NAVY, lw=1.6))
    ax.text(5.92, 7.85, "MalTwin — Training, Evaluation and Simulation", ha="center", fontsize=11.5, weight="bold")
    L, R = 4.35, 7.55
    U = {
        "13": ((L, 6.15), "Run Digital Twin\nSimulation  UC-13", "planned"),
        "11": ((L, 4.35), "Train Detection\nModels  UC-11", "normal"),
        "12": ((L, 2.25), "Evaluate Detection\nModel  UC-12", "normal"),
        "14": ((R, 7.05), "Monitor Digital\nTwin  UC-14", "planned"),
        "15": ((R, 5.35), "Check Twin\nPrerequisites  UC-15", "normal"),
        "10": ((R, 3.45), "Prepare Training\nDataset  UC-10", "normal"),
    }
    P = {k: v[0] for k, v in U.items()}
    rs = actor(ax, 1.05, 4.2, "Security\nResearcher")
    ad = actor(ax, 10.3, 5.95, "System\nAdministrator")
    ev = actor(ax, 10.3, 1.9, "Academic\nEvaluator")
    for k in ["13", "11", "12"]:
        assoc(ax, rs, P[k])
    for k in ["13", "15"]:
        assoc(ax, ad, P[k])
    assoc(ax, ev, P["12"])
    for k, (c, label, kind) in U.items():
        usecase(ax, c, label, kind)
    dep(ax, P["14"], P["13"], "extend", lpos=(6.0, 6.75))
    dep(ax, P["11"], P["10"], "include", lpos=(6.0, 3.95))
    legend(ax, 3.2, 0.75, [("normal", "Implemented"), ("planned", "Planned (final evaluation)")])
    fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


if __name__ == "__main__":
    d = sys.argv[1]
    diagram_a(f"{d}/usecase_a.png")
    diagram_b(f"{d}/usecase_b.png")
