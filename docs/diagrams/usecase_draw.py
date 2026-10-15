"""Hand-laid UML use case diagrams (standard notation: stick-figure actors,
ellipse use cases, system boundary, solid associations, dashed <<include>>/<<extend>>)."""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, Rectangle, FancyArrowPatch

NAVY, FILL, ADD = "#1F3864", "#EEF2F8", "#FFF7E6"
EW, EH = 2.55, 0.62   # ellipse size (inches in data units)


def actor(ax, x, y, name):
    s = 0.22
    ax.add_patch(plt.Circle((x, y + 0.55), s * 0.55, fill=False, lw=1.6, color=NAVY))
    ax.plot([x, x], [y + 0.43, y + 0.05], color=NAVY, lw=1.6)
    ax.plot([x - 0.25, x + 0.25], [y + 0.32, y + 0.32], color=NAVY, lw=1.6)
    ax.plot([x, x - 0.2], [y + 0.05, y - 0.25], color=NAVY, lw=1.6)
    ax.plot([x, x + 0.2], [y + 0.05, y - 0.25], color=NAVY, lw=1.6)
    ax.text(x, y - 0.38, name, ha="center", va="top", fontsize=10.5)
    return (x, y + 0.2)


def usecase(ax, x, y, label, addendum=False):
    ax.add_patch(Ellipse((x, y), EW, EH, facecolor=ADD if addendum else FILL, edgecolor=NAVY, lw=1.4))
    ax.text(x, y, label, ha="center", va="center", fontsize=9.6)


def edge_point(c, toward, w=EW, h=EH):
    """Point on an ellipse boundary in the direction of `toward`."""
    import math
    dx, dy = toward[0] - c[0], toward[1] - c[1]
    if dx == dy == 0:
        return c
    a, b = w / 2, h / 2
    t = 1 / math.sqrt((dx / a) ** 2 + (dy / b) ** 2)
    return (c[0] + dx * t, c[1] + dy * t)


def assoc(ax, actor_pt, uc):
    p = edge_point(uc, actor_pt)
    ax.plot([actor_pt[0], p[0]], [actor_pt[1], p[1]], color="#333333", lw=1.0)


def dashed(ax, src, dst, label, via=None, label_at=None):
    pts = [src] + (via or []) + [dst]
    start = edge_point(src, pts[1])
    end = edge_point(dst, pts[-2])
    path = [start] + (via or []) + [end]
    for a, b in zip(path[:-2], path[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color="#333333", lw=1.0, ls=(0, (5, 4)))
    ax.add_patch(FancyArrowPatch(path[-2], path[-1], arrowstyle="->,head_length=6,head_width=4",
                                 linestyle=(0, (5, 4)), color="#333333", lw=1.0, mutation_scale=1.5))
    lx, ly = label_at or ((path[0][0] + path[-1][0]) / 2, (path[0][1] + path[-1][1]) / 2)
    ax.text(lx, ly, f"«{label}»", fontsize=8.5, ha="center", va="center",
            bbox=dict(facecolor="white", edgecolor="none", pad=0.6))


def tip(pos, side):
    x, y = pos
    return (x - EW / 2, y) if side == "L" else (x + EW / 2, y)


def assoc_tip(ax, actor_pt, uc, side):
    p = tip(uc, side)
    ax.plot([actor_pt[0], p[0]], [actor_pt[1], p[1]], color="#333333", lw=1.0, zorder=1)


def vdashed(ax, src, dst, label):
    """Dashed dependency arrow between vertically adjacent use cases (src -> dst)."""
    down = dst[1] < src[1]
    sy = src[1] - EH / 2 if down else src[1] + EH / 2
    dy = dst[1] + EH / 2 if down else dst[1] - EH / 2
    ax.add_patch(FancyArrowPatch((src[0], sy), (dst[0], dy), arrowstyle="->,head_length=7,head_width=4.5",
                                 linestyle=(0, (4, 3)), color="#333333", lw=1.0, shrinkA=1, shrinkB=1))
    ax.text(src[0] + 0.12, (sy + dy) / 2, f"«{label}»", fontsize=8.5, ha="left", va="center")


def diagram_a(out):
    fig, ax = plt.subplots(figsize=(11, 13.4))
    ax.set_xlim(0, 11); ax.set_ylim(-0.1, 13.2); ax.axis("off")
    ax.add_patch(Rectangle((2.9, 0.15), 5.2, 12.85, fill=False, edgecolor=NAVY, lw=1.6))
    ax.text(5.5, 12.7, "MalTwin System — analysis and reporting", ha="center", fontsize=11.5, weight="bold")
    C, step = 5.5, 1.0
    order = [
        ("upload", "Upload Binary File\n(UC-01)"),
        ("convert", "Convert Binary to\nGrayscale Image"),
        ("meta", "View File Metadata"),
        ("xai", "View XAI Heatmap"),
        ("run", "Run Malware Detection\n(UC-02)"),
        ("hybrid", "Compute Hybrid Verdict\n(UC-07, addendum)"),
        ("capture", "Analyse Network Capture\n(UC-06, addendum)"),
        ("pred", "View Prediction &\nConfidence Score"),
        ("download", "Download Report\n(PDF/JSON)"),
        ("report", "Generate Forensic Report\n(UC-03)"),
        ("mitre", "Map to MITRE\nATT&CK for ICS"),
        ("log", "Log Detection Events"),
    ]
    pos = {}
    for i, (k, label) in enumerate(order):
        pos[k] = (C, 12.1 - i * step)
    sa = actor(ax, 0.9, 6.1, "Security\nAnalyst")
    sr = actor(ax, 10.1, 7.6, "Security\nResearcher")
    ae = actor(ax, 10.1, 3.0, "Academic\nEvaluator")
    for k in ["upload", "meta", "xai", "run", "hybrid", "capture", "pred", "download", "report"]:
        assoc_tip(ax, sa, pos[k], "L")
    for k in ["upload", "meta", "xai", "run", "hybrid", "capture", "pred", "report"]:
        assoc_tip(ax, sr, pos[k], "R")
    for k in ["pred", "download"]:
        assoc_tip(ax, ae, pos[k], "R")
    for i, (k, label) in enumerate(order):
        usecase(ax, *pos[k], label, addendum=k in ("capture", "hybrid"))
    vdashed(ax, pos["upload"], pos["convert"], "include")
    vdashed(ax, pos["xai"], pos["run"], "extend")
    vdashed(ax, pos["hybrid"], pos["run"], "include")
    vdashed(ax, pos["hybrid"], pos["capture"], "include")
    vdashed(ax, pos["download"], pos["report"], "extend")
    vdashed(ax, pos["report"], pos["mitre"], "include")
    # report -> log: route around MITRE on the right
    r, l = pos["report"], pos["log"]
    xr = C + EW / 2 + 0.35
    a0 = (C + EW * 0.36, r[1] - EH * 0.35)
    ax.plot([a0[0], xr, xr], [a0[1], a0[1] - 0.25, l[1]], color="#333333", lw=1.0, ls=(0, (4, 3)))
    ax.add_patch(FancyArrowPatch((xr, l[1]), (C + EW / 2, l[1]), arrowstyle="->,head_length=6,head_width=4",
                                 linestyle=(0, (4, 3)), color="#333333", lw=1.0, mutation_scale=1.5))
    ax.text(xr + 0.08, (r[1] + l[1]) / 2 - 0.2, "«include»", fontsize=8.5, ha="left", va="center")
    fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


def diagram_b(out):
    fig, ax = plt.subplots(figsize=(11.5, 5.6))
    ax.set_xlim(0, 11.5); ax.set_ylim(0, 5.6); ax.axis("off")
    ax.add_patch(Rectangle((1.9, 0.2), 8.0, 5.1, fill=False, edgecolor=NAVY, lw=1.6))
    ax.text(5.9, 5.05, "MalTwin System — simulation and training", ha="center", fontsize=11.5, weight="bold")
    C, R = 4.0, 7.75
    U = {
        "sim": (C, 4.35, "Simulate IIoT Environment\n(UC-04)"),
        "mon": (C, 3.4, "Monitor Digital\nTwin Status"),
        "infra": (R, 2.45, "Manage Container\nInfrastructure"),
        "train": (C, 2.0, "Train Detection Model\n(UC-05)"),
        "enh": (C, 0.85, "Apply Data\nEnhancement"),
        "metrics": (R, 1.05, "View Model\nEvaluation Metrics"),
    }
    for k, (x, y, l) in U.items():
        usecase(ax, x, y, l)
    pos = {k: (v[0], v[1]) for k, v in U.items()}
    sr = actor(ax, 0.85, 2.8, "Security\nResearcher")
    ad = actor(ax, 10.75, 3.3, "System\nAdministrator")
    ae = actor(ax, 10.75, 0.75, "Academic\nEvaluator")
    for k in ["sim", "mon", "train"]:
        assoc_tip(ax, sr, pos[k], "L")
    for k in ["sim", "mon", "infra"]:
        assoc_tip(ax, ad, pos[k], "R")
    assoc_tip(ax, ae, pos["metrics"], "R")
    vdashed(ax, pos["train"], pos["enh"], "include")
    dashed(ax, pos["metrics"], pos["train"], "extend")
    fig.savefig(out, dpi=200, bbox_inches="tight"); plt.close(fig)


if __name__ == "__main__":
    d = sys.argv[1]
    diagram_a(f"{d}/usecase_a.png")
    diagram_b(f"{d}/usecase_b.png")
