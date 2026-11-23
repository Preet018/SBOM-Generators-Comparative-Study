"""Paper figures (PDF for LaTeX + PNG preview) from results/tables/*.csv.

Palette: validated categorical slots 1-3 (blue/orange/aqua, all-pairs CVD-safe, dataviz validator run 23 Nov).
Aqua is below 3:1 contrast on white, so identity never relies on colour alone: every tool also has its own
marker shape and a legend, and heatmap cells carry their value as text.
"""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

from common import ROOT, RESULTS_DIR, log  # noqa: E402

T = RESULTS_DIR / "tables"
OUT = ROOT / "paper" / "figures"
TOOLS = ["syft", "trivy", "cdxgen"]
LABEL = {"syft": "Syft", "trivy": "Trivy", "cdxgen": "cdxgen"}
COLOR = {"syft": "#2a78d6", "trivy": "#eb6834", "cdxgen": "#1baf7a"}
MARKER = {"syft": "o", "trivy": "s", "cdxgen": "^"}
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
SEQ = LinearSegmentedColormap.from_list("blue_seq", ["#cde2fb", "#86b6ef", "#3987e5", "#256abf", "#184f95", "#0d366b"])
WIDTH = 5.4  # inches, Springer sn-jnl text width


def style():
    plt.rcParams.update({"font.size": 8, "axes.edgecolor": GRID, "axes.linewidth": 0.8, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2, "xtick.major.size": 0, "ytick.major.size": 0,
                         "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
                         "pdf.fonttype": 42, "font.family": "DejaVu Sans"})


def legend_top(fig, y=1.0):
    handles = [plt.Line2D([], [], color=COLOR[t], marker=MARKER[t], linestyle="", markersize=6,
                          markeredgecolor=SURFACE, markeredgewidth=1.0, label=LABEL[t]) for t in TOOLS]
    fig.legend(handles=handles, loc="upper center", ncol=3, bbox_to_anchor=(0.5, y), handletextpad=0.3, columnspacing=1.5)


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(OUT / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    log(f"wrote paper/figures/{name}.pdf/.png")


# ----------------------------------------------------------------------------- Fig. RQ1: recall & precision by layer
LAYER_NAME = {"os": "OS packages", "java": "Java (Maven)", "npm": "npm", "python": "Python (PyPI)",
              "go": "Go modules", "native": "Native / vendored"}


def fig_rq1():
    overall = pd.read_csv(T / "rq1_overall_images.csv").set_index("tool")
    by_layer = pd.read_csv(T / "rq1_by_layer_images.csv")
    rows = ["all"] + [l for l in ["os", "java", "npm", "python", "go", "native"] if l in set(by_layer.layer)]
    n_of = {l: int(by_layer[by_layer.layer == l].gt_components.iloc[0]) for l in rows if l != "all"}
    n_of["all"] = int(overall.gt_components.iloc[0])
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH, 2.6), sharey=True)
    for ax, metric, title in zip(axes, ["recall_strict", "precision_strict"], ["Recall (strict)", "Precision (strict)"]):
        for i, layer in enumerate(rows):
            for j, tool in enumerate(TOOLS):
                if layer == "all":
                    v = overall.loc[tool, metric]
                else:
                    v = by_layer[(by_layer.layer == layer) & (by_layer.tool == tool)][metric].iloc[0]
                if pd.isna(v):
                    continue
                ax.plot(v, i + (j - 1) * 0.22, marker=MARKER[tool], color=COLOR[tool], markersize=6,
                        markeredgecolor=SURFACE, markeredgewidth=1.0, linestyle="")
        ax.set_xlim(-0.03, 1.03)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.xaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
        ax.set_title(title, fontsize=8.5, color=INK, loc="left")
        for i in range(len(rows) - 1):
            ax.axhline(i + 0.5, color=GRID, linewidth=0.5)
    axes[0].set_yticks(range(len(rows)))
    axes[0].set_yticklabels([("All components" if l == "all" else LAYER_NAME[l]) + f"\n(n={n_of[l]})" for l in rows])
    axes[0].invert_yaxis()
    legend_top(fig, 1.06)
    fig.tight_layout()
    save(fig, "fig_rq1_layers")


# ----------------------------------------------------------------------------- Fig. RQ2: same app across stages
STAGE_LABEL = {
    "J-S1": "S1 pom.xml", "J-S2": "S2 fat JAR", "J-S3-ubuntu": "S3 Ubuntu", "J-S3-alpine": "S3 Alpine",
    "J-S3-distroless": "S3 distroless", "J-S3-layered": "S3 layered", "J-P": "P planted",
    "N-S1": "S1 lockfile", "N-S1-nolock": "S1 no lockfile", "N-S2": "S2 bundle", "N-S3-node": "S3 node",
    "N-S3-nginx": "S3 nginx",
    "P-S1": "S1 unpinned", "P-S1-pinned": "S1 pinned", "P-S3-pred": "S3 predict", "P-S3-drift": "S3 drift",
    "P-S3-front": "S3 frontend", "P-S3-ml": "S3 ml", "P-S3-distroless": "S3 distroless", "P-P": "P planted"}
SUBJECT_TITLE = {"bakery-backend": "Bakery backend, Java dependencies",
                 "bakery-frontend": "Bakery frontend, npm dependencies",
                 "log-anomaly": "Log Anomaly, Python dependencies"}


def fig_rq2():
    d = pd.read_csv(T / "rq2_app_layer_by_stage.csv")
    fig, axes = plt.subplots(3, 1, figsize=(WIDTH, 5.6))
    for ax, subj in zip(axes, SUBJECT_TITLE):
        s = d[d.subject == subj]
        order = [t for t in STAGE_LABEL if t in set(s.target)]
        x = np.arange(len(order))
        for j, tool in enumerate(TOOLS):
            st = s[s.tool == tool].set_index("target").reindex(order)
            ax.plot(x + (j - 1) * 0.12, st.recall_strict, color=COLOR[tool], linewidth=1.2, alpha=0.55)
            ax.plot(x + (j - 1) * 0.12, st.recall_strict, marker=MARKER[tool], color=COLOR[tool], linestyle="",
                    markersize=5.5, markeredgecolor=SURFACE, markeredgewidth=1.0)
        n = int(s["gt"].max())   # s.gt would be DataFrame.gt(), the comparison method
        ax.set_title(f"{SUBJECT_TITLE[subj]} (up to n={n})", fontsize=8.5, color=INK, loc="left")
        ax.set_xticks(x)
        ax.set_xticklabels([STAGE_LABEL[t] for t in order], fontsize=7)
        ax.set_ylim(-0.05, 1.08)
        ax.set_yticks([0, 0.5, 1.0])
        ax.set_ylabel("Recall (strict)")
        ax.yaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
    legend_top(fig, 1.02)
    fig.tight_layout()
    save(fig, "fig_rq2_lifecycle")


# ----------------------------------------------------------------------------- Fig. RQ3: recall by inclusion mechanism
MECH_NAME = {"os-pm": "OS package manager", "nested-jar": "Nested JAR (fat JAR)", "wheel-embedded-sbom": "Wheel-embedded SBOM",
             "lang-pm": "Language package manager", "runtime-bundled": "Bundled with runtime (npm)",
             "layered-jar": "Layered/exploded JAR", "go-module-in-binary": "Go module in binary",
             "wheel-vendored-so": "Wheel-vendored .so", "runtime-outside-pm": "Runtime from tarball",
             "bundled-js": "Bundled JavaScript", "manual-download": "Manually downloaded binary",
             "static-link": "Statically linked C library", "vendored-source": "Vendored source copy",
             "manual-copy": "Manually copied JAR", "manual-install": "Manually unpacked npm pkg",
             "shaded": "Shaded JAR", "shaded-relocated": "Shaded + relocated JAR"}


def fig_rq3():
    d = pd.read_csv(T / "rq3_recall_by_mechanism_images.csv").set_index("mechanism")
    d = d.sort_values("gt_components", ascending=False)
    vals = d[TOOLS].to_numpy(dtype=float)
    fig, ax = plt.subplots(figsize=(WIDTH * 0.72, 0.24 * len(d) + 0.8))
    ax.imshow(vals, cmap=SEQ, vmin=0, vmax=1, aspect="auto")
    for i in range(vals.shape[0]):
        for j in range(vals.shape[1]):
            v = vals[i, j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7, color="#ffffff" if v > 0.55 else INK)
    ax.set_xticks(range(3))
    ax.set_xticklabels([LABEL[t] for t in TOOLS])
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(d)))
    ax.set_yticklabels([f"{MECH_NAME.get(m, m)} (n={int(n)})" for m, n in zip(d.index, d.gt_components)])
    ax.set_xticks(np.arange(-0.5, 3), minor=True)
    ax.set_yticks(np.arange(-0.5, len(d)), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)   # 2px surface gap between cells
    ax.tick_params(which="minor", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    fig.tight_layout()
    save(fig, "fig_rq3_mechanisms")


def main() -> int:
    style()
    fig_rq1()
    fig_rq2()
    fig_rq3()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
