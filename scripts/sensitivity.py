"""Sensitivity analysis: do the headline results depend on our ground-truth and scoring choices?

Every variant is computed from the per-component match records written by score.py (results/matches/), so no tool
is re-run and the baseline reproduces results/metrics.csv exactly (checked at start-up). A variant changes only how
each GT component counts:
  keep        primary: in the recall denominator (the default)
  secondary   not in recall; a tool that lists it is still correct (precision unchanged)
  drop        out of scope: not in recall, and every tool component matched to it leaves the precision count too

Variants (main condition: default config, rep 1, CycloneDX; images = S3+P, source/artifact = S1+S2):
  baseline                     as reported
  lenient                      lenient matching classes count as found / correct
  crates-secondary             Rust crates known only from SBOMs embedded in wheels (PEP 770) -> secondary
  no-tarball-runtimes          language runtimes installed from tarballs (CPython, Temurin, Node) -> drop
  no-wheel-so                  native libraries vendored inside wheels (*.libs/*.so) -> drop
  no-go-stdlib                 Go standard library entries -> drop
  runtime-scope                source/artifact targets: dev / test / optional dependencies -> secondary
  combined                     all five GT variants above together
  without-ghost                the one image that dominates npm (X-ghost) left out
  macro                        baseline, but each target weighs the same: mean of per-target recall / precision
                               (micro-averages are dominated by the largest images)
Plus leave-one-image-out: the tool ranking by micro strict recall with each image left out in turn.

Outputs: results/tables/sensitivity.csv, sensitivity_loo.csv
Usage:   python scripts/sensitivity.py
"""
from __future__ import annotations

import json
from collections import Counter

import pandas as pd

from common import RESULTS_DIR, ROOT, load_catalog, log
from score import LENIENT, MATCH_DIR, STRICT

T = RESULTS_DIR / "tables"
TOOLS = ["syft", "trivy", "cdxgen"]
IMAGE_STAGES = {"S3", "P"}


def rule_crates(c, t):
    return "secondary" if c["mechanism"] == "wheel-embedded-sbom" else "keep"


def rule_runtimes(c, t):
    return "drop" if c["mechanism"] == "runtime-outside-pm" else "keep"


def rule_wheel_so(c, t):
    return "drop" if c["mechanism"] == "wheel-vendored-so" else "keep"


def rule_go_stdlib(c, t):
    return "drop" if c["eco"] == "golang" and c["name"] == "stdlib" else "keep"


def rule_scope(c, t):
    return "secondary" if t["stage"] not in IMAGE_STAGES and c.get("scope") in ("dev", "test", "optional") else "keep"


def combined(c, t):
    order = {"drop": 2, "secondary": 1, "keep": 0}
    return max((r(c, t) for r in (rule_crates, rule_runtimes, rule_wheel_so, rule_go_stdlib, rule_scope)), key=order.get)


VARIANTS = {   # name -> (GT rule, classes that count as found, targets left out)
    "baseline": (None, STRICT, set()),
    "lenient": (None, LENIENT, set()),
    "crates-secondary": (rule_crates, STRICT, set()),
    "no-tarball-runtimes": (rule_runtimes, STRICT, set()),
    "no-wheel-so": (rule_wheel_so, STRICT, set()),
    "no-go-stdlib": (rule_go_stdlib, STRICT, set()),
    "runtime-scope": (rule_scope, STRICT, set()),
    "combined": (combined, STRICT, set()),
    "without-ghost": (None, STRICT, {"X-ghost"}),
}
ORDER = list(VARIANTS) + ["macro"]


def counts(detail: dict, gt: dict, target: dict, rule, found: set) -> dict:
    """tp_gt / gt_primary / tp_tool / tool_identities for one SBOM under one variant (layer 'all')."""
    status = [("keep" if c["tier"] == "primary" else "secondary") if rule is None else
              (rule(c, target) if c["tier"] == "primary" else "secondary") for c in gt["components"]]
    gt_primary = [i for i, s in enumerate(status) if s == "keep"]
    tp_gt = sum(1 for i in gt_primary if set(detail["gt"][i]["matched_by"]) & found)
    tools = [r for r in detail["tool_components"] if r["gt_index"] is None or status[r["gt_index"]] != "drop"]
    tp_tool = sum(1 for r in tools if r["class"] in found)
    return {"tp_gt": tp_gt, "n_gt": len(gt_primary), "tp_tool": tp_tool, "n_tool": len(tools)}


def main() -> int:
    targets = {t["id"]: t for t in load_catalog()["targets"]}
    gts = {tid: json.loads((ROOT / "ground_truth" / f"{tid}.json").read_text(encoding="utf-8")) for tid in targets}
    # exactly the SBOMs of the main condition in metrics.csv (results/matches/ may hold older files too)
    m = pd.read_csv(RESULTS_DIR / "metrics.csv")
    m = m[(m.config == "default") & (m.rep == 1) & (m.format == "cyclonedx") & (m.layer == "all")]
    details = {(r.tool, r.target): json.loads((MATCH_DIR / f"default-{r.tool}-rep1-cyclonedx-{r.target}.json")
                                              .read_text(encoding="utf-8")) for r in m.itertuples()}

    # the baseline must reproduce score.py's own numbers exactly
    for r in m.itertuples():
        c = counts(details[(r.tool, r.target)], gts[r.target], targets[r.target], None, STRICT)
        if (c["tp_gt"], c["n_gt"], c["tp_tool"], c["n_tool"]) != (r.tp_gt_strict, r.gt_primary, r.tp_tool_strict, r.tool_identities):
            raise SystemExit(f"baseline mismatch {r.tool} {r.target}: {c} vs metrics.csv")
    log(f"baseline reproduces metrics.csv on all {len(m)} SBOMs")

    per = []   # one row per (variant, tool, target)
    for name, (rule, found, left_out) in VARIANTS.items():
        for (tool, tid), d in details.items():
            if tid in left_out:
                continue
            per.append({"variant": name, "tool": tool, "target": tid,
                        "group": "images" if targets[tid]["stage"] in IMAGE_STAGES else "source+artifact",
                        **counts(d, gts[tid], targets[tid], rule, found)})
    p = pd.DataFrame(per)
    agg = p.groupby(["variant", "group", "tool"]).agg(targets=("target", "nunique"), gt_components=("n_gt", "sum"),
                                                      tp_gt=("tp_gt", "sum"), tool_ids=("n_tool", "sum"),
                                                      tp_tool=("tp_tool", "sum")).reset_index()
    agg["recall"] = agg.tp_gt / agg.gt_components
    agg["precision"] = agg.tp_tool / agg.tool_ids
    b = p[p.variant == "baseline"].copy()
    b["r"] = b.tp_gt / b.n_gt.where(b.n_gt > 0)          # targets with no primary GT have no recall
    b["pr"] = b.tp_tool / b.n_tool.where(b.n_tool > 0)    # SBOMs with no components have no precision
    macro = b.groupby(["group", "tool"]).agg(targets=("target", "nunique"), recall=("r", "mean"),
                                             precision=("pr", "mean")).reset_index()
    macro["variant"] = "macro"
    agg = pd.concat([agg, macro], ignore_index=True)
    agg["rank_recall"] = agg.groupby(["variant", "group"]).recall.rank(ascending=False, method="min").astype(int)
    base = agg[agg.variant == "baseline"].set_index(["group", "tool"])
    agg["d_recall"] = agg.apply(lambda r: r.recall - base.loc[(r.group, r.tool), "recall"], axis=1)
    agg["d_precision"] = agg.apply(lambda r: r.precision - base.loc[(r.group, r.tool), "precision"], axis=1)
    order = {v: i for i, v in enumerate(ORDER)}
    agg = agg.sort_values(["group", "variant", "tool"], key=lambda s: s.map(order) if s.name == "variant" else s)
    T.mkdir(parents=True, exist_ok=True)
    agg.to_csv(T / "sensitivity.csv", index=False)

    # leave-one-image-out: is the tool ranking (micro strict recall on images) driven by any single image?
    img = p[(p.variant == "baseline") & (p.group == "images")]
    loo = []
    for out in sorted(img.target.unique()):
        s = img[img.target != out].groupby("tool")[["tp_gt", "n_gt"]].sum()
        rec = (s.tp_gt / s.n_gt).reindex(TOOLS)
        loo.append({"left_out": out, **{t: rec[t] for t in TOOLS},
                    "ranking": " > ".join(rec.sort_values(ascending=False).index)})
    loo = pd.DataFrame(loo)
    loo.to_csv(T / "sensitivity_loo.csv", index=False)

    wide = agg.pivot_table(index=["group", "variant"], columns="tool", values="recall").reindex(columns=TOOLS)
    log("== recall (micro, strict unless 'lenient') ==\n" + wide.round(3).to_string())
    log("== leave-one-image-out rankings ==\n" + str(Counter(loo.ranking).most_common()))
    changers = loo[loo.ranking != Counter(loo.ranking).most_common(1)[0][0]]
    if len(changers):
        log("images whose removal changes the ranking: " + ", ".join(changers.left_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
