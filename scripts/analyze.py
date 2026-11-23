"""Aggregate the scored results into the tables used in the paper (RQ1-RQ4 + network + determinism).

Inputs: results/metrics.csv, results/misses.csv, results/tool_runs.json, results/sbom_inventory.json,
        ground_truth/*.json, the SBOMs themselves (for RQ4 field checks).
Outputs: results/tables/*.csv  (one file per table, plain numbers; figures.py renders them)

Aggregation: micro-average = sum of matched GT components / sum of GT components over the targets in a group
(every component counts once per target). Main condition: config "default", rep 1, CycloneDX.
"""
from __future__ import annotations

import json
from collections import defaultdict

import pandas as pd
from scipy.stats import friedmanchisquare

from common import RESULTS_DIR, ROOT, load_catalog, log
from normalize import load_sbom
from score import GTIndex, STRICT, vnorm

T = RESULTS_DIR / "tables"
TOOLS = ["syft", "trivy", "cdxgen"]
IMAGE_STAGES = {"S3", "P"}


def main_slice(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df.config == "default") & (df.rep == 1) & (df.format == "cyclonedx")]


def micro(g: pd.DataFrame) -> pd.Series:
    gt, tool = g.gt_primary.sum(), g.tool_identities.sum()
    return pd.Series({
        "targets": g.target.nunique(), "gt_components": int(gt), "tool_components": int(tool),
        "recall_strict": g.tp_gt_strict.sum() / gt if gt else None,
        "recall_lenient": g.tp_gt_lenient.sum() / gt if gt else None,
        "precision_strict": g.tp_tool_strict.sum() / tool if tool else None,
        "precision_lenient": g.tp_tool_lenient.sum() / tool if tool else None})


# ----------------------------------------------------------------------------- RQ1
def rq1(m: pd.DataFrame):
    img = m[m.stage.isin(IMAGE_STAGES)]
    overall = img[img.layer == "all"].groupby("tool").apply(micro, include_groups=False).reindex(TOOLS)
    by_layer = img[img.layer != "all"].groupby(["layer", "tool"]).apply(micro, include_groups=False)
    per_target = m[m.layer == "all"].pivot_table(index=["subject", "stage", "target"], columns="tool",
                                                 values=["recall_strict", "precision_strict"]).reindex(columns=TOOLS, level=1)
    overall.to_csv(T / "rq1_overall_images.csv")
    by_layer.to_csv(T / "rq1_by_layer_images.csv")
    per_target.to_csv(T / "rq1_per_target.csv")
    # Friedman test: do the three tools differ in per-target strict recall on images?
    wide = img[img.layer == "all"].pivot_table(index="target", columns="tool", values="recall_strict").dropna()
    stat, p = friedmanchisquare(*(wide[t] for t in TOOLS))
    pd.DataFrame([{"test": "Friedman (per-image strict recall)", "n_targets": len(wide), "chi2": stat, "p": p}]) \
        .to_csv(T / "rq1_friedman.csv", index=False)
    return overall, by_layer


def component_tests(ms: pd.DataFrame, gts: dict, img_targets: set):
    """Paired tests at the right unit: each PRIMARY GT component of each image is found (1) or missed (0) by
    each tool. Cochran's Q across the three tools, then pairwise exact McNemar tests (Holm-corrected)."""
    from itertools import combinations
    from scipy.stats import binomtest, chi2
    # versionless components are NaN in the CSV but None in the GT JSON: normalise both to "" before comparing
    vkey = lambda v: "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)   # noqa: E731
    missed = {(r.tool, r.target, r.key, vkey(r.version)) for r in ms.itertuples()}
    rows = []
    for tid in sorted(img_targets):
        for c in gts[tid]["components"]:
            if c["tier"] == "primary":
                rows.append([0 if (t, tid, c["key"], vkey(c["version"])) in missed else 1 for t in TOOLS])
    x = pd.DataFrame(rows, columns=TOOLS)
    k, cols, rs = 3, x.sum(axis=0), x.sum(axis=1)
    n_total = cols.sum()
    q = (k - 1) * (k * (cols ** 2).sum() - n_total ** 2) / (k * n_total - (rs ** 2).sum())
    out = [{"test": "Cochran's Q (component found by tool)", "n_components": len(x), "statistic": q,
            "p": chi2.sf(q, k - 1), "detail": "; ".join(f"{t}={cols[t] / len(x):.3f}" for t in TOOLS)}]
    pairs = []
    for a, b in combinations(TOOLS, 2):
        only_a, only_b = int(((x[a] == 1) & (x[b] == 0)).sum()), int(((x[a] == 0) & (x[b] == 1)).sum())
        p = binomtest(only_a, only_a + only_b, 0.5).pvalue if only_a + only_b else 1.0
        pairs.append({"test": f"McNemar exact {a} vs {b}", "n_components": len(x), "statistic": None, "p": p,
                      "detail": f"only {a}={only_a}, only {b}={only_b}"})
    for rank, pr in enumerate(sorted(pairs, key=lambda r: r["p"])):   # Holm step-down correction
        pr["p_holm"] = min(1.0, pr["p"] * (len(pairs) - rank))
    df = pd.DataFrame(out + pairs)
    df.to_csv(T / "rq1_component_tests.csv", index=False)
    return df


# ----------------------------------------------------------------------------- RQ2
STAGE_ORDER = {"S1": 0, "S2": 1, "S3": 2, "P": 3}


def rq2(m: pd.DataFrame):
    a = m[m.layer == "all"].copy()
    a["stage_order"] = a.stage.map(STAGE_ORDER)
    tab = a.pivot_table(index=["subject", "stage_order", "stage", "target"], columns="tool",
                        values="recall_strict").reindex(columns=TOOLS).sort_index()
    tab.to_csv(T / "rq2_lifecycle.csv")
    # same application, application-layer only: how many of the app's OWN dependencies are found per stage
    app_layer = {"bakery-backend": "java", "bakery-frontend": "npm", "log-anomaly": "python"}
    rows = []
    for subj, lyr in app_layer.items():
        s = m[(m.subject == subj) & (m.layer == lyr)]
        for (target, stage, tool), g in s.groupby(["target", "stage", "tool"]):
            rows.append({"subject": subj, "layer": lyr, "target": target, "stage": stage, "tool": tool,
                         "gt": int(g.gt_primary.sum()), "recall_strict": g.recall_strict.iloc[0],
                         "recall_lenient": g.recall_lenient.iloc[0], "precision_strict": g.precision_strict.iloc[0]})
    pd.DataFrame(rows).to_csv(T / "rq2_app_layer_by_stage.csv", index=False)
    return tab


# ----------------------------------------------------------------------------- RQ3
def rq3(ms: pd.DataFrame, gts: dict, targets: dict, suffix: str = ""):
    """Recall per inclusion mechanism: GT primary components by mechanism vs strict misses.
    Called once for images (S3+P) and once for source/artifact targets (S1+S2), never pooled."""
    gt_counts = defaultdict(int)
    for tid, g in gts.items():
        for c in g["components"]:
            if c["tier"] == "primary":
                for mech in c.get("mechanisms") or [c["mechanism"]]:
                    gt_counts[(tid, mech)] += 1
    rows = []
    for tool in TOOLS:
        mt = ms[ms.tool == tool]
        miss_counts = defaultdict(int)
        for _, r in mt.iterrows():
            for mech in str(r.mechanisms).split("|"):
                miss_counts[(r.target, mech)] += 1
        agg = defaultdict(lambda: [0, 0, set()])
        for (tid, mech), n in gt_counts.items():
            if tid not in targets:
                continue
            agg[mech][0] += n
            agg[mech][1] += miss_counts.get((tid, mech), 0)
            agg[mech][2].add(tid)
        for mech, (n, missed, tids) in agg.items():
            rows.append({"mechanism": mech, "tool": tool, "gt_components": n, "found_strict": n - missed,
                         "recall_strict": (n - missed) / n if n else None, "targets": len(tids)})
    df = pd.DataFrame(rows)
    df.pivot_table(index="mechanism", columns="tool", values="recall_strict").reindex(columns=TOOLS) \
        .join(df.groupby("mechanism").gt_components.first()).sort_values("gt_components", ascending=False) \
        .to_csv(T / f"rq3_recall_by_mechanism{suffix}.csv")
    df.to_csv(T / f"rq3_recall_by_mechanism{suffix}_long.csv", index=False)
    # planted hard cases: found or not, per tool
    planted = []
    for tid, g in gts.items():
        for c in g["components"]:
            if c.get("planted"):
                for tool in TOOLS:
                    missed = not ms[(ms.tool == tool) & (ms.target == tid) & (ms.key == c["key"])].empty
                    lenient = ms[(ms.tool == tool) & (ms.target == tid) & (ms.key == c["key"])].lenient_match
                    planted.append({"target": tid, "component": f"{c['name']}@{c['version']}", "mechanism": c["mechanism"],
                                    "tool": tool, "found_strict": not missed,
                                    "lenient": None if not missed else lenient.iloc[0]})
    if planted:   # planted components exist only in image targets
        pd.DataFrame(planted).pivot_table(index=["target", "component", "mechanism"], columns="tool",
                                          values="found_strict", aggfunc="first").reindex(columns=TOOLS) \
            .to_csv(T / f"rq3_planted{suffix}.csv")
    return df


# ----------------------------------------------------------------------------- RQ4
def norm_lic(s: str | None) -> set:
    if not s:
        return set()
    s = s.replace("(", " ").replace(")", " ")
    return {t.strip().lower() for t in s.replace(" AND ", " OR ").replace(" and ", " OR ").split(" OR ") if t.strip()}


def rq4(runs: list, gts: dict, targets: dict):
    """Field correctness on strictly matched components (primary GT) + NTIA/CISA element presence per SBOM."""
    rows, docs = [], []
    for r in runs:
        if r["config"] != "default" or r["rep"] != 1 or r["status"] != "ok" or r["target"] not in targets:
            continue
        out = (r.get("outputs") or {}).get("cyclonedx")
        if not out or not (ROOT / out["path"]).exists():
            continue
        raw = json.loads((ROOT / out["path"]).read_text(encoding="utf-8"))
        meta = raw.get("metadata") or {}
        docs.append({"tool": r["tool"], "target": r["target"],
                     "timestamp": bool(meta.get("timestamp")),
                     "tool_name": bool(meta.get("tools")),
                     "author": bool(meta.get("authors") or meta.get("author")),
                     "supplier_doc": bool(meta.get("supplier") or meta.get("manufacturer")),
                     "dependency_graph": bool(raw.get("dependencies")) and any(d.get("dependsOn") for d in raw["dependencies"]),
                     "lifecycle_phase": bool(meta.get("lifecycles"))})
        sbom = load_sbom(ROOT / out["path"])
        idx = GTIndex(gts[r["target"]])
        raw_by_purl = {c.get("purl"): c for c in iter_cdx(raw.get("components"))}
        for c in sbom["components"]:
            cls, gi = idx.match(c)
            if cls not in STRICT or gi is None or idx.comps[gi]["tier"] != "primary":
                continue
            g = idx.comps[gi]
            rc = raw_by_purl.get(c["purl"], {})
            gl, tl = norm_lic(g.get("license")), set().union(*(norm_lic(x) for x in c["licenses"])) if c["licenses"] else set()
            # GT hashes: {"sha1": .., "sha256": ..} (JAR files). Tool hashes normalised to {"SHA1": .., "SHA256": ..}.
            gh, th = g.get("hashes") or {}, c.get("hashes") or {}
            comparable = [a for a in ("sha1", "sha256") if a in gh and a.upper() in th]
            hash_correct = all(th[a.upper()] == gh[a] for a in comparable) if comparable else None
            rows.append({"tool": r["tool"], "target": r["target"], "eco": g["eco"], "mechanism": g["mechanism"],
                         "purl_present": bool(c["purl"]), "purl_type_correct": c["eco"] == g["eco"],
                         "license_present": bool(c["licenses"]), "gt_license_known": bool(gl),
                         "license_overlap": bool(gl & tl) if gl and tl else None,
                         "hash_present": bool(th), "gt_hash_known": bool(gh), "hash_correct": hash_correct,
                         "hash_algs": ",".join(sorted(th)),
                         "cpe_present": bool(c["cpes"]), "supplier_present": bool(rc.get("supplier") or rc.get("publisher") or rc.get("author"))})
    comp = pd.DataFrame(rows)
    agg = comp.groupby("tool").agg(
        matched=("eco", "size"), purl_present=("purl_present", "mean"), purl_type_correct=("purl_type_correct", "mean"),
        license_present=("license_present", "mean"),
        license_correct_when_both_known=("license_overlap", lambda s: s.dropna().mean()),
        license_comparisons=("license_overlap", lambda s: s.notna().sum()),
        hash_present=("hash_present", "mean"),
        hash_correct_when_comparable=("hash_correct", lambda s: s.dropna().mean()),
        hash_comparisons=("hash_correct", lambda s: s.notna().sum()),
        cpe_present=("cpe_present", "mean"), supplier_present=("supplier_present", "mean")).reindex(TOOLS)
    agg.to_csv(T / "rq4_field_correctness.csv")
    comp.groupby(["tool", "eco"]).agg(n=("eco", "size"), license_present=("license_present", "mean"),
                                      license_correct=("license_overlap", lambda s: s.dropna().mean()),
                                      hash_present=("hash_present", "mean")).to_csv(T / "rq4_fields_by_eco.csv")
    d = pd.DataFrame(docs)
    d.groupby("tool").mean(numeric_only=True).reindex(TOOLS).to_csv(T / "rq4_document_elements.csv")
    return agg, d


def iter_cdx(comps):
    for c in comps or []:
        yield c
        yield from iter_cdx(c.get("components"))


def rq4_formats(runs: list, targets: dict):
    """Does a tool's SPDX output describe the same packages as its CycloneDX output from the same run?
    Compared on purl-bearing identities (key+version); purl-less SPDX extras are counted separately, because a
    format conversion that turns non-packages (e.g. CycloneDX cryptographic-asset) into packages loses type info."""
    rows = []
    for r in runs:
        if r["config"] != "default" or r["rep"] != 1 or r["status"] != "ok" or r["target"] not in targets:
            continue
        outs = r.get("outputs") or {}
        cdx_out = outs.get("cyclonedx")
        if not cdx_out:
            continue
        spdx_rec = next((x for x in runs if x["config"] == "default" and x["rep"] == 1 and x["tool"] == r["tool"]
                         and x["target"] == r["target"] and (x.get("outputs") or {}).get("spdx")), None)
        if spdx_rec is None:
            continue
        a = load_sbom(ROOT / cdx_out["path"])["components"]
        b = load_sbom(ROOT / spdx_rec["outputs"]["spdx"]["path"])["components"]
        ia = {(c["key"], vnorm(c["eco"], c["version"])) for c in a if c["purl"]}
        ib = {(c["key"], vnorm(c["eco"], c["version"])) for c in b if c["purl"]}
        rows.append({"tool": r["tool"], "target": r["target"], "cdx_ids": len(ia), "spdx_ids": len(ib),
                     "identical_ids": ia == ib, "jaccard": len(ia & ib) / len(ia | ib) if ia | ib else 1.0,
                     "spdx_only_without_purl": sum(1 for c in b if not c["purl"]) - sum(1 for c in a if not c["purl"]),
                     "spdx_spec": load_sbom(ROOT / spdx_rec["outputs"]["spdx"]["path"])["spec"]})
    df = pd.DataFrame(rows).drop_duplicates(["tool", "target"])
    df.to_csv(T / "rq4_format_agreement.csv", index=False)
    df.groupby("tool").agg(pairs=("target", "size"), identical_ids=("identical_ids", "mean"),
                           mean_jaccard=("jaccard", "mean"),
                           targets_with_extra_purlless=("spdx_only_without_purl", lambda s: int((s > 0).sum())),
                           spec=("spdx_spec", "first")).reindex(TOOLS).to_csv(T / "rq4_format_agreement_summary.csv")
    return df


# ----------------------------------------------------------------------------- network + determinism
def network(m_all: pd.DataFrame):
    j = m_all[(m_all.tool == "cdxgen") & (m_all.format == "cyclonedx") & (m_all.layer == "java")
              & (m_all.target.str.startswith("J-")) & (m_all.stage != "S1")]
    tab = j.pivot_table(index=["target", "rep"], columns="config",
                        values=["recall_strict", "precision_strict", "recall_lenient"])
    tab.to_csv(T / "network_cdxgen_java.csv")
    return tab


def best_vs_default(m_all: pd.DataFrame, ms_all: pd.DataFrame, gts: dict, targets: dict):
    """Capability vs defaults: the same tools with their documented opt-in options (config 'best')."""
    s = m_all[(m_all.rep == 1) & (m_all.format == "cyclonedx") & (m_all.layer == "all")]
    rows = []
    for group, stages in (("images", IMAGE_STAGES), ("source+artifact", {"S1", "S2"})):
        g = s[s.stage.isin(stages)]
        for (cfg, tool), x in g.groupby(["config", "tool"]):
            if cfg not in ("default", "best"):
                continue
            r = micro(x)
            rows.append({"group": group, "config": cfg, "tool": tool, **r.to_dict()})
    df = pd.DataFrame(rows)
    df.to_csv(T / "best_vs_default.csv", index=False)
    per_target = s[s.config.isin(["default", "best"])].pivot_table(
        index=["stage", "target"], columns=["tool", "config"], values="recall_strict")
    per_target.to_csv(T / "best_vs_default_per_target.csv")
    # which mechanisms does best-effort unlock?
    img_t = {k: v for k, v in targets.items() if v["stage"] in IMAGE_STAGES}
    out = []
    for cfg in ("default", "best"):
        ms = ms_all[(ms_all.config == cfg) & (ms_all.rep == 1) & (ms_all.format == "cyclonedx")]
        d = rq3(ms[ms.target.isin(img_t)], {k: gts[k] for k in img_t}, img_t, f"_images_{cfg}")
        d["config"] = cfg
        out.append(d)
    mech = pd.concat(out).pivot_table(index="mechanism", columns=["tool", "config"], values="recall_strict")
    mech.to_csv(T / "best_vs_default_mechanisms.csv")
    return df, mech


def determinism(inv: dict):
    d = pd.DataFrame(inv["determinism"])
    d.groupby(["config", "tool"]).agg(pairs=("target", "size"), identical=("identical", "sum")).to_csv(T / "determinism.csv")
    return d


def main() -> int:
    T.mkdir(parents=True, exist_ok=True)
    targets = {t["id"]: t for t in load_catalog()["targets"]}
    m_all = pd.read_csv(RESULTS_DIR / "metrics.csv")
    m = main_slice(m_all)
    ms = main_slice(pd.read_csv(RESULTS_DIR / "misses.csv"))
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    inv = json.loads((RESULTS_DIR / "sbom_inventory.json").read_text(encoding="utf-8"))
    gts = {tid: json.loads((ROOT / "ground_truth" / f"{tid}.json").read_text(encoding="utf-8")) for tid in targets}

    overall, by_layer = rq1(m)
    log("== RQ1 overall (images, micro) ==\n" + overall.round(3).to_string())
    log("== RQ1 by layer ==\n" + by_layer[["gt_components", "recall_strict", "precision_strict"]].round(3).to_string())
    tests = component_tests(ms, gts, {t for t, v in targets.items() if v["stage"] in IMAGE_STAGES})
    log("== RQ1 component-level tests (images) ==\n" + tests.to_string())
    rq2(m)
    img_t = {k: v for k, v in targets.items() if v["stage"] in IMAGE_STAGES}
    src_t = {k: v for k, v in targets.items() if v["stage"] not in IMAGE_STAGES}
    src = rq3(ms[ms.target.isin(src_t)], {k: gts[k] for k in src_t}, src_t, "_source_artifact")
    mech = rq3(ms[ms.target.isin(img_t)], {k: gts[k] for k in img_t}, img_t, "_images")
    for label, df in (("images S3+P", mech), ("source/artifact S1+S2", src)):
        log(f"== RQ3 recall by mechanism ({label}) ==\n" + df.pivot_table(index="mechanism", columns="tool",
            values="recall_strict").reindex(columns=TOOLS).join(df.groupby("mechanism").gt_components.first())
            .round(2).to_string())
    agg, _ = rq4(runs, gts, targets)
    log("== RQ4 fields ==\n" + agg.round(3).to_string())
    rq4_formats(runs, targets)
    log("== network (cdxgen java) ==\n" + network(m_all).round(3).to_string())
    determinism(inv)
    if (m_all.config == "best").any():
        bvd, bmech = best_vs_default(m_all, pd.read_csv(RESULTS_DIR / "misses.csv"), gts, targets)
        log("== best-effort vs default (micro) ==\n" + bvd[["group", "config", "tool", "recall_strict",
                                                             "precision_strict", "tool_components"]].round(3).to_string())
    log(f"tables written to {T.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
