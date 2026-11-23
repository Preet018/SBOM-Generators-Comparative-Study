"""Score every SBOM against the ground truth (RQ1-RQ4 raw data).

Matching works on unique identities (normalised key + normalised version). For each SBOM component, the first
rule that applies decides its class:
  exact            same key, same version                           -> strict TP
  alias            GT component is a runtime/native/planted item (eco generic/github) and the tool names it
                   by one of its alt_names (e.g. "openjdk" vs pkg:generic/java), same version -> strict TP
  alias-noversion  as alias, but GT or tool has no version / versions differ                  -> lenient TP
  version-mismatch same key, different (or missing) version                                    -> lenient TP
  namespace-diff   same eco + name, different namespace (e.g. wrong Maven groupId)              -> lenient TP
  eco-diff         same name + version under another purl type                                  -> lenient TP
  path-alias       identifier-less component named by a file path that holds a GT component    -> lenient TP
  unmatched        anything else                                                                -> FP
A tool component matched to a SECONDARY GT item counts as correct for precision; secondary items are never
in the recall denominator. Recall = matched PRIMARY GT identities / PRIMARY GT identities.

Outputs: results/metrics.csv           one row per (config, tool, rep, format, target, layer)
         results/misses.csv            every PRIMARY GT component a tool did not find (strict), with mechanism
         results/false_positives.csv   every SBOM component that matched nothing in the GT
         results/matches/<config>-<tool>-rep<N>-<format>-<target>.json   full per-component detail
"""
from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path

from packaging.version import InvalidVersion, Version

from common import RESULTS_DIR, ROOT, load_catalog, log, write_json
from normalize import load_sbom

GT_DIR = ROOT / "ground_truth"
MATCH_DIR = RESULTS_DIR / "matches"
STRICT = {"exact", "alias"}
LENIENT = STRICT | {"alias-noversion", "version-mismatch", "namespace-diff", "eco-diff", "path-alias"}
LAYER_OF_ECO = {"deb": "os", "apk": "os", "rpm": "os", "maven": "java", "npm": "npm", "pypi": "python",
                "golang": "go", "generic": "native", "github": "native"}


def vnorm(eco: str, v: str | None) -> str | None:
    """Version normalisation applied identically to GT and SBOM versions."""
    if v in (None, "", "UNKNOWN", "NOASSERTION", "(devel)"):   # "(devel)" = Go's "no version recorded"
        return None
    v = str(v).strip()
    if eco in ("deb", "rpm"):
        v = re.sub(r"^\d+:", "", v)               # epoch (some tools drop it, some keep it)
    if eco in ("golang", "generic", "github"):
        v = re.sub(r"^(go|v)(?=\d)", "", v)       # go1.22.5 / v1.22.5 / v4.44.3
    if eco == "pypi":
        try:
            v = str(Version(v))
        except InvalidVersion:
            pass
    return v.lower()


def layer(eco: str) -> str:
    return LAYER_OF_ECO.get(eco, "other")


class GTIndex:
    def __init__(self, gt: dict):
        self.comps = gt["components"]
        self.exact = {}
        self.by_key = defaultdict(list)
        self.by_eco_name = defaultdict(list)
        self.by_name_version = defaultdict(list)
        self.alias = defaultdict(list)
        self.by_path = defaultdict(list)
        for i, c in enumerate(self.comps):
            v = vnorm(c["eco"], c["version"])
            # Two GT records can normalise to the same identity (e.g. binary rpm "1:4.8.0-7.el9" and its source
            # package "4.8.0-7.el9"). Never let a secondary record shadow a primary one.
            prev = self.exact.get((c["key"], v))
            if prev is None or (self.comps[prev]["tier"] == "secondary" and c["tier"] == "primary"):
                self.exact[(c["key"], v)] = i
            self.by_key[c["key"]].insert(0, i) if c["tier"] == "primary" else self.by_key[c["key"]].append(i)
            self.by_eco_name[(c["eco"], c["name"].lower())].append(i)
            self.by_name_version[(c["name"].lower(), v)].append(i)
            aliases = {x.lower() for x in c.get("alt_names", [])}
            if c["eco"] in ("generic", "github") or c.get("planted"):
                aliases.add(c["name"].lower())
            for a in aliases:
                self.alias[a].append(i)
            # tools sometimes name a binary by its file path; index only the component that IS the file
            # (main module / planted / runtime), not the dependencies compiled into it
            if c["mechanism"] not in ("go-module-in-binary", "os-pm", "source-package", "nested-jar"):
                for p in c.get("paths", []):
                    if "!/" not in p and not p.startswith("var/lib/"):
                        self.by_path[p.lstrip("/")].append(i)

    def match(self, t: dict) -> tuple[str, int | None]:
        v = vnorm(t["eco"], t["version"])
        if (t["key"], v) in self.exact:
            return "exact", self.exact[(t["key"], v)]
        name = (t["name"] or "").lower()
        short = name.rsplit("/", 1)[-1]
        for cand_name in (name, short):
            for i in self.alias.get(cand_name, []):
                gv = vnorm(self.comps[i]["eco"], self.comps[i]["version"])
                tv = vnorm(self.comps[i]["eco"], t["version"])
                if gv is not None and gv == tv:
                    return "alias", i
            if self.alias.get(cand_name):
                return "alias-noversion", self.alias[cand_name][0]
        if self.by_key.get(t["key"]):
            return "version-mismatch", self.by_key[t["key"]][0]
        if self.by_eco_name.get((t["eco"], name)):
            return "namespace-diff", self.by_eco_name[(t["eco"], name)][0]
        if v is not None and self.by_name_version.get((name, v)):
            return "eco-diff", self.by_name_version[(name, v)][0]
        if t["eco"] == "unknown" and self.by_path.get(name.lstrip("/")):
            return "path-alias", self.by_path[name.lstrip("/")][0]
        return "unmatched", None


def prf(tp_tool: int, n_tool: int, tp_gt: int, n_gt: int) -> tuple:
    p = tp_tool / n_tool if n_tool else None
    r = tp_gt / n_gt if n_gt else None
    f = 2 * p * r / (p + r) if p is not None and r is not None and (p + r) else (0.0 if p is not None and r is not None else None)
    return p, r, f


def score_one(run: dict, fmt: str, out: dict, target: dict, gt: dict) -> tuple[list[dict], list[dict], list[dict], dict]:
    sbom = load_sbom(ROOT / out["path"])
    idx = GTIndex(gt)
    # unique tool identities (duplicates counted separately)
    uniq: dict[tuple, dict] = {}
    for c in sbom["components"]:
        uniq.setdefault((c["key"], vnorm(c["eco"], c["version"])), c)
    tool_rows = []
    gt_hits: dict[int, set] = defaultdict(set)
    for ident, c in uniq.items():
        cls, gi = idx.match(c)
        if gi is not None:
            gt_hits[gi].add(cls)
        tool_rows.append({"key": c["key"], "version": c["version"], "eco": c["eco"], "name": c["name"], "purl": c["purl"],
                          "class": cls, "gt_index": gi,
                          "gt_tier": idx.comps[gi]["tier"] if gi is not None else None, "paths": c["paths"][:3]})

    rows, misses = [], []
    base = {"config": run["config"], "tool": run["tool"], "rep": run["rep"], "format": fmt, "target": target["id"],
            "stage": target["stage"], "subject": target["subject"], "kind": target["kind"]}
    for lyr in ["all", "os", "java", "npm", "python", "go", "native"]:
        in_l = (lambda e: True) if lyr == "all" else (lambda e, L=lyr: layer(e) == L)
        gt_primary = [i for i, c in enumerate(idx.comps) if c["tier"] == "primary" and in_l(c["eco"])]
        tools_l = [r for r in tool_rows if in_l(r["eco"]) or (r["gt_index"] is not None and in_l(idx.comps[r["gt_index"]]["eco"]))]
        if not gt_primary and not tools_l:
            continue
        tp_tool_s = sum(1 for r in tools_l if r["class"] in STRICT)
        tp_tool_l = sum(1 for r in tools_l if r["class"] in LENIENT)
        tp_gt_s = sum(1 for i in gt_primary if gt_hits.get(i, set()) & STRICT)
        tp_gt_l = sum(1 for i in gt_primary if gt_hits.get(i, set()) & LENIENT)
        ps, rs, fs_ = prf(tp_tool_s, len(tools_l), tp_gt_s, len(gt_primary))
        pl, rl, fl = prf(tp_tool_l, len(tools_l), tp_gt_l, len(gt_primary))
        rows.append({**base, "layer": lyr, "gt_primary": len(gt_primary), "tool_identities": len(tools_l),
                     "tp_gt_strict": tp_gt_s, "tp_gt_lenient": tp_gt_l, "tp_tool_strict": tp_tool_s,
                     "tp_tool_lenient": tp_tool_l, "fp_lenient": len(tools_l) - tp_tool_l,
                     "precision_strict": ps, "recall_strict": rs, "f1_strict": fs_,
                     "precision_lenient": pl, "recall_lenient": rl, "f1_lenient": fl,
                     "duplicates": len(sbom["components"]) - len(uniq) if lyr == "all" else None})
    for i, c in enumerate(idx.comps):
        if c["tier"] != "primary" or gt_hits.get(i, set()) & STRICT:
            continue
        misses.append({**{k: base[k] for k in ("config", "tool", "rep", "format", "target", "stage")},
                       "eco": c["eco"], "key": c["key"], "version": c["version"], "mechanism": c["mechanism"],
                       "mechanisms": "|".join(c.get("mechanisms") or [c["mechanism"]]),
                       "lenient_match": "|".join(sorted(gt_hits.get(i, set()))) or "none",
                       "planted": bool(c.get("planted")), "path": (c["paths"] or [""])[0]})
    fps = [{**{k: base[k] for k in ("config", "tool", "rep", "format", "target", "stage")},
            "eco": r["eco"], "key": r["key"], "version": r["version"], "purl": r["purl"], "path": (r["paths"] or [""])[0]}
           for r in tool_rows if r["class"] == "unmatched"]
    detail = {"run": base, "tool_components": tool_rows,
              "gt": [{"key": c["key"], "version": c["version"], "tier": c["tier"], "mechanism": c["mechanism"],
                      "matched_by": sorted(gt_hits.get(i, set()))} for i, c in enumerate(idx.comps)]}
    return rows, misses, fps, detail


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(rows[0].keys())
    for r in rows:
        cols += [k for k in r if k not in cols]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    targets = {t["id"]: t for t in load_catalog()["targets"]}
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    gts = {tid: json.loads((GT_DIR / f"{tid}.json").read_text(encoding="utf-8")) for tid in targets}
    metrics, misses, fps, skipped = [], [], [], []
    for run in runs:
        if run["target"] not in targets or run.get("status") != "ok":
            continue
        for fmt, out in (run.get("outputs") or {}).items():
            if not out:
                continue
            if not (ROOT / out["path"]).exists():   # job currently being re-run (outputs deleted first)
                skipped.append(f"{run['config']}/{run['tool']}/rep{run['rep']}/{run['target']}/{fmt}")
                continue
            rows, m, f, detail = score_one(run, fmt, out, targets[run["target"]], gts[run["target"]])
            metrics += rows
            misses += m
            fps += f
            write_json(MATCH_DIR / f"{run['config']}-{run['tool']}-rep{run['rep']}-{fmt}-{run['target']}.json", detail)
    write_csv(RESULTS_DIR / "metrics.csv", metrics)
    write_csv(RESULTS_DIR / "misses.csv", misses)
    write_csv(RESULTS_DIR / "false_positives.csv", fps)
    log(f"scored {len({(m['config'], m['tool'], m['rep'], m['format'], m['target']) for m in metrics})} SBOMs: "
        f"{len(metrics)} metric rows, {len(misses)} misses, {len(fps)} false positives")
    if skipped:
        log(f"WARNING: {len(skipped)} SBOM(s) missing on disk (job in progress?) and NOT scored: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
