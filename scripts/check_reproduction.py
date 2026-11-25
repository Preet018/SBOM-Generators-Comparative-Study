"""Compare regenerated results with the shipped ones (replication check).

run_all copies results/ to work/expected_results/ before it regenerates anything; this script then compares every
CSV and JSON result file. CSVs: same columns, same rows (order-independent), numbers equal within 1e-9.
JSON: equal after removing run-time-only fields (timestamps, durations). Figures are regenerated, not compared
(their files embed creation dates).

Usage: python scripts/check_reproduction.py [--expected work/expected_results] [--only metrics.csv tables/rq1_*.csv]
Exit 0 = every file reproduced; 1 = differences (listed).
"""
from __future__ import annotations

import argparse
import fnmatch
import json

import pandas as pd

from common import RESULTS_DIR, WORK, log

VOLATILE = {"updated_utc", "generated_utc", "seconds", "build_seconds", "timestamp", "created"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in VOLATILE}
    if isinstance(o, list):
        return [strip(v) for v in o]
    return o


def cell_equal(u: str, v: str) -> bool:
    if u == v:
        return True
    try:
        return abs(float(u) - float(v)) <= 1e-9      # same number written differently
    except ValueError:
        return False


def same_csv(a, b) -> str | None:
    """Raw text comparison (no type inference: an empty cell stays ''), rows in any order."""
    try:
        x = pd.read_csv(a, dtype=str, keep_default_na=False, header=None)
        y = pd.read_csv(b, dtype=str, keep_default_na=False, header=None)
    except pd.errors.EmptyDataError:
        return None if a.stat().st_size == b.stat().st_size == 0 else "one file is empty"
    if x.shape != y.shape:
        return f"shape {x.shape} vs {y.shape}"
    rows_x = sorted(map(tuple, x.values.tolist()))
    rows_y = sorted(map(tuple, y.values.tolist()))
    for rx, ry in zip(rows_x, rows_y):
        if not all(cell_equal(u, v) for u, v in zip(rx, ry)):
            diff = next((i, u, v) for i, (u, v) in enumerate(zip(rx, ry)) if not cell_equal(u, v))
            n = sum(1 for p, q in zip(rows_x, rows_y) if not all(cell_equal(u, v) for u, v in zip(p, q)))
            return f"{n} rows differ (e.g. column #{diff[0]}: {diff[1]!r} vs {diff[2]!r})"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", default=str(WORK / "expected_results"))
    ap.add_argument("--only", nargs="+", help="glob patterns relative to results/")
    a = ap.parse_args()
    from pathlib import Path
    exp_dir = Path(a.expected)
    files = sorted(p for p in exp_dir.rglob("*") if p.is_file() and p.suffix in (".csv", ".json")
                   and "matches" not in p.parts)
    if a.only:
        files = [p for p in files if any(fnmatch.fnmatch(p.relative_to(exp_dir).as_posix(), g) for g in a.only)]
    ok, bad, missing = 0, [], []
    for e in files:
        rel = e.relative_to(exp_dir)
        g = RESULTS_DIR / rel
        if not g.exists():
            missing.append(str(rel))
            continue
        if e.suffix == ".csv":
            why = same_csv(e, g)
        else:
            why = None if strip(json.loads(e.read_text(encoding="utf-8"))) == strip(json.loads(g.read_text(encoding="utf-8"))) \
                else "JSON content differs"
        if why:
            bad.append(f"{rel}: {why}")
        else:
            ok += 1
    log(f"reproduced {ok}/{len(files)} result files exactly" + (f"; {len(missing)} not regenerated" if missing else ""))
    for m in missing:
        log(f"  NOT REGENERATED {m}")
    for b in bad:
        log(f"  DIFFERS {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
