"""Preserve cdxgen Java runs made while Maven Central was rate-limiting this machine as a separate condition.

Finding (23 Nov): cdxgen identifies JARs that carry no pom.properties by looking their SHA-1 up on Maven Central
("hash-comparison" evidence). Once Maven Central rate-limited us (HTTP 429), those lookups failed SILENTLY and
cdxgen fell back to guessing groupIds from the MANIFEST ("manifest-analysis", lower confidence), with no warning.

Runs whose SBOM contains zero hash-comparison identifications although the target has JARs without pom.properties
are copied to config "netblocked" (work/sboms/netblocked/...) and recorded in results/tool_runs.json, so that the
"default" config can be re-run under normal network conditions and both conditions can be compared.

Usage: python scripts/snapshot_netblocked.py
"""
from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import datetime, timezone

from common import RESULTS_DIR, ROOT, WORK, log, rel, write_json

JAVA_TARGETS = ("J-S2", "J-S3-ubuntu", "J-S3-alpine", "J-S3-distroless", "J-S3-layered", "J-P")


def hash_lookups(path) -> int:
    d = json.loads(path.read_text(encoding="utf-8"))
    return sum(1 for c in d.get("components", []) if (c.get("purl") or "").startswith("pkg:maven")
               for idn in (c.get("evidence") or {}).get("identity") or [] for m in idn.get("methods") or []
               if m.get("technique") == "hash-comparison")


def main() -> int:
    runs_file = RESULTS_DIR / "tool_runs.json"
    data = json.loads(runs_file.read_text(encoding="utf-8"))
    new = []
    for r in data["runs"]:
        if r["config"] != "default" or r["tool"] != "cdxgen" or r["target"] not in JAVA_TARGETS or r["status"] != "ok":
            continue
        out = r["outputs"].get("cyclonedx")
        lookups = hash_lookups(ROOT / out["path"])
        r["hash_lookups"] = lookups
        if lookups > 0:
            continue
        nr = json.loads(json.dumps(r))
        nr["config"] = "netblocked"
        nr["note"] = "cdxgen Maven Central SHA-1 lookups failed (HTTP 429 period); copied from the default config"
        for fmt, o in list(nr["outputs"].items()):
            if not o:
                continue
            src = ROOT / o["path"]
            dst = WORK / "sboms" / "netblocked" / "cdxgen" / f"rep{r['rep']}" / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            o["path"] = rel(dst)
        new.append(nr)
    keyf = lambda x: (x["config"], x["tool"], x["rep"], x["target"], tuple(x["formats"]))
    merged = {keyf(x): x for x in data["runs"]}
    for nr in new:
        merged[keyf(nr)] = nr
    data["runs"] = sorted(merged.values(), key=lambda x: (x["config"], x["tool"], x["rep"], x["target"]))
    data["updated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_json(runs_file, data)
    log(f"snapshotted {len(new)} degraded cdxgen runs as config 'netblocked': "
        f"{Counter((x['rep']) for x in new)} -> {sorted({x['target'] for x in new})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
