"""Re-run network-dependent Java jobs one at a time, spaced out so Maven Central's rate limit is never hit.

Why: cdxgen identifies JARs without pom.properties with one Maven Central search request per JAR, with no cache,
a 1-second response timeout, and MAX_SEARCH_MAVEN_ORG_ERRORS = 1 (a single failure disables lookups for the rest
of the run). About 2-3 back-to-back scans of our Java targets (~45 lookups each) trip the rate limit, after which
cdxgen silently falls back to guessing. Trivy resolves pom.xml parents from Maven Central and fails hard when blocked.

Each job: wait until a probe shows Maven Central answering normally, run the job, then VERIFY it really ran online
(cdxgen: >0 hash-comparison identifications; trivy: exit 0). A job that ran degraded is retried later.

Usage: python scripts/rerun_online.py [--gap-minutes 35]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

from common import RESULTS_DIR, ROOT, log
from snapshot_netblocked import hash_lookups

# (tool, target, rep)
# Already done online: cdxgen rep1 J-S2, J-S3-ubuntu (45 lookups each, 22 Nov 20:18), J-S3-alpine, J-S3-distroless
# (45 each, 23 Nov 04:18/05:11). Trivy J-S1 now uses a pre-populated local Maven cache (run_tools.py), no network.
JOBS = [("cdxgen", "J-S3-layered", 1), ("cdxgen", "J-P", 1),
        ("cdxgen", "J-S2", 2), ("cdxgen", "J-S3-ubuntu", 2), ("cdxgen", "J-S3-alpine", 2),
        ("cdxgen", "J-S3-distroless", 2), ("cdxgen", "J-S3-layered", 2), ("cdxgen", "J-P", 2)]
PROBES = {
    # Exactly the request cdxgen makes (SHA-1 of mysql-connector-j-9.7.0.jar). When rate-limited, Central answers
    # HTTP 404 + Retry-After (a block disguised as "not found"), which cdxgen deliberately ignores -> silent fallback.
    "cdxgen": "https://central.sonatype.com/solrsearch/select?q=1:%224e6e3e8765e4a9d0609744b3e8fe75afe1b98cba%22&rows=20&wt=json",
    "trivy": "https://repo.maven.apache.org/maven2/org/springframework/data/spring-data-bom/2026.0.0/spring-data-bom-2026.0.0.pom",
}
UA = {"cdxgen": "got (https://github.com/sindresorhus/got)", "trivy": "Go-http-client/1.1"}


def probe(tool: str) -> int:
    req = urllib.request.Request(PROBES[tool], headers={"User-Agent": UA[tool]})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


JAVA_NET_TARGETS = ["J-S2", "J-S3-ubuntu", "J-S3-alpine", "J-S3-distroless", "J-S3-layered", "J-P"]


def job_ok(tool: str, target: str, rep: int, config: str = "default") -> tuple[bool, str]:
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    recs = [r for r in runs if r["config"] == config and r["tool"] == tool and r["target"] == target
            and r["rep"] == rep and "cyclonedx" in r["formats"]]
    if not recs or any(r["status"] != "ok" for r in recs):
        return False, f"status={[r['status'] for r in recs]}"
    if tool == "cdxgen":
        n = hash_lookups(ROOT / recs[0]["outputs"]["cyclonedx"]["path"])
        return n > 0, f"hash-comparison identifications={n}"
    return True, "exit 0"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gap-minutes", type=float, default=50)   # observed Retry-After: 2684 s (~45 min)
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--config", choices=["default", "best"], default="default")
    ap.add_argument("--java-cdxgen-rep1", action="store_true",
                    help="job list = cdxgen rep1 on the 6 network-dependent Java targets (instead of JOBS)")
    args = ap.parse_args()
    pending = [("cdxgen", t, 1) for t in JAVA_NET_TARGETS] if args.java_cdxgen_rep1 else list(JOBS)
    attempts: dict[tuple, int] = {}
    last_run = 0.0
    while pending:
        tool, target, rep = pending.pop(0)
        wait = last_run + args.gap_minutes * 60 - time.time()
        if wait > 0:
            log(f"{time.strftime('%H:%M')} waiting {wait / 60:.0f} min before {tool} {target} rep{rep}")
            time.sleep(wait)
        while subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            log(f"{time.strftime('%H:%M')} Docker engine not reachable; retry in 5 min")
            time.sleep(300)
        while (code := probe(tool)) != 200:
            log(f"{time.strftime('%H:%M')} probe for {tool} -> {code}; retry in 15 min")
            time.sleep(900)
        attempts[(tool, target, rep)] = attempts.get((tool, target, rep), 0) + 1
        log(f"{time.strftime('%H:%M')} [{args.config}] running {tool} {target} rep{rep} (attempt {attempts[(tool, target, rep)]})")
        subprocess.run([sys.executable, str(ROOT / "scripts" / "run_tools.py"), "--only", target, "--tools", tool,
                        "--reps", str(rep), "--force", "--config", args.config], capture_output=True, text=True)
        last_run = time.time()
        ok, why = job_ok(tool, target, rep, args.config)
        log(f"{time.strftime('%H:%M')}   -> {'ONLINE OK' if ok else 'DEGRADED/FAILED'} ({why})")
        if not ok and attempts[(tool, target, rep)] < args.max_attempts:
            pending.append((tool, target, rep))
    log("all jobs processed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
