#!/usr/bin/env bash
# Reproduce the study. Linux, macOS or Git Bash on Windows. See docs/REPLICATION.md.
#
#   ./run_all.sh analysis   Recompute every table and figure from the archived SBOMs and scan outputs
#                           (data archive unpacked into work/). No Docker. Minutes. Must reproduce the shipped
#                           results exactly; the last step checks that.
#   ./run_all.sh full       Rebuild all targets, re-extract and re-verify the ground truth, re-run the three tools
#                           (default x2, best-effort x1), the paced network-verified cdxgen Java runs, RQ5 scans
#                           (needs the DB snapshot archive in work/cache/), then the analysis. Docker. Many hours.
set -euo pipefail
cd "$(dirname "$0")"
LEVEL="${1:-analysis}"
export PYTHONUTF8=1

# ---------------------------------------------------------------- Python environment (pinned; tested with 3.14)
pick_python() {   # first interpreter that really runs and is >= 3.11 (skips e.g. the Windows Store "python3" stub)
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sys; sys.exit(sys.version_info < (3, 11))" >/dev/null 2>&1; then
      echo "$c"; return
    fi
  done
  echo "Python >= 3.11 not found" >&2; exit 2
}
if [ ! -d .venv ]; then "$(pick_python)" -m venv .venv; fi
PY=.venv/bin/python; [ -x "$PY" ] || PY=.venv/Scripts/python
"$PY" -m pip install -q -r requirements.lock.txt

step() { echo; echo "== $(date +%H:%M:%S) $*"; }
run() { step "$*"; "$PY" "$@"; }

ANALYSIS_FILES=(sbom_inventory.json metrics.csv misses.csv false_positives.csv 'tables/*.csv')
NET_TARGETS=(J-S2 J-S3-ubuntu J-S3-alpine J-S3-distroless J-S3-layered J-P G-S2 G-S3-ubuntu G-S3-alpine G-S3-distroless X-jenkins X-keycloak)
NET_EXPECT=(J-S2=45 J-S3-ubuntu=45 J-S3-alpine=45 J-S3-distroless=45 J-S3-layered=45 J-P=45 G-S2=55 G-S3-ubuntu=55 G-S3-alpine=55 G-S3-distroless=55 X-jenkins=19 X-keycloak=71)

analysis() {
  run scripts/normalize.py
  run scripts/score.py
  run scripts/analyze.py
  run scripts/sensitivity.py
  run scripts/vuln_scan.py --skip-scan
  run scripts/figures.py
}

case "$LEVEL" in
  analysis)
    [ -d work/sboms/default ] || { echo "work/sboms/ missing: unpack the data archive (p16-data-*.tar.gz) into the repository root first"; exit 2; }
    step "snapshot shipped results -> work/expected_results"
    rm -rf work/expected_results && cp -r results work/expected_results
    analysis
    run scripts/check_reproduction.py --only "${ANALYSIS_FILES[@]}"
    ;;
  full)
    docker info >/dev/null 2>&1 || { echo "Docker engine not reachable"; exit 2; }
    [ -d work/cache/trivy/java-db ] || { echo "work/cache/ missing: unpack the DB snapshot archive (p16-db-snapshots-*.tar.gz) first"; exit 2; }
    step "snapshot shipped results -> work/expected_results"
    rm -rf work/expected_results && cp -r results work/expected_results
    run scripts/build_targets.py
    run scripts/verify_build.py
    run scripts/extract_gt.py
    run scripts/verify_gt.py
    run scripts/run_tools.py --reps 1 2 --force
    run scripts/run_tools.py --reps 1 --config best --force
    # cdxgen identifies pom-less JARs on Maven Central, which rate-limits: paced runs, each verified to have made
    # the target's full number of lookups (a throttled run is retried later)
    run scripts/rerun_online.py --targets "${NET_TARGETS[@]}" --reps 1 2 --expect "${NET_EXPECT[@]}" --gap-minutes 40 --max-attempts 5
    run scripts/rerun_online.py --targets "${NET_TARGETS[@]}" --reps 1 --config best --expect "${NET_EXPECT[@]}" --gap-minutes 40 --max-attempts 5
    run scripts/vuln_scan.py
    analysis
    # rebuilt images and live registries drift over time: differences are expected and explained in docs/REPLICATION.md
    run scripts/check_reproduction.py || echo "(differences listed above: see docs/REPLICATION.md, 'Full re-run')"
    ;;
  *)
    echo "usage: $0 analysis|full"; exit 2 ;;
esac
step "done"
