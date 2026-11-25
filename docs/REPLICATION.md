# Replication guide

This study can be reproduced at two levels. The **analysis level** recomputes every number, table and figure in the paper from the archived SBOMs. It is exact and quick. The **full level** re-runs everything, from building the targets to the vulnerability scans. It is slow and depends on the network and on registries that change over time.

## 1. The package

`python scripts/make_archive.py [--with-db]` writes three archives to `dist/`, with `SHA256SUMS` and `MANIFEST.json`:

| Archive | Size | Contents | Needed for |
|---|---|---|---|
| `p16-code-<date>.zip` | ~9 MB | The repository: scripts, frozen corpus, `targets.yaml`, ground truth, results, docs, figures | both levels |
| `p16-data-<date>.tar.gz` | ~305 MB (1.8 GB unpacked) | `work/sboms` (every SBOM: default ×2, best-effort, netblocked), `work/rq5` (reference SBOMs, scanner outputs, validation scans), `work/buildinfo`, `work/artifacts` (S2 artifacts), `work/logs` (all tool logs, including the online-verification evidence) | both levels |
| `p16-db-snapshots-<date>.tar.gz` | several GB | Frozen Grype DB, Trivy vulnerability DB, Trivy Java DB and the pre-populated Maven cache (`work/cache/`) | full level only |

Unzip the code archive, then unpack the other archives **into the repository root** (they contain `work/…`).

Not archived: container image tars and exported root filesystems (~16 GB). The full level rebuilds them.
- Public images and tools are pinned by digest (`targets.yaml`, `tools/versions.lock`).
- Base-image digests of the built targets are recorded in `results/build_manifest.json`.

## 2. Analysis level (exact)

```bash
./run_all.sh analysis          # Linux, macOS, Git Bash
.\run_all.ps1 analysis         # Windows PowerShell
```

What it does:
1. Creates `.venv` from `requirements.lock.txt` (Python ≥ 3.11; tested with 3.14).
2. Copies the shipped `results/` to `work/expected_results/`.
3. Runs `normalize → score → analyze → sensitivity → vuln_scan --skip-scan → figures`.
4. Runs `scripts/check_reproduction.py`, which compares every regenerated result file with the shipped one. Rows are matched in any order and numbers within 1e-9; it exits 1 on any difference.

**Verified** on a fresh copy built only from the two archives: `reproduced 46/46 result files exactly`, about 4 minutes.
- The checker is not vacuous: changing one recall value by 0.001, or one character of one component name, is reported as a difference.
- Figures are regenerated but not compared, because PDF and PNG files embed creation dates.

## 3. Full level

```bash
./run_all.sh full
```

Requirements: Docker, about 30 GB of free disk space, network access (registries, Maven Central), and many hours. Most of the time goes into the paced Maven Central runs.

Steps:
1. `build_targets.py` (images, artifacts, build info) and `verify_build.py` (268 checks).
2. `extract_gt.py` and `verify_gt.py` (230 independent-oracle checks).
3. `run_tools.py` (default ×2, best-effort ×1).
4. `rerun_online.py`: the cdxgen runs that need Maven Central, 40 minutes apart. Each is accepted only with the target's full number of SHA-1 lookups (J-* 45, G-* 55, X-jenkins 19, X-keycloak 71); a throttled run is retried.
5. `vuln_scan.py` (RQ5, offline against the frozen DBs).
6. The analysis level.

**Verified end to end on two digest-pinned targets** (X-prometheus, O-alpine), in a fresh copy:
- the re-extracted ground truth is identical;
- all six re-generated SBOMs have exactly the archived component sets;
- `metrics.csv`, `misses.csv` and `false_positives.csv` are identical.

### Expected differences in a full re-run

| Source of drift | Affects | Why |
|---|---|---|
| Built targets (J-, N-, P-, C-, M-, G-) | OS packages in our own images | Dockerfiles install distro packages (`apt`, `apk`) at build time; the mirrors serve newer patch versions later. Base images are recorded by digest; pinning them (`FROM image@sha256:…`) removes the base-image part of the drift but not the package installs. |
| Source targets without a lockfile (N-S1-nolock, P-S1) | cdxgen | cdxgen installs dependencies itself and gets whatever the registry serves on the day ("registry drift", already observed between runs hours apart). |
| Maven Central rate limiting | cdxgen Java runs | Handled by the paced runner; the `netblocked` condition (archived) cannot be re-created on purpose. |
| `resolve_public_java.py` (not run by `run_all`) | identities of 95 pom-less JARs | Uses repo1.maven.org and repo.jenkins-ci.org; its result is committed (`results/public_java_ids.json`) so the GT does not depend on the network. |
| `screen_images.py` (not run by `run_all`) | image selection only | Pulls floating tags as they are today; the study uses the digests in `targets.yaml`. |
| RQ5 without the DB archive | vulnerability findings | Newer DBs contain newer advisories. With the archived snapshots the scans are offline and repeatable. |

The digest-pinned public images (X-*, O-*) and the corpus source trees are stable. The two-target test above relied on exactly that.

## 4. What the main scripts produce

| Script | Output |
|---|---|
| `build_targets.py`, `verify_build.py` | `results/build_manifest.json`, `results/verify_build.json` |
| `extract_gt.py`, `verify_gt.py` | `ground_truth/*.json`, `results/verify_gt.json` |
| `run_tools.py`, `rerun_online.py` | `work/sboms/<config>/<tool>/rep<N>/`, `results/tool_runs.json` |
| `normalize.py`, `score.py` | `results/sbom_inventory.json`, `metrics.csv`, `misses.csv`, `false_positives.csv`, `results/matches/` |
| `analyze.py`, `sensitivity.py` | `results/tables/*.csv` (RQ1–RQ4, cohorts, network, determinism, best-effort, licenses, sensitivity) |
| `vuln_scan.py` | `work/rq5/`, `results/rq5_scans.json`, `results/tables/rq5_*.csv`; `--validate` gives `rq5_reference_validation.csv` |
| `figures.py` | `paper/figures/*.pdf`, `*.png` |
| `check_reproduction.py` | comparison report (exit 0 = exact) |
| `make_archive.py` | `dist/` |
