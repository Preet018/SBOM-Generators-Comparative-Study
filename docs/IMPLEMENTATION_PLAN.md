# P16 — 5-Day Implementation Plan

*Goal: a finished experiment and a complete first paper draft in 5 days (Mon 23 Nov – Fri 27 Nov 2026). The draft then goes to the professor. Revisions and submission to EMSE (SECUTE special issue, deadline 28 Feb 2027) follow in December.*

Research design, RQs and venue are fixed in [`P16_Literature_Review_and_Plan.md`](P16_Literature_Review_and_Plan.md). This document covers **how** we build it and **what gets done each day**.

---

## 0. OS packages: who does what

**Handled by the pipeline; no manual setup is needed.** OS packages are not files we add to `corpus/`. They are the packages inside a container image's base layer (`apt`/`dpkg` on Debian/Ubuntu, `apk` on Alpine, `rpm` on Red Hat UBI). We get them two ways:

1. **Inside every app image we build.** For example, the Bakery backend on `eclipse-temurin:25-jre` carries Ubuntu `.deb` packages, and on `alpine` it carries `apk` packages.
2. **Five plain OS baseline images** (`debian:bookworm-slim`, `ubuntu:24.04`, `alpine:3.x`, `ubi9-minimal`, `distroless/base-debian12`). Each is listed in `targets.yaml` and pinned by digest. Docker downloads them automatically.

So `corpus/` keeps only *your* projects. All study-made material (Dockerfiles, planted components, OS baselines) lives under `variants/`. The ground truth for OS packages is read straight from each image's package database, so nobody has to type anything in by hand.

---

## 1. Environment (checked 22 Nov)

| Item | Status |
|---|---|
| Docker Desktop 29.1.3, 16 CPU, ~8 GB RAM | ✅ running |
| Disk | ✅ 96 GB free. We need about 15–20 GB for image tars and tool images. Docker also has ~25 GB of reclaimable cache if we need it. |
| Python 3.14 (host) | ✅ for analysis scripts. Runs in a venv with pinned `requirements.txt`. |
| JDK / Maven / Node / gcc | Not needed on the host. All builds happen in Docker build stages. |
| Syft / Trivy / cdxgen | Run from their **official Docker images, pinned by digest** on Day 1 |

---

## 2. Repository layout (created on Day 1)

```
corpus/                     frozen subject projects (done, read-only)
variants/
  bakery-backend/<variant>/Dockerfile
  bakery-frontend/<variant>/Dockerfile
  log-anomaly/<variant>/Dockerfile
  tcp-server/<variant>/Dockerfile (+ vendored lib for the planted variant)
  os-baselines/             only image references, no Dockerfiles
  planted/                  hard-case components (copied JAR, downloaded binary…) + planted.json
targets.yaml                one entry per scan target: id, subject, stage, kind (dir|file|image), build info
tools/versions.lock         pinned tool image digests + exact CLI commands used
scripts/
  build_targets.py          docker build → docker save (.tar) → docker export (rootfs) for each image target
  extract_gt.py             rootfs / build outputs → ground_truth/<id>.json
  run_tools.py              Syft, Trivy, cdxgen × CycloneDX/SPDX → sboms/…, logs exit code, runtime, version
  normalize.py              SBOMs and ground truth → canonical component records (PURL-based)
  score.py                  matching → results/*.csv (P/R/F1, Jaccard, field correctness, misses)
  figures.py                plots (PDF) + LaTeX tables into paper/
run_all.ps1                 one command reproduces everything
paper/                      Springer sn-jnl LaTeX template (EMSE)
generated (git-ignored):    work/images/*.tar, work/rootfs/
generated (committed):      ground_truth/, sboms/, results/   (small JSON/CSV)
```

---

## 3. Target matrix (~32 targets)

Stages: **S1** source tree · **S2** built artifact · **S3** container image · **P** = image with planted hard cases.

| Subject | ID | Stage | What it is |
|---|---|---|---|
| **Bakery backend** (Java 25, Spring Boot 4.1) | J-S1 | S1 | `corpus/.../bakery-inventory-backend` (pom.xml only, no lockfile) |
| | J-S2 | S2 | Spring Boot fat JAR (`BOOT-INF/lib`) |
| | J-S3-ubuntu | S3 | `eclipse-temurin:25-jre` + fat JAR |
| | J-S3-alpine | S3 | `eclipse-temurin:25-jre-alpine` + fat JAR |
| | J-S3-distroless | S3 | `gcr.io/distroless/java*` + fat JAR (Java 21 fallback if no Java 25 image exists, noted as a limitation) |
| | J-S3-layered | S3 | `java -Djarmode=tools extract` → exploded `lib/*.jar` on temurin |
| | J-P | P | J-S3-ubuntu + **manually copied** `log4j-core-2.14.1.jar` in `/opt/lib` + a **shaded** uber-JAR of a small library |
| **Bakery frontend** (React/Vite) | N-S1 | S1 | source with `package-lock.json` |
| | N-S1-nolock | S1 | same, lockfile removed (manifest-only) |
| | N-S2 | S2 | `dist/` bundle (minified JS) |
| | N-S3-nginx | S3 | `nginx:alpine` serving `dist/` (no `node_modules`) |
| | N-S3-node | S3 | `node:22-slim` with full `node_modules` (dev server) |
| **Log Anomaly** (Python) | P-S1 | S1 | repo as committed (unpinned `requirements.txt`) |
| | P-S1-pinned | S1 | same + `requirements.lock.txt` from `pip freeze` |
| | P-S3-pred / drift / front / ml | S3 | the **4 original Dockerfiles, unchanged** (`python:3.11-slim`) |
| | P-S3-distroless | S3 | prediction service, multi-stage → `distroless/python3` |
| | P-S3-alpine | S3 | prediction service on `python:3.11-alpine` *(first to cut if musl wheels fail to build)* |
| | P-P | P | P-S3-pred + **curl-downloaded static binary** (e.g. `jq`) + a **vendored pure-Python module** copied into the app |
| | M-S3 | S3 | `mongo:6.0` data-store image from the project |
| **TCP server** (C) | C-S1 | S1 | source + committed Mach-O binaries |
| | C-S2 | S2 | ELF `server` built with gcc (dynamic, glibc) |
| | C-S3-debian | S3 | `debian:bookworm-slim` + dynamic binary |
| | C-S3-alpine | S3 | `alpine` + musl dynamic binary |
| | C-S3-scratch | S3 | `scratch` + **static** musl binary |
| | C-P | P | copy of the project + **vendored cJSON source** + **zlib built from source, statically linked** |
| **OS baselines** | O-debian / O-ubuntu / O-alpine / O-ubi / O-distroless | S3 | plain base images (dpkg, apk, rpm, distroless `status.d`) |

**Runs:** 32 targets × 3 tools × 2 formats (CycloneDX 1.6, SPDX 2.3) ≈ **190 SBOMs**. CycloneDX runs are repeated once more for the determinism check, giving ~290 tool runs in total. These run in minutes, not hours.

---

## 4. How the pipeline works

### 4.1 Tool invocation (identical input for all tools)

| Target kind | Syft | Trivy | cdxgen |
|---|---|---|---|
| dir (S1, N-S2) | `syft dir:/src` | `trivy fs /src` | `cdxgen -r /src` |
| file (fat JAR, ELF) | `syft file:/a/app.jar` | `trivy rootfs /a` | `cdxgen /a` (dir containing the file) |
| image | `syft docker-archive:/img.tar` | `trivy image --input /img.tar` | `cdxgen -t docker /img.tar` (or `-t oci`; checked Day 1) |

- **Default settings** are the main condition. Then one **"best-effort"** run per tool (Trivy `--include-dev-deps`, Syft `--select-catalogers +all`, cdxgen `--deep`) separates *capability* from *defaults*.
- Every run logs: tool version + digest, command, exit code, wall time, stderr. A crashing tool counts as a finding, not a failure.

### 4.2 Ground truth: read from authoritative sources, never from the tools

| Layer | How `extract_gt.py` gets it |
|---|---|
| deb | parse `/var/lib/dpkg/status` + `status.d/*` (distroless) from the exported rootfs |
| apk | parse `/lib/apk/db/installed` |
| rpm | `rpm -qa --root` in a UBI helper container |
| Java | `META-INF/maven/**/pom.properties` of every JAR in `BOOT-INF/lib` or `lib/`, cross-checked against `mvn dependency:list -DincludeScope=runtime` saved during the build |
| npm (installed) | every `node_modules/**/package.json` |
| npm (bundled `dist/`) | build once **with sourcemaps**. The `node_modules/<pkg>` paths in the sourcemaps list exactly which packages were bundled. The `.map` files are then deleted from the shipped image. |
| Python | `site-packages/*.dist-info/METADATA` + files under `*.libs/` (OpenBLAS, gfortran, gomp vendored in wheels) |
| C | `readelf -d` NEEDED libraries → owning package from dpkg/apk file lists. Static builds: from the build recipe (musl, zlib versions). |
| Runtimes outside the package manager | CPython in `/usr/local` (python images), JDK in `/opt/java/openjdk` (temurin `release` file), Node in `/usr/local` |
| Planted | `planted.json`, written when we plant them |
| Source stage (S1) | resolved runtime closure (Maven resolve, `npm ls --omit=dev`, `pip install --dry-run --report`), with dev/test **scopes reported separately** |

Every ground-truth record is labelled with an **inclusion mechanism**: os-pm, lang-pm, nested-jar, layered-jar, bundled-js, wheel-vendored-so, runtime-outside-pm, static-link, vendored-source, manual-download, manual-copy, foreign-binary. These labels make RQ3 a direct group-by.

### 4.3 Matching and metrics

- Normalise everything to PURL (`packageurl-python`):
  - PyPI names per PEP 503
  - Maven namespace/name
  - npm scopes
  - deb/apk/rpm: name + version, with epoch and release handled per distro
- **Strict** match = type + namespace + name + version. **Lenient** match = name only. Every normalisation rule is logged.
- Per target × tool × mechanism: TP/FP/FN → precision, recall, F1. Also pairwise Jaccard, duplicate rate, and determinism (whether two runs give identical component sets).
- RQ4 (on matched components): version correct, PURL valid and correct type, license matches ground truth (Java/Python/npm/apk/deb where available), hash matches the file's real SHA-1/SHA-256, CPE present and well-formed, CISA-2025 elements present (incl. Generation Context).
- Statistics: Friedman test + effect size across tools. Small-n results are reported descriptively, without overclaiming.
- *(Optional RQ5)* run Grype and `trivy sbom` on each SBOM. Does the planted `log4j-core 2.14.1` (Log4Shell) get flagged?

---

## 5. Day-by-day plan

Each day ends with a **checkpoint**. If it isn't met, apply the cut list (§6) before moving on.

### Day 1 (Mon 23 Nov) — Testbed: everything builds
- Repo skeleton, `.gitignore`/`.gitattributes` (LF line endings for shell files), Python venv + `requirements.txt`
- Pull and **pin** Syft, Trivy and cdxgen images by digest. Smoke-test each on one image tar and one directory.
- Write all Dockerfiles in `variants/`, `targets.yaml`, `build_targets.py`
- Build every image → `docker save` + `docker export`
- **Checkpoint:** all ~32 targets exist as dir, file or tar. Known build problems (Java 25 distroless, Alpine scikit-learn) are fixed or logged and cut.

### Day 2 (Tue 24 Nov) — Data: SBOMs + ground truth
- `run_tools.py`: full matrix, both formats, repeat runs, logs
- `extract_gt.py` for every layer and mechanism (§4.2)
- Hand-check the ground truth for 3 targets (one per ecosystem) to make sure it's right
- **Checkpoint:** `sboms/` (~290 files) + `ground_truth/` (32 files) complete. Ground truth verified on 3 targets.

### Day 3 (Wed 25 Nov) — Analysis: RQ1 + RQ2
- `normalize.py` + `score.py` → `results/metrics.csv`, `results/misses.csv`
- RQ1 tables (tool × ecosystem P/R/F1). RQ2 figures (recall by stage, base-image comparison).
- Writer starts: Introduction, Background, Related Work (from the literature review), Methodology
- **Checkpoint:** RQ1 and RQ2 numbers final. First 4 paper sections drafted.

### Day 4 (Thu 26 Nov) — Analysis: RQ3 + RQ4 (+ RQ5)
- RQ3: group misses by inclusion mechanism. For each (tool, mechanism) cell, find the root cause in the tool's docs or source (cataloger, analyzer, default flag) and confirm it with the best-effort run.
- RQ4: field-correctness table and CycloneDX vs SPDX comparison
- RQ5 only if on schedule
- `figures.py` → all figures and tables into `paper/`
- Writer: Results section (RQ1–RQ4)
- **Checkpoint:** all results final. Every figure and table in the paper.

### Day 5 (Fri 27 Nov) — Paper: complete first draft
- Discussion, **Practitioner Guide** (decision matrix: artifact type → tool + flags, or merging tools), Threats to Validity, Conclusion, Abstract
- Replication package: `run_all.ps1` re-runs end to end. README with exact versions and digests.
- Internal team read-through, then **send the draft to the professor**
- **Checkpoint:** PDF sent to the professor. Repo ready to push (only after your approval).

### After Day 5
Professor review → revise → repeat → submit to EMSE SECUTE (+ arXiv preprint) as soon as the professor approves, well before the end of December.

---

## 6. Cut list (drop in this order if behind)

1. RQ5 (vulnerability-scan impact)
2. `P-S3-alpine` (musl wheel builds are the riskiest)
3. Best-effort configuration runs (keep defaults only)
4. Dependency-edge correctness in RQ4 (keep version, PURL, license, hash)
5. Determinism repeat runs
6. SPDX output (keep CycloneDX only, and drop the format part of RQ4)

RQ1–RQ3 and the lifecycle comparison are the **core contribution** and are never cut.

---

## 7. Who does what in the 5 days

| Member (P16 role) | Days 1–2 | Days 3–4 | Day 5 |
|---|---|---|---|
| **Testbed & Implementation** | Write and review Dockerfiles and variants. Re-run the build on a second machine (reproducibility). | Investigate failing builds or tool crashes | Replication README, `run_all.ps1` check |
| **Measurement & Analysis** | Hand-verify ground truth on 3 targets | Root-cause triage for RQ3 (read Syft/Trivy/cdxgen docs and source). Check the numbers. | Results text, figure captions |
| **Related Work & Writing** | Set up the Springer template. Turn the literature review into Related Work + Background. | Introduction, Methodology, Results text | Discussion, Practitioner Guide, Threats, Abstract, full proofread |

The Testbed & Implementation member writes the scripts and Dockerfiles and runs the pipeline. All three members review and verify the results and own the final text.

---

## 8. Progress log

### Day 1 — done (22 Nov, finished ahead of schedule)

**Status: 32 of 33 targets built, one cut as planned. Cross-verification: 205/205 checks pass** (`results/verify_build.json`).

| Item | Result |
|---|---|
| Tools pinned (`tools/versions.lock`) | **Syft 1.57.2, Trivy 0.76.2, cdxgen 13.2.0**, by image digest |
| Base images | All 16 pinned by the digest each build actually resolved (`results/build_manifest.json`) |
| Targets | 23 images (2.5 GB), 3 S2 artifacts, 6 source trees. The corpus is byte-identical to the originals (checked file by file). |
| Smoke test | All 3 tools ran on all 3 input types (image tar, JAR, directory) and produced valid CycloneDX |

**Decisions and changes made on Day 1:**
1. **CycloneDX 1.7, not 1.6.** All three tools now default to 1.7, so we use every tool's default spec version instead of forcing a downgrade.
2. **`P-S3-alpine` cut.** scikit-learn has no musllinux wheel, so pip tries a source build and fails without a compiler. Adding a toolchain would change the image under test. **This is a finding for the paper:** the project cannot be moved to Alpine without a toolchain.
3. **Planted zlib now exercised realistically.** The hook calls `compress2`/`uncompress`, so the binary carries the `deflate/inflate 1.3.1` version banners a real static zlib user would have. With only `zlibVersion()`, the linker kept a tiny fraction of the library.

**Bugs found by cross-verification and fixed before they could affect results:**
1. **Windows long paths.** Corpus files are up to 275 characters deep and `LongPathsEnabled=0`, so Python silently skipped 63 backend `.java` files. All scripts now use `\\?\` extended-length paths. No system setting was changed. Docker and containers were never affected.
2. **Hidden-file names.** `lstrip("./")` turned `.dockerenv` into `dockerenv`. Fixed with `removeprefix`. This matters for ground truth.
3. **`docker export` placeholders.** Every export contains empty `.dockerenv`, `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf`. They are not part of the image and must be ignored by ground truth (`EXPORT_INJECTED` in `verify_build.py`).
4. **Silent drift risk.** `--force` used to rebuild buildinfo too. The unpinned pip resolution could then drift from `P-S1-pinned`. Now a separate `--force-buildinfo` flag is required, and the verifier checks that the pins match the reports and that the reports match what each image installed (all equal today).

**Notes for Day 2:**
- **Trivy downloads its ~958 MB Java DB on every run** unless it is cached. We download it once into a shared cache, then run with `--skip-java-db-update` so every scan uses the same DB. The DB version is recorded.
- **Component filtering.** Syft and cdxgen also list *files* as CycloneDX components (≈3,000 and ≈1,500 on a Debian image). Scoring counts only package components (`library`, `application`, `framework`, plus OS where relevant).
- **Maven `dependency:list` lines** may end in `(optional)` and `-- module …`. The parser must strip both.
- **Before the first commit**, run `git config core.longpaths true` in this repo, otherwise git can't add the deep corpus files. Commits only with the user's approval.

### Day 2 — in progress (23 Nov)

**Built:** `run_tools.py` (full matrix runner), `extract_gt.py` (ground truth), `verify_gt.py` (independent oracles),
`ident.py` (shared identity normalisation), `normalize.py` (CycloneDX 1.7 / SPDX 2.3 / SPDX 3.0.1 parser +
determinism), and `score.py` (matcher, pulled forward from Day 3).

**Ground-truth verification: 79/79 oracle checks pass** (`results/verify_gt.json`):
- Every OS-package set equals the image's own `dpkg-query` / `apk info` / `rpm -qa`.
- Python equals `pip list`, and npm equals `npm query '*'`.
- Our Go build-info parser equals the official `go version -m`, and our ELF parser equals `readelf`.
- Fat JAR = Maven runtime list minus documented exclusions.

**Ground-truth bugs found by the checks and fixed:**
1. **Many JARs have no `pom.properties`** (Spring, Hibernate and MySQL Connector are not built with Maven). The extractor's fallback gave no groupId, and for Tomcat it gave **the Servlet spec version "6.1" instead of 11.0.22**. Fixed: version from the Maven-written filename, groupId from the build's own `mvn dependency:list`.
2. **A planted component collided with a real one.** `pip` already vendors `six 1.16.0`, so a planted `six` was indistinguishable from it. Replaced with `decorator 5.1.1`, which is present in no image.
3. **Only the first route was recorded.** `debug`, `ms` and `fdir` are both app dependencies and inside npm itself. GT now records every mechanism per component.
4. **Wheel-vendored `.so` names with two hash suffixes** were split inconsistently. Fixed.
5. **Wrong build command:** `apk info -v musl` prints the description, not the version, so the static musl version was missing. Fixed in the same build step that compiles the binary. The verifier now checks the format.

**Tool findings so far:**
- **Maven Central rate-limited Trivy** (HTTP 429, 30-minute block) while it resolved `pom.xml` parents. This is environmental, so Trivy's J-S1 runs are redone after the matrix. No other run was affected; cdxgen's concurrent J-S1 run found all 153 dependencies.
- **cdxgen's SPDX 3.0.1 export of an empty BOM fails its own validation** and aborts the whole run without writing anything. The runner keeps that failure as a finding and retries CycloneDX alone.
- **cdxgen's default mode finds nothing in a bare ELF binary**, while `-t binary` finds one component. This is a default-vs-capability gap for the best-effort runs.
- **Syft guesses Maven groupIds** for JARs without `pom.properties` and gets 21 of 109 wrong on the fat JAR (`org.hibernate` vs `org.hibernate.orm`, artifactId reused as groupId). That means wrong PURLs and missed CVE lookups (RQ4).
- **Determinism:** 92 of 95 rep1/rep2 pairs are identical. The 3 that differ (cdxgen, Java) are explained by the network finding below, not by the tool itself.

**Major finding: Java SBOMs depend silently on the network (two of three tools).**
- **cdxgen** identifies JARs without `pom.properties` by looking up their SHA-1 on Maven Central (`hash-comparison` evidence). After Maven Central rate-limited this machine, **every lookup failed silently**: no warning, exit code 0. cdxgen then fell back to guessing from the JAR MANIFEST (`manifest-analysis`, lower confidence) and produced different groupIds (`com.mysql` → `com.mysql.cj`, `io.micrometer` → `micrometer-commons`). Measured from its evidence fields: 45 hash identifications per run before the block, 39 at the start of it, then 0.
- **Trivy** resolves `pom.xml` parents and BOMs from Maven Central at scan time. While blocked it **fails hard** (exit 1, no SBOM) instead of degrading.
- **The block is per user agent:** Go- and Node-based clients get 429 while normal `curl` from the same IP gets 200.
- **Root cause of cdxgen's silence (from its source, `lib/ecosystems/ecosystems.js`):**
  - Each unidentified JAR costs one request to `central.sonatype.com/solrsearch` (SHA-1 query), with no cache and a 1-second response timeout.
  - `MAX_SEARCH_MAVEN_ORG_ERRORS = 1`: one failure disables lookups for the rest of the run.
  - When rate-limited, Central answers **HTTP 404 with `Retry-After: 2684`**, a block disguised as "not found". The legacy `search.maven.org` still answers 200.
  - cdxgen deliberately ignores 404s (`!err.message.includes("404")`), so it **never prints its own "Maven search appears to be unavailable" warning**. That message appeared in none of the 14 Java logs.
- **cdxgen trips the limit itself.** In the first re-run attempt, only 2½ back-to-back Java scans got their online identifications (45, 45, then 34) before the block returned. Any CI pipeline that scans a few Java images in a row will degrade silently.
- **Syft** made no network requests in its default mode and was unaffected.
- **Handling:** the degraded cdxgen runs are kept as a separate condition, `netblocked` (9 SBOMs, via `snapshot_netblocked.py`), so the paper can quantify the silent loss. Clean online runs come from `rerun_online.py`: one job per ~50-minute window, each gated by a probe that sends the exact request cdxgen makes, and **verified afterwards** (more than 0 `hash-comparison` identifications, otherwise retried). Trivy's J-S1 goes first in a quiet window. This runs unattended for several hours.
- **Paper implications:** threat to validity (scan results depend on registry availability and rate limits), RQ4 (identity correctness changes with the network), and practitioner guide (cache `~/.m2`, check identification evidence, or run offline-by-design tools).

**Completed after the matrix (all 227 tool jobs done):**
- Rebuilt P-P (planted `decorator`), C-S3-alpine and C-S3-scratch (correct musl version) and re-scanned them. `verify_build` **206/206**, `verify_gt` **79/79**.
- All **282 SBOMs parse** (0 unparseable). Scoring covers all 266 package-bearing SBOMs.
- cdxgen's empty-SPDX abort reproduced on all 3 targets with 0 components (C-S1, C-S2, N-S2). The CycloneDX fallback captured each.

### Day 2 close-out (23 Nov, early morning)
- **Trivy J-S1 done** (113 components, both reps identical) with a local Maven repository pre-populated by `mvn dependency:resolve` (`work/cache/m2`, mounted read-only). This is exactly what Trivy's own 429 error message recommends. Maven's own client was never blocked. Probes showed only Trivy's Go client and cdxgen's Node client were.
- **The paced cdxgen online re-runs died once** when the machine slept and Docker Desktop stopped (exit 4, nothing in the log). Docker was restarted, keep-awake was enabled, and `rerun_online.py` now waits for Docker instead of dying. Results so far: J-S2, J-S3-ubuntu, J-S3-alpine, J-S3-distroless and J-S3-layered rep1 are all **verified online (45 hash identifications each)**. J-P rep1 and the six rep2 runs continue in the background (~50 min each).

### Day 3 — analysis (23 Nov)

**False-positive audit (before any number is reported).** The first scoring showed cdxgen with 948 "FPs". Every cluster was traced to its cause and fixed at the right level:

| Cluster | Cause | Fix |
|---|---|---|
| deb 523 / apk 35 / rpm 30 (`glibc`, `bzip2`, `audit`…) | cdxgen lists **source packages** next to binaries | GT: secondary `source-package` records from the DB's own `Source:` / `o:` / `SOURCERPM` fields |
| cargo 320 (`syn`, `pyo3-ffi`…) | **PEP 770 SBOMs embedded in wheels** (pydantic-core 101 crates, rpds-py 17, Pillow, auditwheel). Real code compiled into extensions, read only by cdxgen. | GT: new primary mechanism `wheel-embedded-sbom`. auditwheel entries *enrich* the matching `.so` record with its exact version instead of double counting. |
| npm `js-yaml` (all 3 tools) | mongo image unpacks js-yaml by hand into `/opt/js-yaml` | GT gap: new mechanism `manual-install` |
| Trivy `requirements.txt`, `usr/bin/mongodump`… | Trivy's **grouping nodes** (`application`, no purl, `aquasecurity:trivy:Class`) | normaliser drops them, counted as `trivy-aggregation-node` |
| cdxgen `libjpeg%2520…` | cdxgen **double-encodes** purls | normaliser decodes for matching (an RQ4 defect) |

Result: main-condition FPs went from 1,022 to **75 genuine ones**: Syft reports setuptools' Windows `.exe` launchers and names the app `JarLauncher/app`; cdxgen parses Meson build files inside numpy/scipy wheels as projects.

**Further GT and matcher bugs found by the new checks** (each now guarded by a permanent check in `verify_gt.py`, **146/146 pass**):
1. **Matcher collision.** A binary rpm `1:4.8.0-7.el9` and its source package `4.8.0-7.el9` normalise to the same identity, and the lookup kept the secondary one. So all 3 tools were wrongly charged with 3 misses on UBI. Primary now always wins, and the extractor no longer creates epoch-only twins.
2. **Planted yq recorded twice.** Its Go build info says `(devel)` (the release number is injected by ldflags), so it was recorded once without a version and once as v4.44.3 from `planted.json`. Now merged.
3. **Pillow libraries recorded twice** (versionless `.so` + versioned embedded-SBOM entry). Exact-name matches now merge.
4. **Mechanism attribution.** Secondary echoes (source-package, archived wheel, embedded pom) were being credited as inclusion routes of primary components in RQ3. Only same-tier routes count now.

**Independent cross-check of the scorer:** a separate ~30-line re-implementation (plain set arithmetic, no shared code) reproduces the GT counts and strict hits of `score.py` exactly for 6 SBOMs. The only differences are cdxgen's purl-less Go `stdlib` entries, which `score.py` correctly aliases.

**Outputs:** `scripts/analyze.py` → `results/tables/*.csv` (RQ1 overall, by layer, per target, Friedman test; RQ2 lifecycle; RQ3 by mechanism for images vs source/artifact, planted cases; RQ4 field correctness, document elements, CDX-vs-SPDX agreement; network condition; determinism). `scripts/figures.py` → `paper/figures/fig_rq1_layers`, `fig_rq2_lifecycle`, `fig_rq3_mechanisms` (PDF + PNG). Palette validated with the dataviz validator: CVD-safe for all pairs, plus marker shapes for print.

### Day 3 — final results review (23 Nov, after all paced re-runs)

**Data is final.** All 12 default-config cdxgen Java SBOMs are verified online (45 hash identifications each), and all 9 `netblocked` ones are verified degraded (0). All verifiers pass on the final data: `verify_build` 206/206, `verify_gt` 146/146. 297 SBOMs parse with 0 failures.

**Determinism: 99/99 repeat pairs identical.** Once network state is controlled, all three tools are deterministic. The earlier differences were entirely Maven Central's rate limiting.

**Fixed during the final review:**
1. **Go `(devel)`** (Go's "no version recorded") was kept as a literal version string, so mongo-tools counted as a version mismatch for every tool. It is now treated as no version on both sides.
2. **Statistics at the right unit.** The per-image Friedman test is not significant (p = 0.157), because all tools are perfect on the OS layer that dominates every image. Added component-level paired tests: Cochran's Q plus pairwise exact McNemar with Holm correction.
3. **A NaN-vs-None key mismatch in the new tests** counted versionless all-missed components as found. Fixed. Q did not change, which a first-principles recomputation confirmed: rows found by all or by none cancel out of Q, and the bug touched only those rows.
4. **The format-agreement metric** compared raw package counts. Trivy's SPDX grouping nodes were not dropped symmetrically with CycloneDX. It now compares purl identities with the same rules for both formats.

**Final headline numbers (23 images, default config, rep 1, CycloneDX):**

| | Syft | Trivy | cdxgen |
|---|---|---|---|
| Recall, strict (lenient) | 0.815 (0.849) | 0.843 (0.846) | **0.937** (0.939) |
| Precision, strict (lenient) | 0.942 (0.982) | **0.996** (1.000) | 0.986 (0.995) |
| Components only this tool finds (vs Syft / Trivy / cdxgen) | — / 12 / 46 | 100 / — / 34 | 433 / 333 / — |

Cochran's Q = 515.5 over 3,162 components (p ≈ 1e-112). Every pairwise McNemar test is significant after Holm correction.

- **By layer:** all tools are perfect on OS packages (1,648) and equal on npm (0.976; the misses are the 6 bundled packages) and Go (0.978; the misses are yq's ldflags version). Java: Syft 0.80 (groupId guessing) vs 0.98 for the other two. Python: cdxgen 0.84 (misses `pip --target` installs in distroless). Native/vendored: 0.00–0.14 for everyone.
- **RQ3, shared blind spots:** bundled JS, statically linked C, vendored source and wheel-vendored `.so` (cdxgen 0.18 via auditwheel only). **Unique strengths:** cdxgen alone reads wheel-embedded SBOMs (0.76); Syft alone sees tarball runtimes (0.64) and the static `jq`; Syft and Trivy alone see shaded JAR contents (cdxgen reports only the uber-JAR itself).
- **RQ2:** from Java source, recall is Syft 0.03 / Trivy 0.72 / cdxgen 1.00. npm with a lockfile: 0.35 / 0.35 / 1.00 (Syft and Trivy drop dev dependencies); without a lockfile: 0 / 0 / 0.43. The bundle and nginx image are 0 for everyone; the node image is 1.0 for everyone. Unpinned Python: 0 / 0 / 0.92, with cdxgen resolving versions inside *its own* Python environment.
- **RQ4:**
  - **CPE:** Syft 99.5%; Trivy and cdxgen emit no CPEs at all.
  - **JAR hashes:** Syft and Trivy are 100% correct where present; cdxgen emits none for JARs.
  - **License:** cdxgen is present on only 36%, but 93% correct where comparable; Syft 82% and Trivy 78% correct.
  - **Document elements:** only cdxgen sets SBOM author and the lifecycle phase (CISA "Generation Context").
  - **Formats:** Syft and Trivy SPDX = CycloneDX identities in 100% of targets. cdxgen SPDX 3.0.1 matches in only 48% (Jaccard 0.99) and turns non-packages into purpose-less packages in 19/29 targets.
- **Network:** when Maven Central blocks it, cdxgen's Java recall drops silently from 0.980 to 0.922 and precision from 0.990 to 0.931.

### Day 4 — extras: best-effort configuration + RQ5 (24 Nov)

**Status:** both extras are complete and verified. `verify_build` 206/206, `verify_gt` 146/146, 487 SBOMs parse (0 failures), 99/99 repeat pairs identical, 184 RQ5 scans (4 documented aborts).

**Best-effort configuration** (`--config best`, rep 1, all 32 targets; flags verified present in every recorded command):

| Tool | Options |
|---|---|
| Syft | `--override-default-catalogers all` plus its documented opt-ins (default off per `syft config`): transitive Maven resolution from the local Maven repository, npm dev dependencies, guessing unpinned Python versions |
| Trivy | `--detection-priority comprehensive`, plus `--include-dev-deps` on source directories (the flag exists only for `trivy fs`) |
| cdxgen | `--deep`. Java image jobs paced and verified online (45 hash identifications each). |

Results (micro, strict):

| | Images: recall / precision, default → best | Source + artifacts: recall / precision, default → best |
|---|---|---|
| Syft | 0.815 → 0.818 / 0.942 → 0.927 | **0.30 → 0.66 / 0.84 → 0.59** (transitive Maven resolution over-reports: 380 components vs 153 in GT) |
| Trivy | 0.843 → 0.843 / 0.996 → 0.996 | 0.53 → 0.64 / 0.99 → 0.99 |
| cdxgen | **identical** | 0.874 → 0.852 / 0.865 → 0.879 |

- **Tuning fixes none of the image blind spots.** `--deep` changes cdxgen's package set on only 3 of 32 targets: the C source tree (27 source-file names reported as components, all false positives) and the two no-lockfile/unpinned targets.
- **Registry drift.** cdxgen's lower source recall comes from *time*, not from `--deep`. On targets without a lockfile it installs dependencies itself, and hours later the registries served newer versions (`charset-normalizer` 3.5.2 → 3.5.3). SBOMs built from manifests without a lockfile are not reproducible over time.
- **Syft's `guess-unpinned-requirements`** guesses only from a version constraint (`streamlit>=1.29.0` → 1.29.0, not the installed version); bare names stay unreported.

**RQ5: vulnerability impact** (`scripts/vuln_scan.py`). Grype 0.122.1 and Trivy 0.76.2, both on frozen DB snapshots.
- **Reference SBOM** = primary GT components written in **each scanner's native conventions** (Grype: purl `upstream` qualifier; Trivy: `aquasecurity:trivy:Src*` properties, `redhat` family, Debian point release, Go stdlib `v1.x`).
- **Validated against direct image scans:** identical CVE sets (Jaccard 1.000) for both scanners on O-debian and J-P.
- Building the reference exposed three convention mismatches; each is now handled and documented.

| Scanner ← SBOM | Syft | Trivy | cdxgen |
|---|---|---|---|
| Grype, CVE recall | **0.995** | 0.41 | 0.99 |
| Trivy, CVE recall | 0.35 | **0.994** | 0.09 (4 of 23 scans aborted) |
| OS-package findings (Grype / Trivy) | 1.00 / 0.11 | 0.13 / 1.00 | 0.13 / 0.00 |
| Application-package findings (Grype / Trivy) | 0.98 / 0.97 | 0.98 / 0.97 | 0.97 / 0.51 |

- **Main RQ5 result:** cross-vendor loss is almost entirely on **OS packages**, and it is a metadata-convention problem, not a coverage problem. All tools list 100% of the OS packages; what is lost is the vendor-private binary-to-source-package link that distro security data needs. In the O-debian trial, 100% of the lost findings were on packages whose source name differs from the binary name.
- **Trivy aborts** on cdxgen SBOMs that contain both deb and rpm entries (auditwheel data copied from inside wheels). The result is zero vulnerabilities reported on 4 Python images.
- **Log4Shell** (CVE-2021-44228, planted in J-P) is flagged by all 6 SBOM-scanner pairs.

**Root-cause analysis:** `docs/ROOT_CAUSES.md`. Every claim is backed by the tool's own configuration dump, cataloger list or source code (e.g. cdxgen `docker.js` looks only in directories named `site-packages`; `getPomPropertiesFromMavenDir` reads only `pomPropertiesFiles[0]`).

**Infrastructure fixes:**
- `run_tools.py` now merges records under an inter-process lock (stress-tested: 2 concurrent writers × 40 records, all 80 kept), so paced and bulk runs can run side by side.
- RQ5 counts aborted scans as zero instead of silently dropping them, in both the summary and the per-layer table.

**New outputs:** `results/tables/best_vs_default*.csv`, `rq5_*.csv`, `rq1_component_tests.csv`; `paper/figures/fig_rq5_scanners`, `fig_best_vs_default`; `tools/versions.lock` now also pins Grype and both vulnerability-DB snapshots.

## 9. Main risks for the 5-day schedule

| Risk | Mitigation |
|---|---|
| Java 25 / Spring Boot 4.1 not supported by a tool or base image | Logged as a finding. Java 21 fallback image only for the distroless variant. |
| cdxgen image scanning is slow or needs the Docker socket | Use the tar input. If needed, give it the exported rootfs instead (documented as a deviation). |
| Ground-truth bugs silently distort every number | Day 2 hand-verification on 3 targets. Lenient + strict matching. Every normalisation logged. |
| Windows-specific issues (CRLF, paths with spaces) | All tools and builds run in Linux containers. `.gitattributes` forces LF. Paths are quoted. |
| Running out of time for writing | Writing starts on Day 3 in parallel. Draft sections come straight from the literature review and the methods in this plan. |
