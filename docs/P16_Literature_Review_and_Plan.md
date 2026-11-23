# P16 — SBOM Generators Compared: Literature Review, Research Gap & Project Plan

*Draft for team review — 22 Nov 2026. Nothing has been built or committed yet.*

---

## 1. What the literature already covers

The field is **crowded in 2026**. A plain "run Syft/Trivy/cdxgen on some repos and count components" study is already published several times. We need a clear new angle. Every paper below was checked online. Items marked *(verify)* still need an exact title or venue check before we cite them.

### 1.1 Studies that compare SBOM generators

| # | Paper (venue, year) | Tools | What they scanned | Ground truth | Key finding | What it does **not** do |
|---|---|---|---|---|---|---|
| 1 | Balliu et al., *Challenges of Producing SBOM for Java*, **IEEE S&P Magazine 21(6), 2023** | cdxgen, CycloneDX-Maven-plugin, Depscan, jbom, OpenRewrite, Build-Info-Go | 26 Java/Maven **source** projects | `mvn dependency:tree` | Large precision/recall gaps. Tools are not reproducible. Scope fields are unreliable. | No Syft/Trivy, no images, no OS packages |
| 2 | Yu et al., *On the Correctness of Metadata-Based SBOM Generation*, **IEEE/IFIP DSN 2024** | Trivy, Syft, MS sbom-tool, GitHub Dependency Graph | ~7.8k repos, 9 languages (**source**) | Mostly differential (no GT). pip dry-run GT for requirements.txt | Low Jaccard agreement. On requirements.txt, Trivy/Syft recall is only 0.10. Introduces a "parser confusion" attack. | No cdxgen, no images, C/C++ excluded |
| 3 | Rabbi et al., *SBOM Generation Tools under Microscope: npm*, **ACM SAC 2024** | ORT, cnn, Syft, cdxgen | 50 npm projects | Manual / package manager | Wide variation, especially in dependency relationships | Single ecosystem, source only |
| 4 | Cofano, Benedetti, Dell'Amico, *SBOM Generation Tools in the Python Ecosystem*, arXiv 2409.01214, 2024 *(verify venue)* | Trivy, Syft, cdxgen, ORT | Python projects | Environment-based | Metadata parsing gaps in Python | Python only, source only |
| 5 | Benedetti et al., *Impact of SBOM Generators on Vulnerability Assessment in Python*, arXiv 2409.06390, 2024 | cdxgen, ORT, Syft, Trivy, GH-sbom (+ their PIP-sbom) | Python repos | pip resolution | Low tool agreement (Jaccard 24–50%) | Python only |
| 6 | O'Donoghue et al., *Impacts of SBOM Generation on Vulnerability Detection*, **ACM SCORED 2024** | Syft, Trivy (CycloneDX + SPDX) | 2,313 Docker Hub **images** | **None** | Changing the generator changes the number of reported CVEs a lot. Same-vendor pairs report more. | No ground truth, no cdxgen, no root-cause analysis |
| 7 | Montana State group, *SBOM generation tools and formats affect [NTIA compliance]*, **MSR4PS 2025** *(verify title)* | Syft, Trivy | 2,225 Docker images | sbomqs score | Compliance scores depend on tool × format | Measures field presence, not component accuracy |
| 8 | **SBOMproof**, arXiv 2510.05798, 2025 | Syft/Grype, Trivy, Docker Scout, sbom-tool, AWS/GCP/Azure | Debian + Alpine images | dpkg/apk database | Tools disagree on package identity. Introduces the "SBOM confusion" vulnerability. | **OS packages only**, no language packages, no cdxgen |
| 9 | *Effectiveness of SBOM Tools for Manually Installed Packages in Docker*, **JISIS 2024** | 2 OSS tools | 3,500+ images | Manual analysis | 51% of images contain manually installed software. Tools miss 30–70% of it. | Only covers manually installed software |
| 10 | Zhou, Dacier, Konstantinou, *A Reality Check on SBOM-based Vulnerability Management*, **ACM CODASPY 2026** | Syft, Trivy (+ Grype) | Python/Rust/Ruby/PHP repos | Lockfiles | Lockfile → SBOM is 100% accurate. Vulnerability scanners have a 92% false-positive rate. | Source only, lockfiles only |
| 11 | Wu et al., *More than Meets the Eye: Evaluating SBOM Tools in Java*, **ACM TOSEM 2026** | sbom-tool, Syft, Trivy, SPDXGen, cdxgen, Dependency-Track | 132 Maven projects | Maven resolution | Component F1: Syft 41%, Trivy 47%, cdxgen 83% | Java only, source only |
| 12 | Wang et al., *Adherence Gap between Standards and Tools in SBOM* (SAP), **ACM TOSEM 2026** | 6 tools | 3,287 repos, 55k SBOMs, 1-year longitudinal | Partial | Tools agree with each other only 7.8–12.8% of the time. License accuracy is below 20%. Tools disagree with their own earlier versions. | Source repos, standards focus |
| 13 | Prado et al., *Mind the Gap: SBOM Specification Ambiguities…*, arXiv 2609.19920, **Sept 2026** | **Syft 1.38.2, Trivy 0.68.2, cdxgen 12.0.0** (our exact three) | 2,050 JS + 1,276 Rust repos | Lockfiles | JS coverage: Syft 44%, Trivy 33%, cdxgen ~99%. Most differences are design choices, not bugs. | **Source only, JS/Rust only. Their RQ3 measures field *presence*, not *correctness* (their own stated limitation)** |
| 14 | Reichmann et al., *Poking Around in the Dark: Why a Shared Understanding of Components Matters*, arXiv 2606.02442, 2026 | cdxgen, Syft, Trivy, ORT, sbom-tool | Python, Java, Go, PHP, Rust, **C** | Constructed test cases | Defines "Component Inclusion Mechanisms" (CIMs). No tool covers all of them. | Source-level. No container images or OS layer. |

### 1.2 Adjacent work (background and motivation)

- **Sahay et al., *Over the Shoulder: SBOMit*, ACM SCORED 2026**: builds SBOMs by watching the build with eBPF. Shows static tools miss build inputs (98 CNCF projects). It does run Syft and Trivy on source *and* build artifact, but the authors state the comparison *"is qualitative and is not intended to establish accuracy scores or tool rankings."* No cdxgen and no container-image stage.
- **Reddypalle, Roellke, Torres-Arias, *Software Dark Matter*, arXiv 2606.13966, 2026**: defines files in an artifact that no package metadata accounts for, with a tool called DARKFILES. It is a metadata-gap measurement, not a three-tool accuracy comparison. Cite it for RQ3.
- **Halbritter et al., *Accuracy Evaluation of SBOM Tools for Web Applications and System-Level Software*, ARES 2024** (ACM, DOI 10.1145/3664476.3670926): small hand-checked projects, source level. Cite it in related work.
- **Chain-of-Experts (CoE), arXiv 2408.16198, 2024**: reverse-engineers SBOMs from bundled JavaScript using ML clone search. It confirms that standard tools can't see npm code once it is bundled, but does not test Syft/Trivy/cdxgen. Supports our Bakery-frontend case.
- **Bufalino, Blaise, Secci, *ORCA*, ACM SCORED 2025**: "obscured" containers that hide their contents from scanners (600 images).
- **Liu et al., C/C++ binary third-party-library detection, FSE 2026 (PACMSE)**: 11 tools, average recall below 60%. Supports including a C subject.
- **Endor Labs, *SBOM vs SBOM* (blog, 2023)**: the *only* lifecycle-stage comparison we found (source → build → image), and it covers **a single Spring Boot app** and is not peer reviewed. It is direct motivation for our RQ2.
- **CISA 2025 draft minimum elements**: adds *Generation Context* (before, during or after build), *Component Hash* and *License*. This gives a timely, standards-based hook for our lifecycle angle.
- **ENISA, *SBOM Adoption State of Play 2026***: 62% of organisations say SBOM completeness is hard. Respondents explicitly ask for *"a guide navigating tool selection based on evaluations and benchmarking"*. That is our practitioner guide, motivated by a regulator.
- **Systematic literature reviews**: O'Donoghue et al. 2025 (arXiv 2506.03507, 40 studies). Mydin et al., *SBOM Tooling Ecosystem: An SLR*, Applied Research (Wiley) 2026. Background: Xia et al. ICSE 2023; Stalnaker et al. *BOMs Away!* ICSE 2024; Nocera et al. MSR 2023 *(verify last three)*.
- **Benchmark to reuse**: DeepBits `sbom-benchmark` on GitHub, from paper #2.

---

## 2. The research gap: what is still open

Taken together, prior work has these blind spots:

1. **Source vs. image.** Nearly all studies with a ground truth (1–5, 10–14) scan **source repositories**. The image studies (6–9) either have **no ground truth** (6, 7), cover **OS packages only** (8), or cover a single mechanism (9).
2. **No lifecycle comparison.** Nobody has measured how the **same application's** SBOM changes from **source → built artifact → container image**, or across **base images** (Debian, Alpine, distroless, scratch). The only evidence is one blog post.
3. **Polyglot images.** A real image mixes OS packages and Java, Python and native C components. No study evaluates all three tools on **both layers at once** against an exact ground truth.
4. **Field correctness.** Field checks measure *presence* (7, 12, 13). Few check whether the **version, PURL, license and hash are correct**.
5. **Hard cases in images**, such as Spring Boot nested JARs, shaded JARs, native libraries vendored inside Python wheels (`numpy.libs`), statically linked or vendored C libraries, manually downloaded binaries, and distroless images. These are documented in GitHub issues and blogs, but no study has measured them systematically with all three tools.

### Proposed angle (working title)

> **"Same App, Different SBOM: A Lifecycle-Aware, Ground-Truth Evaluation of Syft, Trivy and cdxgen on Polyglot Container Images"**

This fits P16 exactly: a corpus of images across Java, Python, C and OS packages, three tools, coverage and accuracy against ground truth, and a characterisation of misses. The new contributions are:

- **C1 — Controlled benchmark.** Reproducible Dockerfiles that vary *stage × base image × packaging* for each subject app. Each variant has an **exact, instrumented ground truth** and deliberately **planted hard-case components**. We release it as open source, which reviewers like.
- **C2 — Lifecycle and base-image effect.** The first systematic measurement of how stage and base image change each tool's recall and precision. It ties directly to CISA's new *Generation Context* element.
- **C3 — Miss taxonomy with root causes.** For every missed component we name the inclusion mechanism and the tool behaviour responsible (which cataloger or analyzer, which flag). We check this by reading the tools' source code.
- **C4 — Field correctness, not just presence**: version, PURL, CPE, license, hash, dependency edges, and CycloneDX vs SPDX output.
- **C5 — Practitioner guide**: a decision matrix ("for artifact X, use tool Y with flags Z, or merge Y+Z"), as requested by the ENISA respondents.

We cite #13 (*Mind the Gap*) as the closest work and position ourselves as its **image-level, lifecycle-level complement**, filling its stated limitations.

### Novelty re-check per research question (22 Nov 2026)

A second targeted search for each RQ found partial overlaps only. None measures what we measure:

| RQ | Closest existing work | Why ours is still new |
|---|---|---|
| RQ1 image accuracy vs. exact ground truth, OS + language layers together | SBOMproof (#8): OS only. O'Donoghue (#6): no ground truth. Vendor reports: not peer reviewed. | First peer-reviewable ground-truth study of **Syft + Trivy + cdxgen on polyglot images** (OS + Java + npm + Python + C in one corpus) |
| RQ2 same app across source → artifact → image, and across base images | Endor Labs blog (1 app, 2023). Sahay SCORED'26 (qualitative, no scores, no image stage, no cdxgen). | First **quantitative** lifecycle × base-image measurement. Tied to CISA's 2025 *Generation Context* element. |
| RQ3 miss taxonomy with root causes in images | Reichmann (#14): source-level inclusion mechanisms. Software Dark Matter: files without metadata. JISIS'24: manual installs only. | Inclusion mechanisms **as they appear in built images** (nested/layered JAR, bundled JS, wheel-vendored `.so`, unpinned manifest + Dockerfile-only install, static C, foreign binaries), each traced to a cataloger or analyzer in tool source |
| RQ4 field *correctness* | #7, #12, #13 measure field *presence* (#13 states this as a limitation) | Correctness of version, PURL, CPE, license, hash and dependency edges against ground truth |

**Verdict: the angle is unique enough to publish.** The main risk is a new arXiv paper appearing in the next 5 weeks, so we re-check in week 2 (§8).

---

## 3. Research questions (final, approved 22 Nov 2026)

- **RQ1 – Coverage and accuracy.** What are the recall, precision and F1 of Syft, Trivy and cdxgen on container images, per ecosystem (OS, Java, Python, C/native), against an instrumented ground truth?
- **RQ2 – Lifecycle and base-image effect.** For the same app, how do the SBOMs differ between source (with and without a lockfile), built artifact (fat JAR, venv or wheel, ELF binary) and final image? How do they differ across Debian-slim, Alpine, distroless and scratch/static bases?
- **RQ3 – Where and why tools miss components.** Which inclusion mechanisms does each tool miss, and what is the root cause in the tool?
- **RQ4 – Field and format accuracy.** How correct are the version, PURL, CPE, license, hash and dependency-relationship fields? Do the CycloneDX and SPDX outputs of the same tool agree?
- *(Optional, only if time allows)* **RQ5 – Downstream impact.** How many known CVEs are missed because of RQ3 misses? For example, a planted vulnerable `log4j-core` hidden in a shaded JAR, scanned with Grype or Trivy.

---

## 4. Experimental design

### 4.1 Corpus profile (inspected 22 Nov 2026)

The corpus folder is `Thangaraju PE/Corpus/`. Our three projects turn out to cover **four ecosystems**, because the Bakery project also has a React frontend. Each project naturally contains a hard case that prior work flagged but never measured on images:

| Subject | What is in it | Ecosystem(s) | Natural "hard case" it gives us |
|---|---|---|---|
| **Bakery backend** | Spring Boot **4.1.0**, **Java 25**, Maven wrapper, 13 direct dependencies (JPA, Security, WebMVC, Mail, mysql-connector-j, razorpay-java, jjwt ×3, springdoc). Has `test`, `runtime` and `optional` scopes (devtools, lombok). **No Dockerfile.** | Java / Maven | Scope handling: does devtools, lombok or a test dependency leak into the SBOM? Spring Boot nested JAR (`BOOT-INF/lib`) vs. exploded "layered" JAR vs. source `pom.xml` with no lockfile. Very new versions (Boot 4, Java 25). |
| **Bakery frontend** | React 19 + Vite 8. `package-lock.json` v3 with 99 packages, **64 of them dev-only**. No Dockerfile. | Node.js / npm | After `vite build`, all npm code is **bundled into minified JS** and served by nginx. The image has *no* `node_modules`, so tools can't see it. Also tests dev-dependency handling (#2 and #13 found Trivy drops dev dependencies). |
| **Log Anomaly Detection** | 4 Python microservices (FastAPI, Streamlit, scikit-learn pipeline) plus MongoDB. **5 existing Dockerfiles** on `python:3.11-slim` and `mongo:6.0`, a docker-compose file, K8s, Ansible, Jenkins. `requirements.txt` files are **completely unpinned** (`pandas`, `numpy`…). | Python / pip + OS (Debian, Ubuntu) | (a) Unpinned manifests: #2 showed Trivy/Syft silently drop unpinned entries, so the source SBOM should be nearly empty. (b) `pymongo` is installed in the **Dockerfile but not listed in requirements.txt**. (c) numpy, scipy and scikit-learn wheels **bundle native libraries** (OpenBLAS, libgfortran, libgomp in `*.libs/`). (d) The `mongo:6.0` image adds a large OS layer and native binaries. |
| **Multi-client TCP server** | Plain C11, Makefile + CMake, uses only libc + pthread. No package manager. The repo also has **committed prebuilt `client`/`server` binaries that are Mach-O arm64 (macOS)**. | C / native + OS | No manifest at all, so ground truth comes from the linker. Tests whether tools tie the ELF binary to glibc or musl. Shows foreign binaries committed to source. A static musl build on `scratch` leaves almost nothing to detect. |

**OS packages are covered by the base images. Nothing needs to be added to the Corpus folder.** Our images span the three main Linux package managers: Debian/Ubuntu (dpkg) from `python:3.11-slim`, `eclipse-temurin` and `mongo:6.0`; Alpine (apk) from `nginx:alpine` and `alpine`; and RHEL (rpm) from `ubi9-minimal`. We also scan a small set of plain OS images (`debian:bookworm-slim`, `ubuntu:24.04`, `alpine:3.x`, `ubi9-minimal`, `distroless/base`) as a pure OS-package baseline, similar to SBOMproof (#8) but including cdxgen. Docker pulls these automatically.

**Rule: the Corpus folder stays untouched.** All Dockerfiles and variants for the study live in the study repo and use the corpus as their build context. The exact corpus snapshot is pinned (copied into the repo or added as git submodules at a fixed commit) so the paper is reproducible.

### 4.2 Variants per subject (factorial)

Stages: **S1** source as committed · **S1′** source with resolved dependencies (lockfile / `pip freeze` / built `node_modules`) · **S2** built artifact · **S3** container image.

| Subject | S1 / S1′ | S2 artifact | S3 image variants |
|---|---|---|---|
| Bakery backend | `pom.xml` only / after `mvn dependency:resolve` | Spring Boot fat JAR | `eclipse-temurin:25-jre` (Ubuntu) · Alpine JRE · `distroless/java25` · layered JAR (`-Djarmode=tools extract`, gives an exploded `lib/`) · **planted:** a shaded-JAR build and a manually copied JAR |
| Bakery frontend | `package.json` only / with `package-lock.json` / with `node_modules` | `dist/` bundle | `nginx:alpine` serving `dist/` (bundled) · a `node:*-slim` dev-server image (`node_modules` present) |
| Log Anomaly (prediction + drift + frontend + ml_pipeline) | unpinned `requirements.txt` / `pip freeze`-pinned | installed venv | the original `python:3.11-slim` Dockerfiles · `python:3.11-alpine` · multi-stage to `distroless/python3` · **planted:** a `curl`-downloaded binary |
| MongoDB data store | — | — | `mongo:6.0` as used in the project |
| TCP server | `.c`/Makefile + committed Mach-O binaries | ELF binary (dynamic, glibc) | `debian-slim` (dynamic) · `alpine` (musl) · `scratch` (static) · **planted:** a vendored C library (e.g. cJSON / sqlite amalgamation) in a copy of the project |

Roughly **35–40 targets** from our corpus plus **~5–15 OS/public images** ≈ 50 targets × 3 tools × 2 formats ≈ **300 SBOMs**. Each run is repeated twice to check **reproducibility** (#1 found non-determinism). Compute takes minutes, so the bottleneck is analysis.

*Public anchor apps (e.g. `spring-petclinic`) are now optional. With four ecosystems and naturally occurring hard cases, our own corpus is strong enough. If time allows, we add 1–2 to answer "toy subject" criticism.*

### 4.3 Ground truth (the most important part)

| Layer | Ground-truth source |
|---|---|
| OS (deb/apk/rpm) | Query the native package database *inside* the image: `dpkg-query`, `apk info -v`, `rpm -qa`. For distroless, read `/var/lib/dpkg/status.d`. |
| Java | `mvn dependency:list` (runtime scope), checked against `BOOT-INF/lib` and `classpath.idx` in the fat JAR |
| Node.js | `package-lock.json` (prod vs. dev split), plus `npm ls --omit=dev` for what ships. For the nginx `dist/` image, the bundled set is the production dependency closure from the Vite build manifest. |
| Python | `pip inspect` / `pip freeze` in the image's environment, plus a file scan of `*.libs/` for vendored native libraries |
| C | Linker map file / `readelf -d` (DT_NEEDED) / `ldd`, plus our own list of vendored libraries |
| Planted cases | Known by construction, since we planted them |

**Matching:** normalise to PURL. Use a **strict** match (type + namespace + name + version) and a **lenient** match (name only), as #1, #2 and #13 do. Normalise PEP 503 names, Debian epochs and Maven group:artifact. Every normalisation is logged.

### 4.4 Tools and setup

- **Syft**, **Trivy** and **cdxgen**, pinned to the latest stable versions on the day we start. All run from their official Docker images for reproducibility.
- Output: CycloneDX 1.6 JSON (primary) and SPDX 2.3 JSON (for RQ4).
- Default settings first, then a "best effort" configuration (Trivy `--include-dev-deps`, Syft `--select-catalogers`, cdxgen `-t <type>` / `--deep`) to separate tool *capability* from tool *defaults*.
- Every tool scans the same input: an image exported with `docker save` to a `.tar` file, so the input is identical across tools.

### 4.5 Metrics

Per target, tool and ecosystem: TP/FP/FN, **precision, recall, F1** (strict and lenient), pairwise **Jaccard** between tools, duplicate rate, field-correctness rate per field, and an NTIA / CISA-2025 minimum-elements checklist. Statistics: Wilcoxon signed-rank or Friedman across tools, effect sizes. Plots: heatmap (tool × inclusion mechanism), recall by stage (line plot), Venn/UpSet diagrams.

---

## 5. Team split (matches the P16 sub-roles)

| Member | Owns | Deliverables |
|---|---|---|
| **Testbed & Implementation** | Dockerfiles for all variants, ground-truth extractors, pinned tool runner, `docker save` pipeline | `subjects/`, `variants/`, `scripts/run_all`, raw SBOMs and ground-truth JSON |
| **Measurement & Analysis** | PURL normaliser, matcher, metrics, statistics, plots, root-cause triage of misses (reading tool source) | `analysis/` notebooks, results tables, figures, miss-taxonomy table |
| **Related Work & Writing** | Related-work section from this review, background (SBOM, CycloneDX/SPDX, NTIA/CISA, CRA), paper skeleton, practitioner guide, threats to validity | LaTeX paper (Springer `sn-jnl` template for EMSE; switch to IEEE Access template only if we use the fallback), BibTeX |

---

## 6. Timeline

> **Updated 22 Nov 2026:** compressed to a **5-day sprint (23–27 Nov)** ending with a complete first draft for the professor. See [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). December is for review cycles and submission. The original 5-week table below is kept for reference only.


| Week | Dates | Testbed | Analysis | Writing |
|---|---|---|---|---|
| 0 | 22–24 Nov | Plan approved. Corpus received ✅. Start Docker Desktop. Pin tool versions. Pin the corpus snapshot. | Fix the matching rules | Venue chosen (EMSE SECUTE). Get the professor's OK. Set up the Springer template. |
| 1 | 25 Nov–1 Dec | Build all variants plus ground-truth extractors. First complete pipeline run. | Normaliser and matcher on 3 sample targets | Related work and background drafted |
| 2 | 2–8 Dec | Full matrix, public images, repeat runs | All metrics, first figures (RQ1, RQ2) | Introduction and methodology |
| 3 | 9–14 Dec | Fixes and reruns | Miss taxonomy and root causes (RQ3), fields (RQ4) | Results. **First full draft to professor ~14–15 Dec.** |
| 4 | 15–22 Dec | Artifact packaging (GitHub + Zenodo DOI) | Address reviewer comments, optional RQ5 | Revision 1, practitioner guide |
| 5 | 23–29 Dec | — | Final checks | Revision 2 → **submit by ~29 Dec** (grade A requires "submitted") |

The professor's review loop is the risk, not the experiments. Sending the first draft by 15 Dec leaves time for two revision cycles.

---

## 7. Venue decision (target grade A = submitted by end of December)

Grade A only requires the paper to be **submitted** before grades go in at the end of December. So the venue must accept a submission between about 22 and 29 Dec 2026. A paper can only be under review at **one** venue at a time.

### ✅ Chosen: *Empirical Software Engineering* (Springer, EMSE), Special Issue "Software Security Testing (SECUTE)"

- **Fit:** the call explicitly lists *"security testing for third-party vulnerabilities and software supply chain security"* and requires *"a strong empirical basis"*. A measurement study with ground truth is exactly that.
- **Deadline:** extended to **28 Feb 2027 (AoE)**. We submit around 29 Dec, so we have a buffer if the professor's review takes an extra round, and the deadline is never at risk.
- **Quality:** EMSE is a long-established, Scopus-indexed (Q1) empirical SE journal. Prior SBOM work (#1, #11, #12) appeared at this level or in similar venues. An EMSE submission looks strong on a CV even before a decision.
- **Cost:** no fee on the standard subscription route. Open access is optional.
- **Format:** Springer journal template (single column). Usually around 25–35 pages, with no hard limit. Submit via Editorial Manager, choose "Research Papers", and select the "SECUTE 2026" special issue.
- **Source:** emsejournal.github.io/special_issues/2026_SI_SECUTE.html (checked 22 Nov 2026).

### Fallback: **IEEE Access** (named by the professor in P16)

- Rolling submissions and quick first decisions. Scopus/SCIE-indexed.
- **APC: US$2,160** for 2026 submissions (US$2,245 from 2027). It is only paid if the paper is accepted. Check whether the institute has an IEEE deposit account. *(Source: ieeeaccess.ieee.org APC page, checked 22 Nov 2026.)*
- Use it if the professor prefers one of the venues listed in P16, or wants a faster decision.

### Considered and rejected

| Venue | Why not |
|---|---|
| NDSS **SafeOSE 2027** workshop (SBOMs in scope, 8 pages) | Deadline **10 Dec 2026** is too early. Experiments would not be finished and the professor's review loop would be skipped. |
| SVCC 2027 (research track) | Deadline 16 Jan 2027, after grading |
| ChainSEC / LLMSC @ ICSE 2027 | Deadlines already passed (13–21 Nov). ChainSEC is also non-archival. |
| SCORED 2027, ESEM, ARES | Deadlines are in spring or summer 2027 |
| IEEE Software / S&P Magazine | Possible, but a ~4,500-word magazine article throws away most of our results. Better as a **follow-up practitioner article** after the journal paper. |

**Also:** post an **arXiv preprint** on the submission day. That timestamps our novelty claim, which matters in a fast-moving area. Check the special-issue policy first; Springer normally allows preprints.

**Action for the team:** confirm the choice with the professor in week 0. If they insist on a P16-listed venue, switch to IEEE Access. The paper content stays the same and only the template changes.

---

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| A newer paper scoops the "image + lifecycle" angle | Re-check arXiv in week 2. Our controlled planted-case benchmark and field-correctness results stay distinct either way. |
| Tool versions change mid-study | Pin versions and image digests. Record them in the paper. Prior work (#12, #13) shows results drift, so this is expected and we report it. |
| Ground truth is debatable (what counts as a "component"?) | Follow #14's inclusion-mechanism definitions. Report strict and lenient matching, and runtime-only vs. all scopes. |
| Our own projects look like "toy" subjects | Add public anchor apps and about 15 popular Docker Hub images. |
| Windows environment problems | Run all tools in Docker. Use WSL2 for the shell scripts. |
| Scope creep | RQ5, public anchor apps and extra public images are optional and get dropped first. |
| Spring Boot 4 / Java 25 are very new, so tools may not handle them yet | That is a finding in itself. If a tool crashes, record it and also build one variant on Java 21 to separate "new version" from "tool limitation". |

---

## 9. Environment status (checked 22 Nov 2026)

| Item | Status | Action |
|---|---|---|
| Corpus (3 projects) | ✅ Frozen snapshot copied into the repo at `corpus/` (see `corpus/README.md` for what was left out and why) | None |
| Docker Desktop | ✅ Running: engine 29.1.3, 16 CPUs, ~8 GB RAM for containers | None. 8 GB is enough for the Java/Node builds and `mongo:6.0`. |
| WSL2 | ✅ `Ubuntu` distro present (stopped). The `docker-desktop` distro is the Docker backend. | No setup needed: commands can run via `wsl -d Ubuntu -- <cmd>` on this machine. Used only for Linux-only checks (`readelf`, `ldd`) if needed, since everything else runs inside containers. |
| Syft / Trivy / cdxgen | Not installed locally | Not needed: we run their pinned official Docker images |
| JDK 25 / Maven / Node / gcc | Not needed locally | Builds happen inside Docker build stages |

## 10. What we need before starting

1. ~~Approval of the angle and RQs~~ — approved, conditional on novelty, which the re-check confirmed (§2).
2. ~~Access to the 3 projects~~ — done.
3. ~~Venue decision~~ — EMSE SECUTE special issue, with IEEE Access as fallback (§7). **The professor still needs to confirm it.**
4. ~~Start Docker Desktop~~ — done.
5. ~~Pin the corpus~~ — frozen snapshot in `corpus/`.
6. **Final go-ahead for implementation (week 1):** repo layout, pinned tool versions, Dockerfiles for the variants, ground-truth extractors, runner.
