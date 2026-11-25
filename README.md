<p align="left">
  <img src="https://img.shields.io/badge/Language-Python%203.14-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.14">
  <img src="https://img.shields.io/badge/Containers-Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/SBOM%20Tools-Syft%20%C2%B7%20Trivy%20%C2%B7%20cdxgen-1BAF7A?style=flat-square&logo=owasp&logoColor=white" alt="Syft, Trivy, cdxgen">
  <img src="https://img.shields.io/badge/SBOM%20Formats-CycloneDX%201.7%20%C2%B7%20SPDX-6250D6?style=flat-square&logo=owasp&logoColor=white" alt="CycloneDX and SPDX">
  <img src="https://img.shields.io/badge/Ecosystems-Java%20%C2%B7%20npm%20%C2%B7%20Python%20%C2%B7%20Go%20%C2%B7%20C%20%C2%B7%20OS-EB6834?style=flat-square&logo=linux&logoColor=white" alt="Ecosystems">
  <img src="https://img.shields.io/badge/Analysis-pandas%20%C2%B7%20SciPy%20%C2%B7%20Matplotlib-150458?style=flat-square&logo=pandas&logoColor=white" alt="Analysis stack">
  <img src="https://img.shields.io/badge/Theme-Supply--Chain%20Security-E34948?style=flat-square&logo=letsencrypt&logoColor=white" alt="Supply-chain security">
  <img src="https://img.shields.io/badge/Status-Research%20in%20progress-EDA100?style=flat-square&logo=github&logoColor=white" alt="Status">
</p>

---

# Same App, Different SBOM: Syft vs Trivy vs cdxgen

## Project Overview

A **Software Bill of Materials (SBOM)** lists every component inside a piece of software. It is the basis for vulnerability management and is becoming a legal requirement, for example under the EU Cyber Resilience Act. Different SBOM generators produce different component lists for the same software, and it is rarely measured **which list is right**.

This project is a **comparative measurement study** of the three most widely used open-source SBOM generators, **Syft**, **Trivy** and **cdxgen**. Each tool is run on the *same applications* at **three lifecycle stages**: the source tree, the built artifact and the final container image. Every SBOM is scored against an **exact, independently extracted ground truth**. The study measures how complete and accurate each tool is, where and **why** each tool misses components, and how correct the reported fields are.

The corpus has **45 scan targets, 34 of them container images**:
- **Our own three projects** at every lifecycle stage: a Spring Boot (Maven) backend, a React/Vite frontend, Python microservices and a multi-threaded C server.
- **A public Gradle project**, Spring PetClinic.
- **Eight popular public images**, pre-screened and pinned by digest: postgres, mysql, jenkins, keycloak, ghost, airflow, prometheus and gitea.
- **Five OS baseline images**: Debian, Ubuntu, Alpine, Red Hat UBI and distroless.

*Planted* hard cases are added on top, such as shaded JARs, manually downloaded binaries, and vendored or statically linked libraries.

---

## Research Questions

| | Question |
|---|---|
| **RQ1** | How complete (recall) and accurate (precision) are Syft, Trivy and cdxgen on container images, per ecosystem? |
| **RQ2** | For the *same* application, how does each SBOM change from source → built artifact → container image, and across base images (Debian, Alpine, distroless, scratch)? |
| **RQ3** | Which inclusion mechanisms (nested JARs, bundled JavaScript, wheel-vendored libraries, static linking...) does each tool miss, and what is the root cause in the tool? |
| **RQ4** | How correct are the reported fields (package URL, version, license, hashes, CPE), and do a tool's CycloneDX and SPDX outputs agree? |
| **RQ5** | How do these SBOM differences change what vulnerability scanners (Grype, Trivy) report, within and across vendors? |

---

## Study Architecture & Workflow

### 1. Corpus & Variants
* **Our own three projects and Spring PetClinic** (frozen snapshot in `corpus/`). Each is built into several variants from `variants/`: source tree (S1), built artifact (S2), container images on different base images (S3), and images with planted hard cases (P).
* **Eight popular public images**, selected by a documented screening (`scripts/screen_images.py`, `results/screening.json`), plus five OS baselines.
* **45 scan targets** in total, catalogued in `targets.yaml`. Every public image and every tool is **pinned by digest**.

### 2. Ground Truth (never taken from the tools)
* Read from **authoritative sources**: dpkg/apk/rpm databases, `*.dist-info` metadata, `node_modules/**/package.json`, Maven `pom.properties` and `mvn dependency:list`, Go build info, ELF `DT_NEEDED`, Vite sourcemaps, and SBOMs embedded in Python wheels (PEP 770).
* **Cross-checked by independent oracles**: each image's own `dpkg-query`, `apk`, `rpm -qa`, `pip list`, `npm query` and pnpm lockfile, Python's `importlib.metadata`, the rpm database's own index, the official `go version -m` and `readelf`. **230 automated checks**, plus 268 build checks.
* JARs without `pom.properties` get their identity from the image's own build, confirmed against the SHA-1 that the Maven repository publishes (`results/public_java_ids.json`).

### 3. SBOM Generation
* Syft **1.57.2**, Trivy **0.76.2** and cdxgen **13.2.0** run from their official Docker images, with identical inputs, default settings, **CycloneDX 1.7 + SPDX** output, and two repetitions for determinism.
* Network-sensitive behaviour (Maven Central rate limiting) is controlled: affected runs are paced and accepted only with the full number of online lookups. Throttled runs are kept as their own condition.
* A **best-effort** configuration (each tool's documented opt-in options) is compared with the defaults.

### 4. Normalisation & Matching
* All SBOMs are parsed into canonical **package-URL identities**. The same normalisation is applied to the ground truth.
* **Strict** matching (name + version) and **lenient** matching (name, alias, namespace or ecosystem differences). Each miss and each false positive is classified.

### 5. Analysis
* Precision, recall and F1 per tool, ecosystem, lifecycle stage, inclusion mechanism and cohort. Component-level **Cochran's Q** and pairwise **McNemar** tests, the per-image **Friedman** test, and a **sensitivity analysis** (9 variants plus leave-one-image-out).
* **Licenses** compared after SPDX normalisation (`scripts/licenses.py`). Field-correctness, document-element (NTIA / CISA 2025) and format-agreement analysis.
* **RQ5:** every SBOM is scanned by **Grype and Trivy** (frozen DB snapshots) and compared with a reference SBOM built from the ground truth. The reference is validated against direct image scans on all 34 images.

---

## Results (34 container images, 45 targets)

| | Syft | Trivy | cdxgen |
|---|:---:|:---:|:---:|
| Recall, strict (pooled over images) | **0.882** | 0.787 | 0.821 |
| Recall, strict (mean per image) | 0.853 | 0.863 | **0.906** |
| Precision, strict | 0.955 | **0.995** | 0.991 |
| Recall, source trees + artifacts | 0.287 | 0.472 | **0.711** |
| License correct when reported | 0.999 | 0.999 | 1.000 |
| CPE identifiers emitted | 99.3 % | 0 % | 0 % |
| SPDX output identical to its CycloneDX | 100 % | 100 % | 50 % |

* **There is no single best tool for images.** The pooled ranking reverses with per-image averaging, and it reverses when one image (Ghost, 1,353 npm packages) is left out. On our own projects cdxgen leads; on the public images Syft does. Tool choice should follow the ecosystem and how components get into the image.
* **Shared blind spots:** no tool detects dependencies bundled into a JavaScript build, statically linked or vendored C code, or native libraries vendored inside Python wheels.
* **Root causes, each with evidence:**
  - Trivy and cdxgen miss npm packages that pnpm installs as hard links (a controlled probe confirms it).
  - cdxgen never enters `node_modules/.pnpm`.
  - Without a Gradle lockfile, Syft and Trivy produce empty SBOMs; cdxgen does too, but silently, with exit code 0, when its image lacks the project's Java toolchain.
  - No tool reads the SBOM embedded in a Spring Boot JAR.
* **Silent network dependence:** when Maven Central rate-limits it, cdxgen's Java recall drops from 0.98 to 0.92 *without any warning*.
* **Vulnerability impact (RQ5):** on its own vendor's SBOM each scanner finds 99 % of the reference CVEs. Across vendors, only 10–13 % of OS-package findings survive, because the link from binary to source package lives in vendor-private fields. Grype on Trivy's SBOMs finds 43 % of CVEs; Trivy on Syft's finds 33 %.

<p align="center">
  <img src="paper/figures/fig_rq3_mechanisms.png" width="520" alt="Recall by inclusion mechanism">
</p>

---

## Repository Structure

| Path | Contents |
|---|---|
| `corpus/` | Frozen snapshot of the three subject projects (read-only) |
| `variants/` | Study Dockerfiles, planted hard cases and their ground truth (`planted.json`) |
| `targets.yaml` | Catalogue of all scan targets |
| `tools/versions.lock`, `tools/spdx/` | Pinned tool image digests and DB snapshots; SPDX License List 3.29.0 |
| `scripts/` | Pipeline: build → verify → ground truth → SBOM generation → normalise → score → analyse → figures |
| `ground_truth/` | Ground-truth component lists, one JSON file per target |
| `run_all.sh`, `run_all.ps1` | One-command reproduction (analysis level or full re-run) |
| `results/` | Build manifest, tool-run records, verification reports, metrics, tables |
| `paper/figures/` | Figures (PDF + PNG) |
| `docs/` | Literature review, research design, implementation log, root causes, replication guide |

---

## Reproducing the Study

The replication package has three archives (`scripts/make_archive.py`): the repository, the data (every SBOM and scan output, 305 MB) and, optionally, the frozen vulnerability-DB snapshots. Unpack them into one folder, then:

```bash
./run_all.sh analysis     # every table and figure from the archived SBOMs; no Docker; ~4 minutes; checks exactness
./run_all.sh full         # rebuild, ground truth, all tools, RQ5 scans; Docker; many hours
```

On Windows use `.\run_all.ps1 analysis` or `.\run_all.ps1 full`.

The analysis level was verified on a fresh copy: **46 of 46 result files reproduced exactly**. A two-target end-to-end re-run also reproduced the ground truth and all SBOM component sets exactly. Details, expected drift and the network caveats are in [`docs/REPLICATION.md`](docs/REPLICATION.md).

Requirements: Python 3.11+ (tested with 3.14). For `full`: Docker and about 30 GB of free disk space. Intermediate outputs go to `work/`, which is not tracked.

---

## Technical Stack

*   **SBOM generators:** Syft (Anchore), Trivy (Aqua Security), cdxgen (OWASP CycloneDX)
*   **SBOM standards:** CycloneDX 1.7, SPDX 2.3, SPDX 3.0.1, Package URL (purl)
*   **Build & containers:** Docker BuildKit, Maven, Gradle, npm / pnpm / Vite, pip, GCC / musl
*   **Base images:** Debian, Ubuntu, Alpine, Red Hat UBI, Google distroless, scratch
*   **Vulnerability scanners (RQ5):** Grype, Trivy (frozen DB snapshots)
*   **Analysis:** Python 3, pandas, SciPy, Matplotlib, packageurl-python
*   **Platform:** Windows 11 + Docker Desktop (WSL2 backend), Linux-compatible

---

## Context

Project Elective **P16**, *SBOM Generators Compared: Coverage and Accuracy of Syft vs Trivy vs cdxgen*. Theme: supply-chain security & DevSecOps.
