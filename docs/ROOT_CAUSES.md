# Root causes of tool behaviour (RQ3 evidence)

Each claim is backed by evidence from the tool itself: its own configuration dump, its cataloger list, or its source
code (cdxgen ships as readable JavaScript in its image). Pinned versions: Syft 1.57.2, Trivy 0.76.2, cdxgen 13.2.0.

## Shared blind spots (all three tools)

| Blind spot | Measured | Root cause | Evidence |
|---|---|---|---|
| **Bundled / minified JavaScript** (`dist/` bundle, nginx image) | recall 0.00 for all | Tools identify npm packages only from lockfiles (source) or `node_modules/*/package.json` (installed). No tool analyses bundled code. | `syft cataloger list`: `javascript-lock-cataloger` (tags *declared, directory*) and `javascript-package-cataloger` (*image, installed*). Nothing for bundles. The Vite output contains none of those files. |
| **Statically linked C library** (zlib in `C-P`) | 0.00 for all | Binary detection relies on (a) a fixed list of known programs recognised by version strings, or (b) ELF package notes. A statically linked library has neither. | Syft `binary-classifier-cataloger` and `elf-binary-package-cataloger`. Syft *does* identify `jq` (on its list) but not zlib inside our binary, although the binary contains the `deflate 1.3.1` banner. |
| **Vendored source copy** (cJSON compiled in, `decorator.py` copied without metadata) | 0.00 for all | No package metadata exists, so metadata-based tools have nothing to read. | By construction (`planted.json`). Matches the *Software Dark Matter* finding (files without metadata). |
| **Native libraries vendored inside wheels** (`*.libs/*.so`) | 0.00 Syft / Trivy; 0.18 cdxgen | auditwheel grafts system libraries into `<pkg>.libs/` without package metadata. Only cdxgen reads auditwheel's embedded SBOM, where one exists (scikit-learn, Pillow; not numpy/scipy). | Embedded SBOMs present: `scikit_learn-*.dist-info/sboms/auditwheel.cdx.json`, `pillow-*.dist-info/sboms/auditwheel.cdx.json`. |

## Tool-specific blind spots and defaults

| Behaviour | Tool | Measured | Root cause | Evidence |
|---|---|---|---|---|
| Finds only direct Maven deps from `pom.xml` | Syft | J-S1 recall 0.03 | Transitive resolution is opt-in. | `syft config`: `java.resolve-transitive-dependencies: false`, `java.use-network: false`. With the options enabled (best-effort run) Syft reports 379 components against 153 in GT, so it over-reports. |
| Drops npm dev dependencies from lockfiles | Syft, Trivy | N-S1 recall 0.35 | Dev dependencies excluded by default. | `syft config`: `javascript.include-dev-dependencies` unset (false); `trivy fs --help`: `--include-dev-deps` (supported: npm, yarn, gradle). With the flag, Trivy goes from 35 to 100 components on N-S1. |
| Empty SBOM for unpinned `requirements.txt` | Syft, Trivy | P-S1 recall 0.00 | Entries without `==` pins are skipped. | `syft config`: `python.guess-unpinned-requirements: false`. Consistent with Yu et al. (DSN 2024). With the option enabled, Syft guesses only from a version *constraint* (`streamlit>=1.29.0` → 1.29.0, which is not the installed version). The 47 bare names stay unreported (1 component). |
| Empty SBOM without npm lockfile | Syft, Trivy | N-S1-nolock 0.00 | Both need a lockfile or `node_modules`; neither resolves `package.json` ranges. | cdxgen instead runs `npm install` itself (`--install-deps` default true), giving recall 0.43: versions resolved *today*, not those of the lockfile. |
| Misses packages installed with `pip install --target` | cdxgen | P-S3-distroless 27/27 missed | The image scanner collects only directories literally named `site-packages` (plus `node_modules`, `gems`, …). | `lib/managers/docker.js`: `const ecoDirNames = ["node_modules", "site-packages", "gems", ".cargo", ".composer"]`. `/app/deps` never matches. |
| Ignores code shaded into an uber-JAR | cdxgen | shaded / shaded-relocated 0.00 | Only the **first** `pom.properties` in a JAR is read. | `lib/inventory/deps.js` `getPomPropertiesFromMavenDir`: `readFileSync(pomPropertiesFiles[0])`. Syft and Trivy read every embedded `pom.properties` (1.00). |
| Guesses Maven groupIds for JARs without `pom.properties` | Syft | 21/102 wrong on the fat JAR (`org.hibernate` vs `org.hibernate.orm`, artifactId reused as groupId) | Without `pom.properties`, Syft infers the groupId from MANIFEST fields and names. Trivy instead looks up the JAR's SHA-1 in its offline Java DB, which is correct; cdxgen looks it up online (see below). | Observed purls in `work/sboms/default/syft/rep1/J-S2.json`; Trivy Java DB (`mirror.gcr.io/aquasec/trivy-java-db:1`). |
| Silent degradation when Maven Central blocks lookups | cdxgen | Java recall 0.980 → 0.922, precision 0.990 → 0.931 | One SHA-1 search per unidentified JAR (`central.sonatype.com/solrsearch`), no cache, 1-second response timeout, `MAX_SEARCH_MAVEN_ORG_ERRORS = 1`. Central signals rate limiting with **HTTP 404 + Retry-After**, and cdxgen ignores errors whose message contains "404", so its own warning never prints. | `lib/ecosystems/ecosystems.js` (the lookup and the `!err.message.includes("404")` branch). `curl` shows `404` with `Retry-After: 2684`. The warning appears in none of the 14 Java logs. |
| Hard failure when Maven Central blocks `pom.xml` resolution | Trivy | J-S1: exit 1, no SBOM | Parent POMs and BOMs are fetched at scan time; a 429 is fatal. | Trivy log: `remote Maven repository returned 429 Too Many Requests … Retry-After: 1800`. Remedy (its own advice): pre-populated `~/.m2`. |
| SPDX export aborts on an empty BOM | cdxgen | 3 targets with 0 components wrote nothing | SPDX 3.0.1 validation fails (`SpdxDocument … must include element refs`), and the whole run exits 1, including the CycloneDX file. | Logs of C-S1, C-S2, N-S2. |
| SPDX 3 output loses component types | cdxgen | identical purl sets in only 48% of targets; purpose-less extras in 19/29 | `software_primaryPurpose` is never set (0 of 394 packages), so `cryptographic-asset` entries become ordinary packages. | `work/sboms/default/cdxgen/rep1/*.spdx.json`. |
| No CPE identifiers | Trivy, cdxgen | 0% (Syft 99.5%) | Not emitted in CycloneDX output. | No `cpe` field on any component in any Trivy or cdxgen SBOM. |

## RQ5: why vulnerability findings get lost between vendors

| Behaviour | Measured (3-image trial) | Root cause | Evidence |
|---|---|---|---|
| A scanner finds far fewer vulnerabilities on another vendor's SBOM, although every tool lists 100% of the OS packages | Grype: Syft SBOM 1.000, Trivy 0.286, cdxgen 0.284 of the reference findings. Trivy: own 1.000, Syft 0.145, cdxgen 0.065. | Distro security data is keyed by **source package** (`glibc`, `shadow`), but SBOMs list binary packages (`libc6`, `passwd`). The binary-to-source link is recorded in **vendor-private** fields: Syft uses the purl qualifier `upstream=glibc`, which Trivy ignores; Trivy uses the properties `aquasecurity:trivy:SrcName/SrcVersion/SrcRelease`, which Grype ignores; cdxgen records neither. Neither CycloneDX nor the purl spec standardises the field. | O-debian: 204/204 findings Grype loses on Trivy's SBOM, and 215/215 Trivy loses on Syft's, are on packages whose source name differs from the binary name. Trivy's `libc6` purl has no `upstream` qualifier. |

| Trivy aborts on cdxgen's SBOMs of the Python images and reports **no vulnerabilities at all** | 4 of 23 scans failed (exit 1) | cdxgen copies the auditwheel entries embedded in wheels (`pkg:rpm/almalinux/libgomp`) into the image SBOM, so one Debian image's SBOM holds both deb and rpm OS packages. Trivy refuses that. | `FATAL … failed to aggregate packages: multiple types of OS packages in SBOM are not supported (["rpm" "deb"])` (logs `work/logs/rq5/trivy-cdxgen-P-*.log`). |
| Grype surfaces the CVEs of cdxgen SBOMs but on **source** packages | Finding level 0.23, but CVE level 0.994 | cdxgen also lists source packages (`glibc`, `shadow`), and Grype matches CVEs on them directly. The vulnerability appears, attached to a package that is not installed under that name. | O-debian: e.g. `CVE-2010-4756` reported on `glibc` rather than `libc6`. |
| Go standard-library version written differently by each vendor | Trivy missed `CVE-2026-97054` in `/usr/bin/pebble` on a `go1.27.3` stdlib entry | Syft (and Grype) write `pkg:golang/stdlib@go1.27.3`; Trivy writes `v1.27.3` and does not match the `go` form. | Trivy direct image scan vs reference: the only difference before the fix. |

Methodological consequence: a "perfect" reference SBOM must carry the source link in each scanner's own convention, otherwise it under-reports too. Our reference is written once per scanner (`work/rq5/ref/{grype,trivy}/`). Check: each scanner finds exactly as many findings on its reference as on its own vendor's SBOM (Grype = Syft 591/591, Trivy = Trivy 496/496).

## Unique strengths

| Strength | Tool | Measured | Root cause |
|---|---|---|---|
| Reads SBOMs embedded in wheels (PEP 770) | cdxgen | 0.76 (421 components, mostly Rust crates) | Parses `*.dist-info/sboms/*.json` (property `cdx:embeddedSbom:source`). |
| Language runtimes installed from tarballs (CPython in `/usr/local`, Temurin JDK, Node) | Syft | 0.64 (Trivy and cdxgen 0.09) | `binary-classifier-cataloger` and `java-jvm-cataloger` recognise the runtime binaries and the JDK `release` file. |
| Exact groupIds without network | Trivy | Java 0.98 strict | SHA-1 lookup in the offline Trivy Java DB. |
