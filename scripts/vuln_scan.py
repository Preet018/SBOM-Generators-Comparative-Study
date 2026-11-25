"""RQ5: how do SBOM differences change what vulnerability scanners report?

For every image target (S3 + P):
  1. Build a REFERENCE SBOM per scanner: exactly the verified ground truth's primary components, in that scanner's
     NATIVE metadata. A GT component that the scanner vendor's own generator (Syft for Grype, Trivy for Trivy)
     strictly matched keeps that generator's component record (CPEs, properties, qualifiers); a component the
     generator missed is written from the GT (purl distro/upstream/epoch/arch, Trivy Src* properties).
     Scanning it yields the findings a complete and correct SBOM would produce for that scanner.
  2. Scan the reference SBOM and each tool's SBOM (default config, rep 1, CycloneDX) with BOTH Grype and Trivy
     (same-vendor and cross-vendor pairs), against frozen vulnerability DB snapshots (no updates during the study).
  3. Compare findings. A finding = (vulnerability id, package name): CVE ids are preferred over GHSA/vendor ids
     via the scanner's alias list; the package NAME (not namespace) is used so that a tool's wrong Maven groupId
     does not hide the fact that the CVE still surfaced.

Outputs: work/rq5/ref/<target>.cdx.json, work/rq5/scans/<scanner>/<sbom>/<target>.json (raw scanner output),
         results/rq5_scans.json (run records), results/tables/rq5_*.csv
Usage:   python scripts/vuln_scan.py [--only ID ...] [--skip-scan]
         python scripts/vuln_scan.py --validate ID ...   (reference-SBOM scan vs direct image scan, CVE sets)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd
from packageurl import PackageURL

from common import RESULTS_DIR, ROOT, ROOTFS_DIR, WORK, load_catalog, log, plain, rel, sha256_file, write_json
from normalize import record

RQ5 = WORK / "rq5"
TABLES = RESULTS_DIR / "tables"
GRYPE_IMAGE = "anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c"  # 0.122.1
GRYPE_CACHE, TRIVY_VULN_CACHE = WORK / "cache" / "grype", WORK / "cache" / "trivy-vuln"
SBOM_SOURCES = ["reference", "syft", "trivy", "cdxgen"]
SCANNERS = ["grype", "trivy"]
LOG4SHELL = "CVE-2021-44228"


def trivy_image() -> str:
    for line in (ROOT / "tools" / "versions.lock").read_text(encoding="utf-8").splitlines():
        if line.startswith("TRIVY_IMAGE="):
            return line.split("=", 1)[1].split()[0]
    raise SystemExit("TRIVY_IMAGE missing from tools/versions.lock")


# ----------------------------------------------------------------------------- reference SBOM
# The reference holds exactly the primary ground-truth components, but is written in each scanner's NATIVE
# conventions, because scanners do not read each other's: Grype (via Syft's decoder) takes the source package
# from the purl `upstream` qualifier; Trivy ignores that and reads its own `aquasecurity:trivy:Src*` properties.
# Measured: Trivy found 45 findings on a Syft-convention reference vs 81 on its own SBOM of the same image.
TRIVY_FAMILY = {"rhel": "redhat", "ol": "oracle"}
NATIVE_GENERATOR = {"grype": "syft", "trivy": "trivy"}   # the vendor's own SBOM generator for each scanner
TRIVY_LANG_TYPE = {"maven": "jar", "pypi": "python-pkg", "npm": "node-pkg", "golang": "gobinary", "cargo": "rust-binary"}


def os_version(tid: str, os_info: dict) -> str | None:
    """Both Syft and Trivy use Debian's point release from /etc/debian_version (12.15), not VERSION_ID (12)."""
    if os_info.get("id") == "debian":
        from fsutil import Rootfs
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        if fs.exists("etc/debian_version"):
            return fs.text("etc/debian_version").strip()
    return os_info.get("version_id")


def split_source(c: dict) -> dict:
    """Source package name/version/release/epoch of an OS package, as Trivy records them."""
    q, version = c.get("qualifiers") or {}, c["version"] or ""
    if c["eco"] == "rpm":
        m = re.match(r"^(.+)-([^-]+)-([^-]+)\.src\.rpm$", q.get("upstream") or "")
        if not m:
            return {}
        return {"SrcName": m.group(1), "SrcVersion": m.group(2), "SrcRelease": m.group(3), "SrcEpoch": q.get("epoch")}
    if c["eco"] == "apk":
        return {"SrcName": q.get("upstream") or c["name"], "SrcVersion": version}
    # deb: upstream "glibc" or "glibc@2.36-9"; binary version may carry an epoch
    up = q.get("upstream") or c["name"]
    name, _, sver = up.partition("@")
    sver = sver or version
    epoch = None
    if re.match(r"^\d+:", sver):
        epoch, sver = sver.split(":", 1)
    ver, _, rel = sver.rpartition("-") if "-" in sver else (sver, "", "")
    return {"SrcName": name, "SrcVersion": ver, "SrcRelease": rel, "SrcEpoch": epoch}


def reference_purl(c: dict, os_info: dict, osv: str | None, flavor: str) -> str | None:
    q = {k: v for k, v in (c.get("qualifiers") or {}).items() if v and k != "vendored_in"}
    version, namespace = c["version"], c["namespace"]
    if c["eco"] in ("deb", "rpm", "apk"):
        family = TRIVY_FAMILY.get(os_info.get("id"), os_info.get("id")) if flavor == "trivy" else os_info.get("id")
        if family and osv:
            q["distro"] = osv if (flavor == "trivy" and c["eco"] == "apk") else f"{family}-{osv}"
        if c["eco"] == "rpm":
            namespace = "redhat" if os_info.get("id") == "rhel" else namespace
            if version and ":" in version:          # purl: epoch is a qualifier, not part of the version
                q["epoch"], version = version.split(":", 1)
        if flavor == "trivy":
            q.pop("upstream", None)                  # Trivy reads the source package from properties instead
    if c["eco"] == "golang":
        ns, _, nm = c["name"].rpartition("/")
        if flavor == "trivy" and c["name"] == "stdlib" and version and version.startswith("go"):
            version = "v" + version[2:]   # Trivy writes Go's stdlib as v1.27.3; Syft/Grype as go1.27.3
        return PackageURL("golang", ns or None, nm, version).to_string()
    try:
        return PackageURL(c["eco"], namespace, c["name"], version, q or None).to_string()
    except ValueError:
        return None


def iter_cdx(comps):
    for c in comps or []:
        yield c
        yield from iter_cdx(c.get("components"))


def native_records(tid: str, flavor: str, gt: dict) -> dict[int, dict]:
    """GT index -> the vendor generator's own CycloneDX record of that component (strict matches on primary GT
    components only). Identity comes from the GT; only the METADATA (CPEs, properties) is taken from the tool."""
    from normalize import load_sbom
    from score import GTIndex, STRICT
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    path = sbom_for(NATIVE_GENERATOR[flavor], tid, runs)
    if path is None or not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_by_purl = {}
    for c in iter_cdx(raw.get("components")):
        raw_by_purl.setdefault(c.get("purl"), c)
    idx, out = GTIndex(gt), {}
    for c in load_sbom(path)["components"]:
        cls, gi = idx.match(c)
        if cls in STRICT and gi is not None and gt["components"][gi]["tier"] == "primary" and c["purl"] in raw_by_purl:
            rec = {k: v for k, v in raw_by_purl[c["purl"]].items() if k not in ("components", "bom-ref")}
            out.setdefault(gi, rec)
    return out


def build_reference(tid: str) -> dict:
    gt = json.loads((ROOT / "ground_truth" / f"{tid}.json").read_text(encoding="utf-8"))
    os_info = gt.get("os") or {}
    osv = os_version(tid, os_info)
    info = {"target": tid}
    for flavor in SCANNERS:
        comps = []
        if os_info.get("id"):
            name = TRIVY_FAMILY.get(os_info["id"], os_info["id"]) if flavor == "trivy" else os_info["id"]
            comps.append({"type": "operating-system", "bom-ref": "os", "name": name, "version": osv})
        native = native_records(tid, flavor, gt)
        info[f"{flavor}_native"] = len(native)
        for i, c in enumerate(gt["components"]):
            if c["tier"] != "primary":
                continue
            if i in native:                       # the vendor generator's own record of this GT component
                comps.append({**native[i], "bom-ref": f"gt-{i}"})
                continue
            # Trivy reads a Go package's identity from `name` (its own SBOMs write the full module path)
            comp = {"type": "library", "bom-ref": f"gt-{i}",
                    "name": c["name"].rsplit("/", 1)[-1] if c["eco"] == "golang" and flavor == "grype" else c["name"]}
            if c["version"]:
                comp["version"] = c["version"].split(":", 1)[1] if c["eco"] == "rpm" and ":" in c["version"] else c["version"]
                if flavor == "trivy" and c["eco"] == "golang" and c["name"] == "stdlib" and comp["version"].startswith("go"):
                    comp["version"] = "v" + comp["version"][2:]
            if c.get("namespace") and c["eco"] in ("maven", "npm"):
                comp["group"] = c["namespace"]
            purl = reference_purl(c, os_info, osv, flavor)
            if purl:
                comp["purl"] = purl
            if flavor == "trivy":
                props = {}
                if c["eco"] in ("deb", "rpm", "apk"):
                    props["PkgType"] = TRIVY_FAMILY.get(os_info.get("id"), os_info.get("id"))
                    props.update(split_source(c))
                elif c["eco"] in TRIVY_LANG_TYPE:
                    props["PkgType"] = TRIVY_LANG_TYPE[c["eco"]]
                comp["properties"] = [{"name": f"aquasecurity:trivy:{k}", "value": str(v)} for k, v in props.items()
                                      if v not in (None, "")]
            comps.append(comp)
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "component": {"type": "container", "bom-ref": "target", "name": tid},
                            "tools": {"components": [{"type": "application", "name": "p16-ground-truth"}]}},
               "components": comps}
        write_json(RQ5 / "ref" / flavor / f"{tid}.cdx.json", bom)
        info[flavor] = len(comps)
    return {"target": tid, "components": info["grype"], "os_version": osv,
            "native_records": {f: info[f"{f}_native"] for f in SCANNERS}}


# ----------------------------------------------------------------------------- scanning
GRYPE_VOLUME = "p16-grype-db"
_grype_ready = False


def grype_db_volume() -> str:
    """The frozen Grype DB (work/cache/grype, 3.4 GB) served from a Docker volume instead of a Windows bind mount:
    Grype reads the whole DB on every run, which takes ~150 s through the bind mount and ~8 s from a volume.
    The volume is (re)filled from work/cache/grype and checked file-by-file with SHA-256, so it is the same DB."""
    global _grype_ready
    if _grype_ready:
        return GRYPE_VOLUME
    check = ("cd /src && find . -type f -exec sha256sum {} + | sort > /tmp/a && "
             "cd /dst && find . -type f -exec sha256sum {} + | sort > /tmp/b && cmp -s /tmp/a /tmp/b")
    base = ["docker", "run", "--rm", "-v", f"{plain(GRYPE_CACHE)}:/src:ro", "-v", f"{GRYPE_VOLUME}:/dst", "alpine", "sh", "-c"]
    if subprocess.run(base + [check], capture_output=True).returncode != 0:
        log(f"[rq5] filling Docker volume {GRYPE_VOLUME} from {rel(GRYPE_CACHE)}")
        subprocess.run(base + ["rm -rf /dst/* && cp -a /src/. /dst/ && " + check], check=True, capture_output=True)
    _grype_ready = True
    return GRYPE_VOLUME


def scan(scanner: str, sbom_path, out_path, log_file) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.unlink(missing_ok=True)
    mounts = ["-v", f"{plain(sbom_path.parent)}:/in:ro", "-v", f"{plain(out_path.parent)}:/out"]
    if scanner == "grype":
        cmd = ["docker", "run", "--rm", *mounts, "-v", f"{grype_db_volume()}:/cache",
               "-e", "GRYPE_DB_CACHE_DIR=/cache", "-e", "GRYPE_DB_AUTO_UPDATE=false", "-e", "GRYPE_DB_VALIDATE_AGE=false",
               "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false", GRYPE_IMAGE,
               f"sbom:/in/{sbom_path.name}", "-o", "json", "--file", f"/out/{out_path.name}"]
    else:
        cmd = ["docker", "run", "--rm", *mounts, "-v", f"{plain(TRIVY_VULN_CACHE)}:/cache", trivy_image(), "sbom",
               "--cache-dir", "/cache", "--skip-db-update", "--skip-java-db-update", "--offline-scan",
               "--format", "json", "--output", f"/out/{out_path.name}", f"/in/{sbom_path.name}"]
    started = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text(f"$ {' '.join(cmd)}\n# exit={p.returncode}\n{p.stdout}\n{p.stderr}", encoding="utf-8")
    ok = p.returncode == 0 and out_path.exists()
    return {"exit_code": p.returncode, "seconds": round(time.time() - started, 1), "status": "ok" if ok else "failed",
            "output": rel(out_path) if out_path.exists() else None, "log": rel(log_file)}


def scan_image(scanner: str, tid: str, out_path, log_file) -> dict:
    """Direct scan of the image tar (the scanner builds its own inventory), same frozen DBs, fully offline."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.unlink(missing_ok=True)
    mounts = ["-v", f"{plain(WORK / 'images')}:/img:ro", "-v", f"{plain(out_path.parent)}:/out"]
    if scanner == "grype":
        cmd = ["docker", "run", "--rm", *mounts, "-v", f"{grype_db_volume()}:/cache",
               "-e", "GRYPE_DB_CACHE_DIR=/cache", "-e", "GRYPE_DB_AUTO_UPDATE=false", "-e", "GRYPE_DB_VALIDATE_AGE=false",
               "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false", GRYPE_IMAGE,
               f"docker-archive:/img/{tid}.tar", "-o", "json", "--file", f"/out/{out_path.name}"]
    else:
        cmd = ["docker", "run", "--rm", *mounts, "-v", f"{plain(TRIVY_VULN_CACHE / 'db')}:/cache/db:ro",
               "-v", f"{plain(WORK / 'cache' / 'trivy' / 'java-db')}:/cache/java-db:ro", trivy_image(), "image",
               "--cache-dir", "/cache", "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update",
               "--offline-scan", "--scanners", "vuln", "--format", "json", "--output", f"/out/{out_path.name}",
               "--input", f"/img/{tid}.tar"]
    started = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text(f"$ {' '.join(cmd)}\n# exit={p.returncode}\n{p.stdout}\n{p.stderr}", encoding="utf-8")
    ok = p.returncode == 0 and out_path.exists()
    return {"exit_code": p.returncode, "seconds": round(time.time() - started, 1), "status": "ok" if ok else "failed"}


def gt_tiers(tid: str) -> dict:
    """(lower-case package name, version) and name alone -> GT tier. The versioned key decides when it exists:
    a package can be primary at one version and a vendored (secondary) copy at another (pip's urllib3)."""
    out: dict = {}
    for c in json.loads((ROOT / "ground_truth" / f"{tid}.json").read_text(encoding="utf-8"))["components"]:
        names = {c["name"].lower(), c["name"].lower().rsplit("/", 1)[-1]} | {a.lower() for a in c.get("alt_names", [])}
        names |= {re.sub(r"[-_.]+", "-", n) for n in names}   # PEP 503: jaraco.context == jaraco-context
        v = (c["version"] or "").lstrip("v")
        for n in names:
            for k in ((n, v), n):
                if out.get(k) != "primary":
                    out[k] = c["tier"]
    return out


def tier_of(tiers: dict, pkg: str, version: str | None) -> str:
    v = re.sub(r"^\d+:", "", (version or "")).lstrip("v")
    alt = re.sub(r"[-_.]+", "-", pkg)
    return tiers.get((pkg, v)) or tiers.get((alt, v)) or tiers.get(pkg) or tiers.get(alt) or "not-in-gt"


def finding_versions(scanner: str, path) -> dict[tuple[str, str], set]:
    """(vulnerability id, package name) -> installed versions it was reported on."""
    d = json.loads(path.read_text(encoding="utf-8"))
    out: dict = defaultdict(set)
    if scanner == "grype":
        for m in d.get("matches", []):
            v, a = m["vulnerability"], m["artifact"]
            k = (canonical_id(v["id"], [r.get("id", "") for r in m.get("relatedVulnerabilities", [])]),
                 pkg_name(a.get("purl"), a.get("name")))
            out[k].add(a.get("version"))
    else:
        for res in d.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                k = (canonical_id(v["VulnerabilityID"], v.get("VendorIDs") or []),
                     pkg_name((v.get("PkgIdentifier") or {}).get("PURL"), v.get("PkgName")))
                out[k].add(v.get("InstalledVersion"))
    return out


def validate(tids: list[str], reuse: bool = False) -> pd.DataFrame:
    """Is the reference SBOM a faithful stand-in for 'what this scanner finds in the image'? Compare the CVE ids
    from scanning the reference SBOM with the CVE ids from the scanner's own direct scan of the image. They can
    only differ where the scanner's own inventory differs from the GT (its misses / false positives)."""
    f = TABLES / "rq5_reference_validation.csv"
    old = pd.read_csv(f) if f.exists() else pd.DataFrame()
    rows = []
    for tid in tids:
        if not reuse:
            build_reference(tid)
        for scanner in SCANNERS:
            ref_out = RQ5 / "validate" / scanner / f"{tid}.ref.json"
            dir_out = RQ5 / "validate" / scanner / f"{tid}.direct.json"
            if reuse and ref_out.exists() and dir_out.exists():   # re-classify existing scan outputs only
                r1 = r2 = {"status": "ok"}
            else:
                r1 = scan(scanner, RQ5 / "ref" / scanner / f"{tid}.cdx.json", ref_out,
                          WORK / "logs" / "rq5" / f"validate-{scanner}-ref-{tid}.log")
                r2 = scan_image(scanner, tid, dir_out, WORK / "logs" / "rq5" / f"validate-{scanner}-direct-{tid}.log")
            if r1["status"] != "ok" or r2["status"] != "ok":
                rows.append({"target": tid, "scanner": scanner, "status": f"ref={r1['status']} direct={r2['status']}"})
                continue
            fr, fd = findings(scanner, ref_out), findings(scanner, dir_out)
            ref, direct = {v for v, _ in fr}, {v for v, _ in fd}
            tiers = gt_tiers(tid)
            # a direct-only finding on a PRIMARY GT package means the reference fails to express that package
            # natively (a gap in the method); on a secondary/absent package it is the scanner's own inventory
            dv, rv = finding_versions(scanner, dir_out), finding_versions(scanner, ref_out)
            # best tier over the versions the finding was reported on (primary if ANY version is primary)
            rank = {"primary": 0, "secondary": 1, "not-in-gt": 2}
            klass, gaps = Counter(), set()
            for v, pk in fd - fr:
                t = min((tier_of(tiers, pk, ver) for ver in dv[(v, pk)] or {None}), key=rank.get)
                klass[t] += 1
                if t == "primary":
                    gaps.add(f"{v}:{pk}@{'/'.join(sorted(x or '' for x in dv[(v, pk)]))}")
            gaps = sorted(gaps)
            ref_only_pkgs = Counter(f"{pk}@{'/'.join(sorted(x or '' for x in rv[(v, pk)]))}" for v, pk in fr - fd)
            rows.append({"target": tid, "scanner": scanner, "status": "ok", "cves_direct": len(direct),
                         "cves_reference": len(ref), "common": len(ref & direct),
                         "jaccard": len(ref & direct) / len(ref | direct) if ref | direct else 1.0,
                         "direct_only_findings_on_primary": klass.get("primary", 0),
                         "direct_only_findings_on_secondary": klass.get("secondary", 0),
                         "direct_only_findings_not_in_gt": klass.get("not-in-gt", 0),
                         "reference_only_findings": len(fr - fd),
                         "primary_gaps": " ".join(gaps[:20]),
                         "reference_only_packages": " ".join(f"{k}({n})" for k, n in ref_only_pkgs.most_common(8)),
                         "direct_only": " ".join(sorted(direct - ref)[:15]), "reference_only": " ".join(sorted(ref - direct)[:15])})
            log(f"[validate] {tid:14} {scanner:5} direct={rows[-1]['cves_direct']:4} reference={rows[-1]['cves_reference']:4} "
                f"Jaccard={rows[-1]['jaccard']:.3f}")
    new = pd.DataFrame(rows)
    if not old.empty:
        old = old[~old.set_index(["target", "scanner"]).index.isin(new.set_index(["target", "scanner"]).index)]
    out = pd.concat([old, new]).sort_values(["target", "scanner"])
    out.to_csv(f, index=False)
    return out


def canonical_id(vid: str, aliases: list[str]) -> str:
    if vid.startswith("CVE-"):
        return vid
    cves = sorted(a for a in aliases if a.startswith("CVE-"))
    return cves[0] if cves else vid


def pkg_name(purl: str | None, name: str | None) -> str:
    if purl:
        r = record(name or "", None, purl, ctype="library")
        return r["name"].lower().rsplit("/", 1)[-1] if r["eco"] == "golang" else r["name"].lower()
    return (name or "").lower()


def findings(scanner: str, path) -> set[tuple[str, str]]:
    d = json.loads(path.read_text(encoding="utf-8"))
    out = set()
    if scanner == "grype":
        for m in d.get("matches", []):
            v, a = m["vulnerability"], m["artifact"]
            aliases = [r.get("id", "") for r in m.get("relatedVulnerabilities", [])]
            out.add((canonical_id(v["id"], aliases), pkg_name(a.get("purl"), a.get("name"))))
    else:
        for res in d.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                purl = (v.get("PkgIdentifier") or {}).get("PURL")
                out.add((canonical_id(v["VulnerabilityID"], v.get("VendorIDs") or []), pkg_name(purl, v.get("PkgName"))))
    return out


def sbom_for(source: str, tid: str, runs: list, scanner: str | None = None):
    if source == "reference":                       # each scanner gets the reference in its own conventions
        return RQ5 / "ref" / scanner / f"{tid}.cdx.json"
    rec = next((r for r in runs if r["config"] == "default" and r["rep"] == 1 and r["tool"] == source
                and r["target"] == tid and r["status"] == "ok" and (r.get("outputs") or {}).get("cyclonedx")), None)
    return ROOT / rec["outputs"]["cyclonedx"]["path"] if rec else None


# ----------------------------------------------------------------------------- analysis
def analyse(records: list, targets: list):
    rows, missed_rows = [], []
    gt_mech = {}
    for tid in targets:
        g = json.loads((ROOT / "ground_truth" / f"{tid}.json").read_text(encoding="utf-8"))
        gt_mech[tid] = defaultdict(set)
        for c in g["components"]:
            if c["tier"] == "primary":
                nm = c["name"].lower().rsplit("/", 1)[-1] if c["eco"] == "golang" else c["name"].lower()
                gt_mech[tid][nm].update(c.get("mechanisms") or [c["mechanism"]])
    # Layer of a finding's package: OS package (deb/apk/rpm) or application package. Cross-vendor loss on OS
    # packages is a metadata-convention effect (source-package link); on application packages it follows coverage.
    os_names = {tid: {(c["name"].lower()) for c in json.loads((ROOT / "ground_truth" / f"{tid}.json")
                .read_text(encoding="utf-8"))["components"] if c["eco"] in ("deb", "apk", "rpm")} for tid in targets}
    layer_rows = []
    by = {(r["scanner"], r["sbom"], r["target"]): r for r in records if r["status"] == "ok"}
    aborted = {(r["scanner"], r["sbom"], r["target"]) for r in records if r["status"] != "ok" and r["target"] in targets}
    for tid in targets:
        for scanner in SCANNERS:
            ref = by.get((scanner, "reference", tid))
            if not ref:
                continue
            ref_f = findings(scanner, ROOT / ref["output"])
            for tool in ["syft", "trivy", "cdxgen"]:
                r = by.get((scanner, tool, tid))
                if not r and (scanner, tool, tid) not in aborted:
                    continue
                f = findings(scanner, ROOT / r["output"]) if r else set()   # aborted scan reports nothing
                for layer in ("os", "application"):
                    sel = (lambda p: p in os_names[tid]) if layer == "os" else (lambda p: p not in os_names[tid])
                    rl, fl = {x for x in ref_f if sel(x[1])}, {x for x in f if sel(x[1])}
                    layer_rows.append({"target": tid, "scanner": scanner, "sbom": tool, "layer": layer,
                                       "ref_findings": len(rl), "found": len(rl & fl), "extra": len(fl - rl)})
    lr = pd.DataFrame(layer_rows)
    if not lr.empty:
        ls = lr.groupby(["layer", "scanner", "sbom"])[["ref_findings", "found", "extra"]].sum()
        ls["finding_recall"] = ls.found / ls.ref_findings
        ls.to_csv(TABLES / "rq5_by_layer.csv")
    for tid in targets:
        for scanner in SCANNERS:
            ref = by.get((scanner, "reference", tid))
            if not ref:
                continue
            ref_f = findings(scanner, ROOT / ref["output"])
            for tool in ["syft", "trivy", "cdxgen"]:
                r = by.get((scanner, tool, tid))
                if not r:
                    continue
                f = findings(scanner, ROOT / r["output"])
                found, missed, extra = ref_f & f, ref_f - f, f - ref_f
                # CVE level: does each vulnerability surface for the image at all, whichever package it is attached
                # to (e.g. cdxgen also lists source packages, so Grype reports CVE-x on "glibc" rather than "libc6").
                ref_v, f_v = {v for v, _ in ref_f}, {v for v, _ in f}
                rows.append({"target": tid, "scanner": scanner, "sbom": tool, "same_vendor":
                             (scanner, tool) in (("grype", "syft"), ("trivy", "trivy")), "scan_failed": False,
                             "ref_findings": len(ref_f), "found": len(found), "missed": len(missed), "extra": len(extra),
                             "finding_recall": len(found) / len(ref_f) if ref_f else None,
                             "ref_cves": len(ref_v), "cves_found": len(ref_v & f_v), "extra_cves": len(f_v - ref_v),
                             "cve_recall": len(ref_v & f_v) / len(ref_v) if ref_v else None,
                             "log4shell_in_ref": any(v == LOG4SHELL for v, _ in ref_f),
                             "log4shell_found": any(v == LOG4SHELL for v, _ in f)})
                for vid, pkg in missed:
                    missed_rows.append({"target": tid, "scanner": scanner, "sbom": tool, "vuln": vid, "package": pkg,
                                        "mechanism": "|".join(sorted(gt_mech[tid].get(pkg, {"(not in GT by name)"})))})
    # A failed scan (scanner aborted on the SBOM) reports nothing: count it explicitly, never drop it silently.
    failed = {(r["scanner"], r["sbom"], r["target"]) for r in records if r["status"] != "ok" and r["target"] in targets}
    for scanner, tool, tid in sorted(failed):
        ref = by.get((scanner, "reference", tid))
        if tool == "reference" or not ref:
            continue
        ref_f = findings(scanner, ROOT / ref["output"])
        rows.append({"target": tid, "scanner": scanner, "sbom": tool, "same_vendor": False, "scan_failed": True,
                     "ref_findings": len(ref_f), "found": 0, "missed": len(ref_f), "extra": 0, "finding_recall": 0.0,
                     "ref_cves": len({v for v, _ in ref_f}), "cves_found": 0, "extra_cves": 0, "cve_recall": 0.0,
                     "log4shell_in_ref": any(v == LOG4SHELL for v, _ in ref_f), "log4shell_found": False})
    df = pd.DataFrame(rows)
    df.to_csv(TABLES / "rq5_per_target.csv", index=False)
    summ = df.groupby(["scanner", "sbom"]).agg(targets=("target", "nunique"), scans_failed=("scan_failed", "sum"),
                                               ref_findings=("ref_findings", "sum"), found=("found", "sum"),
                                               missed=("missed", "sum"), extra=("extra", "sum"),
                                               ref_cves=("ref_cves", "sum"), cves_found=("cves_found", "sum"),
                                               extra_cves=("extra_cves", "sum"))
    summ["finding_recall"] = summ.found / summ.ref_findings
    summ["cve_recall"] = summ.cves_found / summ.ref_cves
    summ.to_csv(TABLES / "rq5_summary.csv")
    md = pd.DataFrame(missed_rows)
    if not md.empty:
        md.to_csv(TABLES / "rq5_missed_findings.csv", index=False)
        md.groupby(["sbom", "scanner", "mechanism"]).size().unstack([0, 1]).fillna(0).astype(int) \
            .to_csv(TABLES / "rq5_missed_by_mechanism.csv")
    df[df.log4shell_in_ref][["target", "scanner", "sbom", "log4shell_found"]].to_csv(TABLES / "rq5_log4shell.csv", index=False)
    return df, summ, md


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="+", metavar="ID")
    ap.add_argument("--skip-scan", action="store_true", help="only re-analyse existing scan outputs")
    ap.add_argument("--validate", nargs="+", metavar="ID", help="reference vs direct image scan for these images")
    ap.add_argument("--reuse", action="store_true", help="with --validate: re-classify existing scan outputs")
    args = ap.parse_args()
    if not args.skip_scan and subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        # an engine outage must never be recorded as 272 failed scans over the previous good results
        raise SystemExit("Docker engine not reachable: start Docker and re-run")
    if args.validate:
        TABLES.mkdir(parents=True, exist_ok=True)
        validate(args.validate, reuse=args.reuse)
        return 0
    TABLES.mkdir(parents=True, exist_ok=True)
    targets = [t["id"] for t in load_catalog()["targets"] if t["stage"] in ("S3", "P")]
    if args.only:
        targets = [t for t in targets if t in args.only]
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    rec_file = RESULTS_DIR / "rq5_scans.json"
    records = json.loads(rec_file.read_text(encoding="utf-8"))["scans"] if rec_file.exists() else []
    if not args.skip_scan:
        keep = {(r["scanner"], r["sbom"], r["target"]): r for r in records}
        for tid in targets:
            info = build_reference(tid)
            for source in SBOM_SOURCES:
                for scanner in SCANNERS:
                    sb = sbom_for(source, tid, runs, scanner)
                    if sb is None or not sb.exists():
                        log(f"[rq5] {tid} {source}: no SBOM, skipped")
                        continue
                    out = RQ5 / "scans" / scanner / source / f"{tid}.json"
                    res = scan(scanner, sb, out, WORK / "logs" / "rq5" / f"{scanner}-{source}-{tid}.log")
                    res.update(scanner=scanner, sbom=source, target=tid, sbom_sha256=sha256_file(sb),
                               ref_components=info["components"] if source == "reference" else None)
                    keep[(scanner, source, tid)] = res
                    log(f"[rq5] {tid:16} {source:9} -> {scanner:5} {res['status']} ({res['seconds']}s)")
        records = sorted(keep.values(), key=lambda r: (r["target"], r["sbom"], r["scanner"]))
        write_json(rec_file, {"scans": records, "grype_image": GRYPE_IMAGE, "trivy_image": trivy_image(),
                              "updated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    failed = [r for r in records if r["status"] != "ok"]
    if failed:
        log(f"FAILED scans: {[(r['scanner'], r['sbom'], r['target']) for r in failed]}")
    df, summ, md = analyse(records, targets)
    log("== RQ5 summary ==\n" + summ.round(3).to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
