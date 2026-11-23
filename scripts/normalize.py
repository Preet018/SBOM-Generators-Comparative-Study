"""Parse SBOMs (CycloneDX 1.x JSON, SPDX 2.3 JSON, SPDX 3.0.1 JSON-LD) into canonical component records.

Only *package* components are kept. Dropped, and counted separately:
  * CycloneDX types file, operating-system, container, data, cryptographic-asset, ... (not packages);
  * the SBOM's own subject (CycloneDX metadata.component; SPDX packages the document DESCRIBES / rootElement);
  * SPDX packages whose purpose is FILE, SOURCE, CONTAINER or OPERATING-SYSTEM.
Each kept record carries the same normalised identity key as the ground truth (ident.norm_key).

CLI: python scripts/normalize.py   -> results/sbom_inventory.json (one row per SBOM) + determinism report.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

from packageurl import PackageURL

from common import RESULTS_DIR, ROOT, log, write_json
from ident import norm_key

PACKAGE_TYPES_CDX = {"library", "framework", "application", "platform"}
SKIP_PURPOSE_SPDX = {"FILE", "SOURCE", "CONTAINER", "OPERATING-SYSTEM", "OPERATING_SYSTEM"}


def parse_purl(purl: str | None):
    if not purl:
        return None
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def record(name: str, version: str | None, purl: str | None, *, ctype: str, licenses=(), hashes=None, cpes=(),
           paths=(), group: str | None = None) -> dict:
    p = parse_purl(purl)
    if p is not None:
        eco, namespace, pname, pversion = p.type.lower(), p.namespace, p.name, p.version
        namespace = unquote(namespace) if namespace else None
        if pname and "%" in pname:   # double-encoded purl (seen in cdxgen: %2520); decode for matching only
            pname = unquote(pname)
    else:
        eco, namespace, pname, pversion = "unknown", group or None, name, None
    version = version if version not in (None, "", "NOASSERTION", "UNKNOWN") else pversion
    return {"eco": eco, "namespace": namespace, "name": pname or name, "version": version,
            "key": norm_key(eco, namespace, pname or name or ""), "purl": purl, "type": ctype,
            "licenses": sorted({l for l in licenses if l}), "hashes": hashes or {}, "cpes": sorted(set(cpes)),
            "paths": sorted(set(paths))}


# ----------------------------------------------------------------------------- CycloneDX
def cdx_licenses(comp: dict) -> list[str]:
    out = []
    for entry in comp.get("licenses") or []:
        if "expression" in entry:
            out.append(entry["expression"])
        lic = entry.get("license") or {}
        out.append(lic.get("id") or lic.get("name"))
    return out


def cdx_hashes(comp: dict) -> dict:
    hashes = {h["alg"].upper().replace("-", ""): h["content"].lower() for h in comp.get("hashes") or []}
    for ref in comp.get("externalReferences") or []:          # Syft puts JAR hashes here
        for h in ref.get("hashes") or []:
            hashes.setdefault(h["alg"].upper().replace("-", ""), h["content"].lower())
    return hashes


def cdx_paths(comp: dict) -> list[str]:
    paths = []
    for prop in comp.get("properties") or []:
        n = prop.get("name", "")
        if n.startswith("syft:location:") and n.endswith(":path") or n in ("aquasecurity:trivy:FilePath", "SrcFile"):
            paths.append(prop.get("value", ""))
    for occ in (comp.get("evidence") or {}).get("occurrences") or []:
        paths.append(occ.get("location", ""))
    return [p for p in paths if p]


def parse_cyclonedx(d: dict) -> tuple[list[dict], Counter]:
    kept, dropped = [], Counter()

    def walk(comps):
        for c in comps or []:
            ctype = c.get("type", "library")
            props = {p.get("name") for p in c.get("properties") or []}
            if ctype == "application" and not c.get("purl") and "aquasecurity:trivy:Class" in props:
                # Trivy's grouping node for a lockfile/manifest/Go binary ("found in this file"), not a package claim
                dropped["trivy-aggregation-node"] += 1
            elif ctype in PACKAGE_TYPES_CDX:
                cpes = [c["cpe"]] if c.get("cpe") else []
                kept.append(record(c.get("name", ""), c.get("version"), c.get("purl"), ctype=ctype,
                                   licenses=cdx_licenses(c), hashes=cdx_hashes(c), cpes=cpes, paths=cdx_paths(c),
                                   group=c.get("group")))
            else:
                dropped[ctype] += 1
            walk(c.get("components"))     # nested components (flattened)
    walk(d.get("components"))
    return kept, dropped


# ----------------------------------------------------------------------------- SPDX 2.3
def parse_spdx2(d: dict) -> tuple[list[dict], Counter]:
    described = {r["relatedSpdxElement"] for r in d.get("relationships", [])
                 if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
    described |= set(d.get("documentDescribes") or [])
    kept, dropped = [], Counter()
    by_trivy = "trivy" in " ".join((d.get("creationInfo") or {}).get("creators") or []).lower()
    for p in d.get("packages", []):
        purpose = (p.get("primaryPackagePurpose") or "").upper()
        if p["SPDXID"] in described:
            dropped["document-subject"] += 1
            continue
        has_purl = any(r.get("referenceType") == "purl" for r in p.get("externalRefs") or [])
        if by_trivy and purpose == "APPLICATION" and not has_purl:
            dropped["trivy-aggregation-node"] += 1    # same grouping node the CycloneDX parser drops
            continue
        if purpose in SKIP_PURPOSE_SPDX:
            dropped[f"purpose:{purpose}"] += 1
            continue
        refs = p.get("externalRefs") or []
        purl = next((r["referenceLocator"] for r in refs if r.get("referenceType") == "purl"), None)
        cpes = [r["referenceLocator"] for r in refs if r.get("referenceType", "").startswith("cpe")]
        lics = [p.get(k) for k in ("licenseDeclared", "licenseConcluded") if p.get(k) not in (None, "NOASSERTION", "NONE")]
        hashes = {c["algorithm"].upper().replace("-", ""): c["checksumValue"].lower() for c in p.get("checksums") or []}
        kept.append(record(p.get("name", ""), p.get("versionInfo"), purl, ctype=purpose.lower() or "package",
                           licenses=lics, hashes=hashes, cpes=cpes))
    return kept, dropped


# ----------------------------------------------------------------------------- SPDX 3.0.1 (JSON-LD)
def parse_spdx3(d: dict) -> tuple[list[dict], Counter]:
    graph = d.get("@graph", [])
    roots = set()
    for e in graph:
        if e.get("type") == "SpdxDocument":
            roots |= set(e.get("rootElement") or [])
    kept, dropped = [], Counter()
    for e in graph:
        if e.get("type") != "software_Package":
            if e.get("type") not in ("CreationInfo", "SpdxDocument"):
                dropped[e.get("type")] += 1
            continue
        purpose = (e.get("software_primaryPurpose") or "").upper()
        if e["spdxId"] in roots:
            dropped["document-subject"] += 1
            continue
        if purpose in ("FILE", "SOURCE", "CONTAINER", "OPERATINGSYSTEM"):
            dropped[f"purpose:{purpose}"] += 1
            continue
        purl = e.get("software_packageUrl") or next(
            (x.get("identifier") for x in e.get("externalIdentifier") or [] if x.get("externalIdentifierType") == "packageUrl"), None)
        kept.append(record(e.get("name", ""), e.get("software_packageVersion"), purl, ctype=purpose.lower() or "package"))
    return kept, dropped


# ----------------------------------------------------------------------------- entry points
def load_sbom(path: Path) -> dict:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    if d.get("bomFormat") == "CycloneDX":
        comps, dropped = parse_cyclonedx(d)
        fmt, spec = "cyclonedx", d.get("specVersion")
    elif "spdxVersion" in d:
        comps, dropped = parse_spdx2(d)
        fmt, spec = "spdx", d["spdxVersion"]
    elif "@graph" in d:
        comps, dropped = parse_spdx3(d)
        fmt, spec = "spdx", "SPDX-3.0.1" if "3.0.1" in str(d.get("@context")) else str(d.get("@context"))
    else:
        raise ValueError(f"{path}: unknown SBOM format")
    return {"format": fmt, "spec": spec, "components": comps, "dropped": dict(dropped)}


def identity_multiset(comps: list[dict]) -> Counter:
    return Counter((c["key"], c["version"]) for c in comps)


def main() -> int:
    runs = json.loads((RESULTS_DIR / "tool_runs.json").read_text(encoding="utf-8"))["runs"]
    inventory, by_job = [], {}
    for r in runs:
        for fmt, out in (r.get("outputs") or {}).items():
            if not out:
                continue
            row = {"config": r["config"], "tool": r["tool"], "rep": r["rep"], "target": r["target"], "format": fmt}
            try:
                sb = load_sbom(ROOT / out["path"])
                comps = sb["components"]
                row.update(parse_ok=True, spec=sb["spec"], packages=len(comps),
                           unique_identities=len({(c["key"], c["version"]) for c in comps}),
                           with_purl=sum(1 for c in comps if c["purl"]), with_version=sum(1 for c in comps if c["version"]),
                           duplicates=len(comps) - len({(c["key"], c["version"]) for c in comps}),
                           dropped=sb["dropped"], ecos=dict(Counter(c["eco"] for c in comps)))
                by_job[(r["config"], r["tool"], r["rep"], r["target"], fmt)] = identity_multiset(comps)
            except Exception as exc:
                row.update(parse_ok=False, error=repr(exc))
            inventory.append(row)

    # Determinism: rep1 vs rep2 (CycloneDX) must list the same package identities with the same multiplicity.
    determinism = []
    for (config, tool, rep, target, fmt), ms in by_job.items():
        if rep != 1 or fmt != "cyclonedx":
            continue
        other = by_job.get((config, tool, 2, target, fmt))
        if other is None:
            continue
        determinism.append({"config": config, "tool": tool, "target": target, "identical": ms == other,
                            "only_rep1": sorted(map(str, (ms - other).keys()))[:10],
                            "only_rep2": sorted(map(str, (other - ms).keys()))[:10]})
    write_json(RESULTS_DIR / "sbom_inventory.json", {"sboms": inventory, "determinism": determinism})
    bad = [r for r in inventory if not r["parse_ok"]]
    nondet = [d for d in determinism if not d["identical"]]
    log(f"{len(inventory)} SBOMs parsed, {len(bad)} unparseable; determinism: {len(determinism)} pairs, "
        f"{len(nondet)} differ")
    for r in bad:
        log(f"  UNPARSEABLE {r['tool']} rep{r['rep']} {r['target']} {r['format']}: {r['error']}")
    for d in nondet:
        log(f"  NON-DETERMINISTIC {d['tool']} {d['target']}: only rep1={d['only_rep1'][:3]} only rep2={d['only_rep2'][:3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
