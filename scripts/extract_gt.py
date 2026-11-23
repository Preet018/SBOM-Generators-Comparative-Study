"""Extract the ground truth (GT) for every target from authoritative sources, never from the SBOM tools.

Output: ground_truth/<target>.json with one record per component:
  eco        purl type of the component (deb, apk, rpm, maven, npm, pypi, golang, generic, github)
  namespace  purl namespace (maven groupId, deb/apk/rpm distro, npm scope); golang keeps the full module path in name
  name, version, purl
  key        normalised identity used for matching (eco + namespace + normalised name)
  tier       primary   = a component that is really part of the target; counts for recall
             secondary = present-but-inert or the subject itself (vendored copies inside other packages, archived
                         wheels, the application's own identity, JDK internals). A tool reporting it is not wrong
                         (counts as correct for precision) but missing it is not penalised (excluded from recall).
  mechanism  how the component got into the target (os-pm, lang-pm, nested-jar, layered-jar, bundled-js,
             wheel-vendored-so, runtime-outside-pm, go-module-in-binary, static-link, vendored-source,
             manual-download, manual-copy, shaded, shaded-relocated, dockerfile-install, ...)
  scope      runtime | dev | test | optional (source stage) ; None if not applicable
  paths, instances, license, hashes, alt_names, evidence

Sources: dpkg/apk/rpm databases, *.dist-info METADATA, node_modules/**/package.json, JAR pom.properties,
Go build info, ELF DT_NEEDED, image config ENV, Maven/npm/pip build outputs (work/buildinfo), planted.json.

Usage: python scripts/extract_gt.py [--only ID ...]
"""
from __future__ import annotations

import argparse
import email.parser
import hashlib
import io
import json
import posixpath
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from packageurl import PackageURL

from common import (BUILDINFO_DIR, IMAGES_DIR, ROOT, ROOTFS_DIR, WORK, load_catalog, log, plain, scan_path,
                    write_json)
from fsutil import Rootfs, elf_info, go_buildinfo, image_env

GT_DIR = ROOT / "ground_truth"
TMP = WORK / "tmp"


# ============================================================================ normalisation (shared with normalize.py)
from ident import norm_key, pep503  # noqa: E402


class GT:
    def __init__(self, target: dict):
        self.target = target
        self.items: dict[tuple, dict] = {}
        self.notes: list[str] = []

    def add(self, eco: str, name: str, version: str | None, *, mechanism: str, evidence: str,
            namespace: str | None = None, tier: str = "primary", scope: str | None = None, path: str | None = None,
            license=None, hashes: dict | None = None, alt_names=(), qualifiers: dict | None = None) -> dict:
        if eco == "golang" and namespace:        # keep the full module path as the name
            name, namespace = f"{namespace}/{name}", None
        version = version or None
        key = norm_key(eco, namespace, name)
        ident = (key, version)
        comp = self.items.get(ident)
        if comp is None:
            if eco == "golang":
                ns, _, nm = name.rpartition("/")
                purl = PackageURL("golang", ns or None, nm, version).to_string()
            else:
                purl = PackageURL(eco, namespace, name, version, qualifiers).to_string()
            comp = {"eco": eco, "namespace": namespace, "name": name, "version": version, "purl": purl,
                    "key": key, "tier": tier, "mechanism": mechanism, "mechanisms": [], "scope": scope, "paths": [],
                    "instances": 0, "license": None, "hashes": {}, "alt_names": [], "evidence": evidence}
            self.items[ident] = comp
        elif tier == "primary" and comp["tier"] == "secondary":   # primary evidence wins
            comp.update(tier="primary", mechanism=mechanism, evidence=evidence, mechanisms=[])
        # The same identity can arrive by several routes. Only routes at the component's own tier count as
        # inclusion mechanisms: a secondary echo (source-package name, archived wheel, embedded pom) of a
        # primary component must not be credited as a way that component got into the target (RQ3).
        if tier == comp["tier"] and mechanism not in comp["mechanisms"]:
            comp["mechanisms"].append(mechanism)
        comp["instances"] += 1
        if path and path not in comp["paths"]:
            comp["paths"].append(path)
        if license and not comp["license"]:
            comp["license"] = license
        if hashes:
            comp["hashes"].update(hashes)
        for a in alt_names:
            if a not in comp["alt_names"]:
                comp["alt_names"].append(a)
        if scope and not comp["scope"]:
            comp["scope"] = scope
        return comp

    def to_json(self) -> dict:
        comps = sorted(self.items.values(), key=lambda c: (c["tier"], c["eco"], c["key"], c["version"] or ""))
        stats: dict = {"total": len(comps)}
        for field in ("tier", "eco", "mechanism"):
            stats[f"by_{field}"] = {}
            for c in comps:
                stats[f"by_{field}"][c[field]] = stats[f"by_{field}"].get(c[field], 0) + 1
        return {"target": self.target["id"], "stage": self.target["stage"], "subject": self.target["subject"],
                "kind": self.target["kind"], "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "stats": stats, "notes": self.notes, "components": comps}


# ============================================================================ license helpers
def python_license(meta) -> str | None:
    if meta.get("License-Expression"):
        return meta["License-Expression"].strip()
    lic = (meta.get("License") or "").strip()
    if lic and lic.upper() != "UNKNOWN" and len(lic) < 120:
        return lic
    cls = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return " OR ".join(cls) if cls else None


def npm_license(pkg: dict) -> str | None:
    lic = pkg.get("license") or pkg.get("licenses")
    if isinstance(lic, dict):
        return lic.get("type")
    if isinstance(lic, list):
        return " OR ".join(l.get("type", str(l)) if isinstance(l, dict) else str(l) for l in lic)
    return lic


def deb_license(fs: Rootfs, pkg: str) -> str | None:
    p = f"usr/share/doc/{pkg}/copyright"
    if not fs.exists(p):
        return None
    try:
        lics = re.findall(r"^License:\s*(\S[^\n]*)", fs.text(p), re.M)
    except KeyError:
        return None
    seen = []
    for l in lics:
        if l.strip() not in seen:
            seen.append(l.strip())
    return " AND ".join(seen) if seen else None


# ============================================================================ OS packages
def os_release(fs: Rootfs) -> dict:
    for p in ("etc/os-release", "usr/lib/os-release"):
        if fs.exists(p):
            try:
                return dict(re.findall(r'^(\w+)="?([^"\n]*)"?', fs.text(p), re.M))
            except KeyError:
                pass
    return {}


def parse_deb822(text: str) -> list[dict]:
    paras, cur, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                paras.append(cur)
            cur, last = {}, None
        elif line[0] in " \t" and last:
            cur[last] += "\n" + line.strip()
        elif ":" in line:
            last, _, val = line.partition(":")
            cur[last] = val.strip()
    if cur:
        paras.append(cur)
    return paras


def add_os_packages(gt: GT, fs: Rootfs) -> dict[str, str]:
    """dpkg / distroless status.d / apk / rpm. Returns a file->package ownership map."""
    osr = os_release(fs)
    distro = (osr.get("ID") or "").lower() or None
    owners: dict[str, str] = {}
    sources = []
    if fs.exists("var/lib/dpkg/status"):
        sources.append(("dpkg-status", fs.text("var/lib/dpkg/status")))
    for p in fs.glob(r"^var/lib/dpkg/status\.d/[^/]+$"):
        if not p.endswith(".md5sums"):
            sources.append(("dpkg-status.d", fs.text(p)))
    for evidence, text in sources:
        for para in parse_deb822(text):
            # exactly "... installed" (not "half-installed", "config-files", ...); status.d entries are installed
            if "Package" not in para or not re.search(r"(^|\s)installed$", para.get("Status", "install ok installed")):
                continue
            name, version = para["Package"], para.get("Version")
            gt.add("deb", name, version, namespace=distro, mechanism="os-pm", evidence=evidence,
                   path=f"var/lib/dpkg/{'status' if evidence == 'dpkg-status' else 'status.d'}",
                   license=deb_license(fs, name), qualifiers={"arch": para.get("Architecture")} if para.get("Architecture") else None)
            src = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", para.get("Source", ""))
            if src:   # the source package this binary was built from (some tools report it too)
                add_source_package(gt, "deb", src.group(1), src.group(2) or version, distro)
    for p in fs.glob(r"^var/lib/dpkg/info/[^/]+\.list$"):
        pkg = Path(p).name.removesuffix(".list").split(":")[0]
        for line in fs.text(p).splitlines():
            owners[merged_usr(line)] = pkg

    if fs.exists("lib/apk/db/installed"):
        for block in fs.text("lib/apk/db/installed").split("\n\n"):
            fields, folder = {}, ""
            for line in block.splitlines():
                if len(line) > 2 and line[1] == ":":
                    k, v = line[0], line[2:]
                    if k == "F":
                        folder = v
                    elif k == "R":
                        owners[merged_usr(f"/{folder}/{v}")] = fields.get("P", "?")
                    else:
                        fields.setdefault(k, v)
            if "P" in fields:
                gt.add("apk", fields["P"], fields.get("V"), namespace=distro, mechanism="os-pm",
                       evidence="apk-installed", path="lib/apk/db/installed", license=fields.get("L"),
                       qualifiers={"arch": fields["A"]} if fields.get("A") else None)
                if fields.get("o"):   # origin = source package (aports name)
                    add_source_package(gt, "apk", fields["o"], fields.get("V"), distro)

    rpmdb = fs.glob(r"^(var/lib/rpm|usr/lib/sysimage/rpm)/rpmdb\.sqlite$")
    if rpmdb:
        for name, epoch, ver, rel, arch, lic, srpm in query_rpmdb(fs, rpmdb[0], gt.target["id"]):
            version = f"{'' if epoch in ('(none)', '') else epoch + ':'}{ver}-{rel}"
            tier = "secondary" if name == "gpg-pubkey" else "primary"   # pseudo-package for imported keys
            gt.add("rpm", name, version, namespace=distro, mechanism="os-pm", evidence="rpmdb", tier=tier,
                   path=rpmdb[0], license=lic, qualifiers={"arch": arch} if arch != "(none)" else None)
            m = re.match(r"^(.+)-([^-]+)-([^-]+)\.src\.rpm$", srpm or "")
            if m:
                add_source_package(gt, "rpm", m.group(1), f"{m.group(2)}-{m.group(3)}", distro)
    gt.notes.append(f"os-release: ID={osr.get('ID')} VERSION_ID={osr.get('VERSION_ID')}")
    return owners


def add_source_package(gt: GT, eco: str, name: str, version: str | None, distro: str | None):
    """Source packages are not installed, but they name the origin of installed binaries (Debian `Source:`,
    Alpine origin `o:`, RPM `SOURCERPM`). A tool listing them is not wrong: secondary, never in recall.
    If a binary package of the same name and version exists, gt.add() keeps it primary (no-op here)."""
    strip_epoch = lambda v: re.sub(r"^\d+:", "", v or "")   # noqa: E731
    key = norm_key(eco, distro, name)
    if any(c["key"] == key and strip_epoch(c["version"]) == strip_epoch(version) for c in gt.items.values()):
        return   # same package as an installed binary (differs at most by epoch): not a separate record
    gt.add(eco, name, version, namespace=distro, mechanism="source-package", tier="secondary",
           evidence="package database source field")


def merged_usr(path: str) -> str:
    """Compare paths across merged-/usr layouts (/lib/x == /usr/lib/x)."""
    p = path.lstrip("/")
    return p[4:] if p.startswith("usr/") else p


def query_rpmdb(fs: Rootfs, dbfile: str, tid: str) -> list[tuple]:
    """Read the rpm sqlite DB with the real `rpm` tool (from the UBI image itself), not with our own parser."""
    tmp = TMP / f"rpmdb-{tid}"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    for p in fs.glob(r"^" + re.escape(posixpath.dirname(dbfile)) + r"/[^/]+$"):
        (tmp / Path(p).name).write_bytes(fs.read(p))
    image = "registry.access.redhat.com/ubi9/ubi-minimal"
    out = subprocess.run(["docker", "run", "--rm", "-v", f"{plain(tmp)}:/rpmdb", "--entrypoint", "rpm", image,
                          "--dbpath", "/rpmdb", "-qa", "--qf",
                          r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{LICENSE}\t%{SOURCERPM}\n"],
                         capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        name, epoch, ver, rel, arch, lic, srpm = line.split("\t")
        rows.append((name, "" if epoch == "0" else epoch, ver, rel, arch, lic, None if srpm == "(none)" else srpm))
    return rows


# ============================================================================ Python
def add_python(gt: GT, fs: Rootfs, owners: dict[str, str]):
    # dist-info/METADATA, egg-info/PKG-INFO, and old-style single-file *.egg-info (common in Debian/Ubuntu python3-*)
    rx = re.compile(r"(?:^|/)([^/]+)\.(dist-info|egg-info)(?:/(METADATA|PKG-INFO))?$")
    for path, member in list(fs.files()):
        m = rx.search(path)
        if not m or (m.group(3) is None and m.group(2) != "egg-info"):
            continue
        meta = email.parser.HeaderParser().parsestr(fs.text(path))
        name, version = meta.get("Name"), meta.get("Version")
        if not name:
            continue
        if "/_vendor/" in path:
            tier, mech = "secondary", "vendored-source"            # e.g. setuptools/_vendor/*.dist-info
        elif merged_usr(path) in owners or merged_usr(posixpath.dirname(path)) in owners:
            tier, mech = "primary", "lang-in-os-pkg"               # python3-xyz installed by dpkg/apk
        else:
            tier, mech = "primary", "lang-pm"
        gt.add("pypi", name, version, mechanism=mech, tier=tier, evidence=m.group(2), path=path,
               license=python_license(meta))

    # pip vendors its own dependencies (pip/_vendor/vendor.txt): present, never installed as packages
    for path in fs.glob(r"site-packages/pip/_vendor/vendor\.txt$"):
        for line in fs.text(path).splitlines():
            mm = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)", line.strip())
            if mm:
                gt.add("pypi", mm.group(1), mm.group(2), mechanism="vendored-source", tier="secondary",
                       evidence="pip-vendor.txt", path=path)

    # wheels archived inside the stdlib (ensurepip) are files, not installed packages
    for path in fs.glob(r"ensurepip/_bundled/[^/]+\.whl$"):
        mm = re.match(r"([^-]+)-([^-]+)-", Path(path).name)
        if mm:
            gt.add("pypi", mm.group(1), mm.group(2), mechanism="archive-file", tier="secondary",
                   evidence="ensurepip-wheel", path=path)

    # native libraries vendored inside wheels (numpy.libs/, scipy.libs/, scikit_learn.libs/ ...)
    for path in fs.glob(r"(?:site-packages|app/deps)/[^/]+\.libs/[^/]+\.so[.\d]*$"):
        fname = Path(path).name
        # auditwheel appends one or more 8-hex-digit hashes: libgfortran-040039e1-0352e75f.so.5.0.0 -> libgfortran
        base = re.sub(r"(-[0-9a-f]{8})+$", "", fname.split(".so")[0])
        alt = {base, base.removeprefix("lib")}
        known = {"libscipy_openblas64_": "openblas", "libscipy_openblas": "openblas", "libopenblas64_": "openblas",
                 "libopenblas": "openblas", "libgfortran": "gfortran", "libquadmath": "quadmath", "libgomp": "gomp",
                 "libstdc++": "libstdc++", "libgcc_s": "libgcc"}
        if base in known:
            alt.add(known[base])
        owner_pkg = path.split("/")[-2].removesuffix(".libs")
        gt.add("generic", base, None, mechanism="wheel-vendored-so", evidence="wheel .libs file", path=path,
               alt_names=sorted(alt), qualifiers={"vendored_in": owner_pkg})

    add_wheel_embedded_sboms(gt, fs)


def add_wheel_embedded_sboms(gt: GT, fs: Rootfs):
    """PEP 770 SBOMs shipped inside wheels (*.dist-info/sboms/*.json), written at wheel build time by
    maturin/cargo-cyclonedx (Rust crates compiled into the extension), auditwheel (system libraries grafted
    into *.libs/) or the project itself (Pillow). Their components are code that is really in the image."""
    for path in fs.glob(r"\.dist-info/sboms/[^/]+\.json$"):
        try:
            d = json.loads(fs.read(path))
        except (ValueError, KeyError):
            gt.notes.append(f"unreadable embedded SBOM {path}")
            continue
        if d.get("bomFormat") != "CycloneDX":
            gt.notes.append(f"non-CycloneDX embedded SBOM not parsed: {path}")
            continue
        wheel = re.sub(r"-[^-/]+\.dist-info/.*$", "", path.split("/")[-3] + "/")
        self_names = {pep503(wheel), pep503(((d.get("metadata") or {}).get("component") or {}).get("name", ""))}
        for c in d.get("components", []):
            purl = c.get("purl")
            p = None
            if purl:
                try:
                    p = PackageURL.from_string(purl)
                except ValueError:
                    p = None
            if p is not None and p.type == "pypi" and pep503(p.name) in self_names:
                continue                     # the wheel itself, or one of its own C-extension modules
            if p is not None and p.type in ("rpm", "deb", "apk") and enrich_vendored_so(gt, p, path):
                continue                     # auditwheel: identity of a grafted *.libs/*.so we already have
            if p is not None:
                gt.add(p.type, p.name, p.version or c.get("version"), namespace=p.namespace,
                       mechanism="wheel-embedded-sbom", evidence=f"embedded SBOM {path.split('/')[-1]} in {wheel}",
                       path=path, license=cdx_license(c))
            elif enrich_vendored_so_by_name(gt, c.get("name", ""), c.get("version"), wheel):
                continue                     # exact-name match with a vendored .so of this wheel: same component
            else:                            # no identifier (Pillow lists vendored libs by display name only)
                gt.add("generic", c.get("name", "?"), c.get("version"), mechanism="wheel-embedded-sbom-noid",
                       tier="secondary", evidence=f"embedded SBOM {path.split('/')[-1]} in {wheel} (no purl)",
                       path=path, alt_names=[c.get("name", "?")])


def enrich_vendored_so(gt: GT, p: PackageURL, sbom_path: str) -> bool:
    """Give a wheel-vendored .so record the exact identity auditwheel recorded for it (no double counting)."""
    for gkey, comp in list(gt.items.items()):
        if comp["mechanism"] == "wheel-vendored-so" and p.name.lower() in {a.lower() for a in comp["alt_names"]}:
            comp["alt_names"] = sorted(set(comp["alt_names"]) | {p.name})
            comp.setdefault("identified_as", [])
            ident = p.to_string()
            if ident not in comp["identified_as"]:
                comp["identified_as"].append(ident)
            comp["evidence"] += f"; identity from auditwheel SBOM ({sbom_path.split('/')[-3]})"
            if comp["version"] is None and p.version:   # adopt the exact version auditwheel recorded
                gt.items.pop(gkey)
                comp["version"] = p.version
                gt.items[(comp["key"], p.version)] = comp
            return True
    return False


def enrich_vendored_so_by_name(gt: GT, name: str, version: str | None, wheel: str) -> bool:
    """The wheel's own SBOM names a library it vendors with exactly the name of one of its *.libs/*.so files:
    give that (versionless) .so record the declared version instead of adding a second record."""
    if not name or not version:
        return False
    for ident, comp in list(gt.items.items()):
        if (comp["mechanism"] == "wheel-vendored-so" and comp["version"] is None
                and comp["name"].lower() == name.lower()
                and pep503(wheel) in {pep503(p.split("/")[-2].removesuffix(".libs")) for p in comp["paths"]}):
            gt.items.pop(ident)
            comp["version"] = version
            comp["purl"] = PackageURL("generic", None, comp["name"], version).to_string()
            comp["evidence"] += f"; version declared by {wheel}'s embedded SBOM"
            gt.items[(comp["key"], version)] = comp
            return True
    return False


def cdx_license(c: dict) -> str | None:
    for entry in c.get("licenses") or []:
        if entry.get("expression"):
            return entry["expression"]
        lic = entry.get("license") or {}
        if lic.get("id") or lic.get("name"):
            return lic.get("id") or lic.get("name")
    return None


# ============================================================================ npm
NPM_RX = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)/package\.json$")


def split_npm(full: str) -> tuple[str | None, str]:
    return (full.split("/")[0], full.split("/")[1]) if full.startswith("@") else (None, full)


def lockfile_packages() -> dict:
    lock = ROOT / "corpus/bakery-inventory-management/bakery-inventory-frontend/package-lock.json"
    return json.loads(lock.read_text(encoding="utf-8"))["packages"]


def add_npm_installed(gt: GT, fs: Rootfs):
    lock = lockfile_packages()
    for path, _ in list(fs.files()):
        m = NPM_RX.search(path)
        if not m:
            if path.endswith("/package.json") and "node_modules/" not in path:
                add_npm_standalone(gt, fs, path)
            continue
        try:
            pkg = json.loads(fs.read(path))
        except (ValueError, KeyError):
            continue
        if not pkg.get("name") or not pkg.get("version"):
            continue
        scope_ns, name = split_npm(pkg["name"])
        if path.startswith("app/node_modules/"):
            entry = lock.get(path.removeprefix("app/").removesuffix("/package.json"), {})
            scope = "dev" if entry.get("dev") else "runtime"
            mech = "lang-pm"
        else:
            scope, mech = None, "runtime-bundled"   # npm/corepack shipped inside the Node.js distribution
        gt.add("npm", name, pkg["version"], namespace=scope_ns, mechanism=mech, scope=scope, evidence="package.json",
               path=path, license=npm_license(pkg))


def add_npm_standalone(gt: GT, fs: Rootfs, path: str):
    """A package.json outside node_modules: the application itself (app/), a runtime shipped as a tarball
    (/opt/yarn-*), or an npm package unpacked by hand (mongo's /opt/js-yaml)."""
    try:
        pkg = json.loads(fs.read(path))
    except (ValueError, KeyError):
        return
    if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
        return
    depth_ok = path.count("/") <= 3          # top of an install dir, not a nested test fixture
    if not depth_ok:
        return
    scope_ns, name = split_npm(pkg["name"])
    if path.startswith("app/"):
        gt.add("npm", name, pkg["version"], namespace=scope_ns, mechanism="self", tier="secondary",
               evidence="application package.json", path=path)
    elif re.match(r"^opt/yarn-v[^/]+/package\.json$", path):
        gt.add("npm", name, pkg["version"], namespace=scope_ns, mechanism="runtime-outside-pm",
               evidence="package.json of tarball-installed runtime", path=path)
    else:
        gt.add("npm", name, pkg["version"], namespace=scope_ns, mechanism="manual-install",
               evidence="package.json outside node_modules", path=path, license=npm_license(pkg))


def add_npm_bundled(gt: GT):
    """Packages whose code ended up in the Vite bundle, from the build's sourcemaps (exact, not estimated)."""
    lock = lockfile_packages()
    maps = list((BUILDINFO_DIR / "bakery-frontend" / "dist-with-maps").rglob("*.map"))
    if not maps:
        raise RuntimeError("no sourcemaps in buildinfo; cannot build bundled-js ground truth")
    found: dict[str, int] = {}
    for mp in maps:
        for src in json.loads(mp.read_text(encoding="utf-8")).get("sources", []):
            if "node_modules/" not in src or src.startswith("\x00"):
                continue   # application code or bundler-generated virtual modules
            # e.g. ../../node_modules/a/node_modules/@s/b/dist/x.js -> lockfile key node_modules/a/node_modules/@s/b
            first, last = src.index("node_modules/"), src.rindex("node_modules/")
            parts = src[last + len("node_modules/"):].split("/")
            pkgname = "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]
            lock_key = src[first:last] + "node_modules/" + pkgname
            found[lock_key] = found.get(lock_key, 0) + 1
    for lock_key, nsrc in sorted(found.items()):
        entry = lock.get(lock_key)
        if not entry:
            gt.notes.append(f"bundled package {lock_key} not in lockfile")
            continue
        full = lock_key.split("node_modules/")[-1]
        scope_ns, name = split_npm(full)
        gt.add("npm", name, entry["version"], namespace=scope_ns, mechanism="bundled-js", scope="runtime",
               evidence=f"sourcemap ({nsrc} source files)", path=lock_key, license=entry.get("license"))


def add_npm_lockfile(gt: GT, with_versions: bool = True):
    """Source stage: every package the lockfile resolves (the resolved closure), with dev flags."""
    for key, entry in lockfile_packages().items():
        if key == "":
            gt.add("npm", entry.get("name", "bakery-inventory-frontend"), entry.get("version"), mechanism="self",
                   tier="secondary", evidence="package-lock.json root")
            continue
        full = key.split("node_modules/")[-1]
        scope_ns, name = split_npm(full)
        scope = "dev" if entry.get("dev") else ("optional" if entry.get("optional") else "runtime")
        gt.add("npm", name, entry["version"], namespace=scope_ns, mechanism="lang-pm", scope=scope,
               evidence="package-lock.json", path=key, license=entry.get("license"))


# ============================================================================ Java
_MAVEN_GROUPS: dict[tuple[str, str], str] | None = None
# Added to the fat JAR by spring-boot-maven-plugin itself (not resolved as project dependencies).
BOOT_PLUGIN_JARS = {"spring-boot-jarmode-tools": "org.springframework.boot", "spring-boot-loader": "org.springframework.boot"}


def maven_groups() -> dict[tuple[str, str], str]:
    """(artifactId, version) -> groupId from the build's own `mvn dependency:list` (all scopes).
    Needed because many JARs (Spring, Hibernate, MySQL Connector...) are not built with Maven and carry no
    pom.properties; their groupId is then known only from the resolution that put the file there."""
    global _MAVEN_GROUPS
    if _MAVEN_GROUPS is None:
        _MAVEN_GROUPS = {}
        text = (BUILDINFO_DIR / "bakery-backend" / "maven-all.txt").read_text(encoding="utf-8")
        for g, a, v in re.findall(r"^\s+([^:\s]+):([^:\s]+):jar:(?:[^:\s]+:)?([^:\s]+):\w+", text, re.M):
            _MAVEN_GROUPS[(a, v)] = g
    return _MAVEN_GROUPS


def jar_identity(data: bytes, fname: str) -> tuple[list[dict], dict]:
    """All Maven identities inside a JAR and the one that names the JAR itself."""
    poms, manifest = [], {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        for n in names:
            if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n):
                props = dict(re.findall(r"^([\w.]+)=(.*)$", z.read(n).decode("utf-8", "replace"), re.M))
                if props.get("artifactId") and props.get("version"):
                    lic = None
                    pom_xml = n.replace("pom.properties", "pom.xml")
                    if pom_xml in names:
                        mm = re.search(r"<licenses>.*?<name>\s*([^<]+?)\s*</name>", z.read(pom_xml).decode("utf-8", "replace"), re.S)
                        lic = mm.group(1) if mm else None
                    poms.append({"g": props.get("groupId", ""), "a": props["artifactId"], "v": props["version"].strip(), "license": lic})
        if "META-INF/MANIFEST.MF" in names:
            text = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").replace("\r\n ", "").replace("\n ", "")
            manifest = dict(re.findall(r"^([\w-]+):\s*(.*?)\s*$", text, re.M))
    stem = fname.removesuffix(".jar")
    main = next((p for p in poms if stem == f"{p['a']}-{p['v']}" or stem.startswith(f"{p['a']}-{p['v']}-")), None)
    if main is None and len(poms) == 1:
        main = poms[0]
    if main is None:
        # No pom.properties naming this JAR. The filename (artifactId-version.jar, as Maven writes it) is the
        # reliable source; MANIFEST Implementation-Version can be a SPEC version (Tomcat says "6.1" = Servlet 6.1).
        mm = re.match(r"^(.+?)-(\d[\w.\-+]*)$", stem)
        a = mm.group(1) if mm else stem
        v = mm.group(2) if mm else (manifest.get("Implementation-Version") or manifest.get("Bundle-Version"))
        g = maven_groups().get((a, v)) or BOOT_PLUGIN_JARS.get(a)
        main = {"g": g, "a": a, "v": v, "license": None, "from_filename": True,
                "group_from": "mvn dependency:list" if maven_groups().get((a, v)) else ("spring-boot plugin" if g else None)}
    others = [p for p in poms if p is not main]
    return others, main


def add_jar(gt: GT, data: bytes, path: str, mechanism: str, tier: str = "primary", depth: int = 0):
    fname = Path(path).name
    others, main = jar_identity(data, fname)
    hashes = {"sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}
    evidence = "pom.properties"
    if main.get("from_filename"):
        evidence = "filename" + (f" + groupId from {main['group_from']}" if main.get("group_from") else " (groupId unknown)")
    gt.add("maven", main["a"], main["v"], namespace=main["g"] or None, mechanism=mechanism, tier=tier,
           evidence=evidence, path=path, license=main.get("license"), hashes=hashes)
    for p in others:   # extra pom.properties inside the same JAR (shaded / embedded artifacts)
        gt.add("maven", p["a"], p["v"], namespace=p["g"] or None, mechanism="embedded-pom", tier="secondary",
               evidence=f"pom.properties inside {fname}", path=path, license=p.get("license"))
    if depth == 0:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            nested = [n for n in z.namelist() if re.match(r"(BOOT-INF|WEB-INF)/lib/[^/]+\.jar$", n)]
            for n in nested:
                add_jar(gt, z.read(n), f"{path}!/{n}", "nested-jar", "primary", depth + 1)
            if nested:   # a Spring Boot fat JAR: its own identity is the application itself
                ident = gt.items.get((norm_key("maven", main["g"] or None, main["a"]), main["v"]))
                if ident:
                    ident.update(tier="secondary", mechanism="self", mechanisms=["self"])
                if any(n.startswith("org/springframework/boot/loader/") for n in z.namelist()):
                    gt.add("maven", "spring-boot-loader", boot_version(gt), namespace="org.springframework.boot",
                           mechanism="boot-loader-classes", tier="secondary", evidence="loader classes in fat JAR",
                           path=path)


def boot_version(gt: GT) -> str | None:
    for c in gt.items.values():
        if c["eco"] == "maven" and c["name"] == "spring-boot" and c["namespace"] == "org.springframework.boot":
            return c["version"]
    raise RuntimeError("fat JAR without org.springframework.boot:spring-boot; cannot date the loader classes")


def add_java_image(gt: GT, fs: Rootfs, owners: dict[str, str]):
    for path, _ in list(fs.files()):
        if not path.endswith(".jar"):
            continue
        if re.match(r"^(opt/java/openjdk|usr/lib/jvm)/", path):
            mech, tier = "runtime-internal", "secondary"
        elif merged_usr(path) in owners:
            mech, tier = "lang-in-os-pkg", "primary"
        elif re.match(r"^app/lib/[^/]+\.jar$", path):
            mech, tier = "layered-jar", "primary"
        elif path == "app/app.jar":
            mech, tier = "self", "secondary"
        else:
            mech, tier = "manual-copy", "primary"
        add_jar(gt, fs.read(path), path, mech, tier)


def add_maven_source(gt: GT):
    text = (BUILDINFO_DIR / "bakery-backend" / "maven-all.txt").read_text(encoding="utf-8")
    rx = re.compile(r"^\s+([^:\s]+):([^:\s]+):([^:\s]+):(?:([^:\s]+):)?([^:\s]+):(compile|runtime|test|provided|system|import)"
                    r"(\s+\(optional\))?")
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        g, a, _type, _classifier, v, scope, optional = m.groups()
        label = "optional" if optional else ("test" if scope == "test" else "runtime")
        gt.add("maven", a, v, namespace=g, mechanism="lang-pm", scope=label, evidence=f"mvn dependency:list ({scope})")
    gt.add("maven", "bakery-inventory-management", "0.0.1-SNAPSHOT", namespace="com.bakery", mechanism="self",
           tier="secondary", evidence="pom.xml")


# ============================================================================ runtimes, Go, native
def add_runtimes(gt: GT, fs: Rootfs, env: dict, owners: dict[str, str]):
    """Language runtimes installed from tarballs by the official base images (no package manager entry)."""
    jdk_pkg = any(c["eco"] in ("deb", "apk", "rpm") and re.match(r"(openjdk|temurin|java-)", c["name"])
                  for c in gt.items.values())
    for rel_file in fs.glob(r"^(opt/java/openjdk|usr/lib/jvm/[^/]+)/release$"):
        if jdk_pkg or merged_usr(rel_file) in owners:
            gt.notes.append(f"JDK at {rel_file} belongs to an OS package; not counted again as a runtime")
            continue
        rel = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', fs.text(rel_file), re.M))
        gt.add("generic", "openjdk", rel.get("JAVA_VERSION"), mechanism="runtime-outside-pm",
               evidence=rel_file, path=posixpath.dirname(rel_file),
               alt_names=["java", "jre", "jdk", "openjdk", "temurin", "eclipse-temurin", "java-runtime"])
    py = [p for p in fs.glob(r"^usr/local/bin/python3\.\d+$")]
    if py and env.get("PYTHON_VERSION") and merged_usr(py[0]) not in owners:
        gt.add("generic", "python", env["PYTHON_VERSION"], mechanism="runtime-outside-pm", evidence="image ENV PYTHON_VERSION",
               path=py[0], alt_names=["python", "python3", "cpython"])
    if fs.exists("usr/local/bin/node") and env.get("NODE_VERSION"):
        gt.add("generic", "node", env["NODE_VERSION"], mechanism="runtime-outside-pm", evidence="image ENV NODE_VERSION",
               path="usr/local/bin/node", alt_names=["node", "nodejs", "node.js"])
    if env.get("YARN_VERSION") and fs.glob(r"^opt/yarn-v[^/]+/package\.json$"):
        gt.add("npm", "yarn", env["YARN_VERSION"], mechanism="runtime-outside-pm", evidence="image ENV YARN_VERSION",
               path=fs.glob(r"^opt/yarn-v[^/]+/package\.json$")[0], alt_names=["yarn"])


def add_go_binaries(gt: GT, fs: Rootfs, owners: dict[str, str]):
    for path, m in list(fs.files()):
        if m.size < 500_000 or fs.head(path, 4) != b"\x7fELF":
            continue
        info = go_buildinfo(fs.read(path))
        if not info:
            continue
        if info.get("unsupported_format"):
            gt.notes.append(f"Go binary with pre-1.18 build info not parsed: {path}")
            continue
        owned = merged_usr(path) in owners
        main_mech = "go-in-os-pkg" if owned else "manual-download"
        if info["main"] and info["main"]["path"]:
            gt.add("golang", info["main"]["path"], info["main"]["version"] if info["main"]["version"] != "(devel)" else None,
                   mechanism=main_mech, evidence="Go build info (main module)", path=path,
                   alt_names=[Path(path).name])
        for d in info["deps"]:
            gt.add("golang", d["path"], None if d["version"] == "(devel)" else d["version"],
                   mechanism="go-module-in-binary", evidence="Go build info (dep)", path=path)
        gt.add("golang", "stdlib", info["go_version"], mechanism="go-module-in-binary", evidence="Go build info (toolchain)",
               path=path, alt_names=["stdlib", "go"])


def add_planted(gt: GT, planted_file: str):
    data = json.loads((ROOT / planted_file).read_text(encoding="utf-8"))
    for p in data["components"]:
        purl = PackageURL.from_string(p["purl"])
        # If the generic scan already recorded this component WITHOUT a version (e.g. a Go binary whose build
        # info says "(devel)" because the release number is injected by ldflags), adopt it under the planted,
        # true version instead of creating a second record for the same thing.
        name = f"{purl.namespace}/{purl.name}" if purl.type == "golang" and purl.namespace else purl.name
        key = norm_key(purl.type, None if purl.type == "golang" else purl.namespace, name)
        stale = gt.items.pop((key, None), None)
        if stale is not None:
            stale["version"] = purl.version
            stale["purl"] = p["purl"]
            stale["evidence"] += f"; version from planted.json (binary metadata says '(devel)')"
            gt.items[(key, purl.version)] = stale
        existing = gt.add(purl.type, purl.name, purl.version, namespace=purl.namespace, mechanism=p["mechanism"],
                          evidence="planted.json", path=p["path"].lstrip("/"), alt_names=p.get("alt_names", []))
        # planted label wins: it is the precise route we built (e.g. shaded-relocated, not the generic scan label)
        existing.update(mechanism=p["mechanism"], tier="primary", planted=True, mechanisms=[p["mechanism"]])


# ============================================================================ per-target dispatch
def image_gt(gt: GT, target: dict):
    tid = target["id"]
    fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
    env = image_env(IMAGES_DIR / f"{tid}.tar")
    owners = add_os_packages(gt, fs)
    add_python(gt, fs, owners)
    add_npm_installed(gt, fs)
    add_java_image(gt, fs, owners)
    add_runtimes(gt, fs, env, owners)
    add_go_binaries(gt, fs, owners)
    if tid == "N-S3-nginx":
        add_npm_bundled(gt)
    if tid.startswith("C-"):
        add_c_binary(gt, fs, owners)
    if target.get("planted"):
        add_planted(gt, target["planted"])


def add_c_binary(gt: GT, fs: Rootfs, owners: dict[str, str]):
    data = fs.read("app/server")
    info = elf_info(data)
    gt.notes.append(f"app/server: interp={info.get('interp')} needed={info.get('needed')}")
    if info.get("interp") is None:   # fully static (scratch): musl is linked into the binary
        mv = (BUILDINFO_DIR / "tcp-server" / "musl-version.txt").read_text(encoding="utf-8").strip()
        mm = re.fullmatch(r"musl-(\d[\w.\-]*)", mv)
        if not mm:
            raise RuntimeError(f"unexpected musl-version.txt content: {mv[:80]!r}")
        gt.add("generic", "musl", mm.group(1), mechanism="static-link",
               evidence="buildinfo musl-version.txt (apk info -v musl in the build stage)", path="app/server",
               alt_names=["musl", "musl-libc"])
    for lib in info.get("needed", []):   # dynamic dependencies must be satisfied by an OS package in the image
        hits = {pkg for f, pkg in owners.items() if f.endswith("/" + lib)}
        gt.notes.append(f"DT_NEEDED {lib} -> owned by {sorted(hits) or 'NOT FOUND'}")


def source_or_artifact_gt(gt: GT, target: dict):
    tid = target["id"]
    if tid == "J-S1":
        add_maven_source(gt)
    elif tid == "J-S2":
        add_jar(gt, scan_path(target).read_bytes(), "app.jar", "self", "secondary")
    elif tid in ("N-S1", "N-S1-nolock"):
        add_npm_lockfile(gt)
        if tid == "N-S1-nolock":
            gt.notes.append("lockfile removed: GT is the closure npm resolves from package-lock.json "
                            "(what `npm ci` installs); a tool can only approximate it from package.json ranges")
    elif tid == "N-S2":
        add_npm_bundled(gt)
        gt.add("npm", "bakery-inventory-frontend", "0.0.0", mechanism="self", tier="secondary", evidence="package.json")
    elif tid in ("P-S1", "P-S1-pinned"):
        for report in sorted((BUILDINFO_DIR / "log-anomaly").glob("pip-report-*.json")):
            for item in json.loads(report.read_text(encoding="utf-8"))["install"]:
                md = item["metadata"]
                gt.add("pypi", md["name"], md["version"], mechanism="lang-pm", scope="runtime",
                       evidence=f"pip dry-run ({report.stem.removeprefix('pip-report-')})",
                       license=md.get("license_expression") or md.get("license"))
        add_dockerfile_installs(gt)
    elif tid == "C-S1":
        gt.notes.append("No package manager and no manifest: no primary components. libc/pthread are implicit "
                        "system dependencies (secondary). The committed client/server are macOS Mach-O binaries.")
        for name in ("glibc", "musl"):
            gt.add("generic", name, None, mechanism="system-implicit", tier="secondary", evidence="#include <pthread.h> etc.",
                   alt_names=[name, "libc6", "libc", "musl-libc"])
    elif tid == "C-S2":
        info = elf_info(scan_path(target).read_bytes())
        gt.notes.append(f"server: interp={info.get('interp')} needed={info.get('needed')} "
                        "(dynamic dependencies are not contained in the artifact)")
        gt.add("generic", "glibc", None, mechanism="dynamic-dependency", tier="secondary", evidence="DT_NEEDED libc.so.6",
               alt_names=["glibc", "libc6", "libc"])
    else:
        raise ValueError(f"no ground-truth recipe for {tid}")


def add_dockerfile_installs(gt: GT):
    """`pip install pymongo` appears only in the Dockerfiles (source tree), never in a requirements file.
    Its version (and dependency closure) is taken from what the project's own image installed."""
    fs = Rootfs(ROOTFS_DIR / "P-S3-pred.tar")
    installed = {}
    for path in fs.glob(r"site-packages/[^/]+\.dist-info/METADATA$"):
        meta = email.parser.HeaderParser().parsestr(fs.text(path))
        installed[pep503(meta["Name"])] = meta
    todo, done = ["pymongo"], set()
    while todo:
        n = pep503(todo.pop())
        if n in done or n not in installed:
            continue
        done.add(n)
        meta = installed[n]
        gt.add("pypi", meta["Name"], meta["Version"], mechanism="dockerfile-install", scope="runtime",
               evidence="RUN pip install pymongo (Dockerfiles); version from P-S3-pred", license=python_license(meta))
        for req in meta.get_all("Requires-Dist") or []:
            if ";" in req and "extra ==" in req:
                continue
            todo.append(re.split(r"[\s<>=!~;\[(]", req.strip(), maxsplit=1)[0])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="+", metavar="ID")
    args = ap.parse_args()
    targets = load_catalog()["targets"]
    if args.only:
        targets = [t for t in targets if t["id"] in args.only]
    failures = []
    for target in targets:
        gt = GT(target)
        try:
            if target["kind"] == "image":
                image_gt(gt, target)
            else:
                source_or_artifact_gt(gt, target)
            if target.get("planted") and target["kind"] != "image":
                add_planted(gt, target["planted"])
            data = gt.to_json()
            write_json(GT_DIR / f"{target['id']}.json", data)
            s = data["stats"]
            log(f"[gt] {target['id']:16} total={s['total']:5} tiers={s['by_tier']} ecos={s['by_eco']}")
        except Exception as exc:
            failures.append(target["id"])
            log(f"[gt] {target['id']}: FAILED {exc!r}")
    if failures:
        log(f"FAILED: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
