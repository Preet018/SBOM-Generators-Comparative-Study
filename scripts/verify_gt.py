"""Cross-check the ground truth with INDEPENDENT oracles before any tool is scored against it.

extract_gt.py parses package databases and files out of exported tars with our own code. Here the same facts
are obtained a different way, mostly by asking the real tools inside the running image:
  dpkg-query / apk info / rpm -qa      vs  GT OS packages
  pip list (json)                      vs  GT Python packages installed by pip
  npm query '*' (Arborist)             vs  GT npm packages in the app's node_modules
  go version -m (official Go toolchain) vs our Go build-info parser
  readelf (from the build)             vs  our ELF DT_NEEDED parser
  dpkg -S                              vs  our file-ownership map (e.g. /usr/bin/pebble)
plus structural expectations (fat JAR == Maven runtime list minus documented exclusions, planted components present,
source-stage GT contained in what the images installed).

Usage: python scripts/verify_gt.py            (writes results/verify_gt.json)
"""
from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

import yaml

from common import BUILDINFO_DIR, RESULTS_DIR, ROOT, ROOTFS_DIR, TMP_DIR, image_tag, load_catalog, log, plain, write_json
from fsutil import Rootfs, elf_info, go_buildinfo

GT_DIR = ROOT / "ground_truth"
GOLANG_IMAGE = "golang:1.25"
# stdlib importlib.metadata runs here for images that ship Python packages but no Python interpreter on PATH
PYTHON_IMAGE = "python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"   # python:3.13-slim


def gt(tid: str) -> dict:
    return json.loads((GT_DIR / f"{tid}.json").read_text(encoding="utf-8"))


def pep503(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def sh(tid: str, script: str) -> str:
    """Run a shell snippet inside the target image (never started for real: entrypoint replaced by sh)."""
    p = subprocess.run(["docker", "run", "--rm", "--entrypoint", "sh", image_tag(tid), "-c", script],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"{tid}: oracle failed: {p.stderr.strip()[-400:]}")
    return p.stdout


class Checker:
    def __init__(self):
        self.results = []

    def check(self, target, name, ok, detail=""):
        self.results.append({"target": target, "check": name, "ok": bool(ok), "detail": str(detail)[:1500]})
        log(f"  [{'PASS' if ok else 'FAIL'}] {target}: {name}{(' -- ' + str(detail)[:300]) if detail and not ok else ''}")


def compare(c: Checker, tid: str, name: str, oracle: set, truth: set):
    missing, extra = sorted(oracle - truth), sorted(truth - oracle)
    c.check(tid, f"{name}: GT == oracle ({len(oracle)} items)", not missing and not extra,
            f"oracle-only={missing[:8]} gt-only={extra[:8]}")


def gt_set(tid: str, eco: str, mech: tuple[str, ...] | None = None, tier: str | None = "primary") -> set:
    """GT identities of one ecosystem; with `mech`, those reached by ANY of the given mechanisms."""
    out = set()
    for comp in gt(tid)["components"]:
        if comp["eco"] != eco or (tier and comp["tier"] != tier):
            continue
        if mech and not set(mech) & set(comp.get("mechanisms") or [comp["mechanism"]]):
            continue
        name = pep503(comp["name"]) if eco == "pypi" else (
            f"{comp['namespace']}/{comp['name']}" if eco == "npm" and comp["namespace"] else comp["name"])
        out.add((name, comp["version"]))
    return out


# ----------------------------------------------------------------------------- oracles
def os_oracles(c: Checker, targets: list[dict]):
    for t in targets:
        tid = t["id"]
        if t["kind"] != "image" or tid in ("C-S3-scratch",):
            continue
        # installed binary packages only (source-package records are a different, secondary kind of record)
        gt_deb, gt_apk, gt_rpm = (gt_set(tid, eco, ("os-pm",), tier=None) for eco in ("deb", "apk", "rpm"))
        # dpkg-query reads var/lib/dpkg/status only; packages recorded in status.d (distroless, Docker Hardened
        # Images) are invisible to it, so compare it with the records that came from `status`
        gt_deb = {(x["name"], x["version"]) for x in gt(tid)["components"]
                  if x["eco"] == "deb" and "var/lib/dpkg/status" in (x.get("paths") or [])} if gt_deb else gt_deb
        try:
            if gt_deb and "distroless" not in tid:
                out = sh(tid, "dpkg-query -W -f '${Package}\\t${Version}\\t${db:Status-Abbrev}\\n'")
                oracle = {(p, v) for p, v, s in (l.split("\t") for l in out.splitlines()) if s.strip()[1:2] == "i"}   # 2nd letter = installed ("ii", and "hi" = held)
                compare(c, tid, "deb packages (dpkg-query)", oracle, gt_deb)
            if gt_apk:
                out = sh(tid, "apk info -v 2>/dev/null")
                gt_strings = {f"{n}-{v}" for n, v in gt_apk}
                compare(c, tid, "apk packages (apk info -v)", set(out.split()), gt_strings)
            if gt_rpm and (not tid.startswith("X-") or has_cmd(tid, "rpm")):
                out = sh(tid, "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\n'")
                oracle = {(n, (f"{e}:" if e != "0" else "") + v) for n, e, v in (l.split("\t") for l in out.splitlines())}
                compare(c, tid, "rpm packages (rpm -qa)", oracle, gt_rpm)
        except RuntimeError as exc:
            c.check(tid, "OS oracle ran", False, exc)


def python_oracles(c: Checker):
    for tid in ("P-S3-pred", "P-S3-drift", "P-S3-front", "P-S3-ml", "P-P"):
        out = sh(tid, "python -m pip list --format json --disable-pip-version-check 2>/dev/null")
        oracle = {(pep503(p["name"]), p["version"]) for p in json.loads(out)}
        compare(c, tid, "pip-installed Python packages (pip list)", oracle, gt_set(tid, "pypi", ("lang-pm",)))


def npm_oracle(c: Checker):
    tid = "N-S3-node"
    out = sh(tid, "cd /app && npm query '*' 2>/dev/null")
    oracle = {(n["name"], n["version"]) for n in json.loads(out) if n.get("location", "").startswith("node_modules/")}
    compare(c, tid, "app node_modules (npm query '*')", oracle, gt_set(tid, "npm", ("lang-pm",)))
    out = sh(tid, "cd /usr/local/lib/node_modules/npm && npm query '*' 2>/dev/null")
    npm_self = {(n["name"], n["version"]) for n in json.loads(out)}
    gt_bundled = gt_set(tid, "npm", ("runtime-bundled",))
    c.check(tid, "npm's own dependency tree is inside GT runtime-bundled", npm_self <= gt_bundled,
            f"missing={sorted(npm_self - gt_bundled)[:8]}")


def go_oracle(c: Checker):
    """Our Go build-info parser vs the official `go version -m` on the same binaries."""
    jobs = {"P-P": ["usr/local/bin/yq"], "M-S3": ["usr/local/bin/gosu", "usr/bin/mongodump"],
            "J-S3-ubuntu": ["usr/bin/pebble"]}
    for t in public_targets():   # every Go binary the public images' GT was built from
        bins = sorted({p for comp in gt(t["id"])["components"] if comp["eco"] == "golang" and comp["name"] == "stdlib"
                       for p in comp.get("paths") or []})
        if bins:
            jobs[t["id"]] = bins
    tmp = TMP_DIR / "go-oracle"
    tmp.mkdir(parents=True, exist_ok=True)
    for tid, paths in jobs.items():
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        for p in paths:
            data = fs.read(p)
            mine = go_buildinfo(data)
            fname = f"{tid}-{Path(p).name}"
            (tmp / fname).write_bytes(data)
            out = subprocess.run(["docker", "run", "--rm", "-v", f"{plain(tmp)}:/b:ro", GOLANG_IMAGE, "go", "version",
                                  "-m", f"/b/{fname}"], capture_output=True, text=True).stdout
            official = {(m.group(1), m.group(2)) for m in re.finditer(r"^\s+dep\s+(\S+)\s+(\S+)", out, re.M)}
            ours = {(d["path"], d["version"]) for d in mine["deps"]}
            go_ver = out.split(":", 1)[1].split()[0] if ":" in out else None
            c.check(tid, f"Go deps of {p} == go version -m ({len(official)} deps, {go_ver})",
                    ours == official and go_ver == mine["go_version"],
                    f"ours-only={sorted(ours - official)[:5]} official-only={sorted(official - ours)[:5]} go={go_ver}/{mine['go_version']}")


def ownership_oracle(c: Checker):
    out = subprocess.run(["docker", "run", "--rm", "--entrypoint", "sh", image_tag("J-S3-ubuntu"), "-c",
                          "dpkg -S /usr/bin/pebble 2>&1; ls -la /usr/bin/pebble"], capture_output=True, text=True).stdout
    mech = [x["mechanism"] for x in gt("J-S3-ubuntu")["components"] if x["name"] == "github.com/canonical/pebble"]
    c.check("J-S3-ubuntu", "pebble not owned by any dpkg package (dpkg -S) and GT says manual-download",
            "no path found" in out and mech == ["manual-download"], out.strip()[:300])


def elf_oracle(c: Checker):
    readelf = (BUILDINFO_DIR / "tcp-server" / "glibc-readelf-server.txt").read_text(encoding="utf-8")
    official = set(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", readelf))
    ours = set(elf_info(Rootfs(ROOTFS_DIR / "C-S3-debian.tar").read("app/server"))["needed"])
    c.check("C-S3-debian", f"ELF DT_NEEDED parser == readelf {sorted(official)}", ours == official, f"ours={sorted(ours)}")


# ----------------------------------------------------------------------------- public images (generic oracles)
def public_targets() -> list[dict]:
    return [t for t in load_catalog()["targets"] if t["id"].startswith("X-")]


def has_cmd(tid: str, cmd: str) -> bool:
    p = subprocess.run(["docker", "run", "--rm", "--entrypoint", "sh", image_tag(tid), "-c", f"command -v {cmd}"],
                       capture_output=True, text=True)
    return p.returncode == 0


PY_LIST = ("import importlib.metadata as m, json, sys; "
           "print(json.dumps([[d.metadata['Name'], d.version] for d in m.distributions(path=sys.argv[1:])]))")


def public_python_oracle(c: Checker):
    """Per site-packages directory: Python's own importlib.metadata (in the image's interpreter when it has one,
    else in python:3.13-slim over the copied *.dist-info / *.egg-info) vs every GT pypi record in that directory."""
    for t in public_targets():
        tid = t["id"]
        sites: dict[str, set] = {}
        for x in gt(tid)["components"]:
            if x["eco"] != "pypi":
                continue
            for path in x.get("paths") or []:
                m = re.match(r"^(.*)/[^/]+\.(dist-info|egg-info)(/|$)", path)
                if m and "/_vendor/" not in path:
                    sites.setdefault(m.group(1), set()).add((pep503(x["name"]), x["version"]))
        if not sites:
            continue
        in_image = has_cmd(tid, "python3")
        fs = None if in_image else Rootfs(ROOTFS_DIR / f"{tid}.tar")
        for site, truth in sorted(sites.items()):
            if in_image:
                p = subprocess.run(["docker", "run", "--rm", "--entrypoint", "python3", image_tag(tid), "-c", PY_LIST,
                                    f"/{site}"], capture_output=True, text=True, check=True)
                out, how = p.stdout, "image's python3"
            else:
                tmp = TMP_DIR / "py-oracle" / tid
                shutil.rmtree(tmp, ignore_errors=True)
                for path, _ in list(fs.files()):
                    rest = path[len(site) + 1:]
                    if path.startswith(site + "/") and re.match(r"^[^/]+\.(dist-info|egg-info)(/|$)", rest):
                        dst = tmp / rest
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_bytes(fs.read(path))
                out = subprocess.run(["docker", "run", "--rm", "-v", f"{plain(tmp)}:/s:ro", PYTHON_IMAGE, "python3", "-c",
                                      PY_LIST, "/s"], capture_output=True, text=True, check=True).stdout
                how = "importlib.metadata in python:3.13-slim"
            oracle = {(pep503(n), v) for n, v in json.loads(out)}
            compare(c, tid, f"Python dists in /{site} ({how})", oracle, truth)


def public_pnpm_oracle(c: Checker):
    """pnpm's own record of what it installed (node_modules/.pnpm/lock.yaml minus .modules.yaml `skipped`)
    vs GT npm records found under that project's node_modules/.pnpm."""
    for t in public_targets():
        tid = t["id"]
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        for lock in fs.glob(r"/node_modules/\.pnpm/lock\.yaml$"):
            root = lock.removesuffix("/node_modules/.pnpm/lock.yaml")
            lk = yaml.safe_load(fs.text(lock))
            skipped = {re.sub(r"\(.*$", "", k)   # snapshot keys carry a peer suffix: name@1.2.2(@peer@1.0)
                       for k in yaml.safe_load(fs.text(f"{root}/node_modules/.modules.yaml")).get("skipped") or []}
            oracle = set()
            for key, meta in (lk.get("packages") or {}).items():
                if key in skipped:
                    continue
                name, _, ver = key.rpartition("@")
                ver = re.sub(r"\(.*$", "", ver)
                if not re.match(r"^\d", ver):            # file:/link: specs: the version is in the entry itself
                    ver = (meta or {}).get("version") or ver
                oracle.add((name, ver))
            truth = set()
            for x in gt(tid)["components"]:
                if x["eco"] == "npm" and any(p.startswith(f"{root}/node_modules/.pnpm/") for p in x.get("paths") or []):
                    truth.add((f"{x['namespace']}/{x['name']}" if x["namespace"] else x["name"], x["version"]))
            compare(c, tid, f"pnpm-installed packages of /{root} (lock.yaml minus skipped)", oracle, truth)


def public_os_extra(c: Checker):
    """Images whose OS package manager binary is absent (Keycloak's ubi-micro has no rpm): read the installed
    package NAMES from the rpm sqlite DB's own Name index table (Python sqlite3, not the rpm tool)."""
    for t in public_targets():
        tid = t["id"]
        recs = gt_set(tid, "rpm", ("os-pm",), tier=None)
        if not recs or has_cmd(tid, "rpm"):
            continue
        truth = {n for n, _ in recs}
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        tmp = TMP_DIR / "rpm-names" / tid
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        for path in fs.glob(r"^var/lib/rpm/rpmdb\.sqlite(-wal|-shm)?$"):
            (tmp / Path(path).name).write_bytes(fs.read(path))
        con = sqlite3.connect(tmp / "rpmdb.sqlite")
        names = {r[0] if isinstance(r[0], str) else r[0].decode() for r in con.execute("SELECT key FROM Name")}
        npk = con.execute("SELECT count(*) FROM Packages").fetchone()[0]
        con.close()
        c.check(tid, f"rpm names == rpmdb.sqlite Name index ({len(names)} names, {npk} headers; no rpm binary in image)",
                names == truth and npk == len(recs),
                f"db-only={sorted(names - truth)[:6]} gt-only={sorted(truth - names)[:6]} headers={npk} gt={len(recs)}")


def public_busybox_oracle(c: Checker):
    for t in public_targets():
        recs = [x for x in gt(t["id"])["components"] if x["eco"] == "generic" and x["name"] == "busybox"]
        if recs:
            banner = sh(t["id"], "busybox 2>&1 | head -1")
            m = re.search(r"BusyBox v([\d.]+)", banner)
            c.check(t["id"], f"busybox version == running `busybox` banner ({banner.strip()[:40]})",
                    bool(m) and m.group(1) == recs[0]["version"], f"gt={recs[0]['version']}")


def public_java_structural(c: Checker):
    ids = json.loads((RESULTS_DIR / "public_java_ids.json").read_text(encoding="utf-8"))
    c.check("X-*", f"every resolved pom-less JAR identity is repository-confirmed ({len(ids['by_sha1'])})",
            all(v.get("confirmed_by", "").startswith("https://") for v in ids["by_sha1"].values()))
    # Jenkins: the WAR's bundled libraries == Maven's runtime resolution of the published jenkins-war pom
    rx = re.compile(r"^\s+([^:\s]+):([^:\s]+):jar:(?:[^:\s]+:)?([^:\s]+):(compile|runtime)", re.M)
    resolved = {(g, a, v) for g, a, v, _ in rx.findall((BUILDINFO_DIR / "X-jenkins" / "maven-list.txt").read_text(encoding="utf-8"))}
    nested = {(x["namespace"], x["name"], x["version"]) for x in gt("X-jenkins")["components"]
              if x["eco"] == "maven" and "nested-jar" in (x.get("mechanisms") or [x["mechanism"]])
              and any("jenkins.war!/WEB-INF/lib/" in p for p in x.get("paths") or [])}
    # commons-logging is BANNED from compile/runtime by Jenkins' root pom (maven-enforcer bannedDependencies,
    # jenkinsci/jenkins tag jenkins-2.580.2, pom.xml); jcl-over-slf4j provides its API. The published jenkins-war
    # pom is flattened (no build section), so Maven alone still resolves it through commons-jexl.
    expected = {x for x in resolved if x[:2] != ("commons-logging", "commons-logging")}
    c.check("X-jenkins", f"WAR WEB-INF/lib == mvn dependency:list of jenkins-war minus banned commons-logging ({len(expected)})",
            nested == expected, f"war-only={sorted(nested - expected)[:6]} mvn-only={sorted(expected - nested)[:6]}")
    for tid in ("X-jenkins", "X-keycloak"):
        nogroup = [x["name"] for x in gt(tid)["components"] if x["eco"] == "maven" and x["tier"] == "primary" and not x["namespace"]]
        c.check(tid, "every primary Maven record has a groupId", not nogroup, nogroup[:8])
        unres = sorted(x["name"] for x in gt(tid)["components"] if x["mechanism"] == "identity-unresolved")
        c.check(tid, f"identity-unresolved JARs are only the documented ones ({len(unres)})",
                set(unres) <= {"jenkins-plugin-manager", "generated-bytecode", "transformed-bytecode", "quarkus-run", "jrt-fs"},
                unres)


# ----------------------------------------------------------------------------- structural expectations
def structural(c: Checker):
    # Fat JAR == Maven runtime closure minus documented exclusions, plus the plugin's own jar.
    rt = set()
    for l in (BUILDINFO_DIR / "bakery-backend" / "maven-runtime.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s+([^:\s]+):([^:\s]+):jar:(?:[^:\s]+:)?([^:\s]+):\w+", l)
        if m:
            rt.add(m.groups())
    excluded = {x for x in rt if x[1].startswith("spring-boot-starter")              # empty starter JARs
                or x[1] in ("lombok", "spring-boot-devtools")}                        # excluded by the plugin
    expected = (rt - excluded) | {("org.springframework.boot", "spring-boot-jarmode-tools", "4.1.0")}
    for tid in ("J-S2", "J-S3-ubuntu", "J-S3-alpine", "J-S3-distroless", "J-P"):
        got = {(x["namespace"], x["name"], x["version"]) for x in gt(tid)["components"] if x["mechanism"] == "nested-jar"}
        c.check(tid, f"nested JARs == Maven runtime - {len(excluded)} documented exclusions + jarmode-tools",
                got == expected, f"missing={sorted(expected - got)[:5]} extra={sorted(got - expected)[:5]}")
    # Gradle subject: fat JAR == Spring Boot's productionRuntimeClasspath - empty starters + jarmode-tools
    prod = set()
    for line in (BUILDINFO_DIR / "petclinic-gradle" / "gradle-productionRuntimeClasspath.txt").read_text(encoding="utf-8").splitlines():
        parts = line.strip().split(":")
        if len(parts) == 3:
            prod.add(tuple(parts))
    g_expected = {x for x in prod if not x[1].startswith("spring-boot-starter")} |         {("org.springframework.boot", "spring-boot-jarmode-tools", "4.1.0")}
    for tid in ("G-S2", "G-S3-ubuntu", "G-S3-alpine", "G-S3-distroless"):
        got = {(x["namespace"], x["name"], x["version"]) for x in gt(tid)["components"] if x["mechanism"] == "nested-jar"}
        c.check(tid, "Gradle: nested JARs == productionRuntimeClasspath - starters + jarmode-tools",
                got == g_expected, f"missing={sorted(g_expected - got)[:5]} extra={sorted(got - g_expected)[:5]}")
        selfc = [x for x in gt(tid)["components"] if x["mechanism"] == "self"]
        c.check(tid, "Gradle: app identity from MANIFEST + build.gradle",
                [(x["namespace"], x["name"], x["version"]) for x in selfc]
                == [("org.springframework.samples", "spring-petclinic", "4.0.0-SNAPSHOT")], selfc[:1])
    g1 = gt("G-S1")["components"]
    dev = [x["name"] for x in g1 if x["name"] == "spring-boot-devtools"]
    c.check("G-S1", "Gradle source: devtools labelled dev scope, not runtime",
            [x["scope"] for x in g1 if x["name"] == "spring-boot-devtools"] == ["dev"], dev)
    c.check("G-S1", "Gradle source: runtime scope == productionRuntimeClasspath",
            {(x["namespace"], x["name"], x["version"]) for x in g1 if x["scope"] == "runtime"} == prod)
    layered = {(x["namespace"], x["name"], x["version"]) for x in gt("J-S3-layered")["components"] if x["mechanism"] == "layered-jar"}
    c.check("J-S3-layered", "exploded lib/ == same set as the fat JAR", layered == expected,
            f"missing={sorted(expected - layered)[:5]} extra={sorted(layered - expected)[:5]}")
    for tid in ("J-S2", "J-S3-ubuntu", "J-S3-layered", "G-S2", "G-S3-ubuntu", "G-S3-alpine", "G-S3-distroless"):
        no_group = [x["name"] for x in gt(tid)["components"] if x["eco"] == "maven" and not x["namespace"]
                    and x["mechanism"] != "runtime-internal"]
        c.check(tid, "every application JAR has a groupId", not no_group, no_group[:5])

    # Planted components are primary GT with the right mechanism.
    for t in load_catalog()["targets"]:
        if not t.get("planted"):
            continue
        spec = json.loads((ROOT / t["planted"]).read_text(encoding="utf-8"))["components"]
        comps = [x for x in gt(t["id"])["components"] if x.get("planted")]
        c.check(t["id"], f"all {len(spec)} planted components in GT as primary",
                len(comps) == len(spec) and all(x["tier"] == "primary" for x in comps),
                [(x["name"], x["version"], x["mechanism"]) for x in comps])

    # Source-stage Python GT must be installed by the project's own images (same resolution day).
    images = set()
    for tid in ("P-S3-pred", "P-S3-drift", "P-S3-front", "P-S3-ml"):
        images |= gt_set(tid, "pypi", ("lang-pm",))
    src = gt_set("P-S1", "pypi", ("lang-pm", "dockerfile-install"))
    c.check("P-S1", "source GT (requirements closure + Dockerfile installs) installed by the 4 images",
            src <= images, f"not installed anywhere={sorted(src - images)[:8]}")

    # Bundled JS: every bundled package is a production (non-dev) lockfile package.
    lock = json.loads((ROOT / "corpus/bakery-inventory-management/bakery-inventory-frontend/package-lock.json")
                      .read_text(encoding="utf-8"))["packages"]
    for tid in ("N-S2", "N-S3-nginx"):
        bundled = [x for x in gt(tid)["components"] if x["mechanism"] == "bundled-js"]
        dev = [x["name"] for x in bundled if lock.get(x["paths"][0], {}).get("dev")]
        c.check(tid, f"{len(bundled)} bundled packages, none of them dev-only", bundled and not dev, dev)

    # Every embedded wheel SBOM component with a purl is in the GT (or enriched a vendored .so record).
    for tid in ("P-S3-pred", "P-S3-front", "P-S3-distroless"):
        g = gt(tid)
        crates = [x for x in g["components"] if x["eco"] == "cargo"]
        enriched = [x for x in g["components"] if x.get("identified_as")]
        expect = {"P-S3-pred": (101, 1), "P-S3-front": (17, 1), "P-S3-distroless": (101, 1)}[tid]
        c.check(tid, f"embedded wheel SBOMs: {expect[0]} cargo crates primary, {expect[1]} .so identified by auditwheel",
                (len(crates), len(enriched)) == expect and all(x["tier"] == "primary" for x in crates),
                (len(crates), [(x["name"], x["identified_as"]) for x in enriched]))
    # Source packages never become primary and never shadow an installed binary package.
    for t in load_catalog()["targets"]:
        bad = [x["name"] for x in gt(t["id"])["components"] if x["mechanism"] == "source-package" and x["tier"] != "secondary"]
        c.check(t["id"], "source-package records are secondary only", not bad, bad[:5])

    # No duplicate identity, also AFTER version normalisation (epochs, go/v prefixes): two GT records that
    # normalise to the same identity would make the matcher credit a tool's answer to the wrong record.
    from score import vnorm
    for t in load_catalog()["targets"]:
        comps = gt(t["id"])["components"]
        ids = [(x["key"], x["version"]) for x in comps]
        norm_ids = [(x["key"], vnorm(x["eco"], x["version"])) for x in comps]
        dupes = sorted({i for i in norm_ids if norm_ids.count(i) > 1})
        c.check(t["id"], "GT identities unique (raw and normalised)", len(ids) == len(set(ids)) and not dupes, dupes[:5])
        versioned = {x["key"] for x in comps if x["version"]}
        shadow = sorted(x["key"] for x in comps if not x["version"] and x["key"] in versioned and x["tier"] == "primary")
        c.check(t["id"], "no primary component recorded both with and without a version", not shadow, shadow[:5])


def main() -> int:
    c = Checker()
    targets = load_catalog()["targets"]
    log("== OS package oracles (inside the running images) ==")
    os_oracles(c, targets)
    log("== Python / npm oracles ==")
    python_oracles(c)
    npm_oracle(c)
    log("== public images: generic oracles ==")
    public_python_oracle(c)
    public_pnpm_oracle(c)
    public_os_extra(c)
    public_busybox_oracle(c)
    public_java_structural(c)
    log("== Go / ELF / ownership parsers vs official tools ==")
    go_oracle(c)
    elf_oracle(c)
    ownership_oracle(c)
    log("== structural expectations ==")
    structural(c)
    fails = [r for r in c.results if not r["ok"]]
    write_json(RESULTS_DIR / "verify_gt.json", {"checks": c.results, "failed": len(fails), "total": len(c.results)})
    log(f"\n{len(c.results) - len(fails)}/{len(c.results)} checks passed.")
    for r in fails:
        log(f"  FAIL {r['target']}: {r['check']} -- {r['detail'][:400]}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
