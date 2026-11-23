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
import subprocess
from pathlib import Path

from common import BUILDINFO_DIR, RESULTS_DIR, ROOT, ROOTFS_DIR, TMP_DIR, image_tag, load_catalog, log, plain, write_json
from fsutil import Rootfs, elf_info, go_buildinfo

GT_DIR = ROOT / "ground_truth"
GOLANG_IMAGE = "golang:1.25"


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
        try:
            if gt_deb and "distroless" not in tid:
                out = sh(tid, "dpkg-query -W -f '${Package}\\t${Version}\\t${db:Status-Abbrev}\\n'")
                oracle = {(p, v) for p, v, s in (l.split("\t") for l in out.splitlines()) if s.strip() == "ii"}
                compare(c, tid, "deb packages (dpkg-query)", oracle, gt_deb)
            if gt_apk:
                out = sh(tid, "apk info -v 2>/dev/null")
                gt_strings = {f"{n}-{v}" for n, v in gt_apk}
                compare(c, tid, "apk packages (apk info -v)", set(out.split()), gt_strings)
            if gt_rpm:
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
    layered = {(x["namespace"], x["name"], x["version"]) for x in gt("J-S3-layered")["components"] if x["mechanism"] == "layered-jar"}
    c.check("J-S3-layered", "exploded lib/ == same set as the fat JAR", layered == expected,
            f"missing={sorted(expected - layered)[:5]} extra={sorted(layered - expected)[:5]}")
    for tid in ("J-S2", "J-S3-ubuntu", "J-S3-layered"):
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
