"""Cross-verify the Day-1 build outputs before any SBOM is generated.

Checks are deliberately independent of the build script: they open the produced files
(image tars, exported filesystems, artifacts, buildinfo) and assert what must be inside.
A failing check means a variant does not contain what the study claims it contains.

Usage:  python scripts/verify_build.py            (writes results/verify_build.json)
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path

from common import (ARTIFACTS_DIR, BUILDINFO_DIR, IMAGES_DIR, RESULTS_DIR, ROOT, ROOTFS_DIR, STAGING_DIR,
                    load_catalog, log, scan_path, sha256_file, write_json)
from fsutil import EXPORT_INJECTED, Rootfs, docker_archive_ok, elf_info

CORPUS_CHECKSUMS = RESULTS_DIR / "corpus_checksums.json"


# ----------------------------------------------------------------------------- check runner
class Checker:
    def __init__(self):
        self.results: list[dict] = []

    def check(self, target: str, name: str, ok: bool, detail="") -> bool:
        self.results.append({"target": target, "check": name, "ok": bool(ok), "detail": str(detail)})
        log(f"  [{'PASS' if ok else 'FAIL'}] {target}: {name}{(' -- ' + str(detail)) if detail else ''}")
        return ok


def corpus_checksums() -> dict:
    corpus = ROOT / "corpus"
    return {p.relative_to(corpus).as_posix(): sha256_file(p) for p in sorted(corpus.rglob("*")) if p.is_file()}


# ----------------------------------------------------------------------------- per-target content checks
def check_java_image(c: Checker, tid: str, fs: Rootfs, layered: bool):
    if layered:
        libs = fs.glob(r"^app/lib/[^/]+\.jar$")
        c.check(tid, "exploded lib/*.jar present (>30)", len(libs) > 30, len(libs))
        c.check(tid, "thin app.jar present", fs.exists("app/app.jar"))
    else:
        c.check(tid, "/app/app.jar present", fs.exists("app/app.jar"))
    java = fs.glob(r"(^|/)bin/java$")
    c.check(tid, "java runtime present", bool(java), java[:2])


def check_target(c: Checker, t: dict, fat_jar_libs: set[str]):
    tid, kind = t["id"], t["kind"]
    path = scan_path(t)
    if not c.check(tid, "scan input exists", path.exists(), path.relative_to(ROOT).as_posix()):
        return
    if kind == "image":
        ok, arch = docker_archive_ok(path)
        c.check(tid, "docker-archive valid, linux/amd64", ok, arch)
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        c.check(tid, "rootfs export non-empty", len(fs.members) > 0, f"{len(fs.members)} entries")
    else:
        fs = None

    # --- Java ---
    if tid == "J-S2":
        with zipfile.ZipFile(path) as z:
            libs = {Path(n).name for n in z.namelist() if n.startswith("BOOT-INF/lib/") and n.endswith(".jar")}
        fat_jar_libs.update(libs)
        c.check(tid, "fat JAR has BOOT-INF/lib (>30 jars)", len(libs) > 30, len(libs))
        c.check(tid, "devtools excluded from fat JAR (Spring Boot default)",
                not any(n.startswith("spring-boot-devtools") for n in libs))
        c.check(tid, "test-scope jars absent (no junit/mockito)",
                not any(n.startswith(("junit", "mockito", "assertj")) for n in libs))
        c.check(tid, "INFO lombok in fat JAR?", True, any(n.startswith("lombok") for n in libs))
    elif tid in ("J-S3-ubuntu", "J-S3-alpine", "J-S3-distroless", "J-P"):
        check_java_image(c, tid, fs, layered=False)
        if tid == "J-S3-alpine":
            c.check(tid, "apk database present", fs.exists("lib/apk/db/installed"))
        if tid == "J-S3-distroless":
            c.check(tid, "distroless dpkg status.d present", bool(fs.glob(r"^var/lib/dpkg/status\.d/")))
            c.check(tid, "no shell (distroless)", not fs.exists("bin/sh"))
        if tid == "J-P":
            c.check(tid, "planted log4j-core-2.14.1.jar", fs.exists("opt/lib/log4j-core-2.14.1.jar"))
            c.check(tid, "planted shaded-demo-1.0.0.jar", fs.exists("opt/lib/shaded-demo-1.0.0.jar"))
            if fs.exists("opt/lib/shaded-demo-1.0.0.jar"):
                with zipfile.ZipFile(io.BytesIO(fs.read("opt/lib/shaded-demo-1.0.0.jar"))) as z:
                    names = z.namelist()
                c.check(tid, "shaded: commons-lang3 relocated to org/p16/shaded/lang3",
                        any(n.startswith("org/p16/shaded/lang3/") for n in names)
                        and not any(n.startswith("org/apache/commons/lang3/") for n in names))
                c.check(tid, "shaded: gson classes bundled unrelocated", any(n.startswith("com/google/gson/") for n in names))
                c.check(tid, "INFO shaded JAR keeps META-INF/maven pom.properties", True,
                        sorted(n for n in names if n.endswith("pom.properties")))
    elif tid == "J-S3-layered":
        check_java_image(c, tid, fs, layered=True)
        libs = {Path(n).name for n in fs.glob(r"^app/lib/[^/]+\.jar$")}
        if fat_jar_libs:
            c.check(tid, "exploded lib/ == fat JAR BOOT-INF/lib", libs == fat_jar_libs,
                    f"only-layered={sorted(libs - fat_jar_libs)[:5]} only-fat={sorted(fat_jar_libs - libs)[:5]}")

    # --- npm ---
    elif tid == "N-S1-nolock":
        c.check(tid, "package-lock.json removed", not (path / "package-lock.json").exists())
        c.check(tid, "package.json kept", (path / "package.json").exists())
    elif tid == "N-S2":
        files = [p for p in path.rglob("*") if p.is_file()]
        c.check(tid, "index.html + JS bundle", (path / "index.html").exists() and any(p.suffix == ".js" for p in files))
        c.check(tid, "no sourcemaps shipped", not any(p.suffix == ".map" for p in files))
    elif tid == "N-S3-nginx":
        c.check(tid, "bundle served from nginx html dir", fs.exists("usr/share/nginx/html/index.html"))
        c.check(tid, "no node_modules in image", not fs.glob(r"(^|/)node_modules/"))
        c.check(tid, "no sourcemaps in image", not fs.glob(r"^usr/share/nginx/html/.*\.map$"))
    elif tid == "N-S3-node":
        c.check(tid, "node_modules with vite (dev dep) present", fs.exists("app/node_modules/vite/package.json"))
        c.check(tid, "node_modules with react (prod dep) present", fs.exists("app/node_modules/react/package.json"))

    # --- Python ---
    elif tid == "P-S1-pinned":
        reqs = list(path.rglob("requirements.txt"))
        bad = []
        for r in reqs:
            for line in r.read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.startswith("#") and "==" not in line:
                    bad.append(f"{r.parent.name}:{line}")
        c.check(tid, "all 5 requirements.txt fully pinned", len(reqs) == 5 and not bad, f"{len(reqs)} files, unpinned={bad[:3]}")
        c.check(tid, "pymongo NOT pinned (it is not in the source manifests)",
                not any("pymongo" in r.read_text(encoding="utf-8").lower() for r in reqs))
    elif tid in ("P-S3-pred", "P-S3-drift", "P-S3-front", "P-S3-ml", "P-S3-alpine", "P-P", "P-S3-distroless"):
        dist = fs.glob(r"\.dist-info/METADATA$")
        names = {re.sub(r"-[^-]+\.dist-info/METADATA$", "", Path(d).parent.name + "/METADATA").lower() for d in dist}
        c.check(tid, "pymongo installed (Dockerfile-only dependency)", any(n.startswith("pymongo") for n in names))
        c.check(tid, "pandas installed", any(n.startswith("pandas") for n in names))
        if tid in ("P-S3-pred", "P-S3-ml", "P-S3-alpine", "P-P", "P-S3-distroless"):
            vend = fs.glob(r"(numpy|scipy|scikit_learn)\.libs/[^/]+\.so")
            c.check(tid, "wheel-vendored native libs (*.libs/*.so) present", bool(vend), f"{len(vend)} files")
        if tid == "P-S3-distroless":
            c.check(tid, "packages under /app/deps (pip --target)", bool(fs.glob(r"^app/deps/[^/]+\.dist-info/METADATA$")))
            c.check(tid, "no pip in final image", not fs.glob(r"(^|/)bin/pip"))
        if tid == "P-S3-alpine":
            c.check(tid, "musl wheels / apk base", fs.exists("lib/apk/db/installed"))
        if tid == "P-P":
            for b in ("usr/local/bin/jq", "usr/local/bin/yq"):
                info = elf_info(fs.read(b)) if fs.exists(b) else {}
                c.check(tid, f"planted {b} is x86-64 ELF", info.get("x86_64"), info)
            c.check(tid, "planted jq is static (no interpreter)", fs.exists("usr/local/bin/jq")
                    and elf_info(fs.read("usr/local/bin/jq")).get("interp") is None)
            c.check(tid, "vendored decorator.py present", fs.exists("app/vendor/decorator.py"))
            c.check(tid, "no decorator dist-info anywhere (pure vendored copy)", not fs.glob(r"decorator-[^/]*.dist-info/"))
    elif tid == "M-S3":
        c.check(tid, "project init.js copied", fs.exists("docker-entrypoint-initdb.d/init.js"))
        c.check(tid, "mongod binary present", bool(fs.glob(r"(^|/)bin/mongod$")))

    # --- C ---
    elif tid == "C-S1":
        info = elf_info((path / "server").read_bytes())
        c.check(tid, "committed server binary is Mach-O (foreign binary case)", info.get("macho"), info)
    elif tid == "C-S2":
        info = elf_info(path.read_bytes())
        c.check(tid, "server is x86-64 ELF, dynamic glibc", info.get("x86_64") and info.get("dynamic")
                and "ld-linux-x86-64" in (info.get("interp") or ""), info)
    elif tid.startswith("C-"):
        info = elf_info(fs.read("app/server")) if fs.exists("app/server") else {}
        expect = {"C-S3-debian": "ld-linux-x86-64", "C-S3-alpine": "ld-musl-x86_64", "C-P": "ld-linux-x86-64"}
        if tid == "C-S3-scratch":
            c.check(tid, "server is static ELF (no interpreter)", info.get("x86_64") and info.get("interp") is None, info)
            real_files = sorted(n for n, m in fs.members.items() if m.isfile() and n not in EXPORT_INJECTED)
            c.check(tid, "image contains only the binary (export placeholders ignored)", real_files == ["app/server"],
                    real_files)
        else:
            c.check(tid, f"server is dynamic ELF via {expect[tid]}", info.get("x86_64")
                    and expect[tid] in (info.get("interp") or ""), info)
        if tid == "C-P" and fs.exists("app/server"):
            blob = fs.read("app/server")
            c.check(tid, "zlib 1.3.1 statically linked (deflate + inflate banners in binary)",
                    b"deflate 1.3.1 Copyright" in blob and b"inflate 1.3.1 Copyright" in blob)
            c.check(tid, "cJSON compiled in (symbol name in binary)", b"cJSON_Version" in blob)
            readelf = (BUILDINFO_DIR / "tcp-server" / "planted-readelf-server.txt").read_text(encoding="utf-8")
            c.check(tid, "libz NOT a dynamic dependency", "libz" not in readelf)

    # --- OS baselines ---
    elif tid in ("O-debian", "O-ubuntu"):
        c.check(tid, "dpkg status present", fs.exists("var/lib/dpkg/status"))
    elif tid == "O-alpine":
        c.check(tid, "apk installed db present", fs.exists("lib/apk/db/installed"))
    elif tid == "O-ubi":
        c.check(tid, "rpm database present", bool(fs.glob(r"^(var/lib/rpm|usr/lib/sysimage/rpm)/")))
    elif tid == "O-distroless":
        c.check(tid, "distroless dpkg status.d present", bool(fs.glob(r"^var/lib/dpkg/status\.d/")))


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pip_report(service: str) -> dict[str, str]:
    data = json.loads((BUILDINFO_DIR / "log-anomaly" / f"pip-report-{service}.json").read_text(encoding="utf-8"))
    return {pep503(i["metadata"]["name"]): i["metadata"]["version"] for i in data["install"]}


def installed_python(fs: Rootfs) -> dict[str, str]:
    out = {}
    for d in fs.glob(r"site-packages/[^/]+\.dist-info/METADATA$"):
        stem = Path(d).parent.name.removesuffix(".dist-info")
        name, _, version = stem.rpartition("-")
        out[pep503(name)] = version
    return out


def check_python_consistency(c: Checker):
    """Source-stage ground truth (pip dry-run reports) must agree with what the images actually installed,
    and P-S1-pinned must be derived from the current reports. Otherwise S1-vs-S3 comparisons mix dates."""
    images = {"P-S3-pred": "prediction_service", "P-S3-drift": "drift_service",
              "P-S3-front": "frontend", "P-S3-ml": "ml_pipeline"}
    for tid, service in images.items():
        report, installed = pip_report(service), installed_python(Rootfs(ROOTFS_DIR / f"{tid}.tar"))
        diff = {n: (v, installed.get(n)) for n, v in report.items() if installed.get(n) != v}
        c.check(tid, f"image installs exactly the versions in pip-report-{service}", not diff, diff)
    pinned = STAGING_DIR / "P-S1-pinned"
    for service in ("root", "prediction_service", "drift_service", "frontend", "ml_pipeline"):
        req = pinned / ("requirements.txt" if service == "root" else f"{service}/requirements.txt")
        pins = {pep503(l.split("==")[0]): l.split("==")[1] for l in req.read_text(encoding="utf-8").splitlines()
                if "==" in l and not l.startswith("#")}
        c.check("P-S1-pinned", f"{service} pins == current pip report", pins == pip_report(service))


def check_buildinfo(c: Checker):
    bi = BUILDINFO_DIR
    for f in ("maven-runtime.txt", "maven-all.txt", "maven-tree.txt"):
        p = bi / "bakery-backend" / f
        n = len(re.findall(r"^\s+[\w.\-]+:[\w.\-]+:jar:", p.read_text(encoding="utf-8"), re.M)) if p.exists() else 0
        c.check("buildinfo", f"bakery-backend/{f} lists dependencies", n > 30 or (f == "maven-tree.txt" and p.exists()), n)
    for f in ("npm-ls-all.json", "npm-ls-prod.json"):
        p = bi / "bakery-frontend" / f
        ok = p.exists() and "dependencies" in json.loads(p.read_text(encoding="utf-8"))
        c.check("buildinfo", f"bakery-frontend/{f} valid", ok)
    maps = list((bi / "bakery-frontend" / "dist-with-maps").rglob("*.map"))
    c.check("buildinfo", "bakery-frontend sourcemaps kept for ground truth", bool(maps), len(maps))
    reports = list((bi / "log-anomaly").glob("pip-report-*.json"))
    c.check("buildinfo", "log-anomaly: 5 pip dry-run reports", len(reports) == 5, [p.name for p in reports])
    for f in ("glibc-readelf-server.txt", "musl-version.txt", "planted-readelf-server.txt"):
        c.check("buildinfo", f"tcp-server/{f} present", (bi / "tcp-server" / f).exists())
    mv = bi / "tcp-server" / "musl-version.txt"
    content = mv.read_text(encoding="utf-8").strip() if mv.exists() else ""
    c.check("buildinfo", "tcp-server/musl-version.txt is exactly one 'musl-<version>' line",
            re.fullmatch(r"musl-\d[\w.\-]*", content) is not None, content[:80])


def main() -> int:
    c = Checker()
    catalog = load_catalog()
    manifest = json.loads((RESULTS_DIR / "build_manifest.json").read_text(encoding="utf-8"))

    log("== corpus integrity ==")
    current = corpus_checksums()
    if CORPUS_CHECKSUMS.exists():
        frozen = json.loads(CORPUS_CHECKSUMS.read_text(encoding="utf-8"))
        changed = sorted(k for k in frozen.keys() | current.keys() if frozen.get(k) != current.get(k))
        c.check("corpus", "corpus unchanged since snapshot", not changed, changed[:10])
    else:
        write_json(CORPUS_CHECKSUMS, current)
        c.check("corpus", "corpus checksums recorded (first run)", True, f"{len(current)} files")

    log("== build manifest ==")
    for t in catalog["targets"]:
        status = manifest["targets"].get(t["id"], {}).get("status")
        c.check(t["id"], "manifest status ok", status in ("ok", "skipped-existing") or t.get("optional"), status)

    log("== buildinfo ==")
    check_buildinfo(c)

    log("== source vs image consistency (Python) ==")
    try:
        check_python_consistency(c)
    except Exception as exc:
        c.check("log-anomaly", "consistency check ran without error", False, repr(exc))

    log("== target contents ==")
    fat_jar_libs: set[str] = set()
    for t in catalog["targets"]:
        if manifest["targets"].get(t["id"], {}).get("status") == "failed":
            continue
        try:
            check_target(c, t, fat_jar_libs)
        except Exception as exc:  # a crash in a check is itself a failure to report
            c.check(t["id"], "verification ran without error", False, repr(exc))

    fails = [r for r in c.results if not r["ok"]]
    write_json(RESULTS_DIR / "verify_build.json", {"checks": c.results, "failed": len(fails), "total": len(c.results)})
    log(f"\n{len(c.results) - len(fails)}/{len(c.results)} checks passed.")
    for r in fails:
        log(f"  FAIL {r['target']}: {r['check']} -- {r['detail']}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
