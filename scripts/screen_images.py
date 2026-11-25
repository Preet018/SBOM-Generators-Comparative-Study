"""Pre-screen candidate public images before adding them to the corpus (external-validity extension).

For each candidate:
  1. pull it (linux/amd64) and pin the digest;
  2. inventory its filesystem from `docker export` (what package databases / ecosystems it really contains,
     and anything our ground truth cannot verify: Ruby gems, PHP composer, .NET, conda, Rust, JARs that carry no
     pom.properties, bundled JavaScript);
  3. run Syft, Trivy and cdxgen once (default config, CycloneDX) and count what each reports by purl type.

Nothing here touches the study's targets, SBOMs or results files: everything goes to work/screen/ and
results/screening.json. Selection rules are applied by hand to that file and written up in the paper.

Usage: python scripts/screen_images.py [--only SLUG ...] [--skip-tools] [--force]
"""
from __future__ import annotations

import argparse
import collections
import io
import json
import re
import subprocess
import tarfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import PLATFORM, RESULTS_DIR, WORK, log, plain, write_json
from fsutil import go_buildinfo
from run_tools import TRIVY_CACHE, tool_args, tool_images

SCREEN = WORK / "screen"
IMG = SCREEN / "images"
SBOMS = SCREEN / "sboms"
LOGS = SCREEN / "logs"
OUT = RESULTS_DIR / "screening.json"

# slug -> image reference (floating tag; the digest pulled is what gets pinned)
CANDIDATES = {
    "python":     "python:3.13-slim",
    "node":       "node:22-slim",
    "postgres":   "postgres:17",
    "redis":      "redis:8",
    "mysql":      "mysql:8.4",
    "jenkins":    "jenkins/jenkins:lts-jdk21",
    "keycloak":   "quay.io/keycloak/keycloak:latest",
    "grafana":    "grafana/grafana-oss:latest",
    "prometheus": "prom/prometheus:latest",
    "gitea":      "gitea/gitea:latest",
    "airflow":    "apache/airflow:slim-latest",
    "ghost":      "ghost:6-alpine",
}

SUPPORTED_PURL_TYPES = {"deb", "rpm", "apk", "pypi", "npm", "maven", "golang", "generic", "github"}
ARCHIVE_EXT = (".jar", ".war", ".ear", ".jpi", ".hpi")
MAX_READ = 400 * 1024 * 1024
TOOL_TIMEOUT = 45 * 60


# ----------------------------------------------------------------------------- docker helpers
def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def pull_and_pin(slug: str, ref: str, force: bool) -> dict:
    p = sh(["docker", "pull", "--platform", PLATFORM, ref])
    if p.returncode != 0:
        return {"error": f"pull failed: {p.stderr.strip()[-300:]}"}
    info = json.loads(sh(["docker", "image", "inspect", ref]).stdout)[0]
    digests = [d for d in info.get("RepoDigests", []) if "@sha256:" in d]
    labels = (info.get("Config") or {}).get("Labels") or {}
    env = dict(e.split("=", 1) for e in (info.get("Config") or {}).get("Env") or [] if "=" in e)
    tar = IMG / f"{slug}.tar"
    if force or not tar.exists():
        IMG.mkdir(parents=True, exist_ok=True)
        s = sh(["docker", "save", "-o", plain(tar), ref])
        if s.returncode != 0:
            return {"error": f"save failed: {s.stderr.strip()[-300:]}"}
    return {"ref": ref, "digest": digests[0] if digests else None, "image_id": info["Id"],
            "size_mb": round(info.get("Size", 0) / 1e6), "created": info.get("Created"),
            "version_labels": {k: v for k, v in labels.items() if "version" in k.lower()},
            "version_env": {k: v for k, v in env.items() if k.endswith("_VERSION")}}


# ----------------------------------------------------------------------------- filesystem inventory
def jar_scan(data: bytes, depth: int = 0) -> dict:
    """pom.properties presence for an archive and (one level down) for the archives nested in it."""
    res = {"archives": 1, "no_pom": 0, "nested": 0, "nested_no_pom": 0}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        res["bad"] = 1
        return res
    names = z.namelist()
    if not any(re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n) for n in names):
        res["no_pom"] = 1
    if depth == 0:
        for n in names:
            if n.endswith(ARCHIVE_EXT) and not n.endswith("/"):
                sub = jar_scan(z.read(n), depth + 1)
                res["nested"] += 1
                res["nested_no_pom"] += sub["no_pom"]
    return res


def inventory(slug: str, ref: str) -> dict:
    cid = sh(["docker", "create", "--platform", PLATFORM, ref, "/nonexistent"]).stdout.strip()
    inv = collections.Counter()
    found: dict[str, list] = collections.defaultdict(list)
    try:
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
            for m in tf:
                n = m.name.removeprefix("./").removeprefix("/")
                base = n.rsplit("/", 1)[-1]
                if n in ("var/lib/dpkg/status",):
                    inv["os:dpkg"] += 1
                elif n.startswith("var/lib/dpkg/status.d/") and m.isfile():
                    inv["os:dpkg-status.d"] += 1
                elif n == "lib/apk/db/installed":
                    inv["os:apk"] += 1
                elif n in ("var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite"):
                    inv["os:rpm"] += 1
                if re.search(r"\.dist-info/METADATA$", n):
                    inv["pypi:dist-info"] += 1
                elif re.search(r"\.egg-info(/PKG-INFO)?$", n) and (m.isfile()):
                    inv["pypi:egg-info"] += 1
                elif re.search(r"(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$", n):
                    inv["npm:node_modules-pkg"] += 1
                elif re.search(r"specifications/[^/]+\.gemspec$", n):
                    inv["UNSUPPORTED:ruby-gem"] += 1
                elif n.endswith("vendor/composer/installed.json"):
                    inv["UNSUPPORTED:php-composer"] += 1
                elif n.endswith(".deps.json"):
                    inv["UNSUPPORTED:dotnet-deps"] += 1
                elif re.search(r"conda-meta/[^/]+\.json$", n):
                    inv["UNSUPPORTED:conda"] += 1
                elif base == "Cargo.lock":
                    inv["UNSUPPORTED:cargo-lock"] += 1
                elif base == "release" and re.search(r"(java|jdk|jre)", n) and m.isfile():
                    inv["runtime:java-release"] += 1
                if not m.isfile():
                    continue
                if base.endswith(ARCHIVE_EXT) and m.size <= MAX_READ:
                    r = jar_scan(tf.extractfile(m).read())
                    for k, v in r.items():
                        inv[f"java:{k}"] += v
                    if r["no_pom"] and len(found["java_no_pom_examples"]) < 8:
                        found["java_no_pom_examples"].append(n)
                elif base.endswith(".js") and m.size > 300_000 and "node_modules/" not in n:
                    inv["npm:bundled-js>300KB"] += 1
                    if len(found["bundled_js_examples"]) < 4:
                        found["bundled_js_examples"].append(n)
                elif m.size > 500_000 and m.size <= MAX_READ and (m.mode & 0o111):
                    data = tf.extractfile(m).read()
                    if data[:4] != b"\x7fELF":
                        continue
                    bi = go_buildinfo(data)
                    if bi and not bi.get("unsupported_format"):
                        inv["golang:binaries"] += 1
                        inv["golang:modules"] += len(bi["deps"]) + (1 if bi.get("main") else 0)
                        found["go_binaries"].append(f"{n} ({bi['go_version']}, {len(bi['deps'])} deps)")
                    elif b".dep-v0" in data:
                        inv["UNSUPPORTED:rust-auditable"] += 1
                    elif b"rustc version" in data or b"/rustc/" in data:
                        inv["UNSUPPORTED:rust-binary"] += 1
        proc.wait()
    finally:
        sh(["docker", "rm", "-f", cid])
    return {"counts": dict(sorted(inv.items())), **{k: v for k, v in found.items()}}


# ----------------------------------------------------------------------------- tools
def run_tool(tool: str, slug: str, images: dict) -> dict:
    out = SBOMS / tool
    out.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    target = {"id": slug, "kind": "image"}
    mounts = ["-v", f"{plain(out)}:/out", "-v", f"{plain(IMG)}:/img:ro"]
    if tool == "trivy":
        mounts += ["-v", f"{plain(TRIVY_CACHE)}:/cache"]
    name = f"p16-screen-{tool}-{slug}"
    cmd = ["docker", "run", "--rm", "--name", name, "-e", "SYFT_CHECK_FOR_APP_UPDATE=false",
           "-e", "CDXGEN_NO_PROGRESS=1", *mounts, images[tool], *tool_args(tool, target, "default", ["cyclonedx"], slug)]
    path = out / f"{slug}.json"
    path.unlink(missing_ok=True)
    t0 = time.time()
    try:
        p = sh(cmd, timeout=TOOL_TIMEOUT)
        code, text = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        sh(["docker", "rm", "-f", name])
        code, text = "timeout", ""
    secs = round(time.time() - t0, 1)
    (LOGS / f"{tool}-{slug}.log").write_text(f"# exit={code} secs={secs}\n{text}", encoding="utf-8")
    res = {"exit": code, "seconds": secs}
    if path.exists() and path.stat().st_size:
        # packages only: Syft/cdxgen also list files, crypto assets, data and the OS itself as components
        comps = [c for c in json.loads(path.read_text(encoding="utf-8")).get("components", [])
                 if c.get("type") in ("library", "application", "framework")]
        types = collections.Counter()
        for c in comps:
            m = re.match(r"pkg:([^/]+)/", c.get("purl") or "")
            types[m.group(1) if m else "(no purl)"] += 1
        res.update(components=len(comps), purl_types=dict(types.most_common()),
                   unsupported=sum(v for k, v in types.items() if k not in SUPPORTED_PURL_TYPES and k != "(no purl)"))
    return res


# ----------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+")
    ap.add_argument("--skip-tools", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    slugs = a.only or list(CANDIDATES)
    data = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {"candidates": {}}
    lock = threading.Lock()

    def save():
        with lock:
            write_json(OUT, data)

    for slug in slugs:
        entry = data["candidates"].setdefault(slug, {})
        log(f"[screen] {slug}: pull + inventory")
        entry["image"] = pull_and_pin(slug, CANDIDATES[slug], a.force)
        if "error" in entry["image"]:
            log(f"[screen] {slug}: {entry['image']['error']}")
            continue
        entry["inventory"] = inventory(slug, CANDIDATES[slug])
        log(f"[screen] {slug}: {entry['inventory']['counts']}")
        save()

    if not a.skip_tools:
        images = tool_images()

        def worker(tool: str):
            for slug in slugs:
                if "error" in data["candidates"][slug].get("image", {"error": 1}):
                    continue
                r = run_tool(tool, slug, images)
                with lock:
                    data["candidates"][slug].setdefault("tools", {})[tool] = r
                log(f"[screen] {tool:6} {slug:10} exit={r['exit']} {r['seconds']}s comps={r.get('components')} "
                    f"types={r.get('purl_types')}")
                save()

        with ThreadPoolExecutor(max_workers=3) as ex:
            list(ex.map(worker, ("syft", "trivy", "cdxgen")))
    save()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
