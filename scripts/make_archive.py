"""Build the replication package (Zenodo-ready) in dist/.

  p16-code-<date>.zip              the repository as it would be committed (git ls-files: tracked + untracked,
                                   minus .gitignore): code, frozen corpus, ground truth, results, docs, figures
  p16-data-<date>.tar.gz           work/sboms (every SBOM: default, best-effort, netblocked), work/rq5 (reference
                                   SBOMs, scan outputs, validation scans), work/buildinfo, work/artifacts (S2
                                   artifacts), work/logs (tool logs, incl. the online-verification evidence)
  p16-db-snapshots-<date>.tar.gz   (--with-db) the frozen vulnerability databases (Grype, Trivy, Trivy Java DB) and
                                   the pre-populated Maven cache: needed only to re-run tools / RQ5 scans offline
  SHA256SUMS, MANIFEST.json        checksums and contents (file count, bytes) of each archive

Container images and exported root filesystems (~16 GB) are not archived: they are rebuilt from pinned digests
(targets.yaml, results/build_manifest.json). Unpack the archives into the repository root; see docs/REPLICATION.md.

Usage: python scripts/make_archive.py [--with-db]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone

from common import ROOT, WORK, log, plain, write_json

DIST = ROOT / "dist"
DATA_DIRS = ["sboms", "rq5", "buildinfo", "artifacts", "logs"]
DB_DIRS = ["cache/grype", "cache/trivy", "cache/trivy-vuln", "cache/m2"]
TOP = "sbom-generators-comparative-study"


def sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_files() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=plain(ROOT),
                         capture_output=True, check=True).stdout.decode("utf-8")
    return sorted(f for f in out.split("\0") if f and (ROOT / f).is_file())


def tar_dirs(dest, dirs: list[str]) -> dict:
    n = size = 0
    with tarfile.open(dest, "w:gz", compresslevel=6) as tf:
        for d in dirs:
            src = WORK / d
            if not src.exists():
                raise SystemExit(f"missing {plain(src)}")
            for p in sorted(src.rglob("*")):
                if p.is_file():
                    tf.add(p, arcname=f"work/{p.relative_to(WORK).as_posix()}", recursive=False)
                    n += 1
                    size += p.stat().st_size
    return {"files": n, "bytes_uncompressed": size}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-db", action="store_true", help="also archive the frozen vulnerability DBs (~6.7 GB)")
    a = ap.parse_args()
    DIST.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "archives": {}}

    code = DIST / f"p16-code-{stamp}.zip"
    files = repo_files()
    with zipfile.ZipFile(code, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in files:
            z.write(ROOT / f, f"{TOP}/{f}")
    manifest["archives"][code.name] = {"files": len(files), "bytes_uncompressed": sum((ROOT / f).stat().st_size for f in files),
                                       "contents": "repository (code, corpus, ground truth, results, docs, figures)"}
    log(f"{code.name}: {len(files)} files")

    data = DIST / f"p16-data-{stamp}.tar.gz"
    manifest["archives"][data.name] = {**tar_dirs(data, DATA_DIRS), "contents": "work/" + ", work/".join(DATA_DIRS)}
    log(f"{data.name}: {manifest['archives'][data.name]['files']} files")

    if a.with_db:
        db = DIST / f"p16-db-snapshots-{stamp}.tar.gz"
        manifest["archives"][db.name] = {**tar_dirs(db, DB_DIRS), "contents": "work/" + ", work/".join(DB_DIRS)}
        log(f"{db.name}: {manifest['archives'][db.name]['files']} files")

    sums = []
    for name, info in manifest["archives"].items():
        p = DIST / name
        info["bytes"] = p.stat().st_size
        info["sha256"] = sha256(p)
        sums.append(f"{info['sha256']}  {name}")
    (DIST / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    write_json(DIST / "MANIFEST.json", manifest)
    for name, info in manifest["archives"].items():
        log(f"  {name}: {info['bytes'] / 1e6:.1f} MB (from {info['bytes_uncompressed'] / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
