"""Shared helpers for the P16 pipeline scripts (paths, target catalog, logging, subprocess)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

_LONG_PREFIX = "\\\\?\\"


def _long(p: Path) -> Path:
    """Windows extended-length form (\\\\?\\C:\\...). Without it, Python silently skips files whose
    full path exceeds 260 characters, and this repo has corpus files up to ~275 characters deep."""
    if os.name == "nt" and not str(p).startswith(_LONG_PREFIX):
        return Path(_LONG_PREFIX + str(p))
    return p


def plain(p) -> str:
    """Normal path string for external programs (docker etc.), which cope with long paths themselves."""
    s = str(p)
    return s[len(_LONG_PREFIX):] if s.startswith(_LONG_PREFIX) else s


ROOT = _long(Path(__file__).resolve().parent.parent)
WORK = ROOT / "work"
IMAGES_DIR = WORK / "images"        # docker save tars (scan input for image targets)
ROOTFS_DIR = WORK / "rootfs"        # docker export tars (ground-truth input for image targets)
ARTIFACTS_DIR = WORK / "artifacts"  # S2 build outputs
STAGING_DIR = WORK / "staging"      # derived source trees
BUILDINFO_DIR = WORK / "buildinfo"  # ground-truth inputs from build stages
LOGS_DIR = WORK / "logs"
TMP_DIR = WORK / "tmp"
RESULTS_DIR = ROOT / "results"

PLATFORM = "linux/amd64"


def load_catalog(include_cut: bool = False) -> dict:
    """Target catalog. Targets marked `cut:` stay documented in targets.yaml but are excluded by default."""
    with open(ROOT / "targets.yaml", encoding="utf-8") as fh:
        catalog = yaml.safe_load(fh)
    ids = [t["id"] for t in catalog["targets"]]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SystemExit(f"duplicate target ids in targets.yaml: {sorted(dupes)}")
    catalog["cut"] = {t["id"]: t["cut"] for t in catalog["targets"] if t.get("cut")}
    if not include_cut:
        catalog["targets"] = [t for t in catalog["targets"] if not t.get("cut")]
    return catalog


def image_tag(target_id: str) -> str:
    return f"p16/{target_id.lower()}:latest"


def scan_path(target: dict) -> Path:
    """Where the scanners should point for this target (file, directory or image tar)."""
    kind, how, tid = target["kind"], target["how"], target["id"]
    if kind == "image":
        return IMAGES_DIR / f"{tid}.tar"
    if how == "path":
        return ROOT / target["path"]
    if how == "derive":
        return STAGING_DIR / tid
    if how == "build":
        return ARTIFACTS_DIR / tid / target["file"]
    raise ValueError(f"cannot work out scan path for {tid}")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def rel(path: Path) -> str:
    """Repo-relative POSIX path, for anything written into committed results."""
    return _long(Path(plain(path))).relative_to(ROOT).as_posix()


def run(cmd: list[str], log_file: Path, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a command, append its full output to log_file, and fail loudly if check is set."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    with open(log_file, "a", encoding="utf-8") as fh:
        fh.write(f"\n$ {' '.join(cmd)}\n# exit={proc.returncode} secs={time.time() - started:.1f}\n")
        fh.write(proc.stdout)
        fh.write(proc.stderr)
    if check and proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-25:]
        raise RuntimeError(f"command failed (exit {proc.returncode}): {' '.join(cmd)}\n" + "\n".join(tail))
    return proc


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def log(msg: str) -> None:
    print(msg, flush=True)
    sys.stdout.flush()
