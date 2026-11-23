"""Build every scan target listed in targets.yaml.

For each target this produces the scanner input and records it in results/build_manifest.json:
  dir   targets -> a repo directory, or a derived copy in work/staging/<id>
  file  targets -> work/artifacts/<id>/<file>              (docker build --output)
  image targets -> work/images/<id>.tar  (docker save,   the scanner input)
                   work/rootfs/<id>.tar  (docker export, the ground-truth input)
Build-stage ground-truth inputs ("buildinfo") go to work/buildinfo/<id>/.

Usage:  python scripts/build_targets.py [--only ID ...] [--force] [--skip-buildinfo]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from common import (ARTIFACTS_DIR, BUILDINFO_DIR, IMAGES_DIR, LOGS_DIR, PLATFORM, RESULTS_DIR, ROOT,
                    ROOTFS_DIR, STAGING_DIR, image_tag, load_catalog, log, plain, rel, run, scan_path,
                    sha256_file, write_json)

BUILD_LOGS = LOGS_DIR / "build"
MANIFEST = RESULTS_DIR / "build_manifest.json"


# ----------------------------------------------------------------------------- docker helpers
def docker_build_cmd(spec: dict, extra: list[str]) -> list[str]:
    cmd = ["docker", "build", "--platform", PLATFORM, "--progress=plain",
           "-f", plain(ROOT / spec["dockerfile"])]
    if spec.get("target"):
        cmd += ["--target", spec["target"]]
    for name, path in (spec.get("build_contexts") or {}).items():
        cmd += ["--build-context", f"{name}={plain(ROOT / path)}"]
    for name, value in (spec.get("build_args") or {}).items():
        cmd += ["--build-arg", f"{name}={value}"]
    return cmd + extra + [plain(ROOT / spec["context"])]


def build_to_dir(spec: dict, dest: Path, log_file: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    run(docker_build_cmd(spec, ["--output", f"type=local,dest={plain(dest)}"]), log_file)


def image_inspect(ref: str, log_file: Path) -> dict:
    out = run(["docker", "image", "inspect", ref], log_file).stdout
    info = json.loads(out)[0]
    return {"image_id": info["Id"], "repo_digests": info.get("RepoDigests") or [],
            "size_bytes": info["Size"], "architecture": info.get("Architecture"), "os": info.get("Os")}


def save_and_export(tid: str, tag: str, log_file: Path) -> dict:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    ROOTFS_DIR.mkdir(parents=True, exist_ok=True)
    img_tar, fs_tar = IMAGES_DIR / f"{tid}.tar", ROOTFS_DIR / f"{tid}.tar"
    run(["docker", "save", "-o", plain(img_tar), tag], log_file)
    # A container is created (never started) only to export its merged filesystem.
    # "p16-noop" fills the command slot for images that define neither ENTRYPOINT nor CMD.
    cid = run(["docker", "create", "--platform", PLATFORM, tag, "p16-noop"], log_file).stdout.strip()
    try:
        run(["docker", "export", "-o", plain(fs_tar), cid], log_file)
    finally:
        run(["docker", "rm", "-f", cid], log_file, check=False)
    return {"image_tar": rel(img_tar), "image_tar_sha256": sha256_file(img_tar),
            "rootfs_tar": rel(fs_tar), "rootfs_tar_sha256": sha256_file(fs_tar)}


# ----------------------------------------------------------------------------- derive recipes
def derive(target: dict, log_file: Path) -> None:
    spec = target["derive"]
    src, dest = ROOT / spec["from"], STAGING_DIR / target["id"]
    if dest.exists():
        shutil.rmtree(dest)
    if spec["recipe"] == "exclude":
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns(*spec["exclude"]))
        for name in spec["exclude"]:
            if any(dest.rglob(name)):
                raise RuntimeError(f"{target['id']}: {name} still present after exclude")
    elif spec["recipe"] == "pin_requirements":
        shutil.copytree(src, dest)
        pin_requirements(dest, BUILDINFO_DIR / spec["buildinfo"], log_file)
    else:
        raise ValueError(f"unknown derive recipe {spec['recipe']}")


def pin_requirements(tree: Path, buildinfo: Path, log_file: Path) -> None:
    """Replace every unpinned requirements.txt with the exact closure pip resolved (name==version)."""
    mapping = {"root": tree / "requirements.txt"}
    for report in buildinfo.glob("pip-report-*.json"):
        key = report.stem.removeprefix("pip-report-")
        req = mapping.get(key, tree / key / "requirements.txt")
        if not req.exists():
            raise RuntimeError(f"pip report {report.name} has no matching requirements file {req}")
        data = json.loads(report.read_text(encoding="utf-8"))
        pins = sorted({f"{i['metadata']['name']}=={i['metadata']['version']}" for i in data["install"]},
                      key=str.lower)
        if not pins:
            raise RuntimeError(f"empty pip report {report}")
        req.write_text("# Pinned by the P16 study from `pip install --dry-run --report` (full resolved closure).\n"
                       + "\n".join(pins) + "\n", encoding="utf-8", newline="\n")
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"pinned {rel(req)}: {len(pins)} packages\n")
    if not any(buildinfo.glob("pip-report-*.json")):
        raise RuntimeError(f"no pip reports in {buildinfo}; build the log-anomaly buildinfo first")


# ----------------------------------------------------------------------------- base images
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)


def base_images(catalog: dict) -> list[str]:
    """External images named in FROM lines (stage names, ARG refs and scratch excluded)."""
    dockerfiles = {e["dockerfile"] for e in catalog["buildinfo"]}
    dockerfiles |= {t["build"]["dockerfile"] for t in catalog["targets"] if t["how"] == "build"}
    refs: set[str] = set()
    for df in dockerfiles:
        text = (ROOT / df).read_text(encoding="utf-8")
        stages = {m.lower() for m in re.findall(r"\bAS\s+(\S+)", text, re.IGNORECASE)}
        for ref in FROM_RE.findall(text):
            if ref.lower() in stages or ref == "scratch" or "$" in ref:
                continue
            refs.add(ref)
    refs |= {t["image"] for t in catalog["targets"] if t["how"] == "pull"}
    return sorted(refs)


# ----------------------------------------------------------------------------- main
def build_target(target: dict, force: bool) -> dict:
    tid, how, kind = target["id"], target["how"], target["kind"]
    log_file = BUILD_LOGS / f"{tid}.log"
    out = scan_path(target)
    record = {"id": tid, "kind": kind, "how": how, "stage": target["stage"], "subject": target["subject"],
              "scan_input": rel(out) if out.is_relative_to(ROOT) else str(out)}
    if how != "path" and not force and out.exists() and (kind != "image" or (ROOTFS_DIR / f"{tid}.tar").exists()):
        record["status"] = "skipped-existing"
        return record
    log_file.unlink(missing_ok=True)
    started = time.time()

    if how == "path":
        if not out.is_dir():
            raise RuntimeError(f"{tid}: path {out} does not exist")
    elif how == "derive":
        derive(target, log_file)
    elif how == "pull":
        tag = image_tag(tid)
        run(["docker", "pull", "--platform", PLATFORM, target["image"]], log_file)
        run(["docker", "tag", target["image"], tag], log_file)
        record.update(image_inspect(target["image"], log_file), image=target["image"])
        record.update(save_and_export(tid, tag, log_file))
    elif how == "build" and kind in ("file", "dir"):
        build_to_dir(target["build"], ARTIFACTS_DIR / tid, log_file)
        if not out.exists():
            raise RuntimeError(f"{tid}: build finished but {out} is missing")
        if out.is_file():
            record["artifact_sha256"] = sha256_file(out)
    elif how == "build" and kind == "image":
        tag = image_tag(tid)
        run(docker_build_cmd(target["build"], ["-t", tag]), log_file)
        record.update(image_inspect(tag, log_file), image=tag)
        record.update(save_and_export(tid, tag, log_file))
    else:
        raise ValueError(f"{tid}: unsupported how/kind {how}/{kind}")

    record["status"] = "ok"
    record["build_seconds"] = round(time.time() - started, 1)
    return record


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="+", metavar="ID", help="build only these target ids")
    ap.add_argument("--force", action="store_true", help="rebuild targets even if outputs exist")
    ap.add_argument("--force-buildinfo", action="store_true",
                    help="also rebuild buildinfo. Careful: unpinned pip resolution can drift, so derived "
                         "targets (P-S1-pinned) must be rebuilt afterwards")
    ap.add_argument("--skip-buildinfo", action="store_true")
    ap.add_argument("--buildinfo", nargs="+", metavar="ID",
                    help="with --force-buildinfo: rebuild only these buildinfo entries")
    args = ap.parse_args()

    catalog = load_catalog()
    targets = catalog["targets"]
    if args.only:
        unknown = set(args.only) - {t["id"] for t in targets}
        if unknown:
            raise SystemExit(f"unknown target ids: {sorted(unknown)}")
        targets = [t for t in targets if t["id"] in args.only]

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {"targets": {}}
    failures: list[str] = []

    if not args.skip_buildinfo:
        for entry in catalog["buildinfo"]:
            dest = BUILDINFO_DIR / entry["id"]
            selected = args.force_buildinfo and (not args.buildinfo or entry["id"] in args.buildinfo)
            if dest.exists() and any(dest.iterdir()) and not selected:
                log(f"[buildinfo] {entry['id']}: exists, skipped")
                continue
            log(f"[buildinfo] {entry['id']} ...")
            log_file = BUILD_LOGS / f"buildinfo-{entry['id']}.log"
            log_file.unlink(missing_ok=True)
            try:
                build_to_dir(entry, dest, log_file)
                files = {p.relative_to(dest).as_posix(): sha256_file(p) for p in sorted(dest.rglob("*")) if p.is_file()}
                manifest.setdefault("buildinfo", {})[entry["id"]] = {"files": files, "status": "ok"}
                log(f"[buildinfo] {entry['id']}: ok ({len(files)} files)")
            except Exception as exc:  # keep going so we see every failure in one run
                failures.append(f"buildinfo:{entry['id']}")
                manifest.setdefault("buildinfo", {})[entry["id"]] = {"status": "failed", "error": str(exc)[-2000:]}
                log(f"[buildinfo] {entry['id']}: FAILED\n{exc}")

    for target in targets:
        tid = target["id"]
        log(f"[target] {tid} ({target['how']}/{target['kind']}) ...")
        try:
            record = build_target(target, args.force)
            if record["status"] == "skipped-existing" and tid in manifest["targets"]:
                record = manifest["targets"][tid]
            manifest["targets"][tid] = record
            log(f"[target] {tid}: {record['status']}")
        except Exception as exc:
            optional = target.get("optional", False)
            failures.append(tid + (" (optional)" if optional else ""))
            manifest["targets"][tid] = {"id": tid, "status": "failed", "optional": optional, "error": str(exc)[-2000:]}
            log(f"[target] {tid}: FAILED{' (optional target)' if optional else ''}\n{exc}")

    for tid, reason in catalog["cut"].items():
        manifest["targets"][tid] = {"id": tid, "status": "cut", "reason": reason}

    # Record the exact digest of every external base image used, for reproducibility.
    # BuildKit keeps base images in its build cache (not as named local images), so the digests
    # it actually resolved are read from the build logs ("FROM <ref>@sha256:...").
    resolved: dict[str, set[str]] = {}
    for logf in BUILD_LOGS.glob("*.log"):
        for ref, digest in re.findall(r"FROM (\S+?)@(sha256:[0-9a-f]{64})", logf.read_text(encoding="utf-8", errors="replace")):
            resolved.setdefault(ref.removeprefix("docker.io/library/").removesuffix(":latest") if "/library/" in ref
                                else ref.removesuffix(":latest"), set()).add(digest)
    bases = {}
    for ref in base_images(catalog):
        key = ref.removesuffix(":latest")
        if key in resolved:
            bases[ref] = sorted(resolved[key])
        else:  # pulled public images (OS baselines) are real local images
            try:
                bases[ref] = image_inspect(ref, BUILD_LOGS / "base-images.log")["repo_digests"]
            except Exception:
                bases[ref] = "UNRESOLVED"
    manifest["base_images"] = bases
    docker_ver = run(["docker", "version", "--format", "{{.Server.Version}}"], BUILD_LOGS / "env.log").stdout.strip()
    manifest["environment"] = {"docker_server": docker_ver, "platform": PLATFORM,
                               "updated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    write_json(MANIFEST, manifest)

    hard = [f for f in failures if not f.endswith("(optional)")]
    log(f"\nDone. {len(failures)} failure(s): {failures}" if failures else "\nDone. All targets built.")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
