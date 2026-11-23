"""Run Syft, Trivy and cdxgen on every target and keep every SBOM plus full run metadata.

Each job = (config, tool, repetition, target). Outputs:
  work/sboms/<config>/<tool>/rep<N>/<target>.json        CycloneDX 1.7 (every tool's default spec)
  work/sboms/<config>/<tool>/rep1/<target>.spdx.json     SPDX (rep 1 only; Syft/Trivy: 2.3, cdxgen: 3.0.1 JSON-LD)
  work/logs/tools/<config>-<tool>-rep<N>-<target>.log    full stdout/stderr
  results/tool_runs.json                                 one record per job (exit code, time, outputs, counts)
Repetition 2 (CycloneDX only) exists to measure determinism.

Fairness rules:
  * Every tool gets an identical input: the same image tar, or a fresh private copy of the same directory
    (cdxgen may install dependencies into the directory it scans, so nothing is shared between runs).
  * "default" config = the tool's minimal documented command for that input kind, no tuning flags.
  * Trivy uses a pre-downloaded Java DB, frozen with --skip-java-db-update, so all runs see the same DB.
  * One worker per tool (tools run in parallel with each other, never with themselves), so a tool's own
    caches are never shared by two concurrent runs. Wall times are therefore indicative only.

Usage: python scripts/run_tools.py [--only ID ...] [--tools syft trivy cdxgen] [--reps 1 2]
                                   [--config default|best] [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from common import (IMAGES_DIR, LOGS_DIR, RESULTS_DIR, ROOT, WORK, load_catalog, log, plain, rel, scan_path,
                    sha256_file, write_json)

SBOM_DIR = WORK / "sboms"
SCAN_DIR = WORK / "scan"            # private per-run copies of dir/file targets
TRIVY_CACHE = WORK / "cache" / "trivy"
M2_CACHE = WORK / "cache" / "m2"
TOOL_LOGS = LOGS_DIR / "tools"
RUNS_FILE = RESULTS_DIR / "tool_runs.json"
TIMEOUT_S = 45 * 60
TOOLS = ("syft", "trivy", "cdxgen")


def tool_images() -> dict[str, str]:
    images = {}
    for line in (ROOT / "tools" / "versions.lock").read_text(encoding="utf-8").splitlines():
        if "_IMAGE=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            images[key.removesuffix("_IMAGE").lower()] = value.split()[0]
    return images


# ----------------------------------------------------------------------------- command construction
def tool_args(tool: str, target: dict, config: str, formats: list[str], stem: str) -> list[str]:
    """Arguments after the image name. Paths are container paths: /img (image tars), /t (input copy), /out."""
    kind = target["kind"]
    if kind == "image":
        src = f"/img/{target['id']}.tar"
    elif kind == "file":
        src = f"/t/{Path(target['file']).name}"
    else:
        src = "/t"

    if tool == "syft":
        source = {"image": f"docker-archive:{src}", "file": f"file:{src}", "dir": f"dir:{src}"}[kind]
        args = [source]
        for fmt in formats:
            args += ["-o", f"{'cyclonedx-json' if fmt == 'cyclonedx' else 'spdx-json'}=/out/{stem}{'.spdx' if fmt == 'spdx' else ''}.json"]
        if config == "best":
            args += ["--override-default-catalogers", "all"]
        return args

    if tool == "trivy":
        assert len(formats) == 1, "trivy writes one format per run"
        fmt = formats[0]
        sub = {"image": ["image", "--input", src], "file": ["rootfs", src], "dir": ["fs", src]}[kind]
        args = sub[:1] + ["--cache-dir", "/cache", "--skip-java-db-update", "--skip-db-update",
                          "--format", "cyclonedx" if fmt == "cyclonedx" else "spdx-json",
                          "--output", f"/out/{stem}{'.spdx' if fmt == 'spdx' else ''}.json"]
        if config == "best":
            args += ["--detection-priority", "comprehensive"]
            if kind == "dir":                 # only the `fs` subcommand has this flag (npm, yarn, gradle)
                args += ["--include-dev-deps"]
        return args + sub[1:]

    if tool == "cdxgen":
        args = ["-o", f"/out/{stem}.json", "--no-progress"]
        if kind == "image":
            args += ["-t", "docker"]
        if formats == ["cyclonedx", "spdx"]:
            args += ["--format", "cyclonedx,spdx"]   # cdxgen writes <stem>.spdx.json next to <stem>.json
        if config == "best":
            args += ["--deep"]
        return args + [src if kind == "image" else "/t"]

    raise ValueError(tool)


def expected_outputs(out_dir: Path, stem: str, formats: list[str]) -> list[Path]:
    return [out_dir / f"{stem}{'.spdx' if f == 'spdx' else ''}.json" for f in formats]


def count_components(path: Path) -> int | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if "components" in data or data.get("bomFormat") == "CycloneDX":
        return len(data.get("components", []))
    if "packages" in data:
        return len(data["packages"])
    if "@graph" in data:
        return sum(1 for e in data["@graph"] if str(e.get("type", "")).endswith("Package"))
    return None


# ----------------------------------------------------------------------------- one job
def run_job(job: dict, images: dict[str, str]) -> dict:
    tool, target, rep, config, formats = job["tool"], job["target"], job["rep"], job["config"], job["formats"]
    tid = target["id"]
    out_dir = SBOM_DIR / config / tool / f"rep{rep}"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = tid
    log_file = TOOL_LOGS / f"{config}-{tool}-rep{rep}-{tid}-{'+'.join(formats)}.log"
    record = {"config": config, "tool": tool, "rep": rep, "target": tid, "formats": formats,
              "tool_image": images[tool], "kind": target["kind"]}

    # Private input copy for dir/file targets (fresh every run).
    work_copy = None
    mounts = ["-v", f"{plain(out_dir)}:/out"]
    if target["kind"] == "image":
        mounts += ["-v", f"{plain(IMAGES_DIR)}:/img:ro"]
    else:
        work_copy = SCAN_DIR / f"{config}-{tool}-rep{rep}-{tid}"
        if work_copy.exists():
            shutil.rmtree(work_copy)
        src = scan_path(target)
        if src.is_dir():
            shutil.copytree(src, work_copy, symlinks=True)
        else:
            work_copy.mkdir(parents=True)
            shutil.copy2(src, work_copy / src.name)
        mounts += ["-v", f"{plain(work_copy)}:/t"]
    if tool == "trivy":
        mounts += ["-v", f"{plain(TRIVY_CACHE)}:/cache"]
        # Local Maven repository, pre-populated once by `mvn dependency:resolve` (work/cache/m2). Trivy resolves
        # pom.xml parents/BOMs from it instead of Maven Central, exactly as its own 429 error message recommends.
        # Only pom.xml scanning (J-S1) reads it; every other target is unaffected.
        if M2_CACHE.exists():
            mounts += ["-v", f"{plain(M2_CACHE)}:/root/.m2:ro"]

    name = f"p16-{tool}-{config}-r{rep}-{tid.lower()}"
    env = ["-e", "SYFT_CHECK_FOR_APP_UPDATE=false", "-e", "CDXGEN_NO_PROGRESS=1"]
    if tool == "syft" and config == "best":
        # Syft's documented opt-in options (all default off, see `syft config`). Maven resolution reads the same
        # pre-populated local repository Trivy uses, not the network (Maven Central rate-limits Go clients).
        env += ["-e", "SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=true",
                "-e", "SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY=true",
                "-e", "SYFT_JAVA_MAVEN_LOCAL_REPOSITORY_DIR=/m2/repository",
                "-e", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true",
                "-e", "SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS=true"]
        if M2_CACHE.exists():
            mounts += ["-v", f"{plain(M2_CACHE)}:/m2:ro"]
    cmd = ["docker", "run", "--rm", "--name", name, *env, *mounts, images[tool],
           *tool_args(tool, target, config, formats, stem)]
    record["command"] = " ".join(cmd[cmd.index(images[tool]):])  # host paths left out of the record
    record["env"] = [e for e in env if e != "-e"]                # tool options passed as environment variables

    for p in expected_outputs(out_dir, stem, formats):
        p.unlink(missing_ok=True)
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_S)
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        exit_code, stdout, stderr = "timeout", exc.stdout or "", exc.stderr or ""
        stdout = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout
        stderr = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr
    record["seconds"] = round(time.time() - started, 1)
    record["exit_code"] = exit_code
    TOOL_LOGS.mkdir(parents=True, exist_ok=True)
    log_file.write_text(f"$ {' '.join(cmd)}\n# exit={exit_code} secs={record['seconds']}\n{stdout}\n{stderr}",
                        encoding="utf-8")
    record["log"] = rel(log_file)

    outputs = {}
    for fmt, p in zip(formats, expected_outputs(out_dir, stem, formats)):
        if p.exists() and p.stat().st_size > 0:
            outputs[fmt] = {"path": rel(p), "bytes": p.stat().st_size, "sha256": sha256_file(p),
                            "components": count_components(p)}
        else:
            outputs[fmt] = None
    record["outputs"] = outputs
    record["status"] = "ok" if exit_code == 0 and all(outputs.values()) else "failed"
    if work_copy is not None:
        shutil.rmtree(work_copy, ignore_errors=True)
    return record


# ----------------------------------------------------------------------------- main
LOCK_FILE = RESULTS_DIR / ".tool_runs.lock"


def save_records(updates: dict, key) -> None:
    """Merge this process's new records into results/tool_runs.json under an inter-process lock.
    Several runner processes may run at once (e.g. paced cdxgen jobs next to a Syft re-run); re-reading the file
    under the lock means no process ever overwrites records written by another."""
    deadline = time.time() + 300
    while True:
        try:
            fd = os.open(plain(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if time.time() > deadline:
                raise RuntimeError(f"could not acquire {LOCK_FILE} (stale lock? delete it if no runner is active)")
            time.sleep(0.2)
    try:
        current = json.loads(RUNS_FILE.read_text(encoding="utf-8")) if RUNS_FILE.exists() else {"runs": []}
        merged = {key(r): r for r in current["runs"]}
        merged.update(updates)
        write_json(RUNS_FILE, {"runs": sorted(merged.values(), key=lambda r: (r["config"], r["tool"], r["rep"], r["target"])),
                               "updated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    finally:
        os.close(fd)
        os.unlink(plain(LOCK_FILE))


def build_jobs(targets: list[dict], tools: list[str], reps: list[int], config: str) -> dict[str, list[dict]]:
    jobs: dict[str, list[dict]] = {t: [] for t in tools}
    for rep in sorted(reps):
        for target in targets:
            for tool in tools:
                if rep == 1 and tool == "trivy":    # trivy: one format per run
                    fmt_sets = [["cyclonedx"], ["spdx"]]
                elif rep == 1:                      # syft / cdxgen: both formats from one run
                    fmt_sets = [["cyclonedx", "spdx"]]
                else:                               # determinism repeat: CycloneDX only
                    fmt_sets = [["cyclonedx"]]
                for formats in fmt_sets:
                    jobs[tool].append({"tool": tool, "target": target, "rep": rep, "config": config,
                                       "formats": formats})
    return jobs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="+", metavar="ID")
    ap.add_argument("--tools", nargs="+", choices=TOOLS, default=list(TOOLS))
    ap.add_argument("--reps", nargs="+", type=int, default=[1, 2])
    ap.add_argument("--config", choices=["default", "best"], default="default")
    ap.add_argument("--force", action="store_true", help="re-run jobs whose outputs already exist")
    args = ap.parse_args()

    targets = load_catalog()["targets"]
    if args.only:
        targets = [t for t in targets if t["id"] in args.only]
    images = tool_images()
    if not TRIVY_CACHE.exists() and "trivy" in args.tools:
        raise SystemExit("Trivy Java DB cache missing: run `trivy image --download-java-db-only` into work/cache/trivy first")

    previous = json.loads(RUNS_FILE.read_text(encoding="utf-8")) if RUNS_FILE.exists() else {"runs": []}
    key = lambda r: (r["config"], r["tool"], r["rep"], r["target"], tuple(r["formats"]))
    runs = {key(r): r for r in previous["runs"]}
    lock = threading.Lock()
    jobs = build_jobs(targets, args.tools, args.reps, args.config)
    total = sum(len(v) for v in jobs.values())
    done = [0]

    def worker(tool: str):
        for job in jobs[tool]:
            k = (job["config"], tool, job["rep"], job["target"]["id"], tuple(job["formats"]))
            with lock:
                prev = runs.get(k)
            if prev and prev["status"] == "ok" and not args.force and all(
                    (ROOT / o["path"]).exists() for o in prev["outputs"].values() if o):
                with lock:
                    done[0] += 1
                continue
            try:
                record = run_job(job, images)
            except Exception as exc:  # infrastructure error: record it, keep going
                record = {"config": job["config"], "tool": tool, "rep": job["rep"], "target": job["target"]["id"],
                          "formats": job["formats"], "status": "error", "error": repr(exc)}
            # cdxgen aborts the whole run (writing nothing) when its SPDX export fails validation, e.g. for an
            # empty BOM. Keep that failed record (a finding) and retry CycloneDX alone so RQ1-RQ3 have data.
            if tool == "cdxgen" and job["formats"] == ["cyclonedx", "spdx"] and record["status"] != "ok":
                retry = dict(job, formats=["cyclonedx"])
                try:
                    retry_record = run_job(retry, images)
                except Exception as exc:
                    retry_record = {"config": job["config"], "tool": tool, "rep": job["rep"],
                                    "target": job["target"]["id"], "formats": ["cyclonedx"], "status": "error",
                                    "error": repr(exc)}
                retry_record["fallback_after"] = "cyclonedx+spdx run failed"
                with lock:
                    runs[(job["config"], tool, job["rep"], job["target"]["id"], ("cyclonedx",))] = retry_record
            with lock:
                runs[k] = record
                done[0] += 1
                log(f"[{done[0]:3}/{total}] {tool:6} rep{job['rep']} {job['target']['id']:16} {'+'.join(job['formats']):15} "
                    f"{record['status']:6} exit={record.get('exit_code')} {record.get('seconds', 0):7.1f}s "
                    f"comps={ {f: (o or {}).get('components') for f, o in (record.get('outputs') or {}).items()} }")
                mine = {k: record}
                if tool == "cdxgen" and job["formats"] == ["cyclonedx", "spdx"] and record["status"] != "ok":
                    ck = (job["config"], tool, job["rep"], job["target"]["id"], ("cyclonedx",))
                    mine[ck] = runs[ck]
                save_records(mine, key)

    with ThreadPoolExecutor(max_workers=len(args.tools)) as pool:
        list(pool.map(worker, args.tools))

    failed = [r for r in runs.values() if r["status"] != "ok"]
    log(f"\nDone: {len(runs) - len(failed)} ok, {len(failed)} not ok")
    for r in failed:
        log(f"  {r['status']}: {r['tool']} rep{r['rep']} {r['target']} {r['formats']} exit={r.get('exit_code')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
