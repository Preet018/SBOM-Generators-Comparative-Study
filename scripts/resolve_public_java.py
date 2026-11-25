"""Ground-truth input: Maven identities of the JARs in the public images that carry NO pom.properties.

Such JARs (Gradle-, Bazel- or Ant-built libraries: Spring, Caffeine, protobuf, ...) say nothing about their own
groupId. We never take an identity from an SBOM tool. Instead:

  1. candidates (group, artifact, version, classifier) come from sources that belong to the image's own build:
       a. the build's own dependency resolution, where one exists (Jenkins: `mvn dependency:list` on the published
          org.jenkins-ci.main:jenkins-war pom -> work/buildinfo/X-jenkins/maven-list.txt);
       b. the Quarkus fast-jar file naming `<groupId>.<artifactId>-<version>[-<classifier>].jar` (Keycloak), tried at
          every dot as the group/artifact boundary;
       c. <dependency> declarations in the pom.xml files shipped inside the image's other JARs;
  2. a candidate is ACCEPTED only if the repository publishes, at exactly that coordinate, a file whose SHA-1
     equals the SHA-1 of the JAR in the image (repo1.maven.org, then repo.jenkins-ci.org for Jenkins artifacts).

Exactly one confirmed coordinate -> identity. None -> listed as unresolved (GT keeps it without groupId).
Output: results/public_java_ids.json (committed: the network lookups need not be repeated to rebuild the GT).

Usage: python scripts/resolve_public_java.py [--only X-jenkins ...]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import time
import urllib.error
import urllib.request
import zipfile

from common import BUILDINFO_DIR, RESULTS_DIR, ROOTFS_DIR, load_catalog, log, write_json
from fsutil import Rootfs

OUT = RESULTS_DIR / "public_java_ids.json"
REPOS = ["https://repo1.maven.org/maven2", "https://repo.jenkins-ci.org/public"]
ARCHIVES = (".jar", ".war", ".ear")
POM_PROPS = re.compile(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$")
_sha1_cache: dict[str, str | None] = {}


def remote_sha1(g: str, a: str, v: str, cls: str | None) -> tuple[str | None, str | None]:
    fname = f"{a}-{v}{'-' + cls if cls else ''}.jar"
    for repo in REPOS:
        url = f"{repo}/{g.replace('.', '/')}/{a}/{v}/{fname}.sha1"
        if url not in _sha1_cache:
            req = urllib.request.Request(url, headers={"User-Agent": "p16-sbom-study-gt/1.0"})
            for attempt in range(4):
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        _sha1_cache[url] = r.read().decode().split()[0].strip().lower()
                    break
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        _sha1_cache[url] = None
                        break
                    time.sleep(5 * (attempt + 1))
                except urllib.error.URLError:
                    time.sleep(5 * (attempt + 1))
            else:
                raise RuntimeError(f"repository unreachable: {url}")
            time.sleep(0.2)
        if _sha1_cache[url]:
            return _sha1_cache[url], url
    return None, None


def own_pom(z: zipfile.ZipFile, stem: str) -> bool:
    """True if a pom.properties inside the JAR names the JAR itself (or it is the only one)."""
    props = []
    for n in z.namelist():
        if POM_PROPS.match(n):
            p = {k: v.strip() for k, v in re.findall(r"^([\w.]+)=(.*)$", z.read(n).decode("utf-8", "replace"), re.M)}
            if p.get("artifactId") and p.get("version"):
                props.append(p)
    if len(props) == 1:
        return True
    if sum(stem == p["artifactId"] for p in props) == 1:   # versionless file name, e.g. Jenkins' winstone.jar
        return True
    return any(stem == f"{p['artifactId']}-{p['version']}" or stem.startswith(f"{p['artifactId']}-{p['version']}-")
               or f".{p['artifactId']}-{p['version']}" in stem for p in props)


def walk_jars(fs: Rootfs):
    """(path, bytes) of every archive in the image, plus archives nested one level inside WAR/EAR/fat JARs."""
    for path, _ in list(fs.files()):
        if not path.endswith(ARCHIVES):
            continue
        data = fs.read(path)
        yield path, data
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            continue
        for n in z.namelist():
            if n.endswith(".jar") and (path.endswith((".war", ".ear")) or n.startswith("BOOT-INF/lib/")):
                yield f"{path}!/{n}", z.read(n)


def declared_groups(jars: list[tuple[str, bytes]]) -> dict[str, set[str]]:
    """artifactId -> groupIds, from <dependency> declarations in every pom.xml shipped inside the image's JARs."""
    out: dict[str, set[str]] = {}
    for _, data in jars:
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            continue
        for n in z.namelist():
            if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.xml$", n):
                text = z.read(n).decode("utf-8", "replace")
                for dep in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
                    g = re.search(r"<groupId>\s*([^<$]+?)\s*</groupId>", dep)
                    a = re.search(r"<artifactId>\s*([^<$]+?)\s*</artifactId>", dep)
                    if g and a:
                        out.setdefault(a.group(1), set()).add(g.group(1))
    return out


def resolved_list(tid: str) -> list[tuple[str, str, str, str | None]]:
    f = BUILDINFO_DIR / tid / "maven-list.txt"
    if not f.exists():
        return []
    rows = []
    for m in re.finditer(r"^\s+([^:\s]+):([^:\s]+):jar:(?:([^:\s]+):)?([^:\s]+):(compile|runtime)", f.read_text(encoding="utf-8"), re.M):
        g, a, cls, v, _ = m.groups()
        rows.append((g, a, v, cls))
    return rows


def candidates(stem: str, resolved, declared) -> list[tuple[str, str, str, str | None, str]]:
    out = []
    for g, a, v, cls in resolved:                                   # (a) the build's own resolution
        if stem == f"{a}-{v}{'-' + cls if cls else ''}":
            out.append((g, a, v, cls, "mvn dependency:list of the image's published build pom"))
    # every "-<digit>" can start the version (artifactIds may contain "-4.3" etc.); the tail after the version
    # is either part of the version (2.28.1-alpha) or a classifier (13.4.0.jre11 has none, x-1.0-linux has one)
    splits = []
    for m in re.finditer(r"-(?=\d)", stem):
        ga, rest = stem[:m.start()], stem[m.end():]
        splits.append((ga, rest, None))
        for mm in re.finditer(r"-(?=[A-Za-z])", rest):
            splits.append((ga, rest[:mm.start()], rest[mm.end():]))
    for ga, v, cls in splits:
        parts = ga.split(".")
        for i in range(1, len(parts)):                               # (b) Quarkus <g>.<a>-<v>[-<cls>]
            out.append((".".join(parts[:i]), ".".join(parts[i:]), v, cls, "Quarkus lib file name"))
        for g in sorted(declared.get(ga, ())):                       # (c) pom.xml declarations in the image
            out.append((g, ga, v, cls, "pom.xml <dependency> inside the image"))
    seen, uniq = set(), []
    for c in out:
        if c[:4] not in seen:
            seen.add(c[:4])
            uniq.append(c)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+")
    a = ap.parse_args()
    targets = [t for t in load_catalog()["targets"] if t["id"].startswith("X-") and t["kind"] == "image"]
    if a.only:
        targets = [t for t in targets if t["id"] in a.only]
    import json
    data = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {"by_sha1": {}, "unresolved": {}}
    for t in targets:
        tid = t["id"]
        fs = Rootfs(ROOTFS_DIR / f"{tid}.tar")
        jars = list(walk_jars(fs))
        declared = declared_groups(jars)
        resolved = resolved_list(tid)
        data["unresolved"].pop(tid, None)
        n_nopom = n_ok = 0
        for path, blob in jars:
            stem = path.rsplit("/", 1)[-1].removesuffix(".jar")
            try:
                z = zipfile.ZipFile(io.BytesIO(blob))
            except zipfile.BadZipFile:
                continue
            if path.endswith((".war", ".ear")) or own_pom(z, stem):
                continue
            n_nopom += 1
            sha1 = hashlib.sha1(blob).hexdigest()
            confirmed, existing = [], []
            for g, art, v, cls, source in candidates(stem, resolved, declared):
                remote, url = remote_sha1(g, art, v, cls)
                hit = {"g": g, "a": art, "v": v, "classifier": cls, "source": source, "confirmed_by": url}
                if remote == sha1:
                    confirmed.append(hit)
                elif remote:
                    existing.append(hit)
            if not confirmed and len({(e["g"], e["a"], e["v"]) for e in existing}) == 1:
                # A modified copy (e.g. Quarkus strips resources from Keycloak's h2): bytes differ from the published
                # file, but exactly one candidate coordinate exists AND the JAR's own MANIFEST states that version.
                text = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace") if "META-INF/MANIFEST.MF" in z.namelist() else ""
                mv = {m.group(2).strip() for m in re.finditer(r"^(Implementation-Version|Bundle-Version):\s*(.+)$", text, re.M)}
                if existing[0]["v"] in mv:
                    confirmed = [{**existing[0], "modified_copy": True,
                                  "source": existing[0]["source"] + "; coordinate exists, SHA-1 differs (modified copy), MANIFEST version agrees"}]
            if len(confirmed) == 1:
                n_ok += 1
                data["by_sha1"][sha1] = {**confirmed[0], "file": stem + ".jar", "seen_in": tid}
            else:
                data["unresolved"].setdefault(tid, []).append(
                    {"path": path, "sha1": sha1, "confirmed": confirmed, "reason": "ambiguous" if confirmed else "no candidate confirmed"})
        log(f"[java-ids] {tid}: {n_nopom} JARs without own pom.properties, {n_ok} resolved, "
            f"{len(data['unresolved'].get(tid, []))} unresolved")
        write_json(OUT, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
