"""Readers for exported container filesystems, docker-save archives, ELF and Go binaries.

Shared by verify_build.py and extract_gt.py so that both use the same (verified) parsing code.
"""
from __future__ import annotations

import json
import posixpath
import re
import struct
import tarfile
from pathlib import Path

# Empty placeholders that `docker export` adds to EVERY exported container filesystem.
# They are not part of the image and are ignored by every rootfs-based check and by ground truth.
EXPORT_INJECTED = {".dockerenv", "etc/hostname", "etc/hosts", "etc/resolv.conf", "dev", "dev/console",
                   "dev/pts", "dev/shm", "proc", "sys"}


class Rootfs:
    """Read-only view of a `docker export` tar, indexed once."""

    def __init__(self, path: Path):
        self.path = path
        self.tar = tarfile.open(path)
        # removeprefix, NOT lstrip("./"): lstrip would also eat the dot of hidden files (".dockerenv").
        self.members = {self.norm(m.name): m for m in self.tar.getmembers()}

    @staticmethod
    def norm(name: str) -> str:
        return name.removeprefix("./").lstrip("/")

    def exists(self, p: str) -> bool:
        return p.lstrip("/") in self.members

    def glob(self, pattern: str) -> list[str]:
        rx = re.compile(pattern)
        return sorted(n for n in self.members if rx.search(n))

    def files(self):
        """Regular files (and hardlinks) that are really part of the image."""
        for name, m in self.members.items():
            if (m.isfile() or m.islnk()) and name not in EXPORT_INJECTED:
                yield name, m

    def resolve(self, p: str) -> tarfile.TarInfo:
        m = self.members[p.lstrip("/")]
        for _ in range(20):  # follow links inside the archive (bounded, in case of loops)
            if not (m.issym() or m.islnk()):
                break
            if m.islnk():
                target = self.norm(m.linkname)
            else:
                base = posixpath.dirname("/" + self.norm(m.name))
                target = posixpath.normpath(posixpath.join(base, m.linkname)).lstrip("/")
            m = self.members[target]
        return m

    def read(self, p: str) -> bytes:
        return self.tar.extractfile(self.resolve(p)).read()

    def head(self, p: str, n: int = 64) -> bytes:
        fh = self.tar.extractfile(self.resolve(p))
        return fh.read(n) if fh else b""

    def text(self, p: str) -> str:
        return self.read(p).decode("utf-8", errors="replace")


def image_config(image_tar: Path) -> dict:
    """The image config (Env, Entrypoint, architecture...) from a `docker save` archive."""
    with tarfile.open(image_tar) as tf:
        manifest = json.load(tf.extractfile("manifest.json"))
        return json.load(tf.extractfile(manifest[0]["Config"]))


def image_env(image_tar: Path) -> dict[str, str]:
    env = image_config(image_tar).get("config", {}).get("Env") or []
    return dict(e.split("=", 1) for e in env if "=" in e)


def elf_info(data: bytes) -> dict:
    """Minimal ELF64 parser: machine, whether dynamically linked, interpreter path, DT_NEEDED entries."""
    if data[:4] != b"\x7fELF":
        return {"elf": False, "macho": data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")}
    if data[4] != 2:
        return {"elf": True, "class": "ELF32"}
    e_machine = struct.unpack_from("<H", data, 18)[0]
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    interp, dyn = None, None
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        if p_type == 3:  # PT_INTERP
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\x00").decode()
        elif p_type == 2:  # PT_DYNAMIC
            dyn = (p_offset, p_filesz)
        elif p_type == 1:  # PT_LOAD (to map DT_STRTAB's virtual address to a file offset)
            loads.append((p_vaddr, p_offset, p_filesz))
    needed = []
    if dyn:
        entries, strtab = [], None
        for j in range(dyn[1] // 16):
            tag, val = struct.unpack_from("<qQ", data, dyn[0] + j * 16)
            if tag == 0:
                break
            if tag == 5:
                strtab = val
            entries.append((tag, val))
        if strtab is not None:
            base = next((o + (strtab - v) for v, o, sz in loads if v <= strtab < v + sz), None)
            if base is not None:
                for tag, val in entries:
                    if tag == 1:  # DT_NEEDED
                        end = data.index(b"\x00", base + val)
                        needed.append(data[base + val:end].decode())
    return {"elf": True, "x86_64": e_machine == 62, "dynamic": dyn is not None, "interp": interp, "needed": needed}


GO_MAGIC = b"\xff Go buildinf:"


def go_buildinfo(data: bytes) -> dict | None:
    """Parse the Go build-info blob (Go >= 1.18 inline format). Returns go version and module list."""
    i = data.find(GO_MAGIC)
    while i != -1 and i % 16:
        i = data.find(GO_MAGIC, i + 1)
    if i == -1:
        return None
    flags = data[i + 15]
    if not flags & 0x2:
        return {"unsupported_format": True}
    pos = i + 32

    def read_str(p: int) -> tuple[str, int]:
        n = shift = 0
        while True:
            b = data[p]
            p += 1
            n |= (b & 0x7F) << shift
            if b < 0x80:
                break
            shift += 7
        return data[p:p + n].decode("utf-8", errors="replace"), p + n

    version, pos = read_str(pos)
    mod, _ = read_str(pos)
    if len(mod) >= 33 and mod[-17] == "\n":
        mod = mod[16:-16]
    main, deps = None, []
    for line in mod.splitlines():
        parts = line.split("\t")
        if parts[0] == "mod" and len(parts) >= 3:
            main = {"path": parts[1], "version": parts[2]}
        elif parts[0] == "dep" and len(parts) >= 3:
            deps.append({"path": parts[1], "version": parts[2]})
        elif parts[0] == "=>" and deps and len(parts) >= 3:  # replacement applies to the previous dep
            deps[-1].update(replaced_by=parts[1], version=parts[2])
    return {"go_version": version, "main": main, "deps": deps}


def docker_archive_ok(path: Path) -> tuple[bool, str]:
    cfg = image_config(path)
    return cfg.get("architecture") == "amd64" and cfg.get("os") == "linux", f"{cfg.get('os')}/{cfg.get('architecture')}"
