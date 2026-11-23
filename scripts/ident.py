"""Component identity normalisation, shared by the ground truth (extract_gt.py) and the SBOM parser
(normalize.py). Both sides MUST use the same function, otherwise matching would compare apples and pears."""
from __future__ import annotations

import re


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def norm_key(eco: str, namespace: str | None, name: str) -> str:
    """Identity of a component WITHOUT its version.
    - pypi: PEP 503 name; npm: scope + name; maven: groupId + artifactId; golang: full module path
    - deb/apk/rpm: package name only (the distro namespace is not part of the identity for matching)
    """
    eco = (eco or "unknown").lower()
    if eco == "pypi":
        return f"pypi::{pep503(name)}"
    if eco == "maven":
        return f"maven:{(namespace or '').lower()}:{name.lower()}"
    if eco == "npm":
        return f"npm:{(namespace or '').lower()}:{name.lower()}"
    if eco == "golang":
        full = f"{namespace}/{name}" if namespace else name
        return f"golang::{full.lower()}"
    return f"{eco}::{name.lower()}"
