"""License strings -> SPDX license identifiers, for comparing tool-reported licenses with the ground truth.

Sources of truth, in order:
  1. the SPDX License List (tools/spdx/licenses.json, exceptions.json; v3.29.0): identifiers (current and deprecated),
     full names, and the reference URLs ("seeAlso") of every license;
  2. ALIASES below: the common free-text spellings that the ecosystems actually use (Maven <licenses><name>,
     PyPI License/classifiers), each mapped only where the text names ONE license and version unambiguously;
  3. SPDX expression syntax (AND / OR / WITH, parentheses).
Ambiguous texts are NOT guessed: "BSD License", "Apache Software License" (a PyPI classifier without version),
"Artistic License", an unversioned CDDL/LGPL, "Dual License", copyright notices, project-specific URLs and the
"sha256:<hash>" Syft writes for license text it could not identify all map to None (unmappable) and are reported
separately, never counted as right or wrong.

Comparison level: license + version, ignoring the -only / -or-later suffix (GPL-2.0-only == GPL-2.0-or-later ==
GPL-2.0), because POM and PyPI texts almost never state it. Exceptions stay attached ("GPL-2.0 WITH
Classpath-exception-2.0"). A component's licenses compare as a SET of such atoms (AND/OR structure ignored).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from common import ROOT

SPDX_DIR = ROOT / "tools" / "spdx"

# free text -> SPDX (keys are canon() forms). Each entry: an unambiguous name of exactly one license/version.
ALIASES = {
    "the apache software license, version 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "the apache license, version 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache license 2": "Apache-2.0",
    "epl 2.0": "EPL-2.0",
    "eclipse public license v. 2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "eclipse public license v2.0": "EPL-2.0",
    "epl 1.0": "EPL-1.0",
    # The Eclipse Distribution License 1.0 is the BSD 3-Clause license (Eclipse Foundation; SPDX lists no EDL id)
    "edl 1.0": "BSD-3-Clause",
    "eclipse distribution license - v 1.0": "BSD-3-Clause",
    "eclipse distribution license v. 1.0": "BSD-3-Clause",
    "public domain, per creative commons cc0": "CC0-1.0",
    "public domain": "LicenseRef-Public-Domain",
    "public-domain": "LicenseRef-Public-Domain",
    "the mit license": "MIT",
    "mit license": "MIT",
    "3-clause bsd license": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    "2-clause bsd license": "BSD-2-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    "openfont-1.1": "OFL-1.1",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "python-software-foundation-license": "PSF-2.0",
    "isc license (iscl)": "ISC",
    "gnu lesser general public license version 2.1": "LGPL-2.1",
    "gnu general public license, version 2, with the classpath exception": "GPL-2.0 WITH Classpath-exception-2.0",
    "the gnu general public license, v2 with universal foss exception, v1.0": "GPL-2.0 WITH Universal-FOSS-exception-1.0",
    "the universal permissive license (upl), version 1.0": "UPL-1.0",
    "indiana university extreme! lab software license": "xpp",
    "indiana-university-extreme--lab-software-license": "xpp",
    "mit -or- apache license 2.0": "MIT OR Apache-2.0",
    # Jakarta EE POMs: "GPL2 w/ CPE" = GPL 2.0 with the Classpath Exception
    "gpl2 w/ cpe": "GPL-2.0 WITH Classpath-exception-2.0",
    "gnu general public license, version 2 with the gnu classpath exception": "GPL-2.0 WITH Classpath-exception-2.0",
    "common development and distribution license (cddl) version 1.0": "CDDL-1.0",
    # deprecated SPDX ids that embed an exception (SPDX: use "<license> WITH <exception>" instead)
    "gpl-2.0-with-classpath-exception": "GPL-2.0 WITH Classpath-exception-2.0",
    # exception spellings seen in tool output
    "classpath-exception": "Classpath-exception-2.0",
    "universal-foss-exception--v1.0": "Universal-FOSS-exception-1.0",
}
# license URLs that name one license but are not in SPDX's seeAlso lists
URL_ALIASES = {
    "repository.jboss.org/licenses/apache-2.0.txt": "Apache-2.0",
    "opensource.org/licenses/apache2.0.php": "Apache-2.0",
    "apache.org/licenses/license-2.0.txt": "Apache-2.0",
    "opensource.org/licenses/mit-license.php": "MIT",
    "creativecommons.org/publicdomain/zero/1.0": "CC0-1.0",
    "eclipse.org/legal/epl-2.0": "EPL-2.0",
}


def canon(s: str) -> str:
    s = s.strip().strip('"').strip("'").strip()
    return re.sub(r"\s+", " ", s).lower().rstrip(".")


def canon_url(u: str) -> str:
    u = re.sub(r"^https?://(www\.)?", "", u.strip().lower()).rstrip("/")
    return re.sub(r"\.(html?|php|txt)$", lambda m: m.group(0), u)


@lru_cache(maxsize=1)
def spdx() -> tuple[dict, dict, dict]:
    lic = json.loads((SPDX_DIR / "licenses.json").read_text(encoding="utf-8"))["licenses"]
    exc = json.loads((SPDX_DIR / "exceptions.json").read_text(encoding="utf-8"))["exceptions"]
    ids = {l["licenseId"].lower(): l["licenseId"] for l in lic}
    ids.update({e["licenseExceptionId"].lower(): e["licenseExceptionId"] for e in exc})
    names = {canon(l["name"]): l["licenseId"] for l in lic}
    urls = {}
    for l in lic:
        for u in l.get("seeAlso") or []:
            urls.setdefault(canon_url(u), l["licenseId"])
    return ids, names, urls


def base(lid: str) -> str:
    """Version-level identity: GPL-2.0-only / GPL-2.0-or-later / GPL-2.0+ -> GPL-2.0."""
    return re.sub(r"(-only|-or-later|\+)$", "", lid)


def atom(text: str) -> str | None:
    """One license (optionally WITH an exception) -> SPDX id at version level, or None."""
    ids, names, urls = spdx()
    t = canon(text)
    t = re.sub(r"\s*\((https?://[^)]*)\)$", "", t)          # "MIT (http://.../license.txt)" -> "MIT"
    if t in ALIASES:                                         # before splitting: some names contain " with "
        return ALIASES[t] if " " in ALIASES[t] else base(ALIASES[t])
    if " with " in t:
        lic, _, exc = t.partition(" with ")
        a, e = atom(lic), atom(exc)
        return f"{a} WITH {e}" if a and e else None
    if t in ids:
        return base(ids[t])
    if t in names:
        return base(names[t])
    if re.match(r"^https?://", t):
        u = canon_url(t)
        hit = URL_ALIASES.get(u) or urls.get(u)
        return base(hit) if hit else None
    return None


def split_top(t: str, sep: str) -> list[str]:
    """Split on ' sep ' (case-insensitive) outside parentheses."""
    parts, depth, cur, i, n = [], 0, "", 0, len(sep) + 2
    while i < len(t):
        ch = t[i]
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and t[i:i + n].lower() == f" {sep} ":
            parts.append(cur)
            cur, i = "", i + n
            continue
        cur += ch
        i += 1
    return parts + [cur]


def parse(t: str) -> set | None:
    """Whole text as ONE license name first (names may contain 'and', e.g. CDDL); otherwise split on top-level
    OR, then AND, and require every part to map. Outer parentheses of an expression are dropped."""
    t = t.strip()
    while t.startswith("(") and t.endswith(")") and split_top(t[1:-1], "or") and t.count("(") == t.count(")"):
        inner = t[1:-1]
        if inner.count("(") != inner.count(")"):
            break
        t = inner.strip()
    a = atom(t)
    if a is not None:
        return set(a.split(" OR "))
    for sep in ("or", "and"):
        parts = split_top(t, sep)
        if len(parts) > 1:
            got = [parse(p) for p in parts]
            if all(g is not None for g in got):
                return set().union(*got)
    return None


def to_spdx(value) -> frozenset | None:
    """A license string (or list of strings) -> set of version-level SPDX atoms; None if any part is unmappable."""
    if not value:
        return frozenset()
    out = set()
    for v in value if isinstance(value, (list, tuple)) else [value]:
        got = parse(canon(str(v)))
        if got is None:
            return None
        out |= got
    return frozenset(out)


def compare(gt_value, tool_values) -> str:
    """equal | partial | conflict | tool-none | gt-unknown | unmappable"""
    if not gt_value:
        return "gt-unknown"
    if not tool_values:
        return "tool-none"
    g, t = to_spdx(gt_value), to_spdx(list(tool_values))
    if g is None or t is None:
        return "unmappable"
    if g == t:
        return "equal"
    return "partial" if g & t else "conflict"


if __name__ == "__main__":   # coverage report over every distinct string seen (work/tmp/license_strings.json)
    d = json.loads((ROOT / "work" / "tmp" / "license_strings.json").read_text(encoding="utf-8"))
    for side in ("gt", "tool"):
        total = sum(n for _, _, n in d[side])
        unm = [(e, s, n) for e, s, n in d[side] if to_spdx(s) is None]
        print(f"{side}: {len(d[side])} distinct strings, unmappable {len(unm)} "
              f"({sum(n for *_, n in unm)} of {total} occurrences)")
        for e, s, n in unm:
            print(f"   {e:5} {n:4}  {s[:90]!r}")
