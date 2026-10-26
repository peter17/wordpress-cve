#!/usr/bin/env python3
"""CVE <-> (type, slug, versions) mapping for WordPress: plugins, themes and core.

Sources:
  1. cvelistV5 (CVE JSON 5)
       - Patchstack: packageName + collectionURL (reliable slug)
       - core: vendor/product WordPress (GitHub_M, Patchstack, MITRE...)
       - other CNAs (Wordfence, MITRE, VulDB...): the record carries no slug;
         it is inferred from the references (plugins/themes.trac.wordpress.org,
         wordpress.org/plugins/...) when unambiguous -> source "cvelistV5-inferred"
  2. Wordfence Intelligence v3 (production feed, API key required): reliable slugs
  3. WPVulnerability.net (incremental cache)

Core is represented as type "core", slug "wordpress".

Output layout (everything is sharded so that no file gets anywhere near GitHub's limits):
  data/cve/<year>.json            CVE-ID -> record            (shard = CVE year; < 2015 grouped)
  data/no-cve/<year>.json         vuln-ID -> record           (shard = published year)
  data/slugs/<type>-<char>.json   "plugin/<slug>" -> index    (shard = first character of the slug)
  data/meta.json                  copyright table (stored once), URL templates, attribution
  data/skipped.json               CVEs that could not be tied to a slug
  data/cache/...                  incremental WPVulnerability cache (internal state)
Optionally, consolidated gzipped files are written to a "dist" directory (release assets).

Usage: build.py <cvelistV5/cves> <out_dir> [wordfence.json|-] [dist_dir]
"""
import gzip
import hashlib
import json
import os
import re
import shutil
import sys

import wpvuln
from ranges import cna_range, wf_range

WP_CNAS = {"Wordfence", "Patchstack", "WPScan"}

CORE_VENDORS = {"wordpress", "wordpress.org", "wordpress foundation"}
CORE_PRODUCTS = {"wordpress", "wordpress-develop", "wordpress core", "wordpress_core"}
UNKNOWN_VENDORS = {"", "n/a", "unknown", "_ n/a _"}

_SLUG = r"([a-z0-9][a-z0-9_-]*)"
PLUGIN_REF_RES = [re.compile(p, re.I) for p in (
    r"plugins\.trac\.wordpress\.org/(?:browser|log|changeset/\d+|export/\d+)/" + _SLUG,
    r"plugins\.trac\.wordpress\.org/changeset\?[^\s]*?new=\d+%40" + _SLUG,
    r"wordpress\.org/plugins/" + _SLUG,
    r"wordpress\.org/support/plugin/" + _SLUG,
)]
THEME_REF_RES = [re.compile(p, re.I) for p in (
    r"themes\.trac\.wordpress\.org/(?:browser|log|changeset/\d+|export/\d+)/" + _SLUG,
    r"themes\.trac\.wordpress\.org/changeset\?[^\s]*?new=\d+%40" + _SLUG,
    r"wordpress\.org/themes/" + _SLUG,
    r"wordpress\.org/support/theme/" + _SLUG,
)]
RESERVED_SLUGS = {"browse", "tags", "tag", "search", "new", "popular", "featured",
                  "trunk", "assets", "branches", "favorites", "beta"}

WORDFENCE_RECORD_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/id/{id}"

# GitHub rejects files > 100 MB (and warns > 50 MB). Above this size, write .json.gz instead.
GZ_THRESHOLD = 90 * 1024 * 1024

LEGACY_FILES = [f"{n}{ext}" for n in ("cve-to-packages", "slug-to-cves", "no-cve",
                                      "wpvulnerability-cache", "wpvulnerability-checked")
                for ext in (".json", ".json.gz")]


# --------------------------------------------------------------------------- #
# In-memory model
#   entry   = {title, published, updated, sources, cvss, wordfence_id,
#              wpvulnerability_id, copyright, packages{"type/slug": pkg}}
#   pkg     = {type, slug, name, ranges{source: set(range)}, fixed[], unfixed, closed}
# --------------------------------------------------------------------------- #
def day(x):
    return x[:10] if isinstance(x, str) and len(x) >= 10 else None


def new_entry():
    return {"title": "", "published": None, "updated": None, "sources": [],
            "cvss": None, "wordfence_id": None, "wpvulnerability_id": None,
            "copyright": None, "packages": {}}


def add_package(entry, ptype, slug, name, ranges, source,
                fixed=None, unfixed=None, closed=None):
    key = f"{ptype}/{slug}"
    pkg = entry["packages"].setdefault(key, {
        "type": ptype, "slug": slug, "name": name, "ranges": {},
        "fixed": [], "unfixed": False, "closed": False})
    pkg["name"] = pkg["name"] or name
    pkg["ranges"].setdefault(source, set()).update(ranges)
    for v in fixed or []:
        if v not in pkg["fixed"]:
            pkg["fixed"].append(v)
    pkg["unfixed"] = pkg["unfixed"] or bool(unfixed)
    pkg["closed"] = pkg["closed"] or bool(closed)


def add_source(entry, source):
    if source not in entry["sources"]:
        entry["sources"].append(source)


# --------------------------------------------------------------------------- #
# Source 1: cvelistV5
# --------------------------------------------------------------------------- #
def collection_type(url):
    url = (url or "").lower().rstrip("/")
    if "wordpress.org/plugins" in url:
        return "plugin"
    if "wordpress.org/themes" in url:
        return "theme"
    return None


def is_core(a):
    prod = (a.get("product") or "").strip().lower()
    vendor = (a.get("vendor") or "").strip().lower()
    return prod in CORE_PRODUCTS and (vendor in CORE_VENDORS or vendor in UNKNOWN_VENDORS)


def infer_slugs(references):
    plugins, themes = set(), set()
    for ref in references or []:
        url = ref.get("url") or ""
        for rx_list, out in ((PLUGIN_REF_RES, plugins), (THEME_REF_RES, themes)):
            for rx in rx_list:
                m = rx.search(url)
                if m and m.group(1).lower() not in RESERVED_SLUGS:
                    out.add(m.group(1).lower())
    return plugins, themes


def process_record(data, cve_map, skipped):
    meta = data.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return
    cve_id = meta["cveId"]
    assigner = meta.get("assignerShortName")
    cna = data.get("containers", {}).get("cna", {})
    plugin_slugs, theme_slugs = infer_slugs(cna.get("references"))

    findings, leftovers = [], []
    for a in cna.get("affected", []):
        ranges = [cna_range(v) for v in a.get("versions", []) if v.get("status") == "affected"]
        ptype = collection_type(a.get("collectionURL"))
        slug = a.get("packageName")
        if ptype and slug:
            findings.append((ptype, slug, a.get("product"), ranges, "cvelistV5"))
        elif ptype:
            skipped.append({"cve": cve_id, "product": a.get("product"),
                            "reason": "packageName missing"})
        elif is_core(a):
            findings.append(("core", "wordpress", "WordPress", ranges, "cvelistV5"))
        else:
            leftovers.append((a, ranges))

    if leftovers:
        candidates = plugin_slugs | theme_slugs
        if len(leftovers) == 1 and len(candidates) == 1:
            a, ranges = leftovers[0]
            ptype = "plugin" if plugin_slugs else "theme"
            findings.append((ptype, next(iter(candidates)), a.get("product"),
                             ranges, "cvelistV5-inferred"))
        elif assigner in WP_CNAS or candidates:
            skipped.append({"cve": cve_id, "assigner": assigner,
                            "products": [a.get("product") for a, _ in leftovers],
                            "candidates": sorted(candidates),
                            "reason": "slug not determined"})

    if not findings:
        return
    entry = cve_map.setdefault(cve_id, new_entry())
    entry["title"] = cna.get("title") or entry["title"]
    entry["published"] = day(meta.get("datePublished")) or entry["published"]
    entry["updated"] = day(meta.get("dateUpdated")) or entry["updated"]
    add_source(entry, f"cvelistV5:{assigner}")
    for ptype, slug, name, ranges, source in findings:
        add_package(entry, ptype, slug, name, ranges, source)


def read_cvelist(cves_dir, cve_map, skipped):
    for root, _, files in os.walk(cves_dir):
        for fn in files:
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, fn), "rb") as f:
                    raw = f.read()
                if b"wordpress" not in raw.lower():
                    continue
                process_record(json.loads(raw), cve_map, skipped)
            except (json.JSONDecodeError, KeyError) as e:
                skipped.append({"file": fn, "reason": str(e)})


# --------------------------------------------------------------------------- #
# Source 2: Wordfence Intelligence v3
# --------------------------------------------------------------------------- #
def copyright_id(obj, table):
    """Store each distinct copyright notice once; entries only keep a short id."""
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    cid = hashlib.sha1(blob.encode("utf-8")).hexdigest()[:8]
    table[cid] = obj
    return cid


def norm_cvss(c):
    if isinstance(c, dict) and c.get("score") is not None:
        return [c["score"], c.get("vector")]
    return None


def read_wordfence(path, cve_map, no_cve, copyrights):
    with open(path, "rb") as f:
        data = json.load(f)
    records = data.values() if isinstance(data, dict) else data
    n = 0
    for rec in records:
        wf_id = rec.get("id")
        cves = rec.get("cve")
        if not cves:
            cves = [None]
        elif isinstance(cves, str):
            cves = [cves]
        sw = [s for s in rec.get("software", []) if s.get("type") in ("plugin", "theme", "core")]
        if not sw:
            continue
        n += 1
        cp = copyright_id(rec["copyrights"], copyrights) if rec.get("copyrights") else None
        for cve_id in cves:
            if cve_id:
                entry = cve_map.setdefault(cve_id, new_entry())
            else:
                entry = no_cve.setdefault(wf_id, new_entry())
            entry["title"] = entry["title"] or rec.get("title", "")
            entry["published"] = entry["published"] or day(rec.get("published"))
            entry["updated"] = day(rec.get("updated")) or entry["updated"]
            entry["cvss"] = norm_cvss(rec.get("cvss")) or entry["cvss"]
            entry["wordfence_id"] = wf_id
            entry["copyright"] = cp or entry["copyright"]
            add_source(entry, "wordfence")
            for s in sw:
                core = s["type"] == "core"
                slug = "wordpress" if core else s.get("slug")
                if not slug:
                    continue
                ranges = [wf_range(r) for r in (s.get("affected_versions") or {}).values()]
                add_package(entry, s["type"], slug, "WordPress" if core else s.get("name"),
                            ranges, "wordfence", fixed=s.get("patched_versions"),
                            unfixed=s.get("patched") is False)
    return n


# --------------------------------------------------------------------------- #
# Source 3: WPVulnerability
# --------------------------------------------------------------------------- #
def merge_wpvuln(cache, cve_map, no_cve):
    n = 0
    for key, c in cache.items():
        ptype, slug = key.split("/", 1)
        for v in c.get("vulns", []):
            ranges = [v["range"]] if v.get("range") else []
            for cve_id in (v.get("cves") or [None]):
                if cve_id:
                    entry = cve_map.setdefault(cve_id, new_entry())
                else:
                    entry = no_cve.setdefault(f"WPV-{v.get('id') or v.get('title')}", new_entry())
                entry["title"] = entry["title"] or v.get("title") or ""
                entry["published"] = entry["published"] or v.get("date")
                entry["wpvulnerability_id"] = v.get("id")
                add_source(entry, "wpvulnerability")
                add_package(entry, ptype, slug, c.get("name"), ranges, "wpvulnerability",
                            unfixed=v.get("unfixed"), closed=v.get("closed"))
                n += 1
    return n


# --------------------------------------------------------------------------- #
# Export (slim records: empty fields omitted, ranges as strings)
# --------------------------------------------------------------------------- #
def pkg_fields(p):
    """Version information of a package, without type/slug."""
    by_src = {s: sorted(r) for s, r in sorted(p["ranges"].items()) if r}
    union = sorted({r for rs in by_src.values() for r in rs})
    # "*" only means a source could not read the versions: a real range from another source wins
    if "*" in union and len(union) > 1:
        union.remove("*")
    out = {}
    if union:
        out["affected"] = union
    if p["fixed"]:
        out["fixed"] = sorted(set(p["fixed"]))
    if p["unfixed"]:
        out["unfixed"] = True
    if p["closed"]:
        out["closed"] = True
    # Per-source ranges only when sources disagree
    if len(by_src) > 1 and len({tuple(rs) for rs in by_src.values()}) > 1:
        out["by_source"] = by_src
    return out


def export_record(e):
    out = {}
    if e["title"]:
        out["title"] = e["title"]
    for k in ("published", "updated"):
        if e[k]:
            out[k] = e[k]
    out["sources"] = sorted(set(e["sources"]))
    if e["cvss"]:
        out["cvss"] = e["cvss"]
    if e["wordfence_id"]:
        out["wordfence"] = e["wordfence_id"]
    if e["wpvulnerability_id"]:
        out["wpvulnerability"] = e["wpvulnerability_id"]
    if e["copyright"]:
        out["copyright"] = e["copyright"]
    out["packages"] = [{"type": p["type"], "slug": p["slug"], **pkg_fields(p)}
                       for _, p in sorted(e["packages"].items())]
    return out


def build_slug_index(cve_map, no_cve):
    idx = {}
    for kind in (cve_map, no_cve):
        for vid in sorted(kind):
            e = kind[vid]
            for key, p in sorted(e["packages"].items()):
                rec = idx.setdefault(key, {"name": None, "vulns": []})
                rec["name"] = rec["name"] or p["name"]
                v = {"id": vid, **pkg_fields(p)}
                if not vid.startswith("CVE-") and e["published"]:
                    v["published"] = e["published"]      # locates the no-cve/<year>.json shard
                rec["vulns"].append(v)
    for rec in idx.values():
        if not rec["name"]:
            del rec["name"]
    return idx


# --------------------------------------------------------------------------- #
# Sharding and output
# --------------------------------------------------------------------------- #
def shard_cve(cid, _rec):
    m = re.match(r"CVE-(\d{4})-", cid)
    year = int(m.group(1)) if m else 0
    return str(year) if year >= 2015 else "pre-2015"


def shard_no_cve(_vid, rec):
    pub = rec.get("published") or ""
    return pub[:4] if pub[:4].isdigit() else "unknown"


def shard_slug(key, _rec):
    ptype, slug = key.split("/", 1)
    if ptype == "core":
        return "core"
    c = slug[:1].lower()
    return f"{ptype}-{c if c.isalpha() else '0-9'}"


def _j(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dump(obj, path, force_gz=False):
    """Write valid JSON with one top-level entry per line (compact yet diff-friendly).
    Writes <path>.gz instead when force_gz is set or the file exceeds GZ_THRESHOLD."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(obj, dict):
            f.write("{\n" + ",\n".join(f"{_j(k)}:{_j(obj[k])}" for k in sorted(obj)) + "\n}\n")
        else:
            f.write("[\n" + ",\n".join(_j(x) for x in obj) + "\n]\n")
    gz_path = path + ".gz"
    if force_gz or os.path.getsize(path) > GZ_THRESHOLD:
        with open(path, "rb") as src, open(gz_path, "wb") as raw, \
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            shutil.copyfileobj(src, gz)
        os.remove(path)
        if not force_gz:
            print(f"Warning: {path} is larger than {GZ_THRESHOLD // 2**20} MB; wrote .gz instead")
    elif os.path.exists(gz_path):
        os.remove(gz_path)


def _json_files(directory, prefix=""):
    if not os.path.isdir(directory):
        return []
    return sorted({fn[:-3] if fn.endswith(".gz") else fn for fn in os.listdir(directory)
                   if fn.startswith(prefix) and re.search(r"\.json(\.gz)?$", fn)})


def load_sharded(directory, prefix=""):
    out = {}
    for fn in _json_files(directory, prefix):
        out.update(wpvuln.load(os.path.join(directory, fn)))
    return out


def write_shards(directory, items, shard_fn, prefix=""):
    """Rewrite all shards of `directory` (stale shards are removed)."""
    os.makedirs(directory, exist_ok=True)
    for fn in os.listdir(directory):
        if fn.startswith(prefix) and re.search(r"\.json(\.gz)?$", fn):
            os.remove(os.path.join(directory, fn))
    groups = {}
    for k in sorted(items):
        groups.setdefault(shard_fn(k, items[k]), {})[k] = items[k]
    for shard, part in groups.items():
        dump(part, os.path.join(directory, f"{prefix}{shard}.json"))
    return len(groups)


def main(cves_dir, out_dir, wf_path=None, dist_dir=None):
    os.makedirs(out_dir, exist_ok=True)
    cve_map, no_cve, skipped, copyrights = {}, {}, [], {}
    read_cvelist(cves_dir, cve_map, skipped)
    n_wf = read_wordfence(wf_path, cve_map, no_cve, copyrights) if wf_path else 0

    # Source 3: incremental cache (already-known slugs + core versions)
    cache_dir = os.path.join(out_dir, "cache")
    cache = load_sharded(cache_dir, "wpvulnerability-")
    checked = wpvuln.load(os.path.join(cache_dir, "checked.json"))
    if os.environ.get("WPVULN_ENABLED", "1") == "1":
        keys = {f"{p['type']}/{p['slug']}"
                for e in list(cve_map.values()) + list(no_cve.values())
                for p in e["packages"].values() if p["type"] != "core"}
        keys |= {f"core/{v}" for v in wpvuln.core_versions()}
        wpvuln.refresh(keys, cache, checked,
                       max_per_run=int(os.environ.get("WPVULN_MAX_PER_RUN", 2500)),
                       time_budget=int(os.environ.get("WPVULN_TIME_BUDGET", 1200)))
        write_shards(cache_dir, cache, shard_slug, prefix="wpvulnerability-")
        dump(checked, os.path.join(cache_dir, "checked.json"))
    n_wpv = merge_wpvuln(cache, cve_map, no_cve)

    cve_out = {cid: export_record(e) for cid, e in sorted(cve_map.items())}
    no_cve_out = {vid: export_record(e) for vid, e in sorted(no_cve.items())}
    slug_idx = build_slug_index(cve_map, no_cve)
    meta = {
        "schema": 2,
        "copyrights": dict(sorted(copyrights.items())),
        "ranges": "'<= 1.2.3', '< 2.0', '>= 1.0, < 2.0', '= 1.5' or '*' (all versions)",
        "wordfence_record_url": WORDFENCE_RECORD_URL,
        "sources": {
            "cvelistV5": "https://github.com/CVEProject/cvelistV5",
            "wordfence": "https://www.wordfence.com/threat-intel/",
            "wpvulnerability": "https://www.wpvulnerability.com/",
        },
    }

    for legacy in LEGACY_FILES:
        p = os.path.join(out_dir, legacy)
        if os.path.exists(p):
            os.remove(p)
    n_cve = write_shards(os.path.join(out_dir, "cve"), cve_out, shard_cve)
    n_nocve = write_shards(os.path.join(out_dir, "no-cve"), no_cve_out, shard_no_cve)
    n_slug = write_shards(os.path.join(out_dir, "slugs"), slug_idx, shard_slug)
    dump(meta, os.path.join(out_dir, "meta.json"))
    dump(sorted(skipped, key=_j), os.path.join(out_dir, "skipped.json"))

    if dist_dir:
        os.makedirs(dist_dir, exist_ok=True)
        for name, obj in (("cve-to-packages", cve_out), ("no-cve", no_cve_out),
                          ("slug-to-cves", slug_idx), ("meta", meta)):
            dump(obj, os.path.join(dist_dir, f"{name}.json"), force_gz=True)

    n_core = len(slug_idx.get("core/wordpress", {}).get("vulns", []))
    print(f"{len(cve_out)} CVEs ({n_cve} shards), {len(no_cve_out)} vulns without CVE "
          f"({n_nocve} shards), {len(slug_idx)} slug keys ({n_slug} shards, {n_core} core entries), "
          f"{len(copyrights)} distinct copyright notices, {n_wf} Wordfence records, "
          f"{n_wpv} WPVulnerability entries, {len(skipped)} skipped")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    a = sys.argv
    main(a[1], a[2], a[3] if len(a) > 3 and a[3] != "-" else None, a[4] if len(a) > 4 else None)
