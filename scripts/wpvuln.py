"""WPVulnerability client (https://www.wpvulnerability.net) with an incremental cache.

The API is queried one unit at a time (there is no bulk export):
  - plugin/<slug> and theme/<slug>: slugs already known from other sources;
  - core/<version>: every published WordPress version.
The least recently checked keys are refreshed first.

Cache: the core vulnerabilities returned for each version are aggregated under
the single key "core/wordpress" (deduplicated by id). Cache records are slim:
    {"name": "Plugin P", "vulns": [{"id", "title", "cves", "date", "range",
                                    "unfixed", "closed"}]}
(empty fields are omitted).
"""
import datetime as dt
import gzip
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from ranges import mk_range

BASE = "https://www.wpvulnerability.net"
CORE_VERSIONS_URL = "https://api.wordpress.org/core/stable-check/1.0/"
# TODO: replace OWNER/REPO with your repository URL (politely identifies this client)
UA = "wp-cve-mapping (+https://github.com/OWNER/REPO)"
INCLUSIVE = {"ge", "gte", "le", "lte", "eq", ">=", "<=", "="}
VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")   # excludes beta/RC (invalid format on the API side)


def load(path):
    """Load a JSON file; falls back to <path>.gz; returns {} if neither exists."""
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        with gzip.open(path + ".gz", "rt", encoding="utf-8") as f:
            return json.load(f)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def core_versions():
    """List of published WordPress versions (api.wordpress.org). [] on failure."""
    try:
        req = urllib.request.Request(CORE_VERSIONS_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        return sorted(v for v in data if VERSION_RE.match(v))
    except Exception as e:  # noqa: BLE001
        print(f"Warning: WordPress core version list unavailable ({e}); skipping core")
        return []


def fetch(ptype, slug, retries=3):
    url = f"{BASE}/{ptype}/{urllib.parse.quote(slug, safe='')}/"
    for i in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}
            if e.code in (429, 500, 502, 503, 504):
                time.sleep((2 ** (i + 1)) * (5 if e.code == 429 else 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(2 ** (i + 1))
    raise RuntimeError(f"request failed: {url}")


def _inc(op):
    return True if op is None else op in INCLUSIVE


def _flag(x):
    return str(x) in ("1", "True", "true")


def normalize(payload):
    """API payload -> (name, [slim vulnerability records])."""
    data = (payload or {}).get("data") or {}
    vulns = []
    for v in data.get("vulnerability") or []:
        op = v.get("operator") or {}
        srcs = v.get("source") or []
        rec = {
            "id": v.get("uuid"),
            "title": v.get("name"),
            "cves": sorted({s["id"] for s in srcs
                            if str(s.get("id", "")).startswith("CVE-")}),
            "date": min((s["date"][:10] for s in srcs if s.get("date")), default=None),
            "range": (mk_range(op.get("min_version"), _inc(op.get("min_operator")),
                               op.get("max_version"), _inc(op.get("max_operator")))
                      if op else None),
            "unfixed": _flag(op.get("unfixed")),
            "closed": _flag(op.get("closed")),
        }
        vulns.append({k: x for k, x in rec.items() if x not in (None, "", [], False)})
    return data.get("name"), vulns


def _vuln_id(v):
    return v.get("id") or v.get("title") or json.dumps(v, sort_keys=True)


def refresh(keys, cache, checked, max_per_run=2500, time_budget=1200,
            workers=3, delay=0.4):
    """Update `cache` (content) and `checked` (dates) for the oldest-checked keys."""
    today = dt.date.today().isoformat()
    todo = sorted(keys, key=lambda k: (checked.get(k, ""), k))[:max_per_run]
    deadline = time.monotonic() + time_budget
    abort = {"v": False}

    def work(k):
        if abort["v"] or time.monotonic() > deadline:
            return k, None
        time.sleep(delay)
        ptype, slug = k.split("/", 1)
        try:
            return k, fetch(ptype, slug)
        except Exception as e:  # noqa: BLE001
            return k, e

    ok = errors = 0
    with ThreadPoolExecutor(workers) as ex:
        for k, res in ex.map(work, todo):
            if res is None:
                continue
            if isinstance(res, Exception):
                errors += 1
                if errors >= 50:
                    abort["v"] = True
                continue
            name, vulns = normalize(res)
            if k.startswith("core/"):
                entry = cache.setdefault("core/wordpress", {"name": "WordPress", "vulns": []})
                by_id = {_vuln_id(v): v for v in entry["vulns"]}
                by_id.update({_vuln_id(v): v for v in vulns})
                entry["vulns"] = [by_id[i] for i in sorted(by_id)]
            else:
                cache[k] = {"name": name, "vulns": vulns}
            checked[k] = today
            ok += 1
    never = len([k for k in keys if k not in checked])
    print(f"WPVulnerability: {ok} keys refreshed, {errors} errors, {never} never checked")
