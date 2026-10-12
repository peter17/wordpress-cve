# wp-cve-mapping

A mapping between **WordPress** CVEs (plugins, themes and core) and the **slugs + versions**
they affect, refreshed daily by GitHub Actions.

- Plugins and themes: keys `plugin/<slug>` and `theme/<slug>`.
- Core: type `core`, slug `wordpress` (key `core/wordpress`).

## Data layout (`data/`)

Everything is sharded and compact, so that no file gets close to GitHub's size limits (and
daily commits only touch the shards that actually changed).

| Path | Content |
|---|---|
| `cve/<year>.json` | `CVE-ID` → record. One file per CVE year (`pre-2015.json` groups older ones) |
| `no-cve/<year>.json` | Vulnerabilities without a CVE (key: Wordfence UUID, or `WPV-<uuid>`). One file per publication year (`unknown.json` if undated) |
| `slugs/<type>-<char>.json` | Reverse index `plugin/<slug>` → affected ranges per vulnerability. Sharded by first character of the slug (`plugin-a.json`, `theme-0-9.json`, `core.json`…) |
| `meta.json` | Copyright notices (each stored **once**), URL templates, source list |
| `skipped.json` | CVEs that could not be tied to a slug (see limitations) |
| `cache/` | Incremental WPVulnerability cache (internal state) |

Every file is valid JSON with one top-level entry per line (compact, diff-friendly). A file
above 90 MB would be written as `<name>.json.gz` instead.

### Single-file downloads

The workflow also uploads consolidated gzipped files to the `data-latest` release (not stored in
git history): `cve-to-packages.json.gz`, `no-cve.json.gz`, `slug-to-cves.json.gz`, `meta.json.gz`.
For example:
`https://github.com/<owner>/<repo>/releases/download/data-latest/cve-to-packages.json.gz`

### CVE / vulnerability record

Empty fields are omitted.

```json
"CVE-2023-4596": {
  "title": "Forminator <= 1.24.6 - Unauthenticated Arbitrary File Upload",
  "published": "2023-08-30", "updated": "2026-04-08",
  "sources": ["cvelistV5:Wordfence", "wordfence"],
  "cvss": [9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
  "wordfence": "<wordfence uuid>",
  "copyright": "8ed17631",
  "packages": [
    {"type": "plugin", "slug": "forminator",
     "affected": ["<= 1.24.6"], "fixed": ["1.24.7"]}
  ]
}
```

- `affected`: union of the ranges from all sources. When sources **disagree**, `by_source` gives
  the ranges per source (`cvelistV5`, `cvelistV5-inferred`, `wordfence`, `wpvulnerability`) so
  you can arbitrate; it is absent when they agree.
- `fixed`: patched versions (when known). `unfixed: true` = no fix available; `closed: true` =
  plugin closed on wordpress.org.
- `copyright`: id of a notice stored in `meta.json` → `copyrights`.
- `wordfence`: Wordfence record id; the record URL is `meta.json` → `wordfence_record_url` with
  `{id}` replaced.
- `wpvulnerability`: WPVulnerability record id.
- `cvss`: `[score, vector]`.

### Version ranges

Ranges are plain strings: `<= 1.2.3`, `< 2.0`, `>= 1.0, < 2.0`, `= 1.5`, or `*` (all versions).

### Slug index record

```json
"plugin/forminator": {
  "name": "Forminator Forms",
  "vulns": [{"id": "CVE-2023-4596", "affected": ["<= 1.24.6"], "fixed": ["1.24.7"]}]
}
```

`id` is a key of `cve/<year>.json` (when it starts with `CVE-`) or of `no-cve/<year>.json`
(then `published` tells which year file to open).

## Sources and slug reliability

1. **[CVE Program – cvelistV5](https://github.com/CVEProject/cvelistV5)**
   - *Patchstack*: `packageName` + `collectionURL` are present → reliable slug (`cvelistV5`).
   - *Core*: product `WordPress` / `wordpress-develop` (GitHub_M, Patchstack, MITRE…) → `core/wordpress`.
     Version expressions (`>= 6.4.0, < 6.4.3`) are parsed.
   - *Other CNAs (Wordfence, MITRE, VulDB, WPScan…)*: **the record carries no slug**. It is inferred
     from the references (`plugins.trac.wordpress.org/…`, `wordpress.org/plugins/<slug>`,
     same for themes) only when unambiguous → source `cvelistV5-inferred` (lower confidence).
2. **[Wordfence Intelligence](https://www.wordfence.com/threat-intel/)** (API v3, key required):
   reliable slugs, affected ranges, patched versions, CVSS, vulnerabilities without a CVE, core.
3. **[WPVulnerability](https://www.wpvulnerability.com/)**: queried incrementally
   (2500 keys per day by default, least recently checked first): one call per already-known slug
   plus one call per published WordPress version (list from api.wordpress.org).
   It only enriches slugs already known from the other sources; it does not discover new ones.

### Known limitations

- **Without a Wordfence key, plugin/theme coverage drops sharply**: cvelistV5 only provides
  reliable slugs for Patchstack; the rest depends on inference.
- CVEs whose slug cannot be determined (e.g. CVEs assigned by WPScan without a trac/wordpress.org
  link, or themes distributed outside wordpress.org) are listed in `skipped.json` with
  `reason: "slug not determined"` and, when possible, some `candidates`.
- Core vulnerabilities seen only by WPVulnerability, with no CVE and no version range, appear in
  `no-cve/` with no `affected`.
- The first runs only refresh part of the WPVulnerability cache (2500 keys/day), so that source
  fills in progressively.

## Setup

1. Create the repository and copy these files.
2. In `scripts/wpvuln.py`, replace `OWNER/REPO` in `UA` with your repository URL.
3. Create an API key in your Wordfence account (*Integrations* section) and add it as the
   Actions **repository** secret `WORDFENCE_API_KEY` (Settings → Secrets and variables → Actions).
4. Run the workflow once manually (*Actions → Update WordPress CVE mapping → Run workflow*)
   and check `data/` and `skipped.json`.

Optional variables (Settings → Variables → Actions): `WPVULN_MAX_PER_RUN` (default 2500).
To disable source 3, set the environment variable `WPVULN_ENABLED=0`.

## Troubleshooting

The commit step prints the total size of `data/`, its 10 largest files and the full `git push`
output. Typical failures:

- `File ... exceeds GitHub's file size limit of 100 MB` → should not happen with the sharded
  layout; the workflow fails before pushing if a file is above 95 MB.
- `Permission denied` / `403` → Settings → Actions → General → Workflow permissions must allow
  writes (the workflow already requests `contents: write`); check also branch protection rules or
  rulesets on the default branch, which can block pushes from `github-actions[bot]`.
- `Push cannot contain secrets` (GH013) → secret-scanning push protection matched something in the
  data; the message names the offending line.
- `Missing WORDFENCE_API_KEY secret` → the secret must be a *repository* secret (or the job must
  declare `environment:`).
- The release step is optional (`continue-on-error`); if it fails, check that the workflow has
  `contents: write` permission.

## Running locally

```bash
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git /tmp/cvelistV5
curl -fsS --compressed -H "Authorization: Bearer $WORDFENCE_API_KEY" \
  -o /tmp/wordfence.json https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production
python scripts/build.py /tmp/cvelistV5/cves data /tmp/wordfence.json /tmp/dist
```

Arguments: `<cvelistV5/cves> <out_dir> [wordfence.json | -] [dist_dir]`.
Python 3.9+ is enough; there are no external dependencies.

## Attribution and licenses

- CVE data is © The MITRE Corporation and may be reused under the
  [CVE Program terms of use](https://www.cve.org/Legal/TermsOfUse).
- Wordfence Intelligence data is subject to the
  [Wordfence Intelligence terms and conditions](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/):
  keep the link to the record (see `wordfence_record_url` in `meta.json`) and the copyright
  notices (`meta.json` → `copyrights`, referenced by each record's `copyright` id) when you reuse
  this data.
- WPVulnerability data comes from the volunteer-run service wpvulnerability.com; please do not
  increase the request rate unnecessarily.
- **Before making this repository public**, check that these terms allow republishing a derived
  dataset.
