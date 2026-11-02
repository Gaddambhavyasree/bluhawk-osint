# Domain-Agnostic Recursive Subdomain Discovery and Intelligence Engine

A passive, domain-agnostic subdomain discovery and intelligence CLI written in
Python. It builds a **hierarchical tree of validated subdomains** with their
parent-child relationships, evidence sources, and a separate list of
**unverified leads** — for any domain you own or are authorised to assess.

## Safety / authorization

> Only run against domains you own or are authorised to assess.

The tool uses **passive sources only**, plus ordinary DNS lookups and normal
public HTTP GETs. There is **no port scanning, no exploitation, and no
brute-force flooding**. The default `User-Agent` identifies the tool.

## Stack

*Core (standard library only):* `urllib`, `socket`, `ssl`, `sqlite3`, `json`,
`concurrent.futures`, `argparse`, `html.parser`.

*Optional:* `dnspython` (DNS record mining), `openpyxl` (XLSX output),
`certifi` (CA bundle for HTTPS verification).

Tested with Python 3.9+ (developed on 3.13). Runs on Windows, macOS and Linux;
console output is UTF-8 (on Windows `sys.stdout.reconfigure(encoding="utf-8")`
is called).

## Installation

No installation is required for the core — just run the single file:

```
python subdomain_engine.py example.com
```

Optional extras (install only if you want the corresponding feature):

```
python -m pip install dnspython   # DNS record mining (MX/NS/TXT/SOA)
python -m pip install openpyxl    # --xlsx output
python -m pip install certifi     # CA bundle for HTTPS verification
```

If `--xlsx` is requested and `openpyxl` is missing, the tool prints
`python -m pip install openpyxl` and continues without XLSX.

## CLI

```
python subdomain_engine.py <domain> [options]
```

| Option | Meaning |
|--------|---------|
| `<domain>` | Root domain you own or are authorised to assess |
| `--depth N` | Recursion depth (default 2) |
| `--out discovery.json` | Base output path (default `discovery.json`) |
| `--db run.db` | SQLite database path (default `run.db`) |
| `--workers N` | Thread pool size (default 50) |
| `--seed a,b` | Comma-separated seed hostnames |
| `--wordlist file` | Wordlist file (one name per line; never truncated) |
| `--import-names file` | Import hostnames from another tool's output |
| `--ct-timeout N` | Certificate-transparency source timeout seconds (default 30) |
| `--no-ct` | Skip certificate-transparency sources |
| `--no-web` | Skip website analysis |
| `--no-tls` | Skip TLS SAN harvesting |
| `--max-candidates N` | Candidate cap (default 600) |
| `--report-all-guesses` | List blind guesses that failed DNS as leads too |
| `--show-unverified` | Print a second UNVERIFIED LEADS section |
| `--annotate` | Append source/IP tags after each tree name |
| `--ascii` | Use ASCII tree rendering (`|--` / `` `-- ``) |
| `--xlsx` | Also write `discovery.xlsx` |
| `--table-rows N` | Max rows in console table (default 60) |
| `--insecure-api` | Opt-in: disable TLS certificate verification (visible warning) |
| `-q` / `--quiet` | Reduce console log noise |

## Discovery pipeline (in order)

1. **Passive sources in parallel** — crt.sh, Certspotter, AlienVault OTX,
   AnubisDB, subdomain.center, HackerTarget, Internet Archive CDX, urlscan.io.
   Each source is logged (`OK - N name(s)` or `FAILED - <error>`). crt.sh 502/
   503/504 is treated as "service down" and fails fast; one dead source never
   stops the run.
2. **TLS SAN harvesting** — TLS handshake to port 443 of each confirmed host;
   certificate SAN names are collected.
3. **Website analysis** — fetches `/`, `/robots.txt`, `/sitemap.xml`, crawls up
   to ~10 same-host pages and up to ~12 same-scope JS bundles. Extracts
   in-scope hostnames (regex, including escaped slashes in JS) and
   **product/service entities** from nav anchors, buttons, headings (<=3
   meaningful words) and URL path slugs. Each entity becomes both a joined
   (`blurasaga`) and a hyphenated (`blura-saga`) candidate. Entities are never
   rank-truncated. Noise (phones, hex hashes, digit-heavy strings, generic
   words, long marketing phrases) is filtered out.
4. **DNS record mining** — hostnames inside MX/NS/TXT/SOA records (dnspython).
5. **Candidate generation**, tagged by origin: website entities, user `--seed`
   names, brand-derived stems × product affixes, common service labels at root,
   generic labels beneath each confirmed host, optional `--wordlist` (never
   truncated), `--import-names`, and pattern-learning candidates.
6. **Pattern learning** — from evidenced names, learns role/product conventions
   (e.g. `api-retaileye` + `gmr-retaileye` → roles `{api, gmr}`, product
   `{retaileye}`), then tries `role-<product>` / `<product>-role` / bare
   product across all known product tokens, for up to 2 learning rounds.
7. **Validation** — resolves A/AAAA/CNAME. Wildcard DNS is detected per parent
   with random labels; a name matching only the wildcard answer is **not**
   confirmed unless it has explicit CT/passive/TLS evidence. A hostname is
   validated only if DNS resolves. The input root is validated only if it
   resolves (otherwise it is marked Unverified and a warning is printed).
8. **Recursion** — every newly validated host is investigated (TLS, web, DNS
   records, child candidates) up to `--depth`. The `%.root` passive queries run
   once at depth 0 only.
9. **Dedup + correlation** — names are normalized (lowercase, trailing dot /
   `*.` stripped, IDNA). One record per hostname with merged, de-duplicated
   evidence. Hosts sharing identical DNS answers are grouped as "shared
   infrastructure".
10. **Persistence** — everything is stored in SQLite (`nodes` + `evidence`
    tables). **Unverified leads are kept separate from validated assets.**
    Leads are listed only when they have real evidence (CT, passive, web, JS,
    TLS, DNS record, import, website entity, user seed). Blind guesses that
    fail DNS are only counted, not listed, unless `--report-all-guesses`.

## Output

The tool writes (next to `--out`):

* `discovery.json` — root, timestamp, stats, nested tree, confirmed assets
  (DNS, parent, origin list, evidence rows), shared infrastructure, unverified
  leads, learned patterns.
* `discovery.csv` — `Status,Hostname,Origin,Parent,IPs,CNAME,Note` (UTF-8 with
  BOM so Excel opens it correctly).
* `discovery_report.txt` — readable report (tree, validated list, unverified
  leads, shared infrastructure, learned patterns, source counts).
* `discovery.xlsx` — with `--xlsx` (sheets: Validated, Unverified, Hierarchy;
  bold header, filters, frozen header row).

### Console tree (validated hosts only)

```
bluecloudsoftech.com
│
├── blutor.bluecloudsoftech.com
│   ├── tech.blutor.bluecloudsoftech.com
│   ├── api.blutor.bluecloudsoftech.com
│   └── dev.blutor.bluecloudsoftech.com
│
├── bluhawk.bluecloudsoftech.com
│   ├── api.bluhawk.bluecloudsoftech.com
│   └── dev.bluhawk.bluecloudsoftech.com
│
└── app.bluecloudsoftech.com
    ├── api.app.bluecloudsoftech.com
    └── dev.app.bluecloudsoftech.com
```

Only validated hosts appear in this tree — guessed names are never reported as
assets. With `--show-unverified` a second "UNVERIFIED LEADS" section is printed,
each lead marked `?` with its origin. With `--annotate` short tags (sources,
IPs, CNAME) are appended after each name.

The default run also prints a summary line, e.g.:

```
13 validated | 42 unverified leads | 187 blind guesses did not resolve
```

## Examples

```
# Basic run against a domain you own
python subdomain_engine.py example.com --depth 2

# Deeper recursion, more candidates, annotate the tree, XLSX output
python subdomain_engine.py example.com --depth 3 --max-candidates 1200 \
    --annotate --xlsx --show-unverified

# Feed in names from another tool (subfinder/amass/crt.sh export) plus seeds
python subdomain_engine.py example.com --seed www,api,dev \
    --import-names subfinder_output.txt --wordlist names.txt
```

## Limitations (honest)

* Guessed names are **leads, not assets**. A name only becomes a validated
  asset when it resolves in DNS (and is not merely a wildcard match without
  explicit evidence).
* Names that exist in no public source and cannot be derived from the domain,
  seeds, wordlist, or imported names **cannot be found by any passive tool**.
  Use `--seed`, `--wordlist`, and `--import-names` to supply additional
  candidate names.
* This is a passive reconnaissance tool. It does not perform active
  interaction beyond normal DNS lookups and public HTTP GETs, so it will not
  discover hosts that are not published anywhere publicly.
* If your environment blocks outbound network access, the live sources will
  fail gracefully; rely on the mocked test suite instead (see below).

## Tests

The test suite lives in `tests/` and runs **offline** by mocking the single
network chokepoint (`http_get`), DNS resolution (`resolve_hostname`), and TLS
SAN harvesting (`tls_san_names`).

```
python -m pytest tests/ -v
```

It includes a fixture modeled on the documented case and asserts:

1. all resolving CT names are validated; `mb` and every website product name
   are unverified;
2. with crt.sh failing (502) and one other source returning `api-retaileye`,
   learning recovers `assets-retaileye` and `feed-retaileye`;
3. wildcard DNS: random labels resolving to one IP cause matching guesses to be
   rejected;
4. an unresolvable input root is not reported as validated;
5. the tree renderer matches the documented golden output byte-for-byte;
6. a `KeyboardInterrupt` in the resolver still exports partial results;
7. the CSV opens with a UTF-8 BOM and has the documented columns; the JSON is
   valid.

## Repository contents

* `subdomain_engine.py` — single-file engine (well commented).
* `tests/test_engine.py` — offline pytest suite.
* `README.md` — this file.

## License

Internal tooling. Use only against domains you own or are authorised to assess.
