# Domain-Agnostic Recursive Subdomain Discovery and Intelligence Engine

A passive, domain-agnostic subdomain discovery and intelligence CLI written in Python. It builds a hierarchical tree of **validated subdomains** with parent-child relationships, evidence sources, and a separate list of **unverified leads** — for any domain you own or are authorised to assess.

> **⚠️ Safety Warning:** Only run against domains you own or are authorised to assess. This tool uses passive sources only — no port scanning, no exploitation, no brute-force flooding.

---

## 1. Technologies

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | Python 3.9+ (tested on 3.13) | Core engine execution |
| **Standard Library** | `urllib`, `socket`, `ssl`, `sqlite3`, `json`, `concurrent.futures`, `argparse`, `html.parser`, `threading`, `datetime`, `re`, `os`, `sys` | All core functionality — no external dependencies required |
| **Optional: DNS mining** | `dnspython` | Extract hostnames from MX/NS/TXT/SOA DNS records |
| **Optional: Excel output** | `openpyxl` | Generate `discovery.xlsx` with Validated / Unverified / Hierarchy sheets |
| **Optional: CA bundle** | `certifi` | HTTPS certificate verification for passive source requests |
| **Testing** | `pytest` | Offline test suite by mocking `http_get`, `resolve_hostname`, `tls_san_names` |

---

## 2. Passive Discovery Sources

The tool queries **9 public passive sources in parallel**. Each source is logged individually (`OK - N name(s)` or `FAILED - <error>`). One dead source never blocks the others.

| # | Source | Endpoint Pattern | API Key? | What It Provides |
|---|--------|-----------------|----------|------------------|
| 1 | **crt.sh** | `https://crt.sh/?q=%25.{domain}&output=json` | No | Certificate Transparency log hostnames |
| 2 | **crt.name** | `https://crt.name/?q=%25.{domain}&output=json` | No | CT fallback when crt.sh is down |
| 3 | **Certspotter** | `https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names` | Optional | CT issuance DNS names with timestamps |
| 4 | **AlienVault OTX** | `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` | Optional | Passive DNS history |
| 5 | **AnubisDB** | `https://anubisdb.com/subdomains/{domain}` | No | Subdomain enumeration data |
| 6 | **subdomain.center** | `https://api.subdomain.center/?domain={domain}` | No | Subdomain API results |
| 7 | **HackerTarget** | `https://api.hackertarget.com/hostsearch/?q={domain}` | No | Host + IP pairs from passive DNS |
| 8 | **Internet Archive CDX** | `https://web.archive.org/cdx/search/cdx?url=*.{domain}/*` | No | Hostnames embedded in archived URLs |
| 9 | **urlscan.io** | `https://urlscan.io/api/v1/search/?q=domain:{domain}` | Optional | URL scan results for the domain |

---

## 3. Discovery Process

The engine runs in this fixed order:

### Stage 1 — Passive Sources (Parallel)
Queries all 9 passive sources simultaneously with per-request timeouts (≤30s). Results are normalized (lowercase, IDNA, strip `*.` and trailing dots) and checked to be in scope of the target domain.

### Stage 2 — TLS SAN Harvesting
Performs a TLS handshake to port 443 of each confirmed host and reads certificate Subject Alternative Name (SAN) DNS entries.

### Stage 3 — Website Analysis
Fetches `/`, `/robots.txt`, `/sitemap.xml`, crawls up to ~40 same-host pages, and inspects up to ~12 JS bundles. Extracts:
- **Hostnames** from HTML/JS (including escaped slashes)

### Stage 4 — DNS Record Mining
Extracts hostnames from MX, NS, TXT, and SOA records (requires `dnspython`).

### Stage 5 — Pattern Learning
From verified hyphenated hostnames (e.g. `api-service-alpha`), learns role/product conventions:

- `api-service-alpha` → role=`api`, product=`service-alpha`
- `assets-primary` → role=`assets`, product=`primary`
- Generates `role-product` and `product-role` candidates across up to 2 learning rounds.

Single-label hostnames (e.g. `adm`, `app`, `www`, `mb`) are **never** used as product tokens.

Single-label hostnames (e.g. `adm`, `app`, `www`, `mb`) are **never** used as product tokens.

### Stage 6 — Candidate Generation
Builds a candidate set tagged by origin:
- Website entities
- User `--seed` names
- Common service labels at root (`www`, `api`, `dev`, `staging`, `admin`, …)
- `--wordlist` (never truncated)
- `--import-names` (from subfinder, amass, etc.)
- Learned pattern candidates
- Generic labels beneath each confirmed host (`api`, `dev`, `test`, `staging`, …)

### Stage 7 — Validation
Resolves A/AAAA/CNAME via DNS. Wildcard DNS is detected per parent using random labels; a name matching only the wildcard answer is **not** confirmed unless it has explicit CT/passive/TLS evidence.

### Stage 8 — Recursion
Investigates every newly validated host (TLS, web, DNS records, child candidates) up to `--depth` (default 2). Passive `%.root` queries run once at depth 0 only.

### Stage 9 — Dedup + Correlation
- Normalizes all names
- One record per hostname with merged, de-duplicated evidence
- Groups hosts sharing identical DNS answers as "shared infrastructure"

### Stage 10 — Persistence
- **JSON**: `discovery.json` — full structured results
- **CSV**: `discovery.csv` (UTF-8 BOM for Excel)
- **TXT**: `discovery_report.txt` — readable report
- **XLSX**: `discovery.xlsx` (optional, requires `openpyxl`)
- **SQLite**: `run.db` — `nodes` + `evidence` tables, plus scan change history

---

## 4. Output Categories

| Category | Meaning |
|----------|---------|
| **Validated assets** | DNS resolves (A/AAAA/CNAME). Appears in the main hierarchy tree. |
| **Unverified leads** | Found in public sources but DNS does not resolve. Listed separately with origin tag. |
| **Blind guesses** | Generated candidates that failed DNS with no evidence. Counted in stats only, never listed as assets unless `--report-all-guesses`. |

---

## 5. Installation

No installation is required for the core — just run the single file:

```bash
python subdomain_engine.py example.com
```

Install optional dependencies only if you need the corresponding features:

```bash
python -m pip install dnspython      # DNS record mining (MX/NS/TXT/SOA)
python -m pip install openpyxl       # --xlsx output
python -m pip install certifi        # CA bundle for HTTPS verification
```

If `--xlsx` is requested and `openpyxl` is missing, the tool prints `python -m pip install openpyxl` and continues without XLSX output.

---

## 6. CLI Usage

```bash
python subdomain_engine.py <domain> [options]
```

### Required

| Argument | Description |
|----------|-------------|
| `<domain>` | Root domain you own or are authorised to assess |

### Common Options

| Option | Default | Description |
|--------|---------|-------------|
| `--depth` | `2` | Recursion depth |
| `--out` | `discovery.json` | Base output path |
| `--db` | `run.db` | SQLite database path |
| `--workers` | `50` | Thread pool size |
| `--seed` | `""` | Comma-separated seed hostnames |
| `--wordlist` | `""` | Wordlist file (one name per line; never truncated) |
| `--import-names` | `""` | Import hostnames from another tool's output |
| `--ct-timeout` | `30` | Certificate-transparency source timeout seconds |
| `--max-candidates` | `600` | Candidate generation cap |
| `--table-rows` | `60` | Max rows in console table |

### Source Toggles

| Option | Description |
|--------|-------------|
| `--no-ct` | Skip certificate-transparency sources |
| `--no-web` | Skip website analysis |
| `--no-tls` | Skip TLS SAN harvesting |
| `--otx-api-key` | AlienVault OTX API key (or set `OTX_API_KEY` env var) |

### Output Options

| Option | Description |
|--------|-------------|
| `--xlsx` | Also write `discovery.xlsx` |
| `--show-unverified` | Print a second UNVERIFIED LEADS section |
| `--annotate` | Append source/IP tags after each tree name |
| `--ascii` | Use ASCII tree rendering (`|--` / `` `-- ``) |
| `--report-all-guesses` | List blind guesses that failed DNS as leads too |

### New Subdomain Filtering

| Option | Default | Description |
|--------|---------|-------------|
| `--new-days` | `0` | Show subdomains with certs issued within last N days (0 = disabled) |
| `--new-only` | — | Only show newly discovered subdomains within `--new-days` |

### Other

| Option | Description |
|--------|-------------|
| `--insecure-api` | Opt-in: disable TLS certificate verification (visible warning) |
| `-q` / `--quiet` | Reduce console log noise |

---

## 7. Examples

```bash
# 1. Basic scan against a domain you own
python subdomain_engine.py example.com

# 2. Deeper recursion with XLSX, annotation, unverified leads shown
python subdomain_engine.py example.com --depth 3 --max-candidates 1200 \
    --annotate --xlsx --show-unverified

# 3. Only newly discovered subdomains from the last 24 hours
python subdomain_engine.py example.com --new-days 1 --new-only --xlsx

# 4. Feed in names from another tool (subfinder, amass, crt.sh export)
python subdomain_engine.py example.com --seed www,api,dev \
    --import-names subfinder_output.txt --wordlist names.txt

# 5. Offline mode (no external APIs) using only seeds and DNS
python subdomain_engine.py example.com --no-ct --no-web --no-tls \
    --seed www,api,dev,vpn,mail

# 6. With AlienVault OTX API key
python subdomain_engine.py example.com --otx-api-key YOUR_OTX_KEY
# Or set environment variable:
#   $env:OTX_API_KEY="YOUR_OTX_KEY"   (PowerShell)
#   export OTX_API_KEY="YOUR_OTX_KEY"  (Linux/macOS)
```

---

## 8. Output Files

| File | Description |
|------|-------------|
| `discovery.json` | Full structured results (JSON) |
| `discovery.csv` | CSV with UTF-8 BOM (Excel-compatible): `Status,Hostname,Origin,Parent,IPs,CNAME,Note` |
| `discovery_report.txt` | Human-readable report (tree, validated list, unverified leads, shared infrastructure, learned patterns) |
| `discovery.xlsx` | Excel workbook with **Validated**, **Unverified**, and **Hierarchy** sheets (bold header, filters, frozen header row) |
| `run.db` | SQLite database (`scans`, `scan_assets`, `nodes`, `evidence` tables) |
| `*_console.log` | Raw console log marked `MODE: LIVE` |

### Console Output Example

```
Only run against domains you own or are authorised to assess.
[engine] target: example.com
[root] example.com: VALIDATED
[passive] ct: OK - 248 name(s)
[passive] certspotter: OK - 36 name(s)
[passive] hackertarget: OK - 9 name(s)
[passive] cdx: OK - 1632 name(s)
...

12 validated | 156 unverified leads | 0 blind guesses did not resolve

VALIDATED TREE
----------------------------------------
example.com
│
├── adm.example.com
├── admin.example.com
├── app.example.com
├── mail.example.com
└── www.example.com
```

---

## 9. Safety & Authorization

This is a **passive reconnaissance tool only**:
- Passive sources + ordinary DNS lookups + normal public HTTP GETs
- **No port scanning, no exploitation, no brute-force flooding**
- Default `User-Agent` identifies the tool (`BluCloud-Subdomain-Engine/1.0`)
- Prints `Only run against domains you own or are authorised to assess.` on every run
- `--insecure-api` is opt-in only with a visible warning

---

## 10. Limitations (Honest)

1. **Guessed names are leads, not assets.** A hostname becomes a validated asset only when it resolves in DNS (and is not merely a wildcard match without explicit evidence).
2. **Names that exist in no public source and cannot be derived cannot be found.** Use `--seed`, `--wordlist`, and `--import-names` to supply additional candidate names.
3. **External APIs may be blocked or rate-limited** in your environment (crt.sh frequently returns 502; OTX may return 429; Anubis may return 403). The tool handles failures gracefully and continues with remaining sources.
4. **CDX (Internet Archive) returns archived URLs, not clean subdomains.** It is noisy; many entries are paths, files, or duplicates.
5. **This tool will not discover internal-only or completely unreferenced subdomains.** Active DNS enumeration (zone transfer, brute-force resolution) is intentionally out of scope.

---

## 11. API Key Setup

Optional API keys for higher rate limits on OTX, urlscan.io, and Certspotter:

Create a `.env` file (copy from `.env.example`):

```ini
OTX_API_KEY=your_otx_key_here
URLSCAN_API_KEY=your_urlscan_key_here
CERTSPOTTER_API_KEY=your_certspotter_key_here
```

Or pass via CLI:

```bash
python subdomain_engine.py example.com --otx-api-key YOUR_OTX_KEY
```

**Never commit `.env` to GitHub.** It is already in `.gitignore`.

---

## 12. Testing

The test suite runs **offline** by mocking `http_get`, `resolve_hostname`, and `tls_san_names`:

```bash
python -m pytest tests/ -v
```

Includes 14 tests covering:
- CT names validated; unresolvable names unverified
- crt.sh failure (502) with learning recovery
- Wildcard DNS rejection
- Unresolvable input root not validated
- Tree renderer golden test (byte-for-byte)
- Ctrl+C exports partial results
- CSV BOM + columns; JSON validity
- Entity derivation and label splitting
- ASCII rendering
- Scan history (new/removed/changed)
- Evidence deduplication
- Source failure reporting

---

## 13. Repository Structure

```
subdomain_engine.py   # Single-file engine (well commented)
tests/test_engine.py  # Offline pytest suite (14 tests)
.env.example          # Template for API keys
.gitignore            # Ignores .env, outputs, caches
README.md             # This file
```

---

## 14. License

Internal tooling. Use only against domains you own or are authorised to assess.

---

## 15. Contributing

Pull requests welcome. Please maintain the passive-only safety model and add tests for new features.
