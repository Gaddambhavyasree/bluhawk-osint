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

The tool queries **8 public passive sources in parallel**. Each source is logged individually (`OK - N name(s)` or `FAILED - <error>`). One dead source never blocks the others.

| Source | Endpoint Pattern | What It Provides |
|--------|-----------------|------------------|
| **crt.sh** | `https://crt.sh/?q=%25.{domain}&output=json` | Certificate Transparency log hostnames |
| **crt.name** | `https://crt.name/?q=%25.{domain}&output=json` | CT fallback when crt.sh is down |
| **Certspotter** | `https://api.certspotter.com/v1/issuances?domain={domain}` | CT issuance DNS names with timestamps |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` | Passive DNS history (requires `OTX_API_KEY` env var or `--otx-api-key` argument) |
| **AnubisDB** | `https://jldc.me/anubis/subdomains/{domain}` | Subdomain enumeration data |
| **subdomain.center** | `https://api.subdomain.center/?q={domain}` | Subdomain API results |
| **HackerTarget** | `https://api.hackertarget.com/hostsearch/?q={domain}` | Host + IP pairs from passive DNS |
| **Internet Archive CDX** | `https://web.archive.org/cdx/search/cdx?url=*.{domain}/*` | Hostnames embedded in archived URLs |
| **urlscan.io** | `https://urlscan.io/api/v1/search/?q=domain:{domain}` | URL scan results for the domain |

---

## 3. Discovery Process

The engine runs in this fixed order:

### Stage 1 — Passive Sources (Parallel)
Queries all 8 passive sources simultaneously with per-request timeouts (≤30s). Results are normalized (lowercase, IDNA, strip `*.` and trailing dots) and checked to be in scope of the target domain.

### Stage 2 — TLS SAN Harvesting
Performs a TLS handshake to port 443 of each confirmed host and reads certificate Subject Alternative Name (SAN) DNS entries.

### Stage 3 — Website Analysis
Fetches `/`, `/robots.txt`, `/sitemap.xml`, crawls up to ~40 same-host pages, and inspects up to ~12 JS bundles. Extracts:
- **Hostnames** from HTML/JS (including escaped slashes)
- **Product/service entities** from nav anchors, buttons, headings (≤3 words), and URL path slugs. Each entity becomes both joined (`blurasaga`) and hyphenated (`blura-saga`) candidate forms.

### Stage 4 — DNS Record Mining
Extracts hostnames from MX, NS, TXT, and SOA records (requires `dnspython`).

### Stage 5 — Pattern Learning
From verified hyphenated hostnames (e.g. `api-retaileye`), learns role/product conventions:
- `api-retaileye` → role=`api`, product=`retaileye`
- `assets-origin` → role=`assets`, product=`origin`
- Generates `role-product` and `product-role` candidates across up to 2 learning rounds.

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

## Output Categories

| Category | Meaning |
|----------|---------|
| **Validated assets** | DNS resolves (A/AAAA/CNAME). Appears in the main hierarchy tree. |
| **Unverified leads** | Found in public sources but DNS does not resolve. Listed separately with origin tag. |
| **Blind guesses** | Generated candidates that failed DNS with no evidence. Counted in stats only, never listed as assets unless `--report-all-guesses`. |

---

## Example CLI

```bash
# Basic scan
python subdomain_engine.py example.com

# Deeper scan with XLSX, annotation, unverified leads shown
python subdomain_engine.py example.com --depth 3 --max-candidates 1200 --annotate --xlsx --show-unverified

# Only newly discovered subdomains (last 24 hours)
python subdomain_engine.py example.com --new-days 1 --new-only --xlsx

# Offline mode using seeds and imports only
python subdomain_engine.py example.com --no-ct --no-web --no-tls --seed www,api,dev --import-names subs.txt --wordlist names.txt

# With AlienVault OTX API key
python subdomain_engine.py example.com --otx-api-key YOUR_OTX_KEY
# Or set environment variable:
#   $env:OTX_API_KEY="YOUR_OTX_KEY"   (PowerShell)
#   export OTX_API_KEY="YOUR_OTX_KEY"  (Linux/macOS)
```

---

## Repository Structure

```
subdomain_engine.py   # Single-file engine (well commented)
tests/test_engine.py  # Offline pytest suite (14 tests)
README.md             # This file
```
