# Subdomain Discovery and Intelligence Engine

A passive, subdomain discovery and intelligence CLI written in Python. It builds a hierarchical tree of **validated subdomains** with parent-child relationships, evidence sources, and a separate list of **unverified leads** — for any domain you own or are authorised to assess.

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

The tool queries **9 public passive sources in parallel**. 

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
- **Product/service entities** from nav anchors, buttons, headings (≤3 words), and URL path slugs

### Stage 4 — DNS Record Mining
Extracts hostnames from MX, NS, TXT, and SOA records (requires `dnspython`).

### Stage 5 — Candidate Generation
Builds a candidate set tagged by origin:
- Website entities
- User `--seed` names
- Common service labels at root (`www`, `api`, `dev`, `staging`, `admin`, …)
- `--wordlist` (never truncated)
- `--import-names` (from subfinder, amass, etc.)
- Generic labels beneath each confirmed host (`api`, `dev`, `test`, `staging`, …)

### Stage 6 — Validation
Resolves A/AAAA/CNAME via DNS. Wildcard DNS is detected per parent using random labels; a name matching only the wildcard answer is **not** confirmed unless it has explicit CT/passive/TLS evidence. Hostnames are additionally checked to ensure they do not resolve to a private/reserved address (SSRF protection against DNS rebinding).

### Stage 7 — Recursion
Investigates every newly validated host (TLS, web, DNS records, child candidates) up to `--depth` (default 2). Passive `%.root` queries run once at depth 0 only.

### Stage 8 — Dedup + Correlation
- Normalizes all names
- One record per hostname with merged, de-duplicated evidence
- Groups hosts sharing identical DNS answers as "shared infrastructure"

### Stage 9 — Persistence
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


## 7. Commands

```bash
# 1. Basic Scan
python subdomain_engine.py example.com
# 2. Excel Output
python subdomain_engine.py example.com --xlsx

```


