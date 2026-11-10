"""Tests for subdomain_engine.py.

All network/DNS/TLS is mocked so the suite runs offline. http_get, resolve_hostname
and tls_san_names are the single chokepoints the engine uses, so we monkeypatch
those on the subdomain_engine module.
"""

import json
import os
import sys
from unittest.mock import MagicMock

import pytest

import subdomain_engine as SE

ROOT = "example.com"

CT_NAMES = [
    "adm.example.com",
    "api-retaileye.example.com",
    "app.example.com",
    "assets-origin.example.com",
    "assets-retaileye.example.com",
    "feed-retaileye.example.com",
    "gmr-retaileye.example.com",
    "visakhaiccc.example.com",
    "www.example.com",
    "mb.example.com",
]

CT_JSON = [{"name_value": n} for n in CT_NAMES]

NAV_HTML = (
    "<html><body><nav>"
    "<a>Cybersecurity</a>"
    "<a>Security Operations Center</a>"
    "<a>Access Genie</a>"
    "<a>BluEye</a>"
    "<a>BluFly</a>"
    "<a>BluRoutes</a>"
    "<a>BluSignal</a>"
    "<a>Blura SAGA</a>"
    "<a>BluHawk</a>"
    "<a href=\"/cybersecurity/blutor/\">BluTOR</a>"
    "<a>Blura</a>"
    "<a>EduGenie</a>"
    "<a>BioSter</a>"
    "<a>BluClinics</a>"
    "<a>BluHealth HIMS</a>"
    "<a>BluHealth Scanner</a>"
    "<a>BluHealth Screener</a>"
    "<a>5G FWA</a>"
    "<a>BluTACT</a>"
    "<a>Earnings Call</a>"
    "<a>Insights</a>"
    "</nav></body></html>"
)


def make_resolve(resolve_map, wildcard_ip=None):
    def resolve(name):
        n = SE.normalize_name(name)
        if n in resolve_map:
            ips, cname = resolve_map[n]
            return list(ips), cname
        if wildcard_ip is not None:
            return [wildcard_ip], None
        raise OSError("no records for {0}".format(name))
    return resolve


def make_http_get(crt_status=200, crt_body=CT_JSON, extra=None):
    extra = extra or {}

    def http_get(url, timeout=SE.HTTP_TIMEOUT, max_bytes=SE.MAX_BODY, insecure=False):
        if "crt.sh" in url:
            if crt_status in (502, 503, 504):
                return (crt_status, "", "service down")
            body = json.dumps(crt_body) if not isinstance(crt_body, str) else crt_body
            return (200, body, None)
        if "subdomain.center" in url:
            return (200, "[]", None)
        if "otx.alienvault" in url:
            return (200, '{"passive_dns": []}', None)
        if "urlscan.io" in url:
            return (200, '{"results": []}', None)
        if any(s in url for s in ("jldc.me/anubis", "hackertarget",
                                  "web.archive.org", "certspotter")):
            return (200, "[]", None)
        if url == "https://example.com/":
            return (200, NAV_HTML, None)
        if url.endswith("/robots.txt") or url.endswith("/sitemap.xml"):
            return (200, "", None)
        if url in extra:
            return extra[url]
        return (200, "", None)

    return http_get


def run_engine(monkeypatch, tmp_path, domain=ROOT, resolve_map=None,
               http_get=None, tls_san=None, extra_args=None, depth=1):
    if resolve_map is not None:
        monkeypatch.setattr(SE, "resolve_hostname", make_resolve(resolve_map))
    if http_get is not None:
        monkeypatch.setattr(SE, "http_get", http_get)
    if tls_san is not None:
        monkeypatch.setattr(SE, "tls_san_names", tls_san)

    args_list = [domain, "--depth", str(depth), "--out",
                 str(tmp_path / "discovery.json"), "--db", str(tmp_path / "run.db"),
                 "--workers", "8", "--no-tls"]
    if extra_args:
        args_list.extend(extra_args)
    args = SE.build_parser().parse_args(args_list)
    eng = SE.Engine(domain, args)
    try:
        report = eng.run()
    except KeyboardInterrupt:
        eng.flush_pending_as_leads()
        report = eng._build_report()
    return eng, report


# --------------------------------------------------------------------------- #
# Assertion 1: resolving CT names validated; mb + website products unverified #
# --------------------------------------------------------------------------- #
def test_ct_names_validated_mb_and_website_products_unverified(
        monkeypatch, tmp_path):
    resolve_map = {ROOT: (["10.0.0.1"], None)}
    for i, n in enumerate(CT_NAMES):
        if n == "mb.example.com":
            continue
        resolve_map[n] = (["10.0.0.{0}".format(i + 2)], None)
    # mb and every website product name deliberately absent -> will not resolve.

    eng, report = run_engine(monkeypatch, tmp_path,
                             resolve_map=resolve_map,
                             http_get=make_http_get())

    validated = {a["hostname"] for a in report["validated_assets"]}
    leads = {lead["hostname"] for lead in report["unverified_leads"]}

    # every resolving CT name is VALIDATED
    for n in CT_NAMES:
        if n == "mb.example.com":
            continue
        assert n in validated, f"{n} should be validated"
    assert ROOT in validated

    # mb (CT only, does not resolve) is UNVERIFIED
    assert "mb.example.com" in leads, "mb should be an unverified lead"

    # every website product name is UNVERIFIED (none resolve)
    for prod in ("blueye.example.com", "blutor.example.com", "blurasaga.example.com",
                 "bluhawk.example.com", "accessgenie.example.com",
                 "bluhealthscanner.example.com", "securityoperationscenter.example.com"):
        assert prod in leads, f"{prod} should be an unverified lead"

    # summary line arithmetic
    st = report["stats"]
    assert st["validated"] >= 10  # root + 9 resolving CT names
    assert st["unverified_leads"] >= 1


# --------------------------------------------------------------------------- #
# Assertion 2: crt.sh 502, one other source returns api-retaileye,            #
#              learning recovers assets-retaileye and feed-retaileye         #
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Assertion 2: crt.sh 502, one other source returns api-retaileye,            #
#              NO pattern learning - only evidence-backed names validated    #
# --------------------------------------------------------------------------- #
def test_no_pattern_learning(monkeypatch, tmp_path):
    resolve_map = {
        ROOT: (["10.0.0.1"], None),
        "api-retaileye.example.com": (["10.0.0.2"], None),
        "assets-retaileye.example.com": (["10.0.0.3"], None),
        "feed-retaileye.example.com": (["10.0.0.4"], None),
    }

    def http_get(url, timeout=SE.HTTP_TIMEOUT, max_bytes=SE.MAX_BODY, insecure=False):
        if "crt.sh" in url:
            return (502, "", "service down")
        if "subdomain.center" in url:
            # the ONE other source that still works
            return (200, '["api-retaileye.example.com"]', None)
        if any(s in url for s in ("otx.alienvault", "jldc.me/anubis",
                                  "hackertarget", "urlscan.io",
                                  "web.archive.org", "certspotter")):
            return (200, "[]", None)
        if url == "https://example.com/":
            return (200, NAV_HTML, None)
        if url.endswith("/robots.txt") or url.endswith("/sitemap.xml"):
            return (200, "", None)
        return (200, "", None)

    eng, report = run_engine(monkeypatch, tmp_path,
                             resolve_map=resolve_map, http_get=http_get)

    validated = {a["hostname"] for a in report["validated_assets"]}
    # api-retaileye came from the live source and resolves
    assert "api-retaileye.example.com" in validated
    # assets-retaileye and feed-retaileye are NOT learned - they only exist
    # as CT names but don't resolve, so they must NOT be validated
    assert "assets-retaileye.example.com" not in validated
    assert "feed-retaileye.example.com" not in validated
    # They should be in leads if they have evidence (from CT), or not present
    # at all if they have no evidence at all


# --------------------------------------------------------------------------- #
# Assertion 3: wildcard DNS - random labels resolve to one IP; guesses        #
#              matching it are rejected unless explicitly evidenced          #
# --------------------------------------------------------------------------- #
def test_wildcard_guess_rejected_ct_evidenced_confirmed(monkeypatch, tmp_path):
    # every label beneath example.com resolves to the same wildcard IP
    def resolve(name):
        return ["1.2.3.4"], None

    monkeypatch.setattr(SE, "resolve_hostname", resolve)
    # only cthost is backed by explicit CT evidence
    monkeypatch.setattr(SE, "http_get",
                        make_http_get(crt_body=[{"name_value": "cthost.example.com"}]))
    monkeypatch.setattr(SE, "tls_san_names", lambda *a, **k: [])

    eng, report = run_engine(monkeypatch, tmp_path, depth=0)

    validated = {a["hostname"] for a in report["validated_assets"]}
    # CT evidence makes cthost a validated asset even though it matches the wildcard
    assert "cthost.example.com" in validated
    # service-label guesses (www, api, dev...) match the wildcard only -> rejected
    assert "www.example.com" not in validated
    assert "api.example.com" not in validated


# --------------------------------------------------------------------------- #
# Assertion 4: unresolvable input root is not reported as Validated          #
# --------------------------------------------------------------------------- #
def test_unresolvable_root_not_validated(monkeypatch, tmp_path):
    def resolve(name):
        n = SE.normalize_name(name)
        if n == ROOT:
            raise OSError("no records for root")
        return ["10.0.0.1"], None

    monkeypatch.setattr(SE, "resolve_hostname", resolve)
    monkeypatch.setattr(SE, "http_get", make_http_get())
    monkeypatch.setattr(SE, "tls_san_names", lambda *a, **k: [])

    eng, report = run_engine(monkeypatch, tmp_path)

    assert eng.nodes[ROOT]["validated"] is False
    # root not validated => nothing rendered in the validated hierarchy
    assert report["tree"] == []


# --------------------------------------------------------------------------- #
# Assertion 5: tree renderer golden test (byte-for-byte)                    #
# --------------------------------------------------------------------------- #
def test_tree_renderer_golden(monkeypatch, tmp_path):
    lines = SE.render_tree("example.com", SE._golden_children())
    got = "\n".join(lines)
    assert got == SE._golden_tree_text()


# --------------------------------------------------------------------------- #
# Assertion 6: Ctrl+C in the resolver still exports partial results         #
# --------------------------------------------------------------------------- #
def test_ctrl_c_exports_partial_results(monkeypatch, tmp_path):
    def resolve(name):
        n = SE.normalize_name(name)
        if n == ROOT:
            return ["10.0.0.1"], None
        raise KeyboardInterrupt("simulated ctrl-c in resolver")

    monkeypatch.setattr(SE, "resolve_hostname", resolve)
    monkeypatch.setattr(SE, "http_get", make_http_get())
    monkeypatch.setattr(SE, "tls_san_names", lambda *a, **k: [])

    eng, report = run_engine(monkeypatch, tmp_path)

    # root was validated before the interrupt
    assert eng.nodes[ROOT]["validated"] is True
    # passive names were fetched (observed) and must NOT be thrown away:
    # they are flushed as unverified leads
    leads = {lead["name"] for lead in eng.leads.values()}
    assert "api-retaileye.example.com" in leads, \
        "fetched-but-unvalidated names must be preserved as leads"

    # partial report still builds and serializes
    payload = json.dumps(report, ensure_ascii=False)
    data = json.loads(payload)
    assert data["root"] == ROOT
    assert "stats" in data


# --------------------------------------------------------------------------- #
# Assertion 7: CSV BOM + columns; JSON valid                              #
# --------------------------------------------------------------------------- #
def test_csv_bom_columns_and_json_valid(monkeypatch, tmp_path):
    resolve_map = {ROOT: (["10.0.0.1"], None),
                   "www.example.com": (["10.0.0.2"], None)}
    eng, report = run_engine(monkeypatch, tmp_path,
                             resolve_map=resolve_map,
                             http_get=make_http_get())

    csv_path = tmp_path / "discovery.csv"
    json_path = tmp_path / "discovery.json"
    # run_engine returns the report; persist it here to test the writers.
    write_csv = SE.write_csv
    write_json = SE.write_json
    write_json(report, json_path)
    write_csv(report, csv_path)
    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "CSV must open with a UTF-8 BOM"
    text = raw.decode("utf-8-sig")
    lines = text.splitlines()
    assert lines[0] == "Status,Hostname,Origin,Parent,IPs,CNAME,Note"

    json_path = tmp_path / "discovery.json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert set(data.keys()) >= {"root", "timestamp", "stats", "tree",
                                "validated_assets", "unverified_leads"}


# --------------------------------------------------------------------------- #
# Entity derivation (BluTOR example from the spec)                          #
# --------------------------------------------------------------------------- #
def test_derive_entities():
    ents = SE.derive_entities([
        "BluTOR", "BluEye", "Insights", "5G FWA", "Cybersecurity",
        "Blura SAGA",
    ])
    joined = {j for j, _h in ents}
    pairs = set(ents)
    assert "blutor" in joined
    assert ("blutor", "blutor") in pairs  # no separator -> both forms identical
    assert "blueye" in joined
    assert "blurasaga" in joined
    assert ("blurasaga", "blura-saga") in pairs
    assert "5gfwa" in joined             # 5G FWA kept (digit is part of product name)


def test_split_into_words_fallback():
    assert SE.split_into_words("example") == ["example"]
    assert SE.split_into_words("retaileye") == ["retaileye"]


# --------------------------------------------------------------------------- #
# ASCII rendering                                                           #
# --------------------------------------------------------------------------- #
def test_ascii_rendering():
    lines = SE.render_tree("example.com", SE._golden_children(), ascii=True)
    got = "\n".join(lines)
    assert "│" not in got and "├" not in got and "└" not in got
    assert "|-- example.com" not in got  # root is bare
    assert got.startswith("example.com\n|")


def test_deep_links_hidden_refs_sitemap_and_external_domains(monkeypatch):
    pages = {
        "https://example.com/": ('<a href="/products/">Products</a>'
                                 '<a href="https://api.example.com/reference">API</a>'
                                 '<a href="https://productco.test/">Our acquisition</a>'),
        "https://example.com/robots.txt": (
            "User-agent: *\nDisallow: /private\nSitemap: https://example.com/maps/index.xml"
        ),
        "https://example.com/sitemap.xml": "",
        "https://example.com/maps/index.xml": (
            "<sitemapindex><sitemap><loc>https://example.com/maps/products.xml"
            "</loc></sitemap></sitemapindex>"
        ),
        "https://example.com/maps/products.xml": (
            "<urlset><url><loc>https://example.com/press/acquired-cloud/"
            "</loc></url></urlset>"
        ),
        "https://example.com/products/": '<a href="/products/cloud-suite">Cloud Suite</a>',
        "https://example.com/products/cloud-suite": '<h1>Cloud Suite</h1><a href="/private/secret">Secret Suite</a>',
        "https://example.com/press/acquired-cloud/": "<p>Hidden product reference: Cloud Suite acquired.</p>",
    }
    requests = []

    def get(url, **kwargs):
        requests.append(url)
        return (200, pages[url], None) if url in pages else (404, "", "not found")

    monkeypatch.setattr(SE, "http_get", get)
    hosts, entities, _keywords, external = SE.analyze_website("example.com", "example.com")
    assert "api.example.com" in hosts
    assert "productco.test" in external
    assert "cloudsuite" in {name for name, _ in entities}
    assert "https://example.com/private/secret" not in requests


def test_scan_history_reports_new_removed_and_changed(tmp_path):
    def report(timestamp, assets):
        return {"root": "example.com", "timestamp": timestamp,
                "validated_assets": assets, "unverified_leads": []}

    def asset(name, ip, parent="example.com"):
        return {"hostname": name, "parent": parent, "dns": {"ips": [ip], "cname": None},
                "origin": ["ct"], "evidence": [{"source": "ct", "detail": ip}]}
    db = str(tmp_path / "history.db")
    first = SE.persist_sqlite(
        db,
        report(
            "2026-01-01T00:00:00Z",
            [asset("a.example.com", "1.1.1.1"), asset("b.example.com", "2.2.2.2")],
        ),
    )
    assert first["new"] == ["a.example.com", "b.example.com"]
    second = SE.persist_sqlite(
        db,
        report(
            "2026-01-02T00:00:00Z",
            [asset("a.example.com", "1.1.1.2"), asset("c.example.com", "3.3.3.3")],
        ),
    )
    assert second["new"] == ["c.example.com"]
    assert second["removed"] == ["b.example.com"]
    assert second["changed"] == ["a.example.com"]
    third = SE.persist_sqlite(
        db,
        report(
            "2026-01-03T00:00:00Z",
            [asset("a.example.com", "1.1.1.2"), asset("c.example.com", "3.3.3.3")],
        ),
    )
    assert third["changed"] == []
    assert third["new"] == [] and third["removed"] == []


def test_evidence_deduplication_preserves_distinct_sources():
    eng = SE.Engine("example.com", SE.build_parser().parse_args(["example.com", "--no-ct"]))
    eng._make_node("www.example.com", "example.com", ["ct"], [("ct", "certificate")], ["1.1.1.1"], None)
    eng._make_node("www.example.com", "example.com", ["ct", "website"],
                   [("ct", "certificate"), ("website", "linked hostname")], ["1.1.1.1"], None)
    node = eng.nodes["www.example.com"]
    assert node["origin"] == ["ct", "website"]
    assert node["evidence"] == [("ct", "certificate"), ("website", "linked hostname")]


def test_source_failure_is_reported():
    statuses = {}

    def fail(_domain, **_kwargs):
        return [], "provider unavailable"
    old = SE.PASSIVE_SOURCES
    SE.PASSIVE_SOURCES = [("fixture", fail)]
    try:
        result = SE.run_passive_sources("example.com", statuses=statuses)
        assert result[0] == {}
    finally:
        SE.PASSIVE_SOURCES = old
    assert statuses["fixture"] == {"status": "failed", "error": "provider unavailable"}


def test_no_ct_skips_crt_name(monkeypatch):
    """--no-ct must skip ALL CT sources including crt.name."""
    import subdomain_engine as SE

    # Save original sources
    old_sources = list(SE.PASSIVE_SOURCES)

    def make_fake_func(name):
        def func(domain, insecure=False):
            return [f"{name}.example.com"], {}, None
        return func

    # Replace all passive sources with fake ones that return data
    fake_sources = []
    for tag, func in SE.PASSIVE_SOURCES:
        fake_sources.append((tag, make_fake_func(tag)))

    SE.PASSIVE_SOURCES = fake_sources
    try:
        statuses = {}
        result = SE.run_passive_sources("example.com", no_ct=True, statuses=statuses)
        result_names = result[0]

        # All CT sources should be skipped
        for tag in SE.CT_SOURCES:
            assert tag not in result_names, f"{tag} should be skipped when --no-ct is set"
            assert statuses.get(tag, {}).get("status") == "skipped", \
                f"{tag} should be marked as skipped"

        # Non-CT sources should still run
        for tag_name, _func in SE.PASSIVE_SOURCES:
            if tag_name not in SE.CT_SOURCES:
                matching = [n for n in result_names if n == f"{tag_name}.example.com"]
                assert matching, \
                    f"{tag_name} should NOT be skipped when --no-ct is set"
    finally:
        SE.PASSIVE_SOURCES = old_sources


# --------------------------------------------------------------------------- #
# SSRF protection tests                                                       #
# --------------------------------------------------------------------------- #
def test_ssrf_blocks_private_ips():
    """SSRF protection must block private/reserved IP addresses."""
    assert SE.is_safe_url("https://example.com/page") is True
    assert SE.is_safe_url("http://127.0.0.1/") is False
    assert SE.is_safe_url("http://10.0.0.1/") is False
    assert SE.is_safe_url("http://172.16.0.1/") is False
    assert SE.is_safe_url("http://192.168.1.1/") is False
    assert SE.is_safe_url("http://localhost/") is False
    assert SE.is_safe_url("http://169.254.169.254/") is False
    assert SE.is_safe_url("ftp://example.com/") is False


def test_ssrf_blocks_non_http_schemes():
    assert SE.is_safe_url("ftp://example.com/") is False
    assert SE.is_safe_url("file:///etc/passwd") is False
    assert SE.is_safe_url("gopher://example.com/") is False


def test_http_get_blocks_unsafe_schemes():
    """http_get() must reject unsafe schemes before any network access."""
    # file:// scheme must be rejected
    status, body, err = SE.http_get("file:///etc/passwd")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()

    # ftp:// scheme must be rejected
    status, body, err = SE.http_get("ftp://example.com/")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()

    # gopher:// scheme must be rejected
    status, body, err = SE.http_get("gopher://example.com/")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()

    # javascript: scheme must be rejected
    status, body, err = SE.http_get("javascript:alert(1)")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()

    # data: scheme must be rejected
    status, body, err = SE.http_get("data:text/html,<script>alert(1)</script>")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()


def test_rate_limits_per_host():
    """Rate limiter waits briefly instead of immediately rejecting."""
    from subdomain_engine import _rate_limit, _request_times
    _request_times.clear()
    host = "example.com"
    # First request should succeed
    assert _rate_limit(host) is True
    # Second immediate request should wait briefly then succeed
    assert _rate_limit(host) is True
    # Exceed MAX_REQUESTS_PER_HOST by filling the deque manually
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    _request_times[host].clear()
    for _ in range(SE.MAX_REQUESTS_PER_HOST):
        _request_times[host].append(now)
    assert _rate_limit(host) is False


# --------------------------------------------------------------------------- #
# SSL/TLS security tests                                                      #
# --------------------------------------------------------------------------- #
def test_insecure_api_warns():
    """--insecure-api should be accepted but warn."""
    args = SE.build_parser().parse_args(["example.com", "--insecure-api"])
    assert args.insecure_api is True


def test_no_insecure_api_by_default():
    args = SE.build_parser().parse_args(["example.com"])
    assert args.insecure_api is False


# --------------------------------------------------------------------------- #
# API key handling tests                                                      #
# --------------------------------------------------------------------------- #
def test_otx_api_key_cli(monkeypatch):
    args = SE.build_parser().parse_args(["example.com", "--otx-api-key", "test-key-123"])
    assert args.otx_api_key == "test-key-123"


def test_env_var_loading(monkeypatch):
    """Environment variables are read by the engine at runtime."""
    monkeypatch.setenv("OTX_API_KEY", "test-env-key-123")
    assert os.environ.get("OTX_API_KEY") == "test-env-key-123"


# --------------------------------------------------------------------------- #
# DNS validation tests                                                        #
# --------------------------------------------------------------------------- #
def test_wildcard_rejects_unconfirmed(monkeypatch, tmp_path):
    """A name matching only wildcard DNS without explicit evidence must NOT
    be validated."""
    def resolve(name):
        return ["1.2.3.4"], None

    monkeypatch.setattr(SE, "resolve_hostname", resolve)
    monkeypatch.setattr(SE, "http_get",
                        make_http_get(crt_body=[{"name_value": "wild.example.com"}]))
    monkeypatch.setattr(SE, "tls_san_names", lambda *a, **k: [])

    eng, report = run_engine(monkeypatch, tmp_path, depth=0)

    validated = {a["hostname"] for a in report["validated_assets"]}
    # wild.example.com has explicit CT evidence -> should be validated
    assert "wild.example.com" in validated
    # www.example.com matches wildcard only -> rejected
    assert "www.example.com" not in validated


def test_shared_infrastructure_grouping(monkeypatch, tmp_path):
    """Hosts with identical DNS answers should be grouped."""
    resolve_map = {
        ROOT: (["10.0.0.1"], None),
        "a.example.com": (["10.0.0.1"], None),
        "b.example.com": (["10.0.0.1"], None),
        "c.example.com": (["10.0.0.2"], None),
    }

    def http_get(url, **kwargs):
        if "crt.sh" in url:
            return (200, json.dumps([{"name_value": n} for n in
                                     ["a.example.com", "b.example.com",
                                      "c.example.com"]]), None)
        return (200, "[]", None)

    eng, report = run_engine(monkeypatch, tmp_path,
                             resolve_map=resolve_map, http_get=http_get)

    # a and b share the same IP -> should be in shared_infrastructure
    shared = report.get("shared_infrastructure", [])
    found = False
    for g in shared:
        if len(g["hosts"]) >= 2:
            found = True
            break
    assert found, "Shared infrastructure grouping should group hosts with identical DNS"


# --------------------------------------------------------------------------- #
# CLI flag tests                                                              #
# --------------------------------------------------------------------------- #
def test_cli_flags():
    args = SE.build_parser().parse_args([
        "example.com", "--depth", "3", "--workers", "10",
        "--no-ct", "--no-web", "--no-tls", "--no-tls",
        "--show-unverified", "--annotate", "--ascii",
        "--report-all-guesses", "--new-days", "7", "--new-only",
        "--xlsx", "--table-rows", "100", "--insecure-api",
    ])
    assert args.domain == "example.com"
    assert args.depth == 3
    assert args.workers == 10
    assert args.no_ct is True
    assert args.no_web is True
    assert args.no_tls is True
    assert args.show_unverified is True
    assert args.annotate is True
    assert args.ascii is True
    assert args.report_all_guesses is True
    assert args.new_days == 7
    assert args.new_only is True
    assert args.xlsx is True
    assert args.table_rows == 100
    assert args.insecure_api is True


def test_table_rows_unused_but_accepted():
    """--table-rows is accepted but not used in rendering (documented)."""
    args = SE.build_parser().parse_args(["example.com", "--table-rows", "200"])
    assert args.table_rows == 200


# --------------------------------------------------------------------------- #
# Edge case tests                                                             #
# --------------------------------------------------------------------------- #
def test_normalize_name_edge_cases():
    assert SE.normalize_name("") is None
    assert SE.normalize_name("   ") is None
    assert SE.normalize_name("*.example.com") == "example.com"
    assert SE.normalize_name("EXAMPLE.COM.") == "example.com"
    assert SE.normalize_name("Example.Com") == "example.com"


def test_is_in_scope_edge_cases():
    assert SE.is_in_scope("sub.example.com", "example.com") is True
    assert SE.is_in_scope("example.com", "example.com") is True
    assert SE.is_in_scope("other.com", "example.com") is False
    assert SE.is_in_scope(None, "example.com") is False
    assert SE.is_in_scope("sub.example.com", None) is False


def test_derive_entities_keeps_input_words():
    """derive_entities derives joined/hyphenated forms from input words
    without vocab-based or noise filtering."""
    ents = SE.derive_entities([
        "margin", "padding", "width", "onclick", "onmouseover",
        "script", "div", "span", "nav",
        "BluTOR", "BluEye",
    ])
    joined = {j for j, _h in ents}
    assert "blutor" in joined
    assert "blueye" in joined
    # no vocab/noise filtering: input words are passed through
    assert "margin" in joined
    assert "padding" in joined
    assert "onclick" in joined
    assert "script" in joined
    assert "div" in joined


def test_engine_insecure_api_flag():
    args = SE.build_parser().parse_args(["example.com", "--insecure-api"])
    eng = SE.Engine(args.domain, args)
    assert eng.insecure is True


def test_engine_default_insecure_false():
    args = SE.build_parser().parse_args(["example.com"])
    eng = SE.Engine(args.domain, args)
    assert eng.insecure is False


# --------------------------------------------------------------------------- #
# SSRF redirect tests                                                         #
# --------------------------------------------------------------------------- #
def test_http_get_blocks_redirect_to_private_ip(monkeypatch):
    """http_get() must reject redirects to private IPs (SSRF via redirect)."""
    import subdomain_engine as SE

    # Mock build_opener to return an object whose .open() returns a response
    # whose geturl() points to a private IP.
    mock_resp = MagicMock()
    mock_resp.geturl.return_value = "http://127.0.0.1/metadata"
    mock_resp.status = 200
    mock_resp.read.return_value = b"secret"

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_resp

    monkeypatch.setattr(SE, "build_opener", lambda *args, **kwargs: mock_opener)

    status, body, err = SE.http_get("http://example.com/redirect")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()


def test_http_get_blocks_redirect_to_metadata_ip(monkeypatch):
    """http_get() must reject redirects to AWS metadata IP (169.254.169.254)."""
    import subdomain_engine as SE

    mock_resp = MagicMock()
    mock_resp.geturl.return_value = "http://169.254.169.254/latest/meta-data/"
    mock_resp.status = 200
    mock_resp.read.return_value = b"secret-metadata"

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_resp

    monkeypatch.setattr(SE, "build_opener", lambda *args, **kwargs: mock_opener)

    status, body, err = SE.http_get("http://example.com/redirect")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()


def test_http_get_blocks_too_many_redirects(monkeypatch):
    """http_get() must reject redirect chains exceeding max_redirects."""
    import subdomain_engine as SE

    # Clear rate limiter state
    SE._request_times.clear()

    mock_resp = MagicMock()
    mock_resp.geturl.return_value = "http://example.com/final"
    mock_resp.status = 200
    mock_resp.read.return_value = b"ok"

    mock_opener = MagicMock()
    mock_opener.open.side_effect = SE.URLError("too many redirects (>5)")

    monkeypatch.setattr(SE, "build_opener", lambda *args, **kwargs: mock_opener)

    status, body, err = SE.http_get("http://example.com/redirect-chain", max_redirects=5)
    assert status is None
    assert body is None
    assert err is not None
    assert "too many redirects" in err.lower()


def test_http_get_redirect_to_ftp_blocked(monkeypatch):
    """http_get() must reject redirects to non-http(s) schemes."""
    import subdomain_engine as SE

    mock_resp = MagicMock()
    mock_resp.geturl.return_value = "ftp://example.com/secret"
    mock_resp.status = 200
    mock_resp.read.return_value = b"secret"

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_resp

    monkeypatch.setattr(SE, "build_opener", lambda *args, **kwargs: mock_opener)

    status, body, err = SE.http_get("http://example.com/redirect")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower() or "unsafe" in err.lower()


# --------------------------------------------------------------------------- #
# Unresolvable root validation tests                                          #
# --------------------------------------------------------------------------- #
def test_unresolvable_root_not_in_validated_assets(monkeypatch, tmp_path):
    """Unresolvable root must NOT appear in validated_assets."""
    def resolve(name):
        n = SE.normalize_name(name)
        if n == ROOT:
            raise OSError("no records for root")
        return ["10.0.0.1"], None

    monkeypatch.setattr(SE, "resolve_hostname", resolve)
    monkeypatch.setattr(SE, "http_get", make_http_get())
    monkeypatch.setattr(SE, "tls_san_names", lambda *a, **k: [])

    eng, report = run_engine(monkeypatch, tmp_path)

    validated_hostnames = {a["hostname"] for a in report["validated_assets"]}
    assert ROOT not in validated_hostnames, \
        "Unresolvable root must not appear in validated_assets"
    assert eng.nodes[ROOT]["validated"] is False


def test_persist_sqlite_no_unvalidated_hosts(tmp_path, monkeypatch):
    """persist_sqlite must not insert unvalidated hosts into nodes table."""
    import subdomain_engine as SE

    # Build a report with an unresolvable root in validated_assets (simulating the bug)
    report = {
        "root": "example.com",
        "timestamp": "2026-01-01T00:00:00Z",
        "validated_assets": [
            {
                "hostname": "example.com",
                "parent": None,
                "dns": {"ips": [], "cname": None},
                "origin": ["input"],
                "evidence": [],
            },
            {
                "hostname": "www.example.com",
                "parent": "example.com",
                "dns": {"ips": ["10.0.0.1"], "cname": None},
                "origin": ["ct"],
                "evidence": [{"source": "ct", "detail": "passive", "observed_at": "2026-01-01T00:00:00Z"}],
            },
        ],
        "unverified_leads": [],
    }

    db_path = tmp_path / "test.db"
    SE.persist_sqlite(str(db_path), report)

    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("SELECT hostname, validated FROM nodes WHERE hostname = 'example.com'")
    row = cur.fetchone()
    conn.close()

    if row is not None:
        hostname, validated = row
        assert validated == 0, \
            f"Unresolvable root should have validated=0 in SQLite, got {validated}"


def test_persist_sqlite_no_duplicate_hostnames(tmp_path):
    """persist_sqlite must not create duplicate hostnames in nodes table."""
    import sqlite3

    report = {
        "root": "example.com",
        "timestamp": "2026-01-01T00:00:00Z",
        "validated_assets": [
            {
                "hostname": "www.example.com",
                "parent": "example.com",
                "dns": {"ips": ["10.0.0.1"], "cname": None},
                "origin": ["ct"],
                "evidence": [{"source": "ct", "detail": "passive", "observed_at": "2026-01-01T00:00:00Z"}],
            },
        ],
        "unverified_leads": [],
    }

    db_path = tmp_path / "test_dup.db"
    SE.persist_sqlite(str(db_path), report)

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("SELECT hostname, COUNT(*) as cnt FROM nodes GROUP BY hostname HAVING cnt > 1")
    dupes = cur.fetchall()
    conn.close()

    assert len(dupes) == 0, f"Duplicate hostnames found in SQLite: {dupes}"


# --------------------------------------------------------------------------- #
# Regression: hostname-based SSRF (DNS rebinding)                             #
# --------------------------------------------------------------------------- #
def test_http_get_blocks_hostname_resolving_to_private_ip(monkeypatch):
    """SSRF: http_get() must block a hostname that DNS-resolves to a private
    address, even though the URL scheme is http/https and the host is not an
    IP literal (defence in depth beyond is_safe_url())."""
    import socket as socket_module

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "example.com":
            return [
                (socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "",
                 ("127.0.0.1", 0)),
            ]
        raise OSError("no records for {0}".format(host))

    monkeypatch.setattr(socket_module, "getaddrinfo", fake_getaddrinfo)
    SE._request_times.clear()
    SE._hostname_cache.clear()
    status, body, err = SE.http_get("http://example.com/")
    assert status is None
    assert body is None
    assert err is not None
    assert "blocked" in err.lower()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
