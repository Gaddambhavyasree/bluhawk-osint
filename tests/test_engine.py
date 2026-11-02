"""Tests for subdomain_engine.py.

All network/DNS/TLS is mocked so the suite runs offline. http_get, resolve_hostname
and tls_san_names are the single chokepoints the engine uses, so we monkeypatch
those on the subdomain_engine module.
"""

import json

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
    leads = {l["hostname"] for l in report["unverified_leads"]}

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
def test_learning_recovers_when_crt_down(monkeypatch, tmp_path):
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
    # api-retaileye came from the live source
    assert "api-retaileye.example.com" in validated
    # learning (role api x product retaileye, cross common roles) recovers these
    assert "assets-retaileye.example.com" in validated, \
        "learning should recover assets-retaileye"
    assert "feed-retaileye.example.com" in validated, \
        "learning should recover feed-retaileye"


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
    leads = {l["name"] for l in eng.leads.values()}
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
                                "validated_assets", "unverified_leads",
                                "learned_patterns"}


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
    # noise filtered out
    assert "insights" not in joined      # single generic word
    assert "cybersecurity" not in joined # single generic/marketing word
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
