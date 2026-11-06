#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain-Agnostic Recursive Subdomain Discovery and Intelligence Engine
======================================================================

A passive, domain-agnostic subdomain discovery and intelligence CLI.

Core dependencies: Python standard library only
(urllib, socket, ssl, sqlite3, json, concurrent.futures, argparse,
html.parser).
Optional: dnspython (DNS record mining), openpyxl (XLSX output),
certifi (CA bundle for HTTPS verification).

Safety: passive sources + ordinary DNS lookups + normal public HTTP GETs
only. No port scanning, no exploitation, no brute-force flooding. The
default User-Agent identifies the tool.

Only run against domains you own or are authorised to assess.
"""

from __future__ import annotations

import argparse
import csv
import html as html_module
import json
import os
import re
import socket
import ssl
import sqlite3
import string
import sys
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

# --------------------------------------------------------------------------- optional dependencies
try:
    import certifi
    HAS_CERTIFI = True
except Exception:  # pragma: no cover - certifi is optional
    certifi = None
    HAS_CERTIFI = False

try:
    import dns.resolver
    import dns.exception as _dns_exc
    import dns.rdatatype as _dns_type
    HAS_DNS = True
except Exception:  # pragma: no cover - dnspython is optional
    dns = None
    _dns_exc = Exception
    _dns_type = None
    HAS_DNS = False

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
    HAS_XLSX = True
except Exception:  # pragma: no cover - openpyxl is optional
    openpyxl = None
    get_column_letter = None
    HAS_XLSX = False


# --------------------------------------------------------------------------- constants
USER_AGENT = "BluCloud-Subdomain-Engine/1.0 (passive reconnaissance; identifies itself)"
HTTP_TIMEOUT = 30
MAX_BODY = 2 * 1024 * 1024
CT_TIMEOUT = 30
DEFAULT_DEPTH = 2
DEFAULT_WORKERS = 50
MAX_CANDIDATES_DEFAULT = 600
DEFAULT_TABLE_ROWS = 60
DEFAULT_NEW_DAYS = 0

CT_SOURCES = ("ct", "certspotter")

GENERIC_WORDS = {
    "home", "contact", "about", "services", "service", "products", "product",
    "solutions", "solution", "platform", "feature", "features", "pricing",
    "blog", "news", "careers", "jobs", "login", "signin", "signup", "register",
    "logout", "sign-out", "signout", "help", "support", "docs", "documentation",
    "api", "dev", "test", "staging", "admin", "administrator", "dashboard",
    "portal", "account", "profile", "settings", "search", "insight", "insights",
    "earnings", "earning", "investor", "investors", "press", "media", "privacy",
    "terms", "legal", "cookie", "cookies", "sitemap", "xml", "www", "app", "web",
    "website", "site", "secure", "security", "cybersecurity", "vpn", "mail",
    "email", "ftp", "cdn", "asset", "assets", "static", "img", "image",
    "images", "video",
}

# CSS properties, HTML/SVG attributes, JS DOM properties/events that appear as
# link/button text or URL slugs on modern websites but are NOT product names.
# These are filtered out of entity extraction to avoid noise like
# mathbackground, maxwidth, meshgradient, mousedown, overflow, etc.
ENTITY_NOISE = {
    # CSS properties
    "margin", "padding", "width", "height", "color", "background", "border",
    "font", "text", "display", "position", "overflow", "margin", "visibility",
    "opacity", "z-index", "transform", "transition", "animation", "flex",
    "grid", "align", "justify", "content", "items", "self", "place", "order",
    "gap", "row", "column", "flow", "wrap", "basis", "grow", "shrink",
    "min-width", "min-height", "max-width", "max-height", "min", "max",
    "border-radius", "border-color", "border-style", "border-width",
    "box-shadow", "box-sizing", "cursor", "outline", "resize", "scroll",
    "scroll-behavior", "tab-size", "user-select", "white-space", "word-break",
    "word-wrap", "writing-mode", "hyphens", "line-height", "letter-spacing",
    "text-align", "text-decoration", "text-indent", "text-justify",
    "text-orientation", "text-overflow", "text-rendering", "text-shadow",
    "text-transform", "vertical-align", "list-style", "marker", "outline",
    "filter", "backdrop-filter", "mix-blend-mode", "isolation", "mask",
    "mask-type", "clip", "clip-path", "shape-image-threshold",
    "shape-margin", "shape-outside", "object-fit", "object-position",
    "image-rendering", "pointer-events", "touch-action", "user-select",
    # MathML attributes
    "mathbackground", "mathcolor", "mathsize", "mathvariant", "mathalign",
    "mathstyle", "mathsize", "decimalpoint", "denomalign", "mathaccent",
    "mathaccentunder", "mathcolor", "mathdepth", "mathsize", "mathstyle",
    "mathvariant", "movablelimits", "selection", "shift", "subscriptshift",
    "supscriptshift", "underline", "overline", "strike", "radical",
    # SVG attributes
    "accent-height", "accumulate", "additive", "alignment-baseline",
    "ascent", "attributeName", "attributeType", "azimuth", "baseFrequency",
    "baseProfile", "baseline-shift", "bbox", "begin", "bias", "by", "calcMode",
    "cap-height", "class", "clip-path", "clip-rule", "clipPathUnits",
    "color-interpolation", "color-interpolation-filters", "color-profile",
    "color-rendering", "contentScriptType", "contentStyleType", "cursor",
    "cx", "cy", "d", "decelerate", "descent", "diffuseConstant", "direction",
    "display", "divisor", "dur", "dx", "dy", "edgeMode", "elevation",
    "enable-background", "end", "exponent", "externalResourcesRequired",
    "fill", "fill-opacity", "fill-rule", "filter", "filterRes", "filterUnits",
    "flood-color", "flood-opacity", "focusable", "font-family", "font-size",
    "font-size-adjust", "font-stretch", "font-style", "font-variant",
    "font-weight", "format", "from", "fr", "fx", "fy", "g1", "g2",
    "glyph-name", "glyph-orientation-horizontal", "glyph-orientation-vertical",
    "glyphRef", "gradientTransform", "gradientUnits", "hanging", "height",
    "href", "horiz-adv-x", "horiz-origin-x", "id", "alphabetic", "arabic",
    "ideographic", "mathematical", "image-rendering", "in", "in2",
    "intercept", "k", "k1", "k2", "k3", "k4", "kernelMatrix", "kernelUnitLength",
    "kerning", "keyPoints", "keySplines", "keyTimes", "lang", "lengthAdjust",
    "letter-spacing", "kernel", "key", "keyTimes", "lighting-color", "limitingConeAngle",
    "local", "marker-end", "marker-mid", "marker-start", "markerHeight",
    "markerUnits", "markerWidth", "mask", "maskContentUnits", "maskUnits",
    "mathematical", "max", "media", "method", "min", "mode", "name", "numOctaves",
    "offset", "opacity", "operator", "order", "orient", "orientation", "origin",
    "overflow", "overline-position", "overline-thickness", "panose-1",
    "path", "pathLength", "patternContentUnits", "patternTransform",
    "patternUnits", "ping", "pixels", "points", "pointsAtX", "pointsAtY",
    "pointsAtZ", "preserveAlpha", "preserveAspectRatio", "primitiveUnits",
    "r", "radius", "refX", "refY", "rendering-intent", "repeatCount",
    "repeatDur", "requiredExtensions", "requiredFeatures", "restart",
    "result", "rotate", "rx", "ry", "scale", "seed", "shape-rendering",
    "slope", "spacing", "specularConstant", "specularExponent", "speed",
    "spreadMethod", "startOffset", "stdDeviation", "stemh", "stemv",
    "stitchTiles", "stop-color", "stop-opacity", "strikethrough-position",
    "strikethrough-thickness", "string", "stroke", "stroke-dasharray",
    "stroke-dashoffset", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
    "stroke-opacity", "stroke-width", "surfaceScale", "targetX", "targetY",
    "text-anchor", "text-decoration", "text-rendering", "to", "transform",
    "transform-origin", "u1", "u2", "underline-position", "underline-thickness",
    "unicode", "unicode-bidi", "units-per-em", "v-alphabetic", "v-hanging",
    "v-ideographic", "v-mathematical", "values", "version", "vert-adv-y",
    "vert-origin-x", "vert-origin-y", "viewBox", "visibility", "width",
    "word-spacing", "writing-mode", "x", "x-height", "x1", "x2", "xChannelSelector",
    "xlink-actuate", "xlink:arcrole", "xlink:href", "xlink:role", "xlink:show",
    "xlink:title", "xlink:type", "xml:base", "xml:lang", "xml:space", "y",
    "y1", "y2", "yChannelSelector", "z", "zoomAndPan",
    # JS / DOM / HTML common terms
    "script", "style", "div", "span", "nav", "section", "article", "header",
    "footer", "main", "aside", "figure", "figcaption", "details", "summary",
    "dialog", "menu", "menuitem", "meter", "progress", "output", "datalist",
    "keygen", "output", "picture", "source", "track", "video", "audio",
    "canvas", "svg", "math", "iframe", "embed", "object", "param", "applet",
    "audio", "video", "map", "area", "br", "wbr", "hr", "pre", "code", "samp",
    "kbd", "var", "sub", "sup", "i", "b", "u", "em", "strong", "small",
    "mark", "ruby", "rt", "rp", "bdi", "bdo", "span", "br", "blockquote",
    "q", "cite", "dfn", "abbr", "address", "ins", "del", "time", "sup",
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
    "onmousemove", "onmouseout", "onmouseenter", "onmouseleave", "onmousewheel",
    "onkeydown", "onkeyup", "onkeypress", "onfocus", "onblur", "onfocusin",
    "onfocusout", "onload", "onunload", "onabort", "onerror", "onscroll",
    "onresize", "onsubmit", "onreset", "onchange", "onselect", "oninput",
    "oninvalid", "onsearch", "onbeforeunload", "onhashchange", "onmessage",
    "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate",
    "onstorage", "ontoggle", "onwheel", "onshow", "oncontextmenu",
    "onformdata", "onpointerdown", "onpointerup", "onpointermove",
    "onpointerenter", "onpointerleave", "onpointerover", "onpointerout",
    "onpointercancel", "ongotpointercapture", "onlostpointercapture",
    "onanimationstart", "onanimationend", "onanimationiteration",
    "ontransitionstart", "ontransitionend", "ontransitionrun",
    "ontransitioncancel", "onbeforeinput", "oncopy", "oncut", "onpaste",
    "onbeforecopy", "onbeforecut", "onbeforepaste", "ondragstart", "ondrag",
    "ondragend", "ondragenter", "ondragleave", "ondragover", "ondrop",
    "oncompositionstart", "oncompositionupdate", "oncompositionend",
    "oncanplay", "oncanplaythrough", "ondurationchange", "onemptied",
    "onended", "onerror", "onloadeddata", "onloadedmetadata", "onloadstart",
    "onpause", "onplay", "onplaying", "onprogress", "onratechange",
    "onseeked", "onseeking", "onstalled", "onsuspend", "ontimeupdate",
    "onvolumechange", "onwaiting", "ontouchstart", "ontouchmove",
    "ontouchend", "ontouchcancel", "webkit", "moz", "ms", "o",
    # Common single words from UI that are not products
    "home", "about", "contact", "services", "products", "product",
    "solutions", "solution", "platform", "feature", "features", "pricing",
    "blog", "news", "careers", "jobs", "login", "signin", "signup", "register",
    "logout", "help", "support", "docs", "documentation", "search",
    "privacy", "terms", "legal", "cookie", "cookies", "sitemap",
    "secure", "security", "vpn", "mail", "email", "ftp", "cdn",
    "asset", "assets", "static", "img", "image", "images", "video",
    "press", "media", "insight", "insights", "earnings", "investor",
    "investors", "portal", "dashboard", "account", "profile", "settings",
    "administrator", "remote", "demo", "alpha", "beta", "test", "qa", "uat",
    "staging", "dev", "api", "admin", "app", "www", "web", "site", "website",
}

MAX_ENTITY_WORDS = 3
ENTITY_MIN_CHARS = 2

SERVICE_LABELS_ROOT = [
    "www", "api", "dev", "staging", "adm", "admin", "app", "apps", "cdn",
    "assets", "static", "media", "mail", "email", "smtp", "imap", "pop3",
    "vpn", "remote", "portal", "dashboard", "test", "qa", "uat", "beta",
    "alpha", "demo", "www2", "api-dev", "api-staging", "ns1", "ns2",
]

CHILD_LABELS = ["api", "dev", "test", "staging", "qa", "uat", "beta",
                "admin", "app", "www"]

LEARNING_ROLES = [
    "api", "app", "dev", "staging", "assets", "feed", "gmr", "admin", "mail",
    "vpn", "cdn", "www", "web", "remote", "portal", "beta", "test", "qa", "uat",
    "ns1", "ns2",
]

EXPLICIT_SOURCES = {
    "ct", "certspotter", "otx", "anubis", "subdomain.center",
    "hackertarget", "cdx", "urlscan", "tls", "dns-record",
    "website", "js", "import", "seed",
}

# Sources that represent real discovered hostnames (CT / passive DNS / TLS).
# Learning is fed ONLY from these — never from website slugs, brand stems,
# service labels, or the domain's own name.
REAL_LEARNING_SOURCES = {
    "ct", "certspotter", "otx", "anubis", "subdomain.center",
    "hackertarget", "cdx", "urlscan", "tls",
}



# --------------------------------------------------------------------------- small helpers
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_name(name):
    """Lowercase, strip trailing dot and leading '*.', IDNA-normalise."""
    if not name:
        return None
    name = str(name).strip().lower()
    if name.startswith("*."):
        name = name[2:]
    if name.endswith("."):
        name = name[:-1]
    name = name.strip()
    if not name:
        return None
    try:
        name = name.encode("idna").decode("ascii").lower()
    except Exception:
        pass
    return name or None


def is_in_scope(name, domain):
    n = normalize_name(name)
    d = normalize_name(domain)
    if not n or not d:
        return False
    return n == d or n.endswith("." + d)


def registrable_label(domain):
    d = normalize_name(domain)
    if not d:
        return ""
    return d.split(".")[0]


def split_into_words(label):
    """Split a registrable label into words using a small vocab.

    Greedy longest-match against the vocab; fall back to the whole label
    (longest partial split) when no multi-character vocab word matched,
    rather than emitting meaningless single characters.
    """
    label = label.lower()
    words = []
    i = 0
    n = len(label)
    multi = False
    while i < n:
        matched = False
        for length in range(min(12, n - i), 0, -1):
            piece = label[i:i + length]
            if piece in BRAND_VOCAB or length == 1:
                words.append(piece)
                if length > 1:
                    multi = True
                i += length
                matched = True
                break
        if not matched:
            i += 1
    if not multi and label and len(label) > 1:
        return [label]
    return [w for w in words if w]


# --------------------------------------------------------------------------- network chokepoint (single mockable entry point)
def http_get(url, timeout=HTTP_TIMEOUT, max_bytes=MAX_BODY, insecure=False):
    """Single HTTP GET chokepoint.

    Returns (status_code_or_None, body_text_or_None, error_or_None).
    Every network call in this module funnels through here so tests can mock
    http_get in one place, and so timeouts / size limits / error capture are
    consistent.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif HAS_CERTIFI:
        try:
            ctx.load_verify_locations(certifi.where())
        except Exception:
            pass
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            status = getattr(resp, "status", None)
            if status is None:
                status = resp.getstatus()
            raw = resp.read(max_bytes)
            body = raw.decode("utf-8", errors="replace")
            return status, body, None
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body, str(e)
    except URLError as e:
        msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in msg.upper() or "ssl" in msg.lower():
            msg = msg + " (hint: install certifi via 'python -m pip install certifi' or use --insecure-api)"
        return None, None, msg
    except Exception as e:
        return None, None, str(e)


# --------------------------------------------------------------------------- passive discovery sources
def fetch_crt_sh(domain, insecure=False):
    """crt.sh certificate transparency. Two URL forms, max 2 attempts each,
    502/503/504 treated as service down (fail fast, never blocks others).

    Returns (names: list[str], first_seen: dict[str, datetime|None], error_or_None).
    first_seen maps hostname -> earliest certificate timestamp if available.
    """
    names = []
    first_seen = {}
    forms = [
        "https://crt.sh/?q=%25.{0}&output=json".format(domain),
        "https://crt.sh/?q={0}&output=json".format(domain),
    ]
    for url in forms:
        for _attempt in range(2):
            status, body, err = http_get(url, timeout=CT_TIMEOUT, insecure=insecure)
            if err is not None and status is None:
                break
            if status in (502, 503, 504):
                break
            if status == 200 and body:
                try:
                    data = json.loads(body)
                except Exception:
                    data = []
                for row in data:
                    nv = row.get("name_value") if isinstance(row, dict) else None
                    if not nv and isinstance(row, str):
                        nv = row
                    ts = None
                    if isinstance(row, dict):
                        ts_raw = row.get("entry_timestamp") or row.get("not_before")
                        if ts_raw:
                            try:
                                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                            except Exception:
                                try:
                                    ts = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
                                    ts = ts.replace(tzinfo=timezone.utc)
                                except Exception:
                                    ts = None
                    if nv:
                        for part in str(nv).split("\n"):
                            nn = normalize_name(part)
                            if nn and is_in_scope(nn, domain):
                                names.append(nn)
                                if nn not in first_seen or (ts and first_seen[nn] and ts < first_seen[nn]):
                                    first_seen[nn] = ts
                                elif nn not in first_seen:
                                    first_seen[nn] = ts
                return names, first_seen, None
            break
    return names, first_seen, "crt.sh: service down or no usable response"


def fetch_crt_name(domain, insecure=False):
    """crt.name certificate transparency fallback (used when crt.sh is down).

    Returns (names: list[str], first_seen: dict[str, datetime|None], error_or_None).
    """
    names = []
    first_seen = {}
    forms = [
        "https://crt.name/?q=%25.{0}&output=json".format(domain),
        "https://crt.name/?q={0}&output=json".format(domain),
        "https://crt.name/api/v1/search?q={0}".format(domain),
    ]
    for url in forms:
        for _attempt in range(2):
            status, body, err = http_get(url, timeout=CT_TIMEOUT, insecure=insecure)
            if err is not None and status is None:
                break
            if status in (502, 503, 504):
                break
            if status == 200 and body:
                try:
                    data = json.loads(body)
                except Exception:
                    data = []
                rows = data if isinstance(data, list) else data.get("data", [])
                for row in rows:
                    nv = row.get("name_value") or row.get("common_name") or row.get("domain") if isinstance(row, dict) else None
                    if not nv and isinstance(row, str):
                        nv = row
                    ts = None
                    if isinstance(row, dict):
                        ts_raw = row.get("entry_timestamp") or row.get("not_before") or row.get("created_at")
                        if ts_raw:
                            try:
                                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                            except Exception:
                                try:
                                    ts = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
                                    ts = ts.replace(tzinfo=timezone.utc)
                                except Exception:
                                    ts = None
                    if nv:
                        for part in str(nv).split("\n"):
                            nn = normalize_name(part)
                            if nn and is_in_scope(nn, domain):
                                names.append(nn)
                                if nn not in first_seen or (ts and first_seen[nn] and ts < first_seen[nn]):
                                    first_seen[nn] = ts
                                elif nn not in first_seen:
                                    first_seen[nn] = ts
                return names, first_seen, None
            break
    return names, first_seen, "crt.name: service down or no usable response"


def fetch_certspotter(domain, insecure=False):
    """Certspotter (paginated, first page primarily).

    Returns (names: list[str], first_seen: dict[str, datetime|None], error_or_None).
    """
    names = []
    first_seen = {}
    url = ("https://api.certspotter.com/v1/issuances?"
           "domain={0}&include_subdomains=true&expand=dns_names").format(domain)
    try:
        for _page in range(3):
            status, body, err = http_get(url, timeout=CT_TIMEOUT, insecure=insecure)
            if err is not None or status != 200:
                break
            try:
                data = json.loads(body)
            except Exception:
                break
            if not isinstance(data, list):
                break
            for issuance in data:
                ts = None
                ts_raw = issuance.get("not_before")
                if ts_raw:
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    except Exception:
                        ts = None
                for dn in issuance.get("dns_names", []) or []:
                    nn = normalize_name(dn)
                    if nn and is_in_scope(nn, domain):
                        names.append(nn)
                        if nn not in first_seen or (ts and first_seen[nn] and ts < first_seen[nn]):
                            first_seen[nn] = ts
                        elif nn not in first_seen:
                            first_seen[nn] = ts
            break
    except Exception as e:
        return names, first_seen, "certspotter: {0}".format(e)
    return names, first_seen, None


def fetch_otx(domain, insecure=False):
    """AlienVault OTX passive DNS."""
    names = []
    url = "https://otx.alienvault.com/api/v1/indicators/domain/{0}/passive_dns".format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return names, "otx: {0}".format(err or "http {0}".format(status))
    try:
        data = json.loads(body)
    except Exception:
        return names, "otx: invalid json"
    for rec in data.get("passive_dns", []) or []:
        host = rec.get("hostname") or rec.get("address")
        nn = normalize_name(host)
        if nn and is_in_scope(nn, domain):
            names.append(nn)
    return names, None


def fetch_anubis(domain, insecure=False):
    """AnubisDB subdomains."""
    names = []
    url = "https://jldc.me/anubis/subdomains/{0}".format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return names, "anubis: {0}".format(err or "http {0}".format(status))
    try:
        data = json.loads(body)
    except Exception:
        return names, "anubis: invalid json"
    if isinstance(data, list):
        for item in data:
            nn = normalize_name(item if isinstance(item, str) else str(item))
            if nn and is_in_scope(nn, domain):
                names.append(nn)
    elif isinstance(data, dict):
        for item in data.get("subdomains", []) or []:
            nn = normalize_name(item)
            if nn and is_in_scope(nn, domain):
                names.append(nn)
    return names, None


def fetch_subdomain_center(domain, insecure=False):
    """subdomain.center API."""
    names = []
    url = "https://api.subdomain.center/?q={0}".format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return names, "subdomain.center: {0}".format(err or "http {0}".format(status))
    try:
        data = json.loads(body)
    except Exception:
        return names, "subdomain.center: invalid json"
    if isinstance(data, list):
        for item in data:
            nn = normalize_name(item)
            if nn and is_in_scope(nn, domain):
                names.append(nn)
    elif isinstance(data, dict):
        for key in ("subdomains", "results", "data"):
            val = data.get(key)
            if isinstance(val, list):
                for item in val:
                    nn = normalize_name(item if isinstance(item, str) else str(item))
                    if nn and is_in_scope(nn, domain):
                        names.append(nn)
    return names, None


def fetch_hackertarget(domain, insecure=False):
    """HackerTarget hostsearch (returns 'host,ip' lines)."""
    names = []
    url = "https://api.hackertarget.com/hostsearch/?q={0}".format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return names, "hackertarget: {0}".format(err or "http {0}".format(status))
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        host = line.split(",")[0].split()[0]
        nn = normalize_name(host)
        if nn and is_in_scope(nn, domain):
            names.append(nn)
    return names, None


def fetch_cdx(domain, insecure=False):
    """Internet Archive CDX: hostnames embedded in archived URLs."""
    names = []
    url = ("https://web.archive.org/cdx/search/cdx?"
           "url=*.{0}/*&output=text&fl=original&collapse=urlkey&limit=5000").format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, max_bytes=MAX_BODY, insecure=insecure)
    if err is not None or status != 200:
        return names, "cdx: {0}".format(err or "http {0}".format(status))
    for m in re.finditer(r"https?://([^/?#]+)", body, re.I):
        nn = normalize_name(m.group(1))
        if nn and is_in_scope(nn, domain):
            names.append(nn)
    return names, None


def fetch_urlscan(domain, insecure=False):
    """urlscan.io search for domain."""
    names = []
    url = "https://urlscan.io/api/v1/search/?q=domain:{0}".format(domain)
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return names, "urlscan: {0}".format(err or "http {0}".format(status))
    try:
        data = json.loads(body)
    except Exception:
        return names, "urlscan: invalid json"
    for rec in data.get("results", []) or []:
        task = rec.get("task", {}) or {}
        host = task.get("domain") or task.get("url")
        if isinstance(host, str) and host.startswith("http"):
            host = urlparse(host).hostname
        nn = normalize_name(host)
        if nn and is_in_scope(nn, domain):
            names.append(nn)
        page = rec.get("page", {}) or {}
        nn = normalize_name(page.get("domain", ""))
        if nn and is_in_scope(nn, domain):
            names.append(nn)
    return names, None


PASSIVE_SOURCES = [
    ("ct", fetch_crt_sh),
    ("crt.name", fetch_crt_name),
    ("certspotter", fetch_certspotter),
    ("otx", fetch_otx),
    ("anubis", fetch_anubis),
    ("subdomain.center", fetch_subdomain_center),
    ("hackertarget", fetch_hackertarget),
    ("cdx", fetch_cdx),
    ("urlscan", fetch_urlscan),
]


def run_passive_sources(domain, insecure=False, no_ct=False, max_workers=DEFAULT_WORKERS,
                        statuses=None):
    """Query every passive source in parallel. Returns dict name -> set of
    source tags that reported it, plus a first_seen dict name -> datetime.
    Logs each source clearly; one dead source never stops the run."""
    results = defaultdict(set)
    first_seen = {}
    lock = threading.Lock()

    def run_source(tag, func):
        if tag in CT_SOURCES and no_ct:
            print(f"[passive] {tag}: skipped (--no-ct)")
            if statuses is not None:
                statuses[tag] = {"status": "skipped", "error": "--no-ct"}
            return
        try:
            result = func(domain, insecure=insecure)
            # CT sources now return (names, first_seen, err); others return (names, err)
            if len(result) == 3:
                names, name_ts, err = result
            else:
                names, err = result
                name_ts = {}
        except Exception as e:  # never let one source kill the run
            names, err = [], "{0}".format(e)
            name_ts = {}
        with lock:
            if err:
                print(f"[passive] {tag}: FAILED - {err}")
                if statuses is not None:
                    statuses[tag] = {"status": "failed", "error": str(err)}
            else:
                print(f"[passive] {tag}: OK - {len(names)} name(s)")
                if statuses is not None:
                    statuses[tag] = {"status": "ok", "count": len(names)}
                for nn in names:
                    results[nn].add(tag)
                    if nn in name_ts and name_ts[nn]:
                        prev = first_seen.get(nn)
                        if prev is None or name_ts[nn] < prev:
                            first_seen[nn] = name_ts[nn]

    with ThreadPoolExecutor(max_workers=min(max_workers, len(PASSIVE_SOURCES))) as ex:
        futures = [ex.submit(run_source, tag, func) for tag, func in PASSIVE_SOURCES]
        for fut in as_completed(futures):
            try:
                fut.result()
            except KeyboardInterrupt:
                raise
            except Exception:
                pass
    return dict(results), first_seen


# --------------------------------------------------------------------------- TLS SAN harvesting
def tls_san_names(hostname, port=443, timeout=10, insecure=False):
    """TLS handshake to port 443; return SAN DNS names."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif HAS_CERTIFI:
        try:
            ctx.load_verify_locations(certifi.where())
        except Exception:
            pass
    names = []
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    for key, val in cert.get("subjectAltName", ()) or ():
        if key == "DNS":
            nn = normalize_name(val)
            if nn:
                names.append(nn)
    return names


# --------------------------------------------------------------------------- DNS resolution (mockable in tests)
def resolve_hostname(name):
    """Resolve A/AAAA/CNAME. Returns (ips:list[str], cname:str|None).

    Without dnspython we use socket.getaddrinfo for A/AAAA and attempt a
    CNAME lookup only when dnspython is installed. Raises OSError on failure.
    """
    ips = []
    cname = None
    if HAS_DNS:
        try:
            answers = dns.resolver.resolve(name, "CNAME", lifetime=10)
            for r in answers:
                cname = normalize_name(r.target.to_text())
        except Exception:
            cname = None
        try:
            answers = dns.resolver.resolve(name, "A", lifetime=10)
            for r in answers:
                ips.append(r.address)
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(name, "AAAA", lifetime=10)
            for r in answers:
                ips.append(r.address)
        except Exception:
            pass
    else:
        try:
            infos = socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    ips.append(addr)
        except Exception:
            ips = []
    if not ips and not cname:
        raise OSError("no records for {0}".format(name))
    return ips, cname


def detect_wildcard(domain, workers=8):
    """Probe random labels beneath `domain`; return the set of IPs that
    resolve for random labels (the wildcard answer) or an empty set."""
    import random
    wild_ips = set()
    trials = []
    for _ in range(5):
        label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        trials.append("{0}.{1}".format(label, domain))
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_to_label = {ex.submit(resolve_hostname, t): t for t in trials}
            for fut in as_completed(future_to_label):
                try:
                    ips, _ = fut.result()
                    wild_ips.update(ips)
                except Exception:
                    pass
    except KeyboardInterrupt:
        raise
    return wild_ips


# --------------------------------------------------------------------------- website analysis
class _LinkExtractor(HTMLParser):
    """Collect anchor texts, hrefs, heading/button texts and script srcs."""
    def __init__(self):
        super().__init__()
        self.anchor_texts = []
        self.hrefs = []
        self.headings = []
        self.buttons = []
        self.scripts = []
        self._stack = []

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "a":
            self._stack.append("a")
            self.hrefs.append(attr.get("href", ""))
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._stack.append(tag)
        elif tag == "button":
            self._stack.append("button")
        elif tag == "script":
            src = attr.get("src", "")
            if src:
                self.scripts.append(src)

    def handle_endtag(self, tag):
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_data(self, data):
        if not data.strip():
            return
        text = data.strip()
        if self._stack and self._stack[-1] in ("a", "h1", "h2", "h3", "h4", "h5", "h6", "button"):
            if self._stack[-1] == "a":
                self.anchor_texts.append(text)
            elif self._stack[-1] == "button":
                self.buttons.append(text)
            else:
                self.headings.append(text)


def _fetch_text(url, insecure):
    status, body, err = http_get(url, timeout=HTTP_TIMEOUT, insecure=insecure)
    if err is not None or status != 200:
        return None
    return body


def _extract_hostnames(text, domain):
    """Find hostnames in raw text; also handle escaped slashes in JS."""
    if not text:
        return []
    text = text.replace("\\/", "/")
    tokens = set()
    dom = normalize_name(domain)
    pattern = re.escape(dom)
    for m in re.finditer(r"([A-Za-z0-9_\-]+\.)+" + pattern + r"\b", text, re.I):
        nn = normalize_name(m.group(0))
        if nn:
            tokens.add(nn)
    return list(tokens)


def analyze_website(hostname, domain, insecure=False):
    """Fetch /, /robots.txt, /sitemap.xml, crawl ~10 same-host pages, ~12 JS bundles.

    Returns (hostnames, entities, keywords). Entities are (joined, hyphenated)
    tuples derived from nav anchors, buttons, headings and URL slugs.
    """
    hostnames = set()
    external_domains = set()
    entity_texts = []
    keywords = defaultdict(int)
    base = "https://{0}".format(hostname)
    visited = set()
    to_crawl = deque([base + "/"])
    js_seen = set()
    js_queue = deque()

    def handle_html(html_text, source_url):
        if not html_text:
            return
        parser = _LinkExtractor()
        try:
            parser.feed(html_text)
        except Exception:
            pass
        for u in parser.hrefs + parser.scripts:
            abs_url = urljoin(source_url, u)
            p = urlparse(abs_url)
            h = normalize_name(p.hostname or "")
            if h and is_in_scope(h, domain):
                hostnames.add(h)
            elif h and p.scheme in ("http", "https") and "." in h:
                # Keep external company/product domains as related leads; do not
                # validate or crawl them from this in-scope investigation.
                if not any(x in h for x in ("facebook.com", "linkedin.com", "twitter.com", "instagram.com", "youtube.com")):
                    external_domains.add(h)
            if h == normalize_name(hostname) and p.scheme in ("http", "https"):
                clean_url = p._replace(fragment="").geturl()
                if (clean_url not in visited and clean_url not in to_crawl and
                        not re.search(r"\.(?:pdf|png|jpe?g|gif|svg|css|js|zip|mp4|woff2?)$", p.path, re.I)):
                    to_crawl.append(clean_url)
            if p.path.lower().endswith(".js"):
                if abs_url not in js_seen:
                    js_seen.add(abs_url)
                    js_queue.append(abs_url)
        entity_texts.extend(parser.anchor_texts)
        entity_texts.extend(parser.headings)
        entity_texts.extend(parser.buttons)

    def fetch_and_handle(url):
        body = _fetch_text(url, insecure)
        if body is not None:
            handle_html(body, url)

    # Homepage is consumed by the same queue as every other page so its links
    # are actually enqueued and deeply nested product/docs links are reachable.

    disallowed_paths = set()
    body = _fetch_text(base + "/robots.txt", insecure)
    if body:
        for m in re.finditer(r"Disallow:\s*(\S+)", body, re.I):
            disallowed_paths.add(m.group(1))

    sitemap_urls = [base + "/sitemap.xml"]
    if body:
        sitemap_urls.extend(urljoin(base + "/", x) for x in re.findall(r"(?im)^Sitemap:\s*(\S+)", body))
    sitemap_seen = set()
    while sitemap_urls and len(sitemap_seen) < 20:
        sitemap_url = sitemap_urls.pop(0)
        if sitemap_url in sitemap_seen:
            continue
        sitemap_seen.add(sitemap_url)
        xml = _fetch_text(sitemap_url, insecure)
        if not xml:
            continue
        for loc in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", xml, re.I | re.S):
            loc = html_module.unescape(loc.strip())
            p = urlparse(loc)
            h = normalize_name(p.hostname or "")
            if h and is_in_scope(h, domain):
                hostnames.add(h)
                if p.path.lower().endswith(".xml"):
                    sitemap_urls.append(loc)
                elif h == normalize_name(hostname) and loc not in to_crawl:
                    to_crawl.append(loc)

    crawled = 0
    while to_crawl and crawled < 40:
        url = to_crawl.popleft()
        if url in visited:
            continue
        p = urlparse(url)
        if normalize_name(p.hostname or "") != normalize_name(hostname):
            continue
        if any(path and path != "/" and p.path.startswith(path) for path in disallowed_paths):
            continue
        visited.add(url)
        body = _fetch_text(url, insecure)
        if body is None:
            continue
        crawled += 1
        handle_html(body, url)
        parser = _LinkExtractor()
        try:
            parser.feed(body)
        except Exception:
            pass
        for u in parser.hrefs:
            abs_url = urljoin(url, u)
            pp = urlparse(abs_url)
            if normalize_name(pp.hostname or "") == normalize_name(hostname):
                if abs_url not in visited and abs_url not in to_crawl:
                    to_crawl.append(abs_url)

    js_fetched = 0
    while js_queue and js_fetched < 12:
        js_url = js_queue.popleft()
        body = _fetch_text(js_url, insecure)
        if body is None:
            continue
        js_fetched += 1
        hostnames.update(_extract_hostnames(body, domain))

    slug_texts = []
    for u in list(visited):
        p = urlparse(u)
        for seg in p.path.split("/"):
            seg = seg.strip("-_")
            if seg and re.search(r"[A-Za-z]", seg):
                slug_texts.append(seg)

    entities = derive_entities(entity_texts + slug_texts)
    return sorted(hostnames), entities, keywords, sorted(external_domains)


def derive_entities(texts):
    """Turn nav/button/heading/slug text into entity candidates.

    Returns list of (joined, hyphenated) tuples. Noise (phones, hex hashes,
    digit-heavy strings, single generic words, long marketing phrases) is
    filtered out. Entities are never rank-truncated.
    """
    out = []
    seen_joined = set()
    for raw in texts:
        if not raw:
            continue
        text = html_module.unescape(raw).strip()
        words = re.findall(r"[A-Za-z0-9]+", text)
        if not words:
            continue
        if len(words) > MAX_ENTITY_WORDS:
            continue
        # skip entities containing an all-digit token (version / phone noise)
        if any(w.isdigit() for w in words):
            continue
        joined = "".join(w.lower() for w in words)
        hyphenated = "-".join(w.lower() for w in words)
        if len(joined) < ENTITY_MIN_CHARS:
            continue
        if re.fullmatch(r"[0-9a-f]{6,}", joined):
            continue
        if re.fullmatch(r"[\d\s\-\+\(\)]{7,}", joined):
            continue
        low = text.lower()
        if len(words) == 1 and joined in GENERIC_WORDS:
            continue
        # filter out CSS/HTML/SVG/JS noise terms
        if joined in ENTITY_NOISE:
            continue
        if joined in seen_joined:
            continue
        seen_joined.add(joined)
        out.append((joined, hyphenated))
    return out


# --------------------------------------------------------------------------- DNS record mining
def dns_mine(hostname):
    """Hostnames found inside MX/NS/TXT/SOA records (dnspython only)."""
    if not HAS_DNS:
        return []
    names = []
    for rtype in ("MX", "NS", "TXT", "SOA"):
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=10)
        except Exception:
            continue
        for r in answers:
            target = getattr(r, "exchange", None) or getattr(r, "target", None)
            if target:
                nn = normalize_name(target.to_text())
                if nn:
                    names.append(nn)
            text = r.to_text()
            for m in re.finditer(
                r"(?:include|a|mx|exists):([A-Za-z0-9.\-]+)", text, re.I
            ):
                nn = normalize_name(m.group(1).rstrip("."))
                if nn:
                    names.append(nn)
            for m in re.finditer(
                r"\b([A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+)\b",
                text,
            ):
                nn = normalize_name(m.group(1))
                if nn and "." in nn:
                    names.append(nn)
    return names


# --------------------------------------------------------------------------- pattern learning
def learn_patterns(evidenced_names, domain, max_rounds=2):
    """From evidenced names learn role/product conventions and propose
    role-<product> / <product>-role / bare-product candidates.

    Only hyphenated hostnames (e.g. api-retaileye) may teach roles/products.
    Single-label hosts (adm, app, www, mb, visakhaiccc) must NEVER become
    product tokens.
    """
    products = set()
    roles = set()
    for name in evidenced_names:
        label = normalize_name(name).split(".")[0]
        # Only hyphenated labels teach conventions; single labels are ignored.
        if "-" not in label:
            continue
        left, right = label.split("-", 1)
        # Convention: left token is a role, right token is a product.
        # Both must be alphabetic to be meaningful.
        if left.isalpha():
            roles.add(left)
        if right.isalpha():
            products.add(right)

    learned_candidates = set()
    for _ in range(max_rounds):
        for prod in products:
            learned_candidates.add("{0}.{1}".format(prod, domain))
            for role in (roles | set(LEARNING_ROLES)):
                learned_candidates.add("{0}-{1}.{2}".format(role, prod, domain))
                learned_candidates.add("{1}-{0}.{2}".format(prod, role, domain))
    return learned_candidates, sorted(roles), sorted(products)


# --------------------------------------------------------------------------- candidate generation
def generate_candidates(domain, validated_hosts, entities, seeds, wordlist_names,
                        imported_names, learned_candidates, max_candidates):
    """Build the candidate set tagged by origin. Returns dict name -> set(origins)."""
    candidates = defaultdict(set)

    # website entities (beneath hosts are handled in the BFS; here we keep the
    # root-level entity forms too)
    for ent in entities:
        candidates[ent].add("website product")
        hy = ent  # hyphenated form already produced by derive_entities caller
        candidates[hy].add("website product")

    for s in seeds:
        nn = normalize_name(s)
        if nn and is_in_scope(nn, domain):
            candidates[nn].add("seed")

    for s in imported_names:
        nn = normalize_name(s)
        if nn and is_in_scope(nn, domain):
            candidates[nn].add("import")

    # common service labels at root
    for lab in SERVICE_LABELS_ROOT:
        cand = "{0}.{1}".format(lab, domain)
        nn = normalize_name(cand)
        if nn and is_in_scope(nn, domain):
            candidates[nn].add("service label")

    # wordlist (never truncated)
    for line in wordlist_names:
        nn = normalize_name(line)
        if nn and is_in_scope(nn, domain):
            candidates[nn].add("wordlist")

    # learned candidates (already fully qualified names)
    for cand in learned_candidates:
        nn = normalize_name(cand)
        if nn and is_in_scope(nn, domain):
            candidates[nn].add("learning")

    # generic labels beneath each confirmed host
    for host in validated_hosts:
        if host == domain:
            continue
        for lab in CHILD_LABELS:
            cand = "{0}.{1}".format(lab, host)
            nn = normalize_name(cand)
            if nn and is_in_scope(nn, domain):
                candidates[nn].add("child label")

    # cap candidates (never truncate seed / import / wordlist / learning)
    if len(candidates) > max_candidates:
        ordered = sorted(candidates.items(),
                         key=lambda kv: (0 if kv[1] & {"seed", "import", "wordlist", "learning"} else 1,
                                         kv[0]))
        candidates = dict(ordered[:max_candidates])

    return candidates


# --------------------------------------------------------------------------- validation
def validate_name(name, parent_domain, wildcard_ips, explicit):
    """Validate a name via DNS.

    Returns (ips, cname, confirmed). confirmed=False means the name only
    matches a wildcard answer without explicit evidence (not an asset).
    Raises OSError if it does not resolve.
    """
    ips, cname = resolve_hostname(name)
    if wildcard_ips and set(ips) <= set(wildcard_ips) and not explicit:
        return ips, cname, False
    return ips, cname, True


# --------------------------------------------------------------------------- engine
class Engine:
    def __init__(self, domain, args):
        self.domain = normalize_name(domain)
        self.args = args
        self.lock = threading.RLock()

        # name -> node dict (VALIDATED assets)
        self.nodes = {}
        # name -> lead dict (UNVERIFIED)
        self.leads = {}
        self.external_domains = {}
        # pending observations awaiting validation
        self.pending = {}
        self.order = []
        self.blind_guesses = 0
        self.blind_guess_names = set()

        self.wildcard_cache = {}
        self.stats = {
            "validated": 0,
            "unverified_leads": 0,
            "blind_guesses": 0,
            "sources": {},
        }
        # Per-origin candidate stats: {origin: {generated, tested, resolved, unresolved}}
        self.origin_stats = defaultdict(lambda: {"generated": 0, "tested": 0,
                                                  "resolved": 0, "unresolved": 0})
        # first_seen timestamps from CT/passive sources
        self.first_seen = {}

        self.insecure = bool(getattr(args, "insecure_api", False))

    # -- observation --------------------------------------------------------
    def observe(self, name, parent=None, source=None, detail=None, explicit=False,
                first_seen=None):
        nn = normalize_name(name)
        if not nn:
            return
        if not is_in_scope(nn, self.domain):
            return
        with self.lock:
            if nn not in self.order:
                self.order.append(nn)
            rec = self.pending.setdefault(
                nn, {"parent": parent, "sources": set(), "explicit": False,
                     "details": []}
            )
            if source:
                rec["sources"].add(source)
                self.stats["sources"][source] = self.stats["sources"].get(source, 0) + 1
                self.origin_stats[source]["generated"] += 1
            if explicit:
                rec["explicit"] = True
            if detail:
                rec["details"].append((source, detail))
            if first_seen:
                prev = self.first_seen.get(nn)
                if prev is None or first_seen < prev:
                    self.first_seen[nn] = first_seen

    def _wildcard_ips(self, parent_domain):
        if parent_domain not in self.wildcard_cache:
            self.wildcard_cache[parent_domain] = detect_wildcard(parent_domain)
        return self.wildcard_cache[parent_domain]

    def _make_node(self, name, parent, origin, details, ips, cname):
        with self.lock:
            if name in self.nodes:
                node = self.nodes[name]
                node["origin"] = sorted(set(node["origin"]) | set(origin))
                seen = set(tuple(d) for d in node["evidence"])
                for s, d in details:
                    if (s, d) not in seen:
                        node["evidence"].append((s, d))
                        seen.add((s, d))
                if ips:
                    node["ips"] = sorted(set(node["ips"]) | set(ips))
                if cname and not node["cname"]:
                    node["cname"] = cname
                return
            self.nodes[name] = {
                "name": name, "parent": parent, "validated": True,
                "origin": list(origin), "evidence": list(details),
                "ips": list(ips) if ips else [], "cname": cname,
            }

    def _make_lead(self, name, rec, reason=None, ips=None, cname=None):
        with self.lock:
            if name in self.leads:
                lead = self.leads[name]
                lead["origin"] = sorted(set(lead["origin"]) | set(rec["sources"]))
                seen = set(tuple(d) for d in lead["evidence"])
                for s, d in rec["details"]:
                    if (s, d) not in seen:
                        lead["evidence"].append((s, d))
                        seen.add((s, d))
                return
            self.leads[name] = {
                "name": name, "parent": rec["parent"], "validated": False,
                "origin": sorted(set(rec["sources"])), "evidence": list(rec["details"]),
                "reason": reason, "ips": list(ips) if ips else [],
                "cname": cname, "error": None,
            }

    def flush_pending_as_leads(self):
        """Convert any still-pending observed names (with evidence) into
        unverified leads so nothing fetched is ever thrown away."""
        with self.lock:
            pending = list(self.pending.items())
            self.pending.clear()
        for name, rec in pending:
            if rec["sources"]:
                self._make_lead(name, rec, reason="interrupted before validation")

    def validate_pending(self):
        """Move pending names to validated nodes or unverified leads."""
        with self.lock:
            to_validate = list(self.pending.items())
            # NOTE: we deliberately do NOT clear self.pending here. Each name is
            # popped below as it is processed, so a KeyboardInterrupt leaves the
            # still-unprocessed names in pending (they are later flushed as leads
            # instead of being thrown away).

        def do_one(item):
            name, rec = item
            parent = rec["parent"] or self.domain
            try:
                wild = self._wildcard_ips(parent)
            except Exception:
                wild = set()
            try:
                ips, cname, confirmed = validate_name(
                    name, parent, wild, rec["explicit"])
                return name, rec, ips, cname, confirmed, None
            except Exception as e:
                return name, rec, None, None, False, str(e)

        try:
            with ThreadPoolExecutor(max_workers=self.args.workers) as ex:
                futs = [ex.submit(do_one, item) for item in to_validate]
                for fut in as_completed(futs):
                    try:
                        name, rec, ips, cname, confirmed, err = fut.result()
                    except KeyboardInterrupt:
                        raise
                    except Exception:
                        continue
                    with self.lock:
                        self.pending.pop(name, None)
                        for src in rec["sources"]:
                            self.origin_stats[src]["tested"] += 1
                        if err is not None or ips is None:
                            if rec["sources"]:
                                self._make_lead(name, rec, reason="no DNS record")
                                for src in rec["sources"]:
                                    self.origin_stats[src]["unresolved"] += 1
                            else:
                                self.blind_guesses += 1
                                self.blind_guess_names.add(name)
                            continue
                        if not confirmed:
                            if rec["sources"]:
                                self._make_lead(name, rec,
                                                reason="wildcard-only DNS match",
                                                ips=ips, cname=cname)
                                for src in rec["sources"]:
                                    self.origin_stats[src]["unresolved"] += 1
                            else:
                                self.blind_guesses += 1
                                self.blind_guess_names.add(name)
                                for src in rec["sources"]:
                                    self.origin_stats[src]["unresolved"] += 1
                            continue
                        origin = sorted(set(rec["sources"]))
                        self._make_node(name, rec["parent"], origin,
                                        rec["details"], ips, cname)
                        for src in rec["sources"]:
                            self.origin_stats[src]["resolved"] += 1
        except KeyboardInterrupt:
            raise

    # -- pipeline -----------------------------------------------------------
    def run(self):
        args = self.args
        domain = self.domain

        print("Only run against domains you own or are authorised to assess.")
        print(f"[engine] target: {domain}")

        if domain.count(".") >= 2:
            print(f"[warn] {domain} looks like a subdomain (3+ labels); "
                  f"only hosts beneath it will be searched.")

        # ---- validate the root ----
        root_ips = root_cname = None
        root_valid = False
        try:
            root_ips, root_cname = resolve_hostname(domain)
            root_valid = True
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[warn] input root {domain} does not resolve: {e}; marking it Unverified")
        with self.lock:
            self.nodes[domain] = {
                "name": domain, "parent": None, "validated": root_valid,
                "origin": ["input"], "evidence": [],
                "ips": list(root_ips) if root_ips else [], "cname": root_cname,
            }
        print(f"[root] {domain}: {'VALIDATED' if root_valid else 'UNVERIFIED (does not resolve)'}")

        max_depth = max(0, int(args.depth))
        max_candidates = int(args.max_candidates)

        seeds = [s.strip() for s in (args.seed or "").split(",") if s.strip()]
        wordlist_names = []
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8") as f:
                    wordlist_names = [l.strip() for l in f if l.strip()]
            except OSError as e:
                print(f"[warn] could not read wordlist {args.wordlist}: {e}")
        imported_names = []
        if args.import_names:
            try:
                with open(args.import_names, "r", encoding="utf-8") as f:
                    imported_names = self._extract_imported_names(f.read())
            except OSError as e:
                print(f"[warn] could not read import file {args.import_names}: {e}")

        # ---- depth 0: passive sources (%.root) ----
        new_cutoff = None
        if bool(getattr(args, "new_only", False)) or getattr(args, "new_days", 0) > 0:
            new_days = int(getattr(args, "new_days", DEFAULT_NEW_DAYS))
            new_cutoff = datetime.now(timezone.utc) - timedelta(days=new_days)
            self.new_cutoff = new_cutoff
            print(f"[new-subdomains] filtering to certs issued within last {new_days} day(s) "
                  f"(on/after {new_cutoff.date()})")
        else:
            self.new_cutoff = None

        if not args.no_ct:
            source_status = self.stats.setdefault("source_status", {})
            passive_result = run_passive_sources(domain, insecure=self.insecure,
                                                 no_ct=args.no_ct, max_workers=args.workers,
                                                 statuses=source_status)
            # New run_passive_sources returns (results, first_seen)
            if isinstance(passive_result, tuple) and len(passive_result) == 2:
                passive, passive_first_seen = passive_result
            else:
                passive, passive_first_seen = passive_result, {}
            for name, srcs in passive.items():
                explicit = bool(srcs & EXPLICIT_SOURCES)
                parent = self._nearest_validated_ancestor(name)
                fs = passive_first_seen.get(name)
                for s in srcs:
                    self.observe(name, parent=parent, source=s,
                                 detail="{0} passive source".format(s),
                                 explicit=explicit, first_seen=fs)
        else:
            print("[passive] certificate-transparency sources skipped (--no-ct)")
            self.stats["source_status"] = {
                name: {"status": "skipped", "error": "--no-ct"}
                for name, _func in PASSIVE_SOURCES if name in CT_SOURCES
            }

        try:
            self.validate_pending()
        except KeyboardInterrupt:
            self.flush_pending_as_leads()
            raise

        # ---- BFS recursion: TLS, web, DNS records, children candidates ----
        queue = deque()
        investigated = set()
        if root_valid:
            queue.append((domain, 0))
            # NOTE: do NOT add domain to `investigated` here; the loop adds each
            # host when it is actually processed, otherwise the root would be
            # skipped on its first pop.

        while queue:
            host, depth = queue.popleft()
            if host in investigated:
                continue
            investigated.add(host)
            print(f"[investigate] {host} (depth {depth})")

            # TLS SAN
            if not args.no_tls:
                try:
                    sans = tls_san_names(host, insecure=self.insecure)
                    print(f"[tls] {host}: {len(sans)} SAN name(s)")
                    for sn in sans:
                        if sn and is_in_scope(sn, domain):
                            self.observe(sn, parent=host, source="tls",
                                         detail="tls SAN: {0}".format(sn),
                                         explicit=True)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"[tls] {host}: failed - {e}")

            # Website analysis
            if not args.no_web:
                try:
                    whosts, entities, _keywords, externals = analyze_website(host, domain,
                                                                  insecure=self.insecure)
                    print(f"[web] {host}: {len(whosts)} hostnames, {len(entities)} entities")
                    if entities:
                        ent_names = [e[0] for e in entities[:200]]
                        print(f"[web-entities] {', '.join(ent_names)}")
                    for h in whosts:
                        self.observe(h, parent=host, source="website",
                                     detail="website HTML/JS hostname",
                                     explicit=True)
                    for ext in externals:
                        rec = self.external_domains.setdefault(ext, {
                            "hostname": ext, "related_to": host, "source": "website link",
                            "evidence": [], "first_seen": now_iso()})
                        evidence = {"source": "website link", "detail": "linked from {0}".format(host),
                                    "observed_at": now_iso()}
                        if evidence not in rec["evidence"]:
                            rec["evidence"].append(evidence)
                    for joined, hyphenated in entities:
                        for cand in (joined, hyphenated):
                            nn = normalize_name("{0}.{1}".format(cand, host))
                            if nn and is_in_scope(nn, domain):
                                self.observe(nn, parent=host, source="website product",
                                             detail="website product entity: {0}".format(cand),
                                             explicit=True)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"[web] {host}: failed - {e}")

            try:
                self.validate_pending()
            except KeyboardInterrupt:
                raise

            # DNS record mining
            if HAS_DNS:
                try:
                    recs = dns_mine(host)
                    print(f"[dns-records] {host}: {len(recs)} record hostnames")
                    for r in recs:
                        self.observe(r, parent=host, source="dns-record",
                                     detail="dns-record record: {0}".format(host),
                                     explicit=True)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"[dns-records] {host}: failed - {e}")
                try:
                    self.validate_pending()
                except KeyboardInterrupt:
                    raise

            if depth < max_depth:
                for child in self._direct_validated_children(host):
                    if child not in investigated:
                        queue.append((child, depth + 1))

        # ---- pattern learning (root, up to 2 rounds) ----
        # Only learn from real hostnames discovered via CT / passive DNS / TLS.
        # Never learn from website slugs, brand stems, service labels, or the
        # domain's own name.
        real_evidenced = set()
        with self.lock:
            for name, node in self.nodes.items():
                if name == self.domain:
                    continue
                if any(s in REAL_LEARNING_SOURCES for s, _d in node["evidence"]):
                    real_evidenced.add(name)
            for name, lead in self.leads.items():
                if any(s in REAL_LEARNING_SOURCES for s, _d in lead["evidence"]):
                    real_evidenced.add(name)
        learned_candidates, roles, products = learn_patterns(
            real_evidenced, domain, max_rounds=2)
        self.stats["learned_roles"] = roles
        self.stats["learned_products"] = products
        print(f"[learning] roles={roles} products={products} "
              f"-> {len(learned_candidates)} candidate(s)")

        # ---- candidate generation ----
        all_entities = []
        # gather website entities discovered so far from leads/nodes evidence
        candidates = generate_candidates(
            domain, list(self.nodes.keys()), all_entities, seeds, wordlist_names,
            imported_names, learned_candidates, max_candidates)

        for name, origins in candidates.items():
            explicit = bool(origins & EXPLICIT_SOURCES)
            parent = self._nearest_validated_ancestor(name)
            for o in origins:
                self.observe(name, parent=parent, source=o,
                             detail="{0} candidate".format(o), explicit=explicit)

        try:
            self.validate_pending()
        except KeyboardInterrupt:
            self.flush_pending_as_leads()
            raise

        # --report-all-guesses: list blind guesses as leads too
        if bool(getattr(args, "report_all_guesses", False)):
            with self.lock:
                bgn = list(self.blind_guess_names)
            for name in bgn:
                self._make_lead(name, {"parent": self._nearest_validated_ancestor(name),
                                       "sources": {"blind guess"},
                                       "details": [("blind guess", "generated candidate")]},
                                reason="blind guess (no evidence)")

        with self.lock:
            self.stats["validated"] = len(self.nodes)
            self.stats["unverified_leads"] = len(self.leads)
            self.stats["blind_guesses"] = self.blind_guesses

        # ---- per-origin candidate stats ----
        print("[origin-stats] generated / tested / resolved / unresolved")
        for origin in sorted(self.origin_stats):
            s = self.origin_stats[origin]
            print(f"[origin-stats] {origin:20s} "
                  f"{s['generated']:6d} / {s['tested']:6d} / "
                  f"{s['resolved']:6d} / {s['unresolved']:6d}")

        # ---- new-subdomain filtering (--new-only / --new-days) ----
        if new_cutoff is not None:
            new_names = []
            with self.lock:
                for name in list(self.nodes.keys()):
                    if name == self.domain:
                        continue
                    ts = self.first_seen.get(name)
                    if ts and ts >= new_cutoff:
                        new_names.append(name)
                for name in list(self.leads.keys()):
                    ts = self.first_seen.get(name)
                    if ts and ts >= new_cutoff:
                        new_names.append(name)
            new_names = sorted(set(new_names))
            self.stats["new_subdomains"] = new_names
            self.stats["new_subdomains_count"] = len(new_names)
            print(f"[new-subdomains] {len(new_names)} new subdomain(s) found in last "
                  f"{int((datetime.now(timezone.utc) - new_cutoff).days)} day(s):")
            for n in new_names:
                print(f"  + {n}")
            if bool(getattr(args, "new_only", False)):
                # Keep only new subdomains in nodes/leads
                with self.lock:
                    self.nodes = {n: self.nodes[n] for n in new_names if n in self.nodes}
                    self.leads = {n: self.leads[n] for n in new_names if n in self.leads}
                    # Also keep the root domain if validated
                    if self.domain in self.nodes:
                        self.nodes[self.domain] = self.nodes[self.domain]

        return self._build_report()

    # -- helpers ------------------------------------------------------------
    def _nearest_validated_ancestor(self, name):
        nn = normalize_name(name)
        parts = nn.split(".")
        for i in range(len(parts) - 1, -1, -1):
            cand = ".".join(parts[i:])
            with self.lock:
                if cand in self.nodes and self.nodes[cand]["validated"]:
                    return cand
        return self.domain

    def _direct_validated_children(self, host):
        children = []
        host_suffix = "." + host
        with self.lock:
            for name, node in self.nodes.items():
                if name == host or not node["validated"]:
                    continue
                if name.endswith(host_suffix):
                    prefix = name[: -len(host_suffix)]
                    if "." not in prefix:
                        children.append(name)
        return sorted(children)

    def _extract_imported_names(self, raw):
        names = []
        domain = self.domain
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = line.split()[0]
            host = host.split(",")[0].split("/")[0].split(":")[0]
            nn = normalize_name(host)
            if nn and is_in_scope(nn, domain):
                names.append(nn)
        return names

    # -- reporting ----------------------------------------------------------
    def _build_report(self):
        domain = self.domain
        report_time = now_iso()
        tree_lines = self._render_validated_tree(
            annotate=bool(getattr(self.args, "annotate", False)))
        report = {
            "root": domain,
            "timestamp": report_time,
            "stats": dict(self.stats),
            "tree": tree_lines,
            "validated_assets": [],
            "unverified_leads": [],
            "external_related_domains": [],
            "shared_infrastructure": [],
            "learned_patterns": {
                "roles": self.stats.get("learned_roles", []),
                "products": self.stats.get("learned_products", []),
            },
            "sources": self.stats["sources"],
            "source_status": self.stats.get("source_status", {}),
            "origin_stats": {k: dict(v) for k, v in self.origin_stats.items()},
            "new_subdomains": self.stats.get("new_subdomains", []),
            "new_subdomains_count": self.stats.get("new_subdomains_count", 0),
            "new_cutoff": self.new_cutoff.isoformat() if self.new_cutoff else None,
        }
        with self.lock:
            for name in sorted(self.nodes):
                node = self.nodes[name]
                report["validated_assets"].append({
                    "hostname": name,
                    "confidence": "high",
                    "dns": {"ips": node["ips"], "cname": node["cname"]},
                    "parent": node["parent"],
                    "origin": node["origin"],
                    "evidence": [{"source": s, "detail": d, "observed_at": report_time}
                                 for s, d in node["evidence"]],
                })
            for name in sorted(self.leads):
                lead = self.leads[name]
                report["unverified_leads"].append({
                    "hostname": name,
                    "confidence": "low",
                    "parent": lead["parent"],
                    "origin": lead["origin"],
                    "evidence": [{"source": s, "detail": d, "observed_at": report_time}
                                 for s, d in lead["evidence"]],
                    "reason": lead["reason"],
                })
            report["external_related_domains"] = [self.external_domains[k]
                                                   for k in sorted(self.external_domains)]
        groups = defaultdict(list)
        with self.lock:
            for name, node in self.nodes.items():
                if not node["validated"]:
                    continue
                key = (tuple(node["ips"]), node["cname"])
                groups[key].append(name)
        for key, members in groups.items():
            if len(members) > 1:
                report["shared_infrastructure"].append({
                    "ips": list(key[0]),
                    "cname": key[1],
                    "hosts": sorted(members),
                })
        return report

    def _render_validated_tree(self, annotate=False):
        nodes = self.nodes
        validated = {n for n, node in nodes.items() if node["validated"]}
        if self.domain not in validated:
            return []
        children_map = defaultdict(list)
        for name in validated:
            if name == self.domain:
                continue
            parent = self._nearest_validated_ancestor(name)
            if parent in validated:
                children_map[parent].append(name)
        children_map.setdefault(self.domain, [])
        return render_tree(
            self.domain,
            {k: sorted(v) for k, v in children_map.items()},
            annotate_fn=(lambda n: self._annotation(n)) if annotate else None,
            ascii=bool(self.args.ascii),
        )

    def _annotation(self, name):
        node = self.nodes.get(name)
        if not node:
            return ""
        srcs = set()
        for s, _d in node.get("evidence", []):
            srcs.add(s)
        srcs |= set(node.get("origin", []))
        parts = []
        if srcs:
            parts.append(", ".join(sorted(srcs)))
        if node.get("ips"):
            parts.append(" ".join(node["ips"]))
        if node.get("cname"):
            parts.append("cname={0}".format(node["cname"]))
        if not parts:
            return ""
        return "[" + "]  [".join(parts) + "]"


# --------------------------------------------------------------------------- tree renderer (pure function)
BOX = {"vert": "│", "tee": "├── ", "last": "└── ", "indent": "│   ",
       "indent_last": "    ", "sep": "│"}
ASCII_STYLE = {"vert": "|", "tee": "|-- ", "last": "`-- ", "indent": "|   ",
               "indent_last": "    ", "sep": "|"}


def render_tree(root, children_map, annotate_fn=None, ascii=False):
    """Pure function: return list of lines (no trailing newline) rendering a
    validated hierarchy. `children_map` maps parent -> list of child names
    (the caller is responsible for sorting); the renderer preserves the order
    given. Box-drawing style by default; --ascii uses |-- / `-- / |."""
    style = ASCII_STYLE if ascii else BOX
    VERT = style["vert"]; TEE = style["tee"]; LAST = style["last"]
    INDENT = style["indent"]; INDENT_LAST = style["indent_last"]; SEP = style["sep"]

    lines = [root]
    top_level = list(children_map.get(root, []))
    lines.append(SEP)
    for i, name in enumerate(top_level):
        is_last = (i == len(top_level) - 1)
        _render_subtree(lines, name, children_map, "", is_last, annotate_fn,
                        VERT, TEE, LAST, INDENT, INDENT_LAST)
        if not is_last:
            lines.append(SEP)
    return lines


def _render_subtree(lines, name, children_map, prefix, is_last, annotate_fn,
                    VERT, TEE, LAST, INDENT, INDENT_LAST):
    connector = LAST if is_last else TEE
    ann = ""
    if annotate_fn:
        ann = "  " + annotate_fn(name)
    lines.append(prefix + connector + name + ann)
    children = list(children_map.get(name, []))
    child_prefix = prefix + (INDENT_LAST if is_last else INDENT)
    for i, child in enumerate(children):
        c_is_last = (i == len(children) - 1)
        _render_subtree(lines, child, children_map, child_prefix, c_is_last,
                        annotate_fn, VERT, TEE, LAST, INDENT, INDENT_LAST)


# --------------------------------------------------------------------------- output writers
def write_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def write_csv(report, path):
    cols = ["Status", "Hostname", "Origin", "Parent", "IPs", "CNAME", "Note"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for a in report["validated_assets"]:
            w.writerow([
                "Validated", a["hostname"], ", ".join(a["origin"]),
                a["parent"] or "", ", ".join(a["dns"]["ips"]),
                a["dns"]["cname"] or "", "DNS-validated asset",
            ])
        for l in report["unverified_leads"]:
            w.writerow([
                "Unverified", l["hostname"], ", ".join(l["origin"]),
                l["parent"] or "", "", "",
                l["reason"] or "no DNS record",
            ])


def write_txt(report, path):
    out = []
    out.append("Domain-Agnostic Subdomain Discovery Report")
    out.append("=" * 60)
    out.append(f"Root: {report['root']}")
    out.append(f"Timestamp: {report['timestamp']}")
    out.append("")
    out.append("SUMMARY")
    out.append("-" * 40)
    st = report["stats"]
    out.append(f"Validated assets : {st['validated']}")
    out.append(f"Unverified leads : {st['unverified_leads']}")
    out.append(f"Blind guesses    : {st['blind_guesses']}")
    out.append("")
    out.append("VALIDATED HIERARCHY")
    out.append("-" * 40)
    out.extend(report["tree"])
    out.append("")
    out.append("VALIDATED ASSETS")
    out.append("-" * 40)
    for a in report["validated_assets"]:
        out.append(f"{a['hostname']}  parent={a['parent'] or '-'} "
                   f"origin={','.join(a['origin'])} ips={','.join(a['dns']['ips'])} "
                   f"cname={a['dns']['cname'] or '-'}")
    out.append("")
    out.append("UNVERIFIED LEADS")
    out.append("-" * 40)
    for l in report["unverified_leads"]:
        out.append(f"? {l['hostname']}  parent={l['parent'] or '-'} "
                   f"origin={','.join(l['origin'])} reason={l['reason'] or '-'}")
    if report.get("external_related_domains"):
        out.append("")
        out.append("EXTERNAL RELATED DOMAINS (not validated or crawled)")
        out.append("-" * 40)
        for item in report["external_related_domains"]:
            out.append(f"{item['hostname']}  linked from={item['related_to']}")
    if report.get("scan_changes"):
        out.append("")
        out.append("CHANGES SINCE PREVIOUS SCAN")
        out.append("-" * 40)
        for key in ("new", "removed", "changed"):
            out.append(f"{key}: {', '.join(report['scan_changes'].get(key, [])) or '-'}")
    if report.get("new_subdomains"):
        out.append("")
        out.append(f"NEW SUBDOMAINS (certs issued within last {report.get('new_subdomains_count', len(report['new_subdomains']))} day(s))")
        out.append("-" * 40)
        for n in report["new_subdomains"]:
            out.append(f"+ {n}")
    failed = {k: v for k, v in report.get("source_status", {}).items()
              if v.get("status") in ("failed", "skipped")}
    if failed:
        out.append("")
        out.append("UNAVAILABLE / SKIPPED SOURCES")
        out.append("-" * 40)
        for source, result in sorted(failed.items()):
            out.append(f"{source}: {result.get('status')} - {result.get('error', '')}")
    out.append("")
    out.append("SHARED INFRASTRUCTURE (identical DNS answers)")
    out.append("-" * 40)
    for g in report["shared_infrastructure"]:
        out.append(f"{','.join(g['ips'])} cname={g['cname'] or '-'} -> {','.join(g['hosts'])}")
    out.append("")
    out.append("LEARNED PATTERNS")
    out.append("-" * 40)
    out.append(f"roles : {','.join(report['learned_patterns']['roles']) or '-'}")
    out.append(f"products: {','.join(report['learned_patterns']['products']) or '-'}")
    out.append("")
    out.append("SOURCE COUNTS")
    out.append("-" * 40)
    for s, c in sorted(report["sources"].items()):
        out.append(f"{s}: {c}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def write_xlsx(report, path):
    if not HAS_XLSX:
        print("python -m pip install openpyxl")
        return
    from openpyxl.styles import Font
    wb = openpyxl.Workbook()

    ws = wb.active
    ws.title = "Validated"
    headers = ["Hostname", "Parent", "Origin", "IPs", "CNAME", "Evidence"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for a in report["validated_assets"]:
        ev = "; ".join("{0}={1}".format(e["source"], e["detail"])
                       for e in a["evidence"])
        ws.append([a["hostname"], a["parent"] or "", ", ".join(a["origin"]),
                   ", ".join(a["dns"]["ips"]), a["dns"]["cname"] or "", ev])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    ws2 = wb.create_sheet("Unverified")
    h2 = ["Hostname", "Parent", "Origin", "Reason", "Evidence"]
    ws2.append(h2)
    for cell in ws2[1]:
        cell.font = Font(bold=True)
    for l in report["unverified_leads"]:
        ev = "; ".join("{0}={1}".format(e["source"], e["detail"])
                       for e in l["evidence"])
        ws2.append([l["hostname"], l["parent"] or "", ", ".join(l["origin"]),
                    l["reason"] or "", ev])
    ws2.freeze_panes = "A2"
    ws2.auto_filter.ref = ws2.dimensions

    ws3 = wb.create_sheet("Hierarchy")
    ws3.append(["Hostname", "Parent", "Level"])
    for cell in ws3[1]:
        cell.font = Font(bold=True)
    parent_map = {a["hostname"]: a["parent"] for a in report["validated_assets"]}

    def children_of(name):
        return [a["hostname"] for a in report["validated_assets"]
                if a["parent"] == name]

    def emit(name, level):
        ws3.append([name, parent_map.get(name) or "", level])

    def walk(name, level):
        emit(name, level)
        for c in sorted(children_of(name)):
            walk(c, level + 1)

    walk(report["root"], 0)
    ws3.freeze_panes = "A2"
    ws3.auto_filter.ref = ws3.dimensions
    wb.save(path)


# --------------------------------------------------------------------------- CLI
# --------------------------------------------------------------------------- CLI logging helper
class LogTee:
    """Duplicate stdout to both the console and a log file.

    The first line of the log marks whether results are live (real network)
    or mocked (tests), so consumers can tell the provenance of the data.
    """
    def __init__(self, path, live=True):
        self.terminal = sys.stdout
        self.log = open(path, "w", encoding="utf-8")
        self.log.write("MODE: {0}\n".format("LIVE" if live else "MOCKED"))
        self.log.write("=" * 60 + "\n")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


def build_parser():
    p = argparse.ArgumentParser(
        description="Domain-Agnostic Recursive Subdomain Discovery and Intelligence Engine")
    p.add_argument("domain", help="Root domain you own or are authorised to assess")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH,
                   help="Recursion depth (default %(default)s)")
    p.add_argument("--out", default="discovery.json", help="Base output path")
    p.add_argument("--db", default="run.db", help="SQLite database path")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Thread pool size")
    p.add_argument("--seed", default="", help="Comma-separated seed hostnames")
    p.add_argument("--wordlist", default="", help="Wordlist file (one name per line)")
    p.add_argument("--import-names", default="", help="Import hostnames from another tool's output")
    p.add_argument("--ct-timeout", type=int, default=CT_TIMEOUT, help="CT source timeout seconds")
    p.add_argument("--no-ct", action="store_true", help="Skip certificate-transparency sources")
    p.add_argument("--no-web", action="store_true", help="Skip website analysis")
    p.add_argument("--no-tls", action="store_true", help="Skip TLS SAN harvesting")
    p.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES_DEFAULT,
                   help="Candidate cap")
    p.add_argument("--report-all-guesses", action="store_true",
                   help="List blind guesses that failed DNS as leads too")
    p.add_argument("--show-unverified", action="store_true",
                   help="Print a second UNVERIFIED LEADS section")
    p.add_argument("--annotate", action="store_true",
                   help="Append source/IP tags after each tree name")
    p.add_argument("--ascii", action="store_true",
                   help="Use ASCII tree rendering (|-- / `--)")
    p.add_argument("--xlsx", action="store_true", help="Also write discovery.xlsx")
    p.add_argument("--table-rows", type=int, default=DEFAULT_TABLE_ROWS,
                   help="Max rows in console table")
    p.add_argument("--new-days", type=int, default=DEFAULT_NEW_DAYS,
                   help="Show subdomains with certs issued within last N days (default %(default)s). "
                        "Set to 0 to disable new-subdomain filtering.")
    p.add_argument("--new-only", action="store_true",
                   help="Only show subdomains newly discovered within --new-days (implies filtering).")
    p.add_argument("--insecure-api", action="store_true",
                   help="Opt-in: disable TLS certificate verification")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce console log noise")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.insecure_api:
        print("!! WARNING --insecure-api: TLS certificate verification is DISABLED (opt-in only).")

    # --- save raw console log (live mode since this is the real CLI) ---
    base_noext = os.path.splitext(args.out)[0]
    log_path = base_noext + "_console.log"
    tee = LogTee(log_path, live=True)
    sys.stdout = tee

    engine = Engine(args.domain, args)
    try:
        report = engine.run()
    except KeyboardInterrupt:
        print("\n[engine] Ctrl+C received; exporting partial results...")
        try:
            engine.flush_pending_as_leads()
        except Exception:
            pass
        report = engine._build_report()

    out_base = args.out
    json_path = out_base
    csv_path = base_noext + ".csv"
    txt_path = base_noext + "_report.txt"

    write_json(report, json_path)
    write_csv(report, csv_path)
    write_txt(report, txt_path)

    xlsx_path = base_noext + ".xlsx"
    if args.xlsx:
        write_xlsx(report, xlsx_path)

    try:
        report["scan_changes"] = persist_sqlite(args.db, report)
        write_json(report, json_path)
        write_txt(report, txt_path)
    except Exception as e:
        print(f"[warn] sqlite persist failed: {e}")

    st = report["stats"]
    print(f"\n{st['validated']} validated | {st['unverified_leads']} unverified leads | "
          f"{st['blind_guesses']} blind guesses did not resolve")
    print(f"[output] JSON: {json_path}")
    print(f"[output] CSV : {csv_path}")
    print(f"[output] TXT : {txt_path}")
    if args.xlsx:
        print(f"[output] XLSX: {xlsx_path}")
    print(f"[output] DB  : {args.db}")
    print(f"[output] LOG : {log_path}")

    # ---- print full validated tree ----
    print("\nVALIDATED TREE")
    print("-" * 40)
    for line in report["tree"]:
        print(line)

    # ---- print full website product leads list ----
    wp_leads = [l for l in report["unverified_leads"]
                if "website product" in l["origin"]]
    print("\nUNVERIFIED LEADS - website products (no DNS record)")
    print("-" * 40)
    if wp_leads:
        for l in wp_leads:
            print(f"? {l['hostname']}  [{','.join(l['origin'])}]  reason={l['reason'] or '-'}")
    else:
        print("(none)")

    # ---- print all unverified leads (if --show-unverified) ----
    if args.show_unverified and report["unverified_leads"]:
        print("\nUNVERIFIED LEADS (all)")
        print("-" * 40)
        for l in report["unverified_leads"]:
            print(f"? {l['hostname']}  [{','.join(l['origin'])}]")

    # ---- print new subdomains section ----
    new_subs = report.get("new_subdomains", [])
    if new_subs:
        print(f"\nNEW SUBDOMAINS (certs issued within last {report.get('new_subdomains_count', len(new_subs))} day(s))")
        print("-" * 40)
        for n in new_subs:
            ts = report.get("new_cutoff")
            print(f"+ {n}")

    tee.close()
    sys.stdout = tee.terminal

    return 0


def persist_sqlite(db_path, report):
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT, root TEXT, timestamp TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS scan_assets (
            scan_id INTEGER, hostname TEXT, status TEXT, fingerprint TEXT,
            PRIMARY KEY(scan_id, hostname))""")
        cur.execute("SELECT scan_id FROM scans WHERE root=? ORDER BY scan_id DESC LIMIT 1",
                    (report["root"],))
        previous_id = cur.fetchone()
        previous = {}
        if previous_id:
            cur.execute("SELECT hostname,status,fingerprint FROM scan_assets WHERE scan_id=?",
                        (previous_id[0],))
            previous = {n: (s, f) for n, s, f in cur.fetchall()}
        current = {}
        for a in report["validated_assets"]:
            evidence = [{k: v for k, v in e.items() if k != "observed_at"}
                        for e in a["evidence"]]
            current[a["hostname"]] = ("confirmed", json.dumps(
                {"parent": a["parent"], "dns": a["dns"], "evidence": evidence}, sort_keys=True))
        for a in report["unverified_leads"]:
            evidence = [{k: v for k, v in e.items() if k != "observed_at"}
                        for e in a["evidence"]]
            current[a["hostname"]] = ("unverified", json.dumps(
                {"parent": a["parent"], "evidence": evidence, "reason": a["reason"]}, sort_keys=True))
        changes = {
            "new": sorted(n for n in current if n not in previous),
            "removed": sorted(n for n in previous if n not in current),
            "changed": sorted(n for n in current.keys() & previous.keys()
                               if current[n] != previous[n]),
        }
        cur.execute("INSERT INTO scans(root,timestamp) VALUES (?,?)",
                    (report["root"], report["timestamp"]))
        scan_id = cur.lastrowid
        cur.executemany("INSERT INTO scan_assets VALUES (?,?,?,?)",
                        [(scan_id, n, s, f) for n, (s, f) in current.items()])
        # Preserve legacy latest-run tables for existing consumers.
        cur.execute("CREATE TABLE IF NOT EXISTS nodes (hostname TEXT PRIMARY KEY,parent TEXT,validated INTEGER,origin TEXT,ips TEXT,cname TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT,hostname TEXT,source TEXT,detail TEXT)")
        cur.execute("DELETE FROM nodes")
        cur.execute("DELETE FROM evidence")
        for a in report["validated_assets"]:
            cur.execute("INSERT INTO nodes VALUES (?,?,?,?,?,?)",
                        (a["hostname"], a["parent"], 1,
                         ",".join(a["origin"]), ",".join(a["dns"]["ips"]),
                         a["dns"]["cname"] or ""))
            for e in a["evidence"]:
                cur.execute("INSERT INTO evidence (hostname, source, detail) VALUES (?,?,?)",
                            (a["hostname"], e["source"], e["detail"]))
        for l in report["unverified_leads"]:
            cur.execute("INSERT INTO nodes VALUES (?,?,?,?,?,?)",
                        (l["hostname"], l["parent"], 0,
                         ",".join(l["origin"]), "", l["reason"] or ""))
            for e in l["evidence"]:
                cur.execute("INSERT INTO evidence (hostname, source, detail) VALUES (?,?,?)",
                            (l["hostname"], e["source"], e["detail"]))
        conn.commit()
        changes["scan_id"] = scan_id
        return changes
    finally:
        conn.close()


# --------------------------------------------------------------------------- golden tree (self-check)
def _golden_tree_text():
    return ("example.com\n"
            "│\n"
            "├── sub1.example.com\n"
            "│   ├── child1.sub1.example.com\n"
            "│   ├── child2.sub1.example.com\n"
            "│   └── child3.sub1.example.com\n"
            "│\n"
            "├── sub2.example.com\n"
            "│   ├── child1.sub2.example.com\n"
            "│   └── child2.sub2.example.com\n"
            "│\n"
            "└── sub3.example.com\n"
            "    ├── child1.sub3.example.com\n"
            "    └── child2.sub3.example.com")


def _golden_children():
    return {
        "example.com": [
            "sub1.example.com",
            "sub2.example.com",
            "sub3.example.com",
        ],
        "sub1.example.com": [
            "child1.sub1.example.com",
            "child2.sub1.example.com",
            "child3.sub1.example.com",
        ],
        "sub2.example.com": [
            "child1.sub2.example.com",
            "child2.sub2.example.com",
        ],
        "sub3.example.com": [
            "child1.sub3.example.com",
            "child2.sub3.example.com",
        ],
        "child1.sub1.example.com": [],
        "child2.sub1.example.com": [],
        "child3.sub1.example.com": [],
        "child1.sub2.example.com": [],
        "child2.sub2.example.com": [],
        "child1.sub3.example.com": [],
        "child2.sub3.example.com": [],
    }


if __name__ == "__main__":
    sys.exit(main())
