#!/usr/bin/env python3
"""SEO + LLM-readiness website checker.

Usage:
    python check.py https://example.com
    python check.py https://example.com --json
    python check.py https://example.com --fail-on warn

Deps: requests, beautifulsoup4
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse, quote
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (compatible; SEOLLMChecker/1.0; +https://github.com/)"
TIMEOUT = 15
AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot"]

# Ahrefs-style thresholds
SLOW_PAGE_WARN_MS = 2000
SLOW_PAGE_FAIL_MS = 5000
HTML_SIZE_WARN = 500 * 1024          # 500 KB
HTML_SIZE_FAIL = 2 * 1024 * 1024     # 2 MB
IMAGE_SIZE_WARN = 200 * 1024         # 200 KB per image (Ahrefs default)
IMAGE_SIZE_FAIL = 500 * 1024         # 500 KB
CSS_SIZE_WARN = 100 * 1024           # 100 KB per CSS file
JS_SIZE_WARN = 300 * 1024            # informational
ASSET_SAMPLE = 10                    # cap HEAD requests per asset type
INLINE_ASSET_WARN = 50 * 1024        # 50 KB of inline <script>/<style>
INLINE_ASSET_FAIL = 150 * 1024
DOM_ELEMENTS_WARN = 1500
DOM_ELEMENTS_FAIL = 3000
DOM_DEPTH_WARN = 32
DOM_DEPTH_FAIL = 60
TEXT_RATIO_WARN = 0.10
TEXT_RATIO_FAIL = 0.05
GENERIC_ANCHOR_TEXT = {
    "click here", "here", "read more", "learn more", "more", "more info",
    "link", "this", "this link", "view", "see more", "details", "go",
    # Danish equivalents for this codebase's .dk sites
    "læs mere", "klik her", "mere", "se mere", "her", "læs", "gå",
}

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
ICON = {PASS: "✅", WARN: "🟡", FAIL: "🔴", INFO: "ℹ️"}


@dataclass
class CheckResult:
    check: str
    category: str
    status: str
    message: str
    evidence: str = ""


@dataclass
class Site:
    """Shared state fetched once, reused by every check."""
    url: str
    final_url: str
    response: requests.Response
    soup: BeautifulSoup
    robots_text: Optional[str]
    robots_content_type: Optional[str]
    robots_status: Optional[int]
    robots_url: str
    session: requests.Session
    tls_info: Optional[dict] = None
    browser_result: Optional[dict] = None
    ads_deep: bool = False
    browser_pool_ref: Optional["BrowserPool"] = None


# --------- helpers ---------

def fetch(session: requests.Session, url: str, allow_redirects: bool = True) -> requests.Response:
    return session.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects,
                       headers={"User-Agent": UA, "Accept": "*/*"})


def root_url(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def percent_encode_path(u: str) -> str:
    p = urlparse(u)
    return urlunparse(p._replace(path=quote(p.path, safe="/")))


# --------- checks ---------

def check_https_reachable(s: Site) -> CheckResult:
    ok = s.response.status_code == 200 and s.final_url.startswith("https://")
    return CheckResult(
        "https_reachable", "shared",
        PASS if ok else FAIL,
        f"{s.response.status_code} on {s.final_url}",
    )


def _dns_families(host: str) -> tuple[bool, bool, Optional[str]]:
    """Return (has_ipv4, has_ipv6, error)."""
    has_v4 = has_v6 = False
    try:
        for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
            fam = info[0]
            if fam == socket.AF_INET:
                has_v4 = True
            elif fam == socket.AF_INET6:
                has_v6 = True
    except socket.gaierror as e:
        return False, False, str(e)
    return has_v4, has_v6, None


def _tcp_ok(host: str, port: int, family: int, timeout: float = 4.0) -> Optional[str]:
    """Try TCP connect via the given address family. Returns None on success, else error."""
    try:
        infos = socket.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return f"DNS: {e}"
    last_err = "no address returned"
    for info in infos:
        try:
            with socket.socket(info[0], info[1]) as sock:
                sock.settimeout(timeout)
                sock.connect(info[4])
                return None
        except OSError as e:
            last_err = str(e)
    return last_err


def check_dual_stack_host(s: Site) -> CheckResult:
    """Primary host resolves (and connects) via IPv4 and IPv6."""
    parsed = urlparse(s.final_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    v4, v6, err = _dns_families(host)
    if err:
        return CheckResult("dual_stack_host", "shared", FAIL,
                           f"DNS error for {host}: {err}")
    if not v4:
        return CheckResult("dual_stack_host", "shared", FAIL,
                           f"{host} has no A record — IPv4 users can't reach it")
    v4_err = _tcp_ok(host, port, socket.AF_INET)
    if v4_err:
        return CheckResult("dual_stack_host", "shared", FAIL,
                           f"{host} A record resolves but IPv4 TCP failed: {v4_err}")
    if not v6:
        return CheckResult("dual_stack_host", "shared", WARN,
                           f"{host} IPv4-only (no AAAA record) — IPv6-only clients "
                           "(mobile carriers, enterprise networks) cannot reach it")
    v6_err = _tcp_ok(host, port, socket.AF_INET6)
    if v6_err:
        return CheckResult("dual_stack_host", "shared", WARN,
                           f"{host} has AAAA but IPv6 TCP failed: {v6_err} "
                           "(may be local network — DNS is the authoritative signal)")
    return CheckResult("dual_stack_host", "shared", PASS,
                       f"{host} reachable via IPv4 + IPv6 on :{port}")


def _collect_asset_hosts(s: Site) -> set[str]:
    """Unique hostnames referenced by <img>, <script>, <link>, <iframe>, <source>, <video>, <audio>."""
    hosts: set[str] = set()
    specs = [("img", "src"), ("script", "src"), ("link", "href"),
             ("iframe", "src"), ("video", "src"), ("audio", "src"),
             ("source", "src"), ("source", "srcset")]
    for tag, attr in specs:
        for el in s.soup.find_all(tag):
            v = (el.get(attr) or "").strip()
            if not v:
                continue
            # srcset has multiple URLs separated by commas; just take the first
            if attr == "srcset":
                v = v.split(",")[0].strip().split()[0]
            url = urljoin(s.final_url, v)
            p = urlparse(url)
            if p.scheme in ("http", "https") and p.hostname:
                hosts.add(p.hostname)
    return hosts


def check_dual_stack_assets(s: Site) -> CheckResult:
    """Every referenced third-party asset host resolves via IPv4 + IPv6."""
    hosts = _collect_asset_hosts(s)
    primary = urlparse(s.final_url).hostname
    hosts.discard(primary or "")
    if not hosts:
        return CheckResult("dual_stack_assets", "shared", INFO,
                           "no third-party asset hosts on page")

    def probe(h: str) -> tuple[str, bool, bool, Optional[str]]:
        v4, v6, err = _dns_families(h)
        return h, v4, v6, err

    results: list[tuple[str, bool, bool, Optional[str]]] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(probe, sorted(hosts)):
            results.append(r)

    broken = [(h, e) for h, v4, v6, e in results if e or not v4]
    v6_missing = [h for h, v4, v6, e in results if v4 and not v6 and not e]

    if broken:
        return CheckResult("dual_stack_assets", "shared", FAIL,
                           f"{len(broken)}/{len(results)} asset host(s) IPv4-broken: "
                           f"{broken[0][0]} ({broken[0][1] or 'no A record'})")
    if v6_missing:
        return CheckResult("dual_stack_assets", "shared", WARN,
                           f"{len(v6_missing)}/{len(results)} asset host(s) lack IPv6 (AAAA): "
                           f"{', '.join(v6_missing[:3])}")
    return CheckResult("dual_stack_assets", "shared", PASS,
                       f"{len(results)} asset host(s) all dual-stack (A + AAAA)")


# ---------- Security: TLS / cert / DNS-security / HTTP headers ----------


# host-level caches so multi-URL runs don't repeat expensive probes
_TLS_CACHE: dict[str, dict] = {}
_ROBOTS_CACHE: dict[str, tuple[Optional[str], Optional[str], Optional[int], str]] = {}
_CACHE_LOCK = threading.Lock()


def _tls_probe_cached(host: str, port: int = 443) -> dict:
    key = f"{host}:{port}"
    with _CACHE_LOCK:
        if key in _TLS_CACHE:
            return _TLS_CACHE[key]
    # probe outside the lock (slow; we don't want to block other hosts)
    result = _tls_probe(host, port)
    with _CACHE_LOCK:
        _TLS_CACHE.setdefault(key, result)
        return _TLS_CACHE[key]


def _tls_probe(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Establish a TLS connection and return cert + version + alpn + chain info."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    info: dict[str, Any] = {"error": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["cert"] = ssock.getpeercert()
                info["version"] = ssock.version()
                info["alpn"] = ssock.selected_alpn_protocol()
                info["cipher"] = ssock.cipher()
                # Python 3.10+: list of certs the server actually sent
                if hasattr(ssock, "get_unverified_chain"):
                    try:
                        chain = ssock.get_unverified_chain() or []
                        info["chain_length"] = len(chain)
                    except Exception:
                        info["chain_length"] = None
                else:
                    info["chain_length"] = None
    except (ssl.SSLError, ssl.CertificateError, OSError, socket.timeout) as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def _tls_version_accepted(host: str, port: int, version: ssl.TLSVersion,
                          timeout: float = 4.0) -> bool:
    """True if the server accepts a connection restricted to exactly this TLS version.

    Probing deprecated versions (1.0/1.1) is intentional — we want to know if
    the server still accepts them. Python rightly warns on using those constants,
    so we silence the warning in this one call site.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, ssl.SSLError):
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError, socket.timeout):
            return False


def check_tls_cert_expiry(s: Site) -> CheckResult:
    if not s.tls_info or s.tls_info.get("error"):
        return CheckResult("tls_cert_expiry", "security", FAIL,
                           f"TLS connect failed: {s.tls_info.get('error') if s.tls_info else 'no probe'}")
    cert = s.tls_info.get("cert") or {}
    not_after = cert.get("notAfter")
    if not not_after:
        return CheckResult("tls_cert_expiry", "security", WARN, "no notAfter in cert")
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expiry - datetime.now(timezone.utc)).days
    when = expiry.strftime("%Y-%m-%d")
    if days < 0:
        return CheckResult("tls_cert_expiry", "security", FAIL, f"EXPIRED {-days} days ago ({when})")
    if days < 15:
        return CheckResult("tls_cert_expiry", "security", FAIL,
                           f"expires in {days} days ({when}) — renew now")
    if days < 30:
        return CheckResult("tls_cert_expiry", "security", WARN,
                           f"expires in {days} days ({when})")
    return CheckResult("tls_cert_expiry", "security", PASS,
                       f"expires in {days} days ({when})")


def check_tls_cert_hostname(s: Site) -> CheckResult:
    if not s.tls_info or s.tls_info.get("error"):
        return CheckResult("tls_cert_hostname_match", "security", FAIL,
                           "TLS connect failed")
    cert = s.tls_info.get("cert") or {}
    host = urlparse(s.final_url).hostname or ""
    san_entries = cert.get("subjectAltName") or []
    sans = [v for k, v in san_entries if k == "DNS"]
    cn = ""
    for rdn in cert.get("subject", []):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    # exact or wildcard match
    def matches(pattern: str, h: str) -> bool:
        if pattern == h:
            return True
        if pattern.startswith("*."):
            return h.count(".") == pattern.count(".") and h.endswith(pattern[1:])
        return False

    if any(matches(s, host) for s in sans):
        return CheckResult("tls_cert_hostname_match", "security", PASS,
                           f"{host} in SAN ({len(sans)} entries)")
    if cn and matches(cn, host):
        return CheckResult("tls_cert_hostname_match", "security", WARN,
                           f"{host} matches CN only (SAN required since 2017)")
    return CheckResult("tls_cert_hostname_match", "security", FAIL,
                       f"{host} not in SAN {sans!r} or CN {cn!r}")


def check_tls_protocol_version(s: Site) -> CheckResult:
    if not s.tls_info or s.tls_info.get("error"):
        return CheckResult("tls_protocol_version", "security", FAIL,
                           "TLS connect failed")
    negotiated = s.tls_info.get("version") or ""
    host = urlparse(s.final_url).hostname or ""
    # Check if server still accepts deprecated TLS versions
    accepts_10 = _tls_version_accepted(host, 443, ssl.TLSVersion.TLSv1)
    accepts_11 = _tls_version_accepted(host, 443, ssl.TLSVersion.TLSv1_1)
    accepts_13 = _tls_version_accepted(host, 443, ssl.TLSVersion.TLSv1_3)
    deprecated = []
    if accepts_10:
        deprecated.append("TLS 1.0")
    if accepts_11:
        deprecated.append("TLS 1.1")
    if deprecated:
        return CheckResult("tls_protocol_version", "security", FAIL,
                           f"negotiated {negotiated}; still accepts {', '.join(deprecated)} "
                           "(PCI/industry requires ≥1.2)")
    if not accepts_13:
        return CheckResult("tls_protocol_version", "security", WARN,
                           f"negotiated {negotiated}; TLS 1.3 not accepted (recommended for modern perf)")
    return CheckResult("tls_protocol_version", "security", PASS,
                       f"TLS 1.3 + 1.2 only; negotiated {negotiated}")


def check_tls_chain_completeness(s: Site) -> CheckResult:
    if not s.tls_info or s.tls_info.get("error"):
        return CheckResult("tls_chain_completeness", "security", FAIL, "TLS connect failed")
    chain_len = s.tls_info.get("chain_length")
    if chain_len is None:
        return CheckResult("tls_chain_completeness", "security", INFO,
                           "chain inspection needs Python 3.13+ (get_unverified_chain)")
    if chain_len <= 1:
        return CheckResult("tls_chain_completeness", "security", FAIL,
                           f"server sent only {chain_len} cert — missing intermediates; "
                           "some older Android/Java clients will fail to verify")
    return CheckResult("tls_chain_completeness", "security", PASS,
                       f"chain length {chain_len} (leaf + intermediates)")


def check_hsts_preload_ready(s: Site) -> CheckResult:
    hsts = s.response.headers.get("Strict-Transport-Security", "")
    if not hsts:
        return CheckResult("hsts_preload_ready", "security", FAIL, "no HSTS header")
    m = re.search(r"max-age=(\d+)", hsts)
    age = int(m.group(1)) if m else 0
    has_sub = "includeSubDomains" in hsts
    has_preload = "preload" in hsts
    issues = []
    if age < 31536000:
        issues.append(f"max-age={age} < 31536000 (1 year required)")
    if not has_sub:
        issues.append("missing includeSubDomains")
    if not has_preload:
        issues.append("missing preload token")
    if issues:
        status = WARN if has_preload else FAIL
        return CheckResult("hsts_preload_ready", "security", status,
                           f"not preload-eligible: {'; '.join(issues)}")
    return CheckResult("hsts_preload_ready", "security", PASS,
                       f"preload-eligible: {hsts}")


def check_caa_record(s: Site) -> CheckResult:
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    try:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0
        answer = resolver.resolve(domain, "CAA", raise_on_no_answer=False)
        records = list(answer) if answer.rrset is not None else []
    except dns.resolver.NXDOMAIN:
        return CheckResult("caa_record", "security", INFO, f"NXDOMAIN for {domain}")
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        return CheckResult("caa_record", "security", INFO, f"DNS error: {e}")
    if records:
        issuers = [str(r).strip() for r in records]
        return CheckResult("caa_record", "security", PASS,
                           f"{len(records)} CAA record(s): {issuers[0][:80]}")
    return CheckResult("caa_record", "security", WARN,
                       f"no CAA records — any CA can issue certs for {domain}")


def check_dnssec(s: Site) -> CheckResult:
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    try:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0
        answer = resolver.resolve(domain, "DS", raise_on_no_answer=False)
        if answer.rrset is not None and len(answer) > 0:
            return CheckResult("dnssec", "security", PASS,
                               f"{len(list(answer))} DS record(s) — zone is DNSSEC-signed")
    except dns.resolver.NXDOMAIN:
        pass
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        return CheckResult("dnssec", "security", INFO, f"DNS error: {e}")
    return CheckResult("dnssec", "security", INFO,
                       f"no DS record for {domain} — zone not DNSSEC-signed")


def _parse_csp(header: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def check_csp_unsafe_inline(s: Site) -> CheckResult:
    csp = s.response.headers.get("Content-Security-Policy", "")
    if not csp:
        return CheckResult("csp_unsafe_inline", "security", INFO,
                           "no CSP header (reported by security_headers)")
    d = _parse_csp(csp)
    script = d.get("script-src") or d.get("script-src-elem") or d.get("default-src") or []
    has_unsafe_inline = "'unsafe-inline'" in script
    has_nonce = any(s.startswith("'nonce-") for s in script)
    has_hash = any(s.startswith("'sha") for s in script)
    has_strict_dynamic = "'strict-dynamic'" in script
    has_unsafe_eval = "'unsafe-eval'" in script
    issues = []
    if has_unsafe_inline and not (has_nonce or has_hash or has_strict_dynamic):
        issues.append("'unsafe-inline' in script-src without nonce/hash/strict-dynamic")
    if has_unsafe_eval:
        issues.append("'unsafe-eval' in script-src")
    if issues:
        return CheckResult("csp_unsafe_inline", "security",
                           FAIL if has_unsafe_inline and not (has_nonce or has_hash or has_strict_dynamic) else WARN,
                           "; ".join(issues))
    return CheckResult("csp_unsafe_inline", "security", PASS,
                       "script-src has no unsafe-inline / unsafe-eval")


def check_cross_origin_isolation(s: Site) -> CheckResult:
    coop = s.response.headers.get("Cross-Origin-Opener-Policy", "").strip()
    coep = s.response.headers.get("Cross-Origin-Embedder-Policy", "").strip()
    if coop == "same-origin" and coep in ("require-corp", "credentialless"):
        return CheckResult("cross_origin_isolation", "security", PASS,
                           f"isolated: COOP={coop} COEP={coep}")
    if coop == "same-origin":
        return CheckResult("cross_origin_isolation", "security", WARN,
                           f"COOP={coop} but COEP missing/weak ({coep!r})")
    if not coop and not coep:
        return CheckResult("cross_origin_isolation", "security", INFO,
                           "no COOP/COEP (only needed for SharedArrayBuffer / high-res timers)")
    return CheckResult("cross_origin_isolation", "security", INFO,
                       f"partial: COOP={coop!r} COEP={coep!r}")


def check_subresource_integrity(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    missing: list[str] = []
    total_xorig = 0
    # cross-origin scripts
    for sc in s.soup.find_all("script", src=True):
        src = sc["src"]
        url = urljoin(s.final_url, src)
        url_host = urlparse(url).hostname
        if url_host and url_host != host:
            total_xorig += 1
            if not sc.get("integrity"):
                missing.append(f"<script src={src[:60]}>")
    # cross-origin stylesheets
    for link in s.soup.find_all("link", href=True):
        rel = link.get("rel") or []
        if "stylesheet" not in [r.lower() for r in rel]:
            continue
        url = urljoin(s.final_url, link["href"])
        url_host = urlparse(url).hostname
        if url_host and url_host != host:
            total_xorig += 1
            if not link.get("integrity"):
                missing.append(f"<link href={link['href'][:60]}>")
    if total_xorig == 0:
        return CheckResult("subresource_integrity", "security", INFO,
                           "no cross-origin scripts or stylesheets")
    if missing:
        return CheckResult("subresource_integrity", "security", WARN,
                           f"{len(missing)}/{total_xorig} cross-origin assets without integrity: {missing[0]}")
    return CheckResult("subresource_integrity", "security", PASS,
                       f"{total_xorig} cross-origin assets all have SRI")


# ---------- SEO rich-result schemas + perf (HTTP/2-3, compression) ----------


def _collect_jsonld(s: Site) -> list[dict]:
    """Return all JSON-LD nodes flattened through @graph."""
    out: list[dict] = []
    for sc in s.soup.find_all("script", attrs={"type": "application/ld+json"}):
        if not sc.string or sc.get("src"):
            continue
        try:
            data = json.loads(sc.string)
        except json.JSONDecodeError:
            continue

        def walk(node) -> None:
            if isinstance(node, list):
                for n in node:
                    walk(n)
                return
            if not isinstance(node, dict):
                return
            out.append(node)
            if "@graph" in node:
                walk(node["@graph"])
        walk(data)
    return out


def _is_type(node: dict, name: str) -> bool:
    t = node.get("@type")
    if isinstance(t, list):
        return name in t
    return t == name


def check_breadcrumb_schema(s: Site) -> CheckResult:
    nodes = _collect_jsonld(s)
    crumbs = [n for n in nodes if _is_type(n, "BreadcrumbList")]
    if not crumbs:
        return CheckResult("breadcrumb_schema", "seo", INFO, "no BreadcrumbList JSON-LD")
    for bc in crumbs:
        items = bc.get("itemListElement") or []
        if not isinstance(items, list) or len(items) < 2:
            return CheckResult("breadcrumb_schema", "seo", FAIL,
                               f"BreadcrumbList needs ≥2 items, got {len(items) if isinstance(items, list) else '?'}")
        for it in items:
            if not isinstance(it, dict):
                return CheckResult("breadcrumb_schema", "seo", FAIL,
                                   "BreadcrumbList itemListElement is not a list of objects")
            missing = [f for f in ("position", "name", "item") if f not in it]
            if missing and "item" not in missing:
                # some pages omit 'item' on the last breadcrumb; that's allowed
                missing = [m for m in missing if m != "item"]
            if missing:
                return CheckResult("breadcrumb_schema", "seo", FAIL,
                                   f"BreadcrumbList item missing {missing}")
    total = sum(len(bc.get("itemListElement") or []) for bc in crumbs)
    return CheckResult("breadcrumb_schema", "seo", PASS,
                       f"{len(crumbs)} BreadcrumbList(s) with {total} items")


def check_product_schema(s: Site) -> CheckResult:
    nodes = _collect_jsonld(s)
    products = [n for n in nodes if _is_type(n, "Product")]
    if not products:
        return CheckResult("product_schema", "seo", INFO, "no Product JSON-LD")
    issues: list[str] = []
    for p in products:
        required = [f for f in ("name", "image") if not p.get(f)]
        if required:
            issues.append(f"missing {required}")
            continue
        has_offer = bool(p.get("offers"))
        has_rating = bool(p.get("aggregateRating"))
        has_review = bool(p.get("review"))
        if not (has_offer or has_rating or has_review):
            issues.append("needs one of offers/aggregateRating/review")
            continue
        if has_offer:
            offers = p["offers"] if isinstance(p["offers"], list) else [p["offers"]]
            for o in offers:
                if not isinstance(o, dict):
                    issues.append("malformed offers")
                    continue
                off_missing = [f for f in ("price", "priceCurrency", "availability")
                               if not o.get(f)]
                if off_missing:
                    issues.append(f"offer missing {off_missing}")
    if issues:
        return CheckResult("product_schema", "seo", FAIL,
                           f"{len(products)} Product(s); {issues[0]}")
    return CheckResult("product_schema", "seo", PASS,
                       f"{len(products)} Product schema(s) complete")


def check_http2_http3(s: Site) -> CheckResult:
    """ALPN negotiates h2; Alt-Svc advertises h3."""
    alpn = (s.tls_info or {}).get("alpn") if s.tls_info else None
    alt_svc = s.response.headers.get("Alt-Svc", "")
    if alpn == "h2":
        if "h3" in alt_svc:
            return CheckResult("http2_http3", "perf", PASS,
                               f"ALPN=h2, Alt-Svc advertises h3: {alt_svc[:80]}")
        return CheckResult("http2_http3", "perf", WARN,
                           "ALPN=h2 but no h3 in Alt-Svc — HTTP/3 recommended")
    if alpn is None:
        return CheckResult("http2_http3", "perf", INFO, "no TLS probe (http site)")
    return CheckResult("http2_http3", "perf", FAIL,
                       f"ALPN={alpn or 'http/1.1'} — HTTP/2 not supported")


def check_compression(s: Site) -> CheckResult:
    """Probe each compression algorithm the server supports."""
    size = len(s.response.content)
    algorithms = ("br", "zstd", "gzip", "deflate")
    supported: dict[str, int] = {}
    def wire_bytes(url: str, accept_encoding: str) -> tuple[Optional[int], str]:
        """Return (bytes-on-the-wire, negotiated Content-Encoding) or (None, '') on failure."""
        try:
            r = s.session.get(url, headers={"Accept-Encoding": accept_encoding,
                                            "User-Agent": UA},
                              timeout=TIMEOUT, allow_redirects=True, stream=True)
        except requests.RequestException:
            return None, ""
        try:
            enc = r.headers.get("Content-Encoding", "").lower().split(",")[0].strip()
            raw = b""
            for chunk in r.raw.stream(decode_content=False):
                raw += chunk
                if len(raw) > 4 * 1024 * 1024:  # safety cap
                    break
            return len(raw), enc
        finally:
            r.close()

    # baseline = identity (uncompressed) wire size
    baseline, _ = wire_bytes(s.final_url, "identity")
    for algo in algorithms:
        wire, enc = wire_bytes(s.final_url, algo)
        if wire is not None and enc == algo:
            supported[algo] = wire
    if size < 10 * 1024 and not supported:
        return CheckResult("compression", "perf", INFO,
                           f"HTML {size // 1024} KB — too small to matter")
    if not supported:
        return CheckResult("compression", "perf", FAIL,
                           f"HTML {size // 1024} KB served uncompressed (no br/zstd/gzip/deflate)")
    # build message
    parts = []
    for algo in algorithms:
        if algo in supported:
            if baseline and baseline > 0:
                saved = int(100 * (1 - supported[algo] / baseline))
                parts.append(f"{algo}={supported[algo] // 1024}KB (-{saved}%)")
            else:
                parts.append(f"{algo}={supported[algo] // 1024}KB")
    if "br" in supported or "zstd" in supported:
        return CheckResult("compression", "perf", PASS,
                           f"modern compression: {', '.join(parts)}")
    if "gzip" in supported:
        return CheckResult("compression", "perf", WARN,
                           f"only legacy compression: {', '.join(parts)} — enable brotli (~15–20% smaller)")
    return CheckResult("compression", "perf", WARN,
                       f"compression supported: {', '.join(parts)}")


# ---------- Headless-browser runtime checks (--browser) ----------


_BROWSER_INIT_SCRIPT = """
    window.__webvitals = { lcp: 0, cls: 0 };
    new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const last = entries[entries.length - 1];
        if (last) window.__webvitals.lcp = last.startTime;
    }).observe({ type: 'largest-contentful-paint', buffered: true });
    new PerformanceObserver((list) => {
        for (const e of list.getEntries()) {
            if (!e.hadRecentInput) window.__webvitals.cls += e.value;
        }
    }).observe({ type: 'layout-shift', buffered: true });
"""


class BrowserPool:
    """One Playwright/Chromium instance reused across many URL navigations."""

    def __init__(self) -> None:
        self.pw = None
        self.browser = None
        self.context = None
        self.error: Optional[str] = None
        self._lock = threading.Lock()

    def start(self) -> Optional[str]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.error = ("playwright not installed — run: pip install -r "
                          "requirements-browser.txt && playwright install chromium")
            return self.error
        try:
            self.pw = sync_playwright().start()
            self.browser = self.pw.chromium.launch(headless=True)
            self.context = self.browser.new_context(
                user_agent=DESKTOP_UA,
                viewport={"width": 1350, "height": 940},
            )
            self.context.add_init_script(_BROWSER_INIT_SCRIPT)
        except Exception as e:
            self.error = f"could not launch chromium — run: playwright install chromium ({e})"
            self.stop()
            return self.error
        return None

    def audit(self, url: str, timeout_ms: int = 30000) -> dict:
        # Playwright sync API is not thread-safe — serialise navigations on the shared context.
        with self._lock:
            return self._audit_locked(url, timeout_ms)

    def _audit_locked(self, url: str, timeout_ms: int) -> dict:
        if self.error or not self.context:
            return {"error": self.error or "browser pool not started"}
        console_errors: list[dict] = []
        console_warnings: list[dict] = []
        page_errors: list[str] = []
        failed_requests: list[dict] = []

        page = self.context.new_page()
        page.on("console", lambda msg: (
            console_errors if msg.type == "error" else console_warnings
        ).append({"text": msg.text[:200], "location": str(msg.location)})
            if msg.type in ("error", "warning") else None)
        page.on("pageerror", lambda err: page_errors.append(str(err)[:300]))
        page.on("requestfailed", lambda req: failed_requests.append({
            "url": req.url[:200],
            "failure": (req.failure or "unknown")[:100],
            "method": req.method,
        }))
        try:
            response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            page.wait_for_timeout(500)
            metrics = page.evaluate("""() => {
                const nav = performance.getEntriesByType('navigation')[0] || {};
                const paint = performance.getEntriesByType('paint');
                const fcp = paint.find(p => p.name === 'first-contentful-paint');
                return {
                    domContentLoaded: nav.domContentLoadedEventEnd || 0,
                    loadComplete: nav.loadEventEnd || 0,
                    fcp: fcp ? fcp.startTime : 0,
                    lcp: (window.__webvitals && window.__webvitals.lcp) || 0,
                    cls: (window.__webvitals && window.__webvitals.cls) || 0,
                };
            }""")
            status = response.status if response else None
        except Exception as e:
            page.close()
            return {"error": f"navigation failed: {e}"}
        finally:
            try:
                page.close()
            except Exception:
                pass

        return {
            "status": status,
            "console_errors": console_errors,
            "console_warnings": console_warnings,
            "page_errors": page_errors,
            "failed_requests": failed_requests,
            "dom_content_loaded_ms": int(metrics.get("domContentLoaded") or 0),
            "load_complete_ms": int(metrics.get("loadComplete") or 0),
            "fcp_ms": int(metrics.get("fcp") or 0),
            "lcp_ms": int(metrics.get("lcp") or 0),
            "cls": float(metrics.get("cls") or 0),
        }

    def stop(self) -> None:
        try:
            if self.browser:
                self.browser.close()
        except Exception:
            pass
        try:
            if self.pw:
                self.pw.stop()
        except Exception:
            pass
        self.browser = None
        self.pw = None
        self.context = None


# kept for backwards compat
def run_browser_audit(url: str, timeout_ms: int = 30000) -> dict:
    pool = BrowserPool()
    err = pool.start()
    if err:
        return {"error": err}
    try:
        return pool.audit(url, timeout_ms)
    finally:
        pool.stop()


def _br(s: Site) -> Optional[dict]:
    """Browser audit dict, or None if --browser wasn't enabled."""
    return s.browser_result


def check_browser_js_errors(s: Site) -> CheckResult:
    br = _br(s)
    if br is None:
        return CheckResult("browser_js_errors", "browser", INFO, "browser mode off (run with --browser)")
    if br.get("error"):
        return CheckResult("browser_js_errors", "browser", FAIL, br["error"])
    errs = br.get("page_errors", [])
    if not errs:
        return CheckResult("browser_js_errors", "browser", PASS, "no uncaught JS exceptions")
    return CheckResult("browser_js_errors", "browser", FAIL,
                       f"{len(errs)} uncaught JS exception(s): {errs[0][:120]}")


def check_browser_console_errors(s: Site) -> CheckResult:
    br = _br(s)
    if br is None:
        return CheckResult("browser_console_errors", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_console_errors", "browser", INFO, "browser failed")
    errs = br.get("console_errors", [])
    warns = br.get("console_warnings", [])
    if errs:
        return CheckResult("browser_console_errors", "browser", FAIL,
                           f"{len(errs)} console error(s), {len(warns)} warning(s): {errs[0]['text'][:100]}")
    if len(warns) > 5:
        return CheckResult("browser_console_errors", "browser", WARN,
                           f"{len(warns)} console warnings: {warns[0]['text'][:100]}")
    return CheckResult("browser_console_errors", "browser", PASS,
                       f"0 errors, {len(warns)} warnings")


def check_browser_failed_requests(s: Site) -> CheckResult:
    br = _br(s)
    if br is None:
        return CheckResult("browser_failed_requests", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_failed_requests", "browser", INFO, "browser failed")
    fails = br.get("failed_requests", [])
    if not fails:
        return CheckResult("browser_failed_requests", "browser", PASS, "all network requests succeeded")
    return CheckResult("browser_failed_requests", "browser", FAIL,
                       f"{len(fails)} failed request(s): {fails[0]['url'][:80]} ({fails[0]['failure']})")


def check_browser_load_time(s: Site) -> CheckResult:
    br = _br(s)
    if br is None:
        return CheckResult("browser_load_time", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_load_time", "browser", INFO, "browser failed")
    t = br.get("load_complete_ms", 0)
    dcl = br.get("dom_content_loaded_ms", 0)
    if t == 0:
        return CheckResult("browser_load_time", "browser", INFO, "no timing data")
    if t > 5000:
        return CheckResult("browser_load_time", "browser", FAIL,
                           f"load={t}ms, DCL={dcl}ms — very slow")
    if t > 3000:
        return CheckResult("browser_load_time", "browser", WARN,
                           f"load={t}ms, DCL={dcl}ms")
    return CheckResult("browser_load_time", "browser", PASS,
                       f"load={t}ms, DCL={dcl}ms")


def check_browser_lcp(s: Site) -> CheckResult:
    """Largest Contentful Paint (Core Web Vital: good <2500ms, poor >4000ms)."""
    br = _br(s)
    if br is None:
        return CheckResult("browser_lcp", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_lcp", "browser", INFO, "browser failed")
    lcp = br.get("lcp_ms", 0)
    if lcp == 0:
        return CheckResult("browser_lcp", "browser", INFO, "LCP not observed")
    if lcp > 4000:
        return CheckResult("browser_lcp", "browser", FAIL, f"{lcp}ms (>4000 = poor)")
    if lcp > 2500:
        return CheckResult("browser_lcp", "browser", WARN, f"{lcp}ms (2500–4000 = needs improvement)")
    return CheckResult("browser_lcp", "browser", PASS, f"{lcp}ms (<2500 = good)")


def check_browser_cls(s: Site) -> CheckResult:
    """Cumulative Layout Shift (Core Web Vital: good <0.1, poor >0.25)."""
    br = _br(s)
    if br is None:
        return CheckResult("browser_cls", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_cls", "browser", INFO, "browser failed")
    cls = br.get("cls", 0.0)
    if cls > 0.25:
        return CheckResult("browser_cls", "browser", FAIL, f"{cls:.3f} (>0.25 = poor)")
    if cls > 0.1:
        return CheckResult("browser_cls", "browser", WARN, f"{cls:.3f} (0.1–0.25 = needs improvement)")
    return CheckResult("browser_cls", "browser", PASS, f"{cls:.3f} (<0.1 = good)")


def check_browser_fcp(s: Site) -> CheckResult:
    """First Contentful Paint: good <1800ms, poor >3000ms."""
    br = _br(s)
    if br is None:
        return CheckResult("browser_fcp", "browser", INFO, "browser mode off")
    if br.get("error"):
        return CheckResult("browser_fcp", "browser", INFO, "browser failed")
    fcp = br.get("fcp_ms", 0)
    if fcp == 0:
        return CheckResult("browser_fcp", "browser", INFO, "FCP not observed")
    if fcp > 3000:
        return CheckResult("browser_fcp", "browser", FAIL, f"{fcp}ms (>3000 = poor)")
    if fcp > 1800:
        return CheckResult("browser_fcp", "browser", WARN, f"{fcp}ms (1800–3000 = needs improvement)")
    return CheckResult("browser_fcp", "browser", PASS, f"{fcp}ms (<1800 = good)")


# ---------- Mobile / desktop checks (PageSpeed-style) ----------

MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
             "Mobile/15E148 Safari/604.1")
DESKTOP_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")


def _fetch_with_ua(session: requests.Session, url: str, ua: str
                   ) -> Optional[requests.Response]:
    try:
        return session.get(url, headers={"User-Agent": ua, "Accept": "*/*"},
                           timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None


def check_mobile_content_parity(s: Site) -> CheckResult:
    """Mobile UA should get the same content as desktop (no cloaking / m. divergence)."""
    mobile_r = _fetch_with_ua(s.session, s.final_url, MOBILE_UA)
    if mobile_r is None:
        return CheckResult("mobile_content_parity", "perf", FAIL,
                           "mobile fetch failed — server may block mobile UA")
    if mobile_r.status_code != 200:
        return CheckResult("mobile_content_parity", "perf", FAIL,
                           f"mobile UA got {mobile_r.status_code} (desktop got 200)")
    # detect redirect to m. subdomain (legacy anti-pattern)
    mobile_host = urlparse(mobile_r.url).hostname or ""
    desktop_host = urlparse(s.final_url).hostname or ""
    if mobile_host != desktop_host:
        if mobile_host.startswith("m.") or "/mobile" in urlparse(mobile_r.url).path:
            return CheckResult("mobile_content_parity", "perf", WARN,
                               f"mobile UA redirected {desktop_host} → {mobile_r.url} "
                               "(m./mobile subdomain is a legacy pattern — prefer responsive design)")
    desktop_size = len(s.response.content)
    mobile_size = len(mobile_r.content)
    if desktop_size == 0:
        return CheckResult("mobile_content_parity", "perf", INFO, "desktop response empty")
    ratio = mobile_size / desktop_size
    # mobile should be the same page or very close
    if ratio < 0.3:
        return CheckResult("mobile_content_parity", "perf", WARN,
                           f"mobile HTML is {int(ratio*100)}% of desktop "
                           f"({mobile_size // 1024} KB vs {desktop_size // 1024} KB) "
                           "— content divergence may hide features from mobile users")
    if ratio > 3:
        return CheckResult("mobile_content_parity", "perf", WARN,
                           f"mobile HTML is {int(ratio*100)}% of desktop — unusual divergence")
    return CheckResult("mobile_content_parity", "perf", PASS,
                       f"mobile HTML {mobile_size // 1024} KB (desktop {desktop_size // 1024} KB); "
                       f"no divergence")


def check_responsive_images_srcset(s: Site) -> CheckResult:
    """Images use srcset or <picture><source> for different display densities."""
    imgs = s.soup.find_all("img")
    if len(imgs) < 3:
        return CheckResult("responsive_images_srcset", "perf", INFO,
                           f"only {len(imgs)} images")
    responsive = 0
    for img in imgs:
        if img.get("srcset"):
            responsive += 1
            continue
        if img.find_parent("picture"):
            responsive += 1
            continue
    pct = responsive * 100 // len(imgs)
    if pct >= 70:
        return CheckResult("responsive_images_srcset", "perf", PASS,
                           f"{responsive}/{len(imgs)} images responsive ({pct}%)")
    if pct >= 30:
        return CheckResult("responsive_images_srcset", "perf", WARN,
                           f"only {responsive}/{len(imgs)} use srcset or <picture> ({pct}%) — "
                           "mobile users download desktop-size images")
    return CheckResult("responsive_images_srcset", "perf", FAIL,
                       f"{responsive}/{len(imgs)} responsive ({pct}%) — "
                       "add srcset for DPR / viewport sizes")


# ---------- Accessibility (a11y) ----------


def check_heading_hierarchy(s: Site) -> CheckResult:
    """Exactly one <h1>, no skipped levels (e.g. H2 → H4)."""
    headings = s.soup.find_all(re.compile("^h[1-6]$"))
    if not headings:
        return CheckResult("heading_hierarchy", "a11y", FAIL, "no headings on page")
    levels = [int(h.name[1]) for h in headings]
    h1_count = levels.count(1)
    if h1_count == 0:
        return CheckResult("heading_hierarchy", "a11y", FAIL, "no <h1>")
    # check for skipped levels
    skips = []
    for i in range(1, len(levels)):
        if levels[i] > levels[i - 1] + 1:
            skips.append(f"h{levels[i-1]} → h{levels[i]}")
    if h1_count > 1:
        return CheckResult("heading_hierarchy", "a11y", WARN,
                           f"{h1_count} <h1> elements" + (f"; skips: {skips[0]}" if skips else ""))
    if skips:
        return CheckResult("heading_hierarchy", "a11y", WARN,
                           f"skipped heading level(s): {', '.join(skips[:3])}")
    return CheckResult("heading_hierarchy", "a11y", PASS,
                       f"{len(headings)} headings, levels {sorted(set(levels))}")


def check_form_inputs_labeled(s: Site) -> CheckResult:
    """Every interactive form control has an accessible name."""
    skip_types = {"hidden", "submit", "button", "reset", "image"}
    inputs = []
    for tag in ("input", "select", "textarea"):
        for el in s.soup.find_all(tag):
            if tag == "input" and (el.get("type") or "text").lower() in skip_types:
                continue
            inputs.append(el)
    if not inputs:
        return CheckResult("form_inputs_labeled", "a11y", INFO, "no form inputs on page")
    # build id → <label for=> map
    label_ids: set[str] = set()
    for lab in s.soup.find_all("label", attrs={"for": True}):
        label_ids.add(lab["for"])
    unlabeled: list[str] = []
    for el in inputs:
        if el.get("aria-label") or el.get("aria-labelledby") or el.get("title"):
            continue
        if el.get("id") and el["id"] in label_ids:
            continue
        # wrapped inside a <label>?
        if el.find_parent("label"):
            continue
        name = el.get("name") or el.get("id") or el.get("type") or el.name
        unlabeled.append(f"<{el.name} {name}>")
    if unlabeled:
        return CheckResult("form_inputs_labeled", "a11y", FAIL,
                           f"{len(unlabeled)}/{len(inputs)} inputs unlabeled: {unlabeled[0]}")
    return CheckResult("form_inputs_labeled", "a11y", PASS,
                       f"{len(inputs)} inputs all have accessible names")


def check_landmark_regions(s: Site) -> CheckResult:
    mains = s.soup.find_all("main") + s.soup.find_all(attrs={"role": "main"})
    navs = s.soup.find_all("nav") + s.soup.find_all(attrs={"role": "navigation"})
    if len(mains) == 0:
        return CheckResult("landmark_regions", "a11y", FAIL,
                           "no <main> or role=main — screen readers can't find primary content")
    if len(mains) > 1:
        return CheckResult("landmark_regions", "a11y", WARN,
                           f"{len(mains)} <main> regions (should be exactly 1)")
    if not navs:
        return CheckResult("landmark_regions", "a11y", WARN,
                           "no <nav> landmark")
    return CheckResult("landmark_regions", "a11y", PASS,
                       f"1 <main>, {len(navs)} <nav>")


def check_button_accessible_name(s: Site) -> CheckResult:
    """Every <button> and <a href> has a visible name, aria-label, or aria-labelledby."""
    nameless: list[str] = []
    for tag in ("button", "a"):
        for el in s.soup.find_all(tag):
            if tag == "a" and not el.get("href"):
                continue
            txt = el.get_text(" ", strip=True)
            if txt:
                continue
            if el.get("aria-label") or el.get("aria-labelledby") or el.get("title"):
                continue
            # check nested <img alt>
            img = el.find("img")
            if img and (img.get("alt") or "").strip():
                continue
            # nested <svg> with role=img and <title>
            svg = el.find("svg")
            if svg and (svg.get("aria-label") or svg.find("title")):
                continue
            snippet = str(el)[:60].replace("\n", " ")
            nameless.append(snippet)
    if nameless:
        return CheckResult("button_accessible_name", "a11y", FAIL,
                           f"{len(nameless)} button(s)/link(s) with no accessible name: {nameless[0]}")
    return CheckResult("button_accessible_name", "a11y", PASS,
                       "all buttons and links have accessible names")


# ---------- Privacy ----------


def check_cookie_flags(s: Site) -> CheckResult:
    """Set-Cookie flags on the HTTPS response: Secure + HttpOnly + SameSite."""
    # get all Set-Cookie values preserving multiples
    raw_headers = s.response.raw.headers.getlist("Set-Cookie") if hasattr(
        s.response.raw.headers, "getlist") else [s.response.headers.get("Set-Cookie", "")]
    cookies = [h for h in raw_headers if h]
    if not cookies:
        return CheckResult("cookie_flags", "privacy", INFO, "no cookies set on response")
    is_https = s.final_url.startswith("https://")
    issues: list[str] = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing: list[str] = []
        if is_https and "; secure" not in low and not low.endswith(";secure"):
            missing.append("Secure")
        if "; httponly" not in low and "httponly" not in low.split(";")[0]:
            if not re.search(r"(?i)\bhttponly\b", c):
                missing.append("HttpOnly")
        if not re.search(r"(?i)\bsamesite\s*=", c):
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: missing {','.join(missing)}")
    if any("Secure" in i for i in issues) and is_https:
        return CheckResult("cookie_flags", "privacy", FAIL,
                           f"{len(issues)}/{len(cookies)} cookie(s) missing flags: {issues[0]}")
    if issues:
        return CheckResult("cookie_flags", "privacy", WARN,
                           f"{len(issues)}/{len(cookies)} cookie(s) missing flags: {issues[0]}")
    return CheckResult("cookie_flags", "privacy", PASS,
                       f"{len(cookies)} cookie(s) all Secure + HttpOnly + SameSite")


# ---------- Email DNS checks (MX, SPF, DKIM, DMARC, MTA-STS) ----------

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "mail", "k1", "k2",
    "s1", "s2", "mandrill", "sendgrid", "mailgun", "postmark", "zoho",
    "smtpapi", "fm1", "fm2", "fm3", "pic", "protonmail", "protonmail2",
    "protonmail3", "mxvault", "microsoft",
]


def _email_domain(site_host: str) -> str:
    """Strip leading www. — email is almost always on the bare apex for the common case."""
    return site_host[4:] if site_host.startswith("www.") else site_host


def _dns_txt(domain: str, timeout: float = 4.0) -> tuple[list[str], Optional[str]]:
    import dns.resolver
    import dns.exception
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(domain, "TXT", raise_on_no_answer=False)
        out: list[str] = []
        if answer.rrset is not None:
            for r in answer:
                out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        return out, None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        return [], str(e)


def _dns_mx(domain: str, timeout: float = 4.0) -> tuple[list[tuple[int, str]], Optional[str]]:
    import dns.resolver
    import dns.exception
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        records: list[tuple[int, str]] = []
        if answer.rrset is not None:
            for r in answer:
                records.append((r.preference, str(r.exchange).rstrip(".")))
        records.sort()
        return records, None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        return [], str(e)


def check_mx_records(s: Site) -> CheckResult:
    """Domain can receive email (has MX records)."""
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    mx, err = _dns_mx(domain)
    if err and err != "NXDOMAIN":
        return CheckResult("mx_records", "email", WARN, f"{domain}: {err}")
    if not mx:
        return CheckResult("mx_records", "email", WARN,
                           f"{domain} has no MX records — domain can't receive email")
    primary = mx[0]
    return CheckResult("mx_records", "email", PASS,
                       f"{len(mx)} MX record(s); primary: {primary[1]} (pref {primary[0]})")


def check_spf_record(s: Site) -> CheckResult:
    """v=spf1 TXT record at the apex prevents email spoofing."""
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    txts, err = _dns_txt(domain)
    if err and err != "NXDOMAIN":
        return CheckResult("spf_record", "email", WARN, f"{domain}: {err}")
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return CheckResult("spf_record", "email", FAIL,
                           f"{domain} has no v=spf1 TXT record — attackers can spoof your emails")
    if len(spf) > 1:
        return CheckResult("spf_record", "email", FAIL,
                           f"{len(spf)} SPF records — RFC forbids more than one; many receivers reject all")
    record = spf[0]
    ending = record.rsplit(" ", 1)[-1].lower()
    if ending in ("-all", "~all"):
        return CheckResult("spf_record", "email", PASS,
                           f"{ending} policy: {record[:100]}")
    if ending == "?all":
        return CheckResult("spf_record", "email", WARN,
                           f"?all (neutral) — attackers still succeed: {record[:100]}")
    if ending == "+all":
        return CheckResult("spf_record", "email", FAIL,
                           f"+all — any host can send as this domain: {record[:100]}")
    return CheckResult("spf_record", "email", WARN,
                       f"no explicit 'all' mechanism — policy ambiguous: {record[:100]}")


def check_dmarc_record(s: Site) -> CheckResult:
    """v=DMARC1 TXT at _dmarc.domain — tells receivers what to do with failing mail."""
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    txts, err = _dns_txt(f"_dmarc.{domain}")
    if err and err != "NXDOMAIN":
        return CheckResult("dmarc_record", "email", WARN, f"_dmarc.{domain}: {err}")
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return CheckResult("dmarc_record", "email", FAIL,
                           f"no DMARC policy at _dmarc.{domain} — spoofed mail is delivered without review")
    record = dmarc[0].lower()
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", record)
    policy = m.group(1) if m else "?"
    pct_m = re.search(r"\bpct\s*=\s*(\d+)", record)
    pct = pct_m.group(1) if pct_m else "100"
    if policy == "reject":
        return CheckResult("dmarc_record", "email", PASS,
                           f"p=reject pct={pct} — strongest policy")
    if policy == "quarantine":
        return CheckResult("dmarc_record", "email", PASS,
                           f"p=quarantine pct={pct}")
    if policy == "none":
        return CheckResult("dmarc_record", "email", WARN,
                           f"p=none (monitoring only) — consider tightening to quarantine/reject")
    return CheckResult("dmarc_record", "email", WARN,
                       f"DMARC TXT present but no p= tag: {dmarc[0][:100]}")


def _probe_dkim_selector(domain: str, selector: str) -> Optional[str]:
    txts, err = _dns_txt(f"{selector}._domainkey.{domain}", timeout=2.0)
    if err or not txts:
        return None
    for t in txts:
        if "v=DKIM1" in t or "k=" in t or "p=" in t:
            return t
    return None


def check_dkim_record(s: Site) -> CheckResult:
    """DKIM key published under at least one common selector."""
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    # parallelise the selector probes
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_dkim_selector, domain, sel): sel
                   for sel in COMMON_DKIM_SELECTORS}
        found: list[str] = []
        for fut in futures:
            sel = futures[fut]
            try:
                txt = fut.result()
            except Exception:
                continue
            if txt:
                found.append(sel)
    if found:
        return CheckResult("dkim_record", "email", PASS,
                           f"DKIM published under selector(s): {', '.join(sorted(found))}")
    return CheckResult("dkim_record", "email", WARN,
                       f"no DKIM key found at any common selector "
                       f"({len(COMMON_DKIM_SELECTORS)} tried) — your provider's "
                       "selector may differ; verify manually if email is configured")


def check_mta_sts(s: Site) -> CheckResult:
    """MTA-STS enforces TLS for inbound mail (optional but modern)."""
    domain = _email_domain(urlparse(s.final_url).hostname or "")
    txts, err = _dns_txt(f"_mta-sts.{domain}")
    if err and err != "NXDOMAIN":
        return CheckResult("mta_sts", "email", INFO, f"_mta-sts.{domain}: {err}")
    sts = [t for t in txts if t.lower().startswith("v=stsv1")]
    if sts:
        return CheckResult("mta_sts", "email", PASS, f"MTA-STS record: {sts[0][:80]}")
    return CheckResult("mta_sts", "email", INFO,
                       "no MTA-STS (optional; enforces TLS for inbound mail)")


def check_http_to_https(s: Site) -> CheckResult:
    p = urlparse(s.final_url)
    http_url = urlunparse(p._replace(scheme="http"))
    try:
        r = fetch(s.session, http_url, allow_redirects=False)
    except requests.RequestException as e:
        return CheckResult("http_to_https_redirect", "shared", WARN, f"http fetch failed: {e}")
    if r.status_code in (301, 308) and r.headers.get("Location", "").startswith("https://"):
        return CheckResult("http_to_https_redirect", "shared", PASS,
                           f"{r.status_code} → {r.headers.get('Location')}")
    return CheckResult("http_to_https_redirect", "shared", FAIL,
                       f"http returned {r.status_code}; Location={r.headers.get('Location')}")


def _canonical_host(s: Site) -> Optional[str]:
    link = s.soup.find("link", rel=lambda v: v and "canonical" in v)
    href = (link.get("href") or "").strip() if link else ""
    return urlparse(href).netloc or None


def check_www_apex(s: Site) -> CheckResult:
    host = urlparse(s.final_url).netloc
    alt = host[4:] if host.startswith("www.") else f"www.{host}"
    alt_url = f"https://{alt}/"
    canonical_host = _canonical_host(s)
    try:
        r = fetch(s.session, alt_url, allow_redirects=False)
    except requests.RequestException as e:
        return CheckResult("www_apex_canonicalization", "shared", WARN, f"{alt_url}: {e}")
    if r.status_code == 200:
        return CheckResult("www_apex_canonicalization", "shared", FAIL,
                           f"Both {host} and {alt} serve 200 — pick one and redirect")
    if r.status_code not in (301, 302, 307, 308):
        return CheckResult("www_apex_canonicalization", "shared", INFO,
                           f"{alt_url} returned {r.status_code}")
    location = r.headers.get("Location", "")
    target_host = urlparse(urljoin(alt_url, location)).netloc
    if target_host != host:
        return CheckResult("www_apex_canonicalization", "shared", FAIL,
                           f"{alt_url} → {location} (expected host {host})")
    if canonical_host and canonical_host != host:
        return CheckResult("www_apex_canonicalization", "shared", FAIL,
                           f"redirects to {host} but canonical says {canonical_host}")
    tag = " (matches canonical)" if canonical_host == host else ""
    return CheckResult("www_apex_canonicalization", "shared", PASS,
                       f"{alt_url} → {location}{tag}")


def check_hsts(s: Site) -> CheckResult:
    hsts = s.response.headers.get("Strict-Transport-Security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    if not hsts:
        return CheckResult("hsts_header", "shared", WARN, "no Strict-Transport-Security header")
    age = int(m.group(1)) if m else 0
    if age >= 15552000:
        return CheckResult("hsts_header", "shared", PASS, hsts)
    return CheckResult("hsts_header", "shared", WARN, f"max-age too low: {age}")


def check_content_type(s: Site) -> CheckResult:
    ct = s.response.headers.get("Content-Type", "")
    ok = "text/html" in ct and "utf-8" in ct.lower()
    return CheckResult("content_type_charset", "shared", PASS if ok else WARN, ct or "missing")


def check_x_robots(s: Site) -> CheckResult:
    xr = s.response.headers.get("X-Robots-Tag", "")
    if "noindex" in xr.lower():
        return CheckResult("x_robots_tag", "shared", FAIL, xr)
    return CheckResult("x_robots_tag", "shared", PASS, xr or "(none)")


def check_title(s: Site) -> CheckResult:
    raw = s.soup.title.string if s.soup.title and s.soup.title.string else ""
    if not raw.strip():
        return CheckResult("title_tag", "seo", FAIL, "no <title>")
    # what browsers/Google actually render after whitespace collapse
    normalized = re.sub(r"\s+", " ", raw).strip()
    n = len(normalized)
    if raw != normalized:
        # embedded newline or run of whitespace — template bug
        return CheckResult("title_tag", "seo", WARN,
                           f"{n} chars but raw title has stray whitespace "
                           f"(newline/indent) — fix your template: {normalized!r}")
    if not (15 <= n <= 65):
        return CheckResult("title_tag", "seo", WARN, f"length {n}: {normalized!r}")
    return CheckResult("title_tag", "seo", PASS, f"{n} chars: {normalized!r}")


def check_meta_description(s: Site) -> CheckResult:
    m = s.soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    c = (m.get("content") or "").strip() if m else ""
    if not c:
        return CheckResult("meta_description", "seo", FAIL, "missing")
    if not (50 <= len(c) <= 160):
        return CheckResult("meta_description", "seo", WARN, f"length {len(c)}")
    return CheckResult("meta_description", "seo", PASS, f"{len(c)} chars")


def check_canonical(s: Site) -> CheckResult:
    links = s.soup.find_all("link", rel=lambda v: v and "canonical" in v)
    if not links:
        return CheckResult("canonical", "seo", WARN, "no <link rel=canonical>")
    if len(links) > 1:
        return CheckResult("canonical", "seo", FAIL, f"{len(links)} canonical tags")
    href = (links[0].get("href") or "").strip()
    if not href.startswith("https://"):
        return CheckResult("canonical", "seo", WARN, f"not absolute https: {href}")
    normalized = percent_encode_path(href).rstrip("/")
    current = percent_encode_path(s.final_url).rstrip("/")
    if normalized != current:
        return CheckResult("canonical", "seo", WARN, f"{href} != {s.final_url}")
    return CheckResult("canonical", "seo", PASS, href)


def check_h1(s: Site) -> CheckResult:
    h1s = s.soup.find_all("h1")
    if len(h1s) == 0:
        return CheckResult("h1_single", "seo", FAIL, "no <h1>")
    if len(h1s) > 1:
        return CheckResult("h1_single", "seo", WARN, f"{len(h1s)} <h1> elements")
    txt = h1s[0].get_text(strip=True)
    if not txt:
        return CheckResult("h1_single", "seo", FAIL, "<h1> empty")
    return CheckResult("h1_single", "seo", PASS, txt[:80])


def check_html_lang(s: Site) -> CheckResult:
    html = s.soup.find("html")
    lang = (html.get("lang") if html else "") or ""
    if not lang:
        return CheckResult("html_lang", "seo", FAIL, "missing lang attr")
    host = urlparse(s.final_url).netloc
    if host.endswith(".dk") and not lang.lower().startswith("da"):
        return CheckResult("html_lang", "seo", WARN, f"lang={lang!r} on .dk site")
    return CheckResult("html_lang", "seo", PASS, lang)


def check_viewport(s: Site) -> CheckResult:
    m = s.soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)})
    c = (m.get("content") or "") if m else ""
    if "width=device-width" in c and "initial-scale=1" in c.replace(" ", ""):
        return CheckResult("viewport_meta", "seo", PASS, c)
    return CheckResult("viewport_meta", "seo", WARN, c or "missing")


def _head_or_get(session: requests.Session, url: str) -> requests.Response:
    r = session.head(url, timeout=TIMEOUT, headers={"User-Agent": UA}, allow_redirects=True)
    if r.status_code in (403, 405):
        r = fetch(session, url)
    return r


def _inspect_image(body: bytes, ct: str) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """Return (format, width, height). width/height may be None for SVG or unparsed formats."""
    if body.startswith(b"\x89PNG\r\n\x1a\n") and len(body) >= 24:
        return "PNG", int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")
    if body[:4] == b"\x00\x00\x01\x00" and len(body) >= 22:  # ICO
        count = int.from_bytes(body[4:6], "little")
        best = (0, 0)
        for i in range(count):
            off = 6 + i * 16
            if off + 2 > len(body):
                break
            w = body[off] or 256
            h = body[off + 1] or 256
            if w * h > best[0] * best[1]:
                best = (w, h)
        return "ICO", best[0] or None, best[1] or None
    if body[:6] in (b"GIF87a", b"GIF89a") and len(body) >= 10:
        return "GIF", int.from_bytes(body[6:8], "little"), int.from_bytes(body[8:10], "little")
    if ct.startswith("image/svg") or b"<svg" in body[:400].lower():
        return "SVG", None, None
    if body[:2] == b"\xff\xd8":
        return "JPEG", None, None
    if body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "WEBP", None, None
    return None, None, None


def check_favicon(s: Site) -> CheckResult:
    """Favicon meets Google Search's favicon requirements."""
    link = s.soup.find("link", rel=lambda v: v and "icon" in v and "apple" not in v)
    declared = link.get("href") if link and link.get("href") else None
    href = declared or "/favicon.ico"
    url = urljoin(s.final_url, href)

    # 1. Crawlable by Googlebot (per robots.txt)
    if s.robots_text:
        path = urlparse(url).path or "/"
        groups = _parse_robots_groups(s.robots_text)
        allowed, matched = _path_allowed_for("Googlebot", path, groups)
        if not allowed:
            return CheckResult("favicon", "seo", FAIL,
                               f"robots.txt blocks Googlebot from favicon "
                               f"({matched[0]}: {matched[1]}): {url}")

    # 2. Fetches 200
    try:
        r = s.session.get(url, timeout=TIMEOUT, allow_redirects=True,
                          headers={"User-Agent": UA})
    except requests.RequestException as e:
        return CheckResult("favicon", "seo", FAIL, f"{url}: {e}")
    if r.status_code != 200:
        return CheckResult("favicon", "seo", FAIL, f"{r.status_code} {url}")

    # 3. Content-Type must be image/* (or ico variant)
    ct = r.headers.get("Content-Type", "").lower().split(";")[0].strip()
    if not (ct.startswith("image/") or "icon" in ct):
        return CheckResult("favicon", "seo", WARN,
                           f"Content-Type={ct!r} (expected image/*): {url}")

    # 4. Format + dimensions
    fmt, w, h = _inspect_image(r.content, ct)
    if fmt is None:
        return CheckResult("favicon", "seo", WARN,
                           f"unknown format ({ct}, {len(r.content)} bytes): {url}")

    declared_note = "" if link else "  (no <link rel=icon>; Google fell back to /favicon.ico)"

    if fmt == "SVG":
        status = PASS if link else WARN
        return CheckResult("favicon", "seo", status,
                           f"SVG (vector, scales){declared_note}: {url}")

    # raster formats
    if w is None or h is None:
        return CheckResult("favicon", "seo", WARN,
                           f"{fmt} — could not read dimensions: {url}")
    if w != h:
        return CheckResult("favicon", "seo", WARN,
                           f"{fmt} {w}×{h} not square — Google needs square{declared_note}: {url}")
    if w < 48:
        return CheckResult("favicon", "seo", WARN,
                           f"{fmt} {w}×{h} too small — Google wants multiple of 48 (48,96,144,192){declared_note}")
    if w % 48 != 0:
        return CheckResult("favicon", "seo", WARN,
                           f"{fmt} {w}×{h} — Google prefers multiple of 48 (next: {((w // 48) + 1) * 48}){declared_note}")
    return CheckResult("favicon", "seo", PASS,
                       f"{fmt} {w}×{h}{declared_note}: {url}")


def check_apple_touch_icon(s: Site) -> CheckResult:
    """Icon used by iOS/iMessage bookmark preview."""
    link = s.soup.find("link", rel=lambda v: v and "apple-touch-icon" in v)
    if not link or not link.get("href"):
        # fallback path Apple tries automatically
        url = urljoin(root_url(s.final_url), "/apple-touch-icon.png")
        try:
            r = _head_or_get(s.session, url)
        except requests.RequestException as e:
            return CheckResult("apple_touch_icon", "seo", WARN, f"{url}: {e}")
        if r.status_code == 200:
            return CheckResult("apple_touch_icon", "seo", WARN,
                               "no <link rel=apple-touch-icon>; Apple fell back to /apple-touch-icon.png")
        return CheckResult("apple_touch_icon", "seo", WARN,
                           "no apple-touch-icon — iMessage/iOS bookmark preview will be generic")
    url = urljoin(s.final_url, link["href"])
    try:
        r = _head_or_get(s.session, url)
    except requests.RequestException as e:
        return CheckResult("apple_touch_icon", "seo", WARN, f"{url}: {e}")
    if r.status_code != 200:
        return CheckResult("apple_touch_icon", "seo", FAIL, f"{r.status_code} {url}")
    ct = r.headers.get("Content-Type", "")
    if "image" not in ct.lower():
        return CheckResult("apple_touch_icon", "seo", WARN,
                           f"Content-Type={ct!r} (expected image/*)")
    return CheckResult("apple_touch_icon", "seo", PASS, f"{url} ({ct})")


def check_images_alt(s: Site) -> CheckResult:
    imgs = s.soup.find_all("img")
    if not imgs:
        return CheckResult("images_alt", "seo", INFO, "no <img> on page")
    missing = [i for i in imgs if not (i.get("alt") or "").strip()]
    if not missing:
        return CheckResult("images_alt", "seo", PASS, f"{len(imgs)} imgs all have alt")
    pct = len(missing) * 100 // len(imgs)
    status = WARN if pct < 30 else FAIL
    return CheckResult("images_alt", "seo", status,
                       f"{len(missing)}/{len(imgs)} missing alt ({pct}%)")


def check_images_dimensions(s: Site) -> CheckResult:
    imgs = s.soup.find_all("img")
    if not imgs:
        return CheckResult("images_dimensions", "perf", INFO, "no <img>")
    missing = [i for i in imgs if not (i.get("width") and i.get("height"))]
    if not missing:
        return CheckResult("images_dimensions", "perf", PASS, "all have width+height")
    pct = len(missing) * 100 // len(imgs)
    return CheckResult("images_dimensions", "perf", WARN,
                       f"{len(missing)}/{len(imgs)} missing width/height ({pct}%) — CLS risk")


def check_open_graph(s: Site) -> CheckResult:
    required = ["og:title", "og:description", "og:image", "og:url", "og:type"]
    found = {m.get("property"): (m.get("content") or "")
             for m in s.soup.find_all("meta", property=re.compile("^og:"))}
    missing = [k for k in required if not found.get(k)]
    if missing:
        return CheckResult("open_graph", "seo", WARN, f"missing: {', '.join(missing)}")
    img = found["og:image"]
    try:
        r = s.session.head(urljoin(s.final_url, img), timeout=TIMEOUT,
                           headers={"User-Agent": UA}, allow_redirects=True)
        if r.status_code >= 400:
            return CheckResult("open_graph", "seo", WARN, f"og:image {r.status_code}: {img}")
    except requests.RequestException as e:
        return CheckResult("open_graph", "seo", WARN, f"og:image fetch failed: {e}")
    return CheckResult("open_graph", "seo", PASS, "all present + og:image reachable")


def check_twitter_card(s: Site) -> CheckResult:
    found = {m.get("name"): (m.get("content") or "")
             for m in s.soup.find_all("meta", attrs={"name": re.compile("^twitter:")})}
    card = found.get("twitter:card", "")
    if not card:
        return CheckResult("twitter_card", "seo", WARN, "no twitter:card")
    if card != "summary_large_image":
        return CheckResult("twitter_card", "seo", INFO, f"card={card} (prefer summary_large_image)")
    return CheckResult("twitter_card", "seo", PASS, card)


def check_json_ld(s: Site) -> CheckResult:
    scripts = s.soup.find_all("script", attrs={"type": "application/ld+json"})
    if not scripts:
        return CheckResult("json_ld_structured_data", "seo", WARN, "no JSON-LD")
    external = [sc for sc in scripts if sc.get("src")]
    if external:
        return CheckResult("json_ld_structured_data", "seo", FAIL,
                           "JSON-LD loaded via src= (Google ignores it)")
    types: list[str] = []

    def collect(node) -> None:
        if isinstance(node, list):
            for n in node:
                collect(n)
            return
        if not isinstance(node, dict):
            return
        if "@type" in node:
            t = node["@type"]
            types.extend(t if isinstance(t, list) else [t])
        if "@graph" in node:
            collect(node["@graph"])

    for sc in scripts:
        if not sc.string:
            continue
        try:
            data = json.loads(sc.string)
        except json.JSONDecodeError:
            return CheckResult("json_ld_structured_data", "seo", FAIL, "invalid JSON in JSON-LD")
        collect(data)
    useful = {"Organization", "WebSite", "LocalBusiness", "Article", "BlogPosting",
              "FAQPage", "Product", "Service", "Person", "BreadcrumbList"}
    if not (set(types) & useful):
        return CheckResult("json_ld_structured_data", "seo", WARN,
                           f"present but none of {sorted(useful)}: got {types}")
    return CheckResult("json_ld_structured_data", "seo", PASS, ", ".join(sorted(set(types))))


def check_hreflang(s: Site) -> CheckResult:
    alts = s.soup.find_all("link", rel=lambda v: v and "alternate" in v, hreflang=True)
    if not alts:
        return CheckResult("hreflang", "seo", INFO, "no hreflang (single-language site)")
    langs = [a.get("hreflang") for a in alts]
    if "x-default" not in langs:
        return CheckResult("hreflang", "seo", WARN, f"no x-default; langs={langs}")
    return CheckResult("hreflang", "seo", PASS, ", ".join(langs))


VALID_ROBOTS_DIRECTIVES = {
    "user-agent", "disallow", "allow", "sitemap", "crawl-delay",
    "host", "noindex",  # noindex is deprecated but still encountered
}


def check_robots_txt(s: Site) -> CheckResult:
    """Status code + Content-Type + parseability + syntax sanity of /robots.txt.

    robots.txt is optional (absent = allow-all); but if present, it must be
    served correctly or crawlers ignore it.
    """
    # --- 1. status code ---
    if s.robots_status is None:
        return CheckResult("robots_txt", "shared", FAIL,
                           f"GET {s.robots_url} failed (network error)")
    if s.robots_status == 404:
        return CheckResult("robots_txt", "shared", INFO,
                           f"404 {s.robots_url} — no robots.txt (defaults to allow-all)")
    if s.robots_status >= 500:
        return CheckResult("robots_txt", "shared", FAIL,
                           f"{s.robots_status} server error on {s.robots_url} — "
                           "Google treats 5xx as full block")
    if s.robots_status != 200:
        return CheckResult("robots_txt", "shared", FAIL,
                           f"{s.robots_status} on {s.robots_url}")

    # --- 2. Content-Type ---
    ct = (s.robots_content_type or "").lower().split(";")[0].strip()
    ct_issues = []
    if not ct:
        ct_issues.append("no Content-Type header")
    elif ct != "text/plain":
        ct_issues.append(f"Content-Type={ct!r} (want text/plain)")

    # --- 3. content / syntax ---
    text = s.robots_text or ""
    if not text.strip():
        return CheckResult("robots_txt", "shared", FAIL,
                           "200 but empty body — crawlers may treat as allow-all or error")
    syntax_issues: list[str] = []
    if text.startswith("\ufeff"):
        syntax_issues.append("BOM at start")
    if "\r\n" in text:
        syntax_issues.append("Windows (CRLF) line endings")
    # unknown directives and rules-before-user-agent
    saw_user_agent = False
    unknown: list[str] = []
    rule_before_ua: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key = line.split(":", 1)[0].strip().lower()
        if key == "user-agent":
            saw_user_agent = True
            continue
        if key not in VALID_ROBOTS_DIRECTIVES:
            if key not in unknown:
                unknown.append(key)
            continue
        if key in ("disallow", "allow") and not saw_user_agent:
            rule_before_ua.append(key)
    if unknown:
        syntax_issues.append(f"unknown directive(s): {', '.join(unknown[:3])}")
    if rule_before_ua:
        syntax_issues.append(f"{rule_before_ua[0]} before any User-agent — ignored")

    # parseable?
    groups = _parse_robots_groups(text)
    if not any(agents for agents, _ in groups):
        return CheckResult("robots_txt", "shared", FAIL,
                           "no User-agent lines — file is unparseable")

    has_sitemap = bool(re.search(r"(?im)^\s*sitemap\s*:", text))

    # aggregate verdict
    if ct_issues:
        # bad Content-Type → Google may refuse to use the file at all
        return CheckResult("robots_txt", "shared", WARN,
                           f"200 + parses ({len(groups)} groups); "
                           f"{ct_issues[0]} — crawlers may ignore")
    if syntax_issues:
        return CheckResult("robots_txt", "shared", WARN,
                           f"200 text/plain, {len(groups)} groups; "
                           f"issues: {'; '.join(syntax_issues)}")
    if not has_sitemap:
        return CheckResult("robots_txt", "shared", WARN,
                           f"200 text/plain, {len(groups)} groups — "
                           "no Sitemap: line (add to help crawlers discover your URLs)")
    return CheckResult("robots_txt", "shared", PASS,
                       f"200 text/plain, {len(groups)} groups, Sitemap: present")


def _sitemap_url(s: Site) -> str:
    if s.robots_text:
        for line in s.robots_text.splitlines():
            m = re.match(r"(?i)\s*sitemap\s*:\s*(\S+)", line)
            if m:
                return m.group(1).strip()
    return urljoin(root_url(s.final_url), "/sitemap.xml")


SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


SITEMAP_GOOD_CTS = ("application/xml", "text/xml", "application/rss+xml",
                    "application/atom+xml", "text/plain")


def _parse_sitemap(session: requests.Session, url: str, depth: int = 0
                   ) -> tuple[Optional[ET.Element], Optional[str], Optional[int], Optional[str]]:
    """Return (root, error, status_code, content_type)."""
    try:
        r = fetch(session, url)
    except requests.RequestException as e:
        return None, f"{url}: {e}", None, None
    ct = r.headers.get("Content-Type", "").lower().split(";")[0].strip()
    if r.status_code != 200:
        return None, f"{r.status_code} {url}", r.status_code, ct
    if not ct or ct not in SITEMAP_GOOD_CTS:
        return None, f"{url} served as {ct!r} (expected application/xml)", r.status_code, ct
    try:
        return ET.fromstring(r.text), None, r.status_code, ct
    except ET.ParseError as e:
        return None, f"{url} invalid XML at {e}", r.status_code, ct


def check_sitemap(s: Site) -> tuple[CheckResult, list[str]]:
    url = _sitemap_url(s)
    root, err, status, ct = _parse_sitemap(s.session, url)

    # explicit status-first reporting (like robots_txt)
    if status is None:
        return CheckResult("sitemap_xml", "seo", FAIL, err or "fetch failed", url), []
    if status == 404:
        return CheckResult("sitemap_xml", "seo", FAIL,
                           f"404 {url} — Google needs a sitemap to discover URLs"), []
    if status >= 500:
        return CheckResult("sitemap_xml", "seo", FAIL,
                           f"{status} server error on {url}"), []
    if status != 200:
        return CheckResult("sitemap_xml", "seo", FAIL, f"{status} {url}"), []
    if ct and ct not in SITEMAP_GOOD_CTS:
        return CheckResult("sitemap_xml", "seo", FAIL,
                           f"200 but Content-Type={ct!r} (want application/xml) — "
                           "Google may reject as not a sitemap"), []
    if root is None:
        return CheckResult("sitemap_xml", "seo", FAIL, err or "parse failed", url), []

    # sitemap index: recurse one level into child sitemaps
    child_locs = [loc.text.strip()
                  for sm in root.iter(f"{SITEMAP_NS}sitemap")
                  for loc in sm.iter(f"{SITEMAP_NS}loc") if loc.text]
    is_index = root.tag.endswith("sitemapindex") or bool(child_locs)
    locs: list[str] = []
    lastmods: list[str] = []
    sub_errors: list[str] = []

    if is_index:
        for child_url in child_locs[:5]:
            sub_root, sub_err, _, _ = _parse_sitemap(s.session, child_url, depth=1)
            if sub_err or sub_root is None:
                sub_errors.append(sub_err or child_url)
                continue
            locs.extend(e.text.strip() for e in sub_root.iter(f"{SITEMAP_NS}loc") if e.text)
            lastmods.extend(e.text for e in sub_root.iter(f"{SITEMAP_NS}lastmod"))
    else:
        locs = [e.text.strip() for e in root.iter(f"{SITEMAP_NS}loc") if e.text]
        lastmods = [e.text for e in root.iter(f"{SITEMAP_NS}lastmod")]

    if not locs:
        return CheckResult("sitemap_xml", "seo", FAIL,
                           "no <loc> URLs" + (f"; sub-errors: {sub_errors[0]}" if sub_errors else ""),
                           url), []
    issues = []
    if sub_errors:
        issues.append(f"{len(sub_errors)} child sitemap(s) failed")
    bad_scheme = [u for u in locs if not u.startswith("https://")]
    if bad_scheme:
        issues.append(f"{len(bad_scheme)} non-https URLs")
    if len(lastmods) < len(locs):
        issues.append(f"{len(locs) - len(lastmods)} URLs missing <lastmod>")
    for u in locs:
        if any(ord(c) > 127 for c in u):
            issues.append("non-ASCII URL not percent-encoded")
            break
    prefix = "sitemap index: " if is_index else ""
    verdict = WARN if issues else PASS
    ct_note = ct or "?"
    msg = (f"200 {ct_note}, {prefix}{len(locs)} URLs"
           + (f"; {', '.join(issues)}" if issues else ""))
    return CheckResult("sitemap_xml", "seo", verdict, msg, url), locs


def check_sitemap_urls_reachable(s: Site, locs: list[str]) -> CheckResult:
    if not locs:
        return CheckResult("sitemap_urls_reachable", "seo", INFO, "no sitemap to sample")
    sample = locs[:10]
    broken = []
    for u in sample:
        try:
            r = fetch(s.session, u, allow_redirects=False)
            if r.status_code >= 400 or r.status_code in (301, 302, 307, 308):
                broken.append(f"{u} [{r.status_code}]")
        except requests.RequestException as e:
            broken.append(f"{u} [{e}]")
    if broken:
        return CheckResult("sitemap_urls_reachable", "seo", WARN,
                           f"{len(broken)}/{len(sample)} not self-200: {broken[0]}")
    return CheckResult("sitemap_urls_reachable", "seo", PASS,
                       f"{len(sample)} sampled, all 200 self-canonical")


def _outgoing_links(s: Site) -> tuple[list[str], list[str]]:
    """Return (internal_links, external_links) on the page, excluding fragments/mailto/tel."""
    host = urlparse(s.final_url).netloc
    internal: list[str] = []
    external: list[str] = []
    seen: set[str] = set()
    for a in s.soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        u = urljoin(s.final_url, href)
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            continue
        if u in seen:
            continue
        seen.add(u)
        (internal if p.netloc == host else external).append(u)
    return internal, external


def check_outgoing_links_present(s: Site) -> CheckResult:
    internal, external = _outgoing_links(s)
    total = len(internal) + len(external)
    if total == 0:
        return CheckResult("outgoing_links_present", "seo", FAIL,
                           "page has no outgoing links — dead-end for crawlers")
    return CheckResult("outgoing_links_present", "seo", PASS,
                       f"{len(internal)} internal, {len(external)} external")


def _probe_internal_links(s: Site) -> tuple[list[CheckResult], None]:
    internal, _ = _outgoing_links(s)
    sample = internal[:10]
    broken: list[str] = []
    redirected: list[str] = []
    if not sample:
        info = CheckResult("internal_links_not_broken", "seo", INFO, "no internal links")
        info2 = CheckResult("internal_links_not_redirecting", "seo", INFO, "no internal links")
        return [info, info2], None
    for u in sample:
        try:
            r = s.session.head(u, timeout=TIMEOUT, allow_redirects=False,
                               headers={"User-Agent": UA})
            if r.status_code in (403, 405):
                r = fetch(s.session, u, allow_redirects=False)
            code = r.status_code
            if code in (301, 302, 303, 307, 308):
                redirected.append(f"{u} [{code}→{r.headers.get('Location', '?')}]")
            elif code >= 400:
                broken.append(f"{u} [{code}]")
        except requests.RequestException as e:
            broken.append(f"{u} [{e}]")
    broken_res = (CheckResult("internal_links_not_broken", "seo", FAIL,
                              f"{len(broken)}/{len(sample)} broken: {broken[0]}")
                  if broken else
                  CheckResult("internal_links_not_broken", "seo", PASS,
                              f"{len(sample)} sampled, none broken"))
    redir_res = (CheckResult("internal_links_not_redirecting", "seo", WARN,
                             f"{len(redirected)}/{len(sample)} go through redirect: {redirected[0]}")
                 if redirected else
                 CheckResult("internal_links_not_redirecting", "seo", PASS,
                             f"{len(sample)} sampled, none redirect"))
    return [broken_res, redir_res], None


def check_canonical_not_redirect(s: Site) -> CheckResult:
    link = s.soup.find("link", rel=lambda v: v and "canonical" in v)
    href = (link.get("href") or "").strip() if link else ""
    if not href:
        return CheckResult("canonical_not_redirect", "seo", INFO, "no canonical tag")
    try:
        r = s.session.head(href, timeout=TIMEOUT, allow_redirects=False,
                           headers={"User-Agent": UA})
        if r.status_code in (403, 405):
            r = fetch(s.session, href, allow_redirects=False)
    except requests.RequestException as e:
        return CheckResult("canonical_not_redirect", "seo", WARN, f"{href}: {e}")
    if r.status_code == 200:
        return CheckResult("canonical_not_redirect", "seo", PASS, f"200 {href}")
    if r.status_code in (301, 302, 303, 307, 308):
        return CheckResult("canonical_not_redirect", "seo", FAIL,
                           f"canonical redirects: {href} → {r.headers.get('Location')}")
    return CheckResult("canonical_not_redirect", "seo", WARN, f"{r.status_code} {href}")


def check_page_response_time(s: Site) -> CheckResult:
    ms = int(s.response.elapsed.total_seconds() * 1000)
    if ms >= SLOW_PAGE_FAIL_MS:
        return CheckResult("page_response_time", "perf", FAIL, f"{ms} ms (very slow)")
    if ms >= SLOW_PAGE_WARN_MS:
        return CheckResult("page_response_time", "perf", WARN, f"{ms} ms")
    return CheckResult("page_response_time", "perf", PASS, f"{ms} ms")


def check_html_size(s: Site) -> CheckResult:
    size = len(s.response.content)
    kb = size / 1024
    if size >= HTML_SIZE_FAIL:
        return CheckResult("html_size", "perf", FAIL, f"{kb:.0f} KB (>2 MB)")
    if size >= HTML_SIZE_WARN:
        return CheckResult("html_size", "perf", WARN, f"{kb:.0f} KB (>500 KB)")
    return CheckResult("html_size", "perf", PASS, f"{kb:.0f} KB")


def _asset_size(session: requests.Session, url: str) -> tuple[Optional[int], Optional[int]]:
    """Return (status_code, bytes) for an asset. bytes=None if Content-Length absent."""
    try:
        r = session.head(url, timeout=TIMEOUT, allow_redirects=True,
                         headers={"User-Agent": UA})
        if r.status_code in (403, 405):
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True,
                            headers={"User-Agent": UA})
            r.close()
    except requests.RequestException:
        return None, None
    cl = r.headers.get("Content-Length")
    return r.status_code, int(cl) if cl and cl.isdigit() else None


def check_image_sizes(s: Site) -> CheckResult:
    imgs = [urljoin(s.final_url, i["src"]) for i in s.soup.find_all("img", src=True)]
    imgs = list(dict.fromkeys(imgs))[:ASSET_SAMPLE]
    if not imgs:
        return CheckResult("image_sizes", "perf", INFO, "no <img> on page")
    too_big: list[str] = []
    warn_big: list[str] = []
    unknown = 0
    for u in imgs:
        code, size = _asset_size(s.session, u)
        if size is None:
            unknown += 1
            continue
        if size >= IMAGE_SIZE_FAIL:
            too_big.append(f"{u} ({size // 1024} KB)")
        elif size >= IMAGE_SIZE_WARN:
            warn_big.append(f"{u} ({size // 1024} KB)")
    if too_big:
        return CheckResult("image_sizes", "perf", FAIL,
                           f"{len(too_big)} image(s) >500 KB: {too_big[0]}")
    if warn_big:
        return CheckResult("image_sizes", "perf", WARN,
                           f"{len(warn_big)} image(s) >200 KB: {warn_big[0]}")
    if unknown == len(imgs):
        return CheckResult("image_sizes", "perf", INFO,
                           "no Content-Length on sampled images")
    return CheckResult("image_sizes", "perf", PASS,
                       f"{len(imgs) - unknown}/{len(imgs)} sampled images under 200 KB")


def check_css_sizes(s: Site) -> CheckResult:
    css = [urljoin(s.final_url, l["href"])
           for l in s.soup.find_all("link", rel=lambda v: v and "stylesheet" in v, href=True)]
    css = list(dict.fromkeys(css))[:ASSET_SAMPLE]
    if not css:
        return CheckResult("css_sizes", "perf", INFO, "no external <link rel=stylesheet>")
    big: list[str] = []
    for u in css:
        code, size = _asset_size(s.session, u)
        if size and size >= CSS_SIZE_WARN:
            big.append(f"{u} ({size // 1024} KB)")
    if big:
        return CheckResult("css_sizes", "perf", WARN,
                           f"{len(big)} CSS file(s) >100 KB: {big[0]}")
    return CheckResult("css_sizes", "perf", PASS, f"{len(css)} CSS file(s) all <100 KB")


def check_js_assets_reachable(s: Site) -> CheckResult:
    js = [urljoin(s.final_url, sc["src"])
          for sc in s.soup.find_all("script", src=True)]
    js = list(dict.fromkeys(js))[:ASSET_SAMPLE]
    if not js:
        return CheckResult("js_assets_reachable", "perf", INFO, "no external <script src>")
    broken: list[str] = []
    huge: list[str] = []
    for u in js:
        code, size = _asset_size(s.session, u)
        if code is None or code >= 400:
            broken.append(f"{u} [{code}]")
        elif size and size >= JS_SIZE_WARN:
            huge.append(f"{u} ({size // 1024} KB)")
    if broken:
        return CheckResult("js_assets_reachable", "perf", FAIL,
                           f"{len(broken)}/{len(js)} JS files broken: {broken[0]}")
    if huge:
        return CheckResult("js_assets_reachable", "perf", WARN,
                           f"{len(huge)} JS file(s) >300 KB: {huge[0]}")
    return CheckResult("js_assets_reachable", "perf", PASS, f"{len(js)} JS files all 2xx")


def check_llms_txt(s: Site) -> CheckResult:
    url = urljoin(root_url(s.final_url), "/llms.txt")
    try:
        r = fetch(s.session, url)
    except requests.RequestException as e:
        return CheckResult("llms_txt", "llm", FAIL, f"{url}: {e}")
    if r.status_code != 200:
        return CheckResult("llms_txt", "llm", FAIL, f"{r.status_code} {url}")
    ct = r.headers.get("Content-Type", "")
    if not ct.lower().startswith("text/plain"):
        return CheckResult("llms_txt", "llm", WARN, f"Content-Type={ct!r} (want text/plain)")
    body = r.text
    if not body.strip():
        return CheckResult("llms_txt", "llm", FAIL, "empty body")
    has_heading = bool(re.search(r"(?m)^#\s", body))
    has_link = bool(re.search(r"\[.+?\]\(.+?\)|https?://", body))
    if not (has_heading and has_link):
        return CheckResult("llms_txt", "llm", WARN, "missing markdown heading or link")
    return CheckResult("llms_txt", "llm", PASS, f"{len(body)} bytes, valid")


def check_llms_full_txt(s: Site) -> CheckResult:
    url = urljoin(root_url(s.final_url), "/llms-full.txt")
    try:
        r = fetch(s.session, url)
    except requests.RequestException as e:
        return CheckResult("llms_full_txt", "llm", INFO, f"optional; {e}")
    if r.status_code != 200 or not r.text.strip():
        return CheckResult("llms_full_txt", "llm", INFO, f"{r.status_code} (optional)")
    ct = r.headers.get("Content-Type", "")
    if not ct.lower().startswith("text/"):
        return CheckResult("llms_full_txt", "llm", WARN,
                           f"{len(r.text)} bytes but Content-Type={ct!r} (want text/plain)")
    return CheckResult("llms_full_txt", "llm", PASS, f"{len(r.text)} bytes, {ct}")


def _parse_robots_groups(txt: str) -> list[tuple[list[str], list[tuple[str, str]]]]:
    groups: list[tuple[list[str], list[tuple[str, str]]]] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []
    last_was_agent = False
    for raw in txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "user-agent":
            if not last_was_agent and (agents or rules):
                groups.append((agents, rules))
                agents, rules = [], []
            agents.append(v)
            last_was_agent = True
        elif k in ("allow", "disallow"):
            rules.append((k, v))
            last_was_agent = False
    if agents or rules:
        groups.append((agents, rules))
    return groups


def _bot_allowed(bot: str, groups) -> Optional[bool]:
    """Return True if allowed, False if disallowed, None if unspecified."""
    for agents, rules in groups:
        if any(a.lower() == bot.lower() for a in agents):
            for k, v in rules:
                if k == "disallow" and v == "/":
                    return False
                if k == "allow" and v == "/":
                    return True
            return True
    return None


def _robots_pattern_to_regex(pattern: str) -> str:
    """Convert a robots.txt Disallow/Allow value to a regex (Google's spec)."""
    end_anchor = pattern.endswith("$")
    if end_anchor:
        pattern = pattern[:-1]
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        else:
            parts.append(re.escape(ch))
    regex = "^" + "".join(parts) + ("$" if end_anchor else "")
    return regex


def _path_allowed_for(bot: str, path: str, groups) -> tuple[bool, Optional[tuple[str, str]]]:
    """Is this path crawlable by bot per robots.txt? Returns (allowed, matched_rule).

    Follows Google's spec: longest-matching rule wins; Allow beats Disallow on ties.
    Falls back to * group when no bot-specific group exists.
    """
    group_rules: list[tuple[str, str]] = []
    star_rules: list[tuple[str, str]] = []
    for agents, rules in groups:
        lowered = [a.lower() for a in agents]
        if bot.lower() in lowered:
            group_rules = rules
            break
        if "*" in lowered:
            star_rules = rules
    rules = group_rules or star_rules
    if not rules:
        return True, None
    best: Optional[tuple[int, str, str, str]] = None  # (length, kind, pattern, path)
    for kind, pattern in rules:
        if not pattern:
            continue
        try:
            if re.search(_robots_pattern_to_regex(pattern), path):
                score = len(pattern)
                # Allow beats Disallow at equal length
                if best is None or score > best[0] or (score == best[0] and kind == "allow"):
                    best = (score, kind, pattern, path)
        except re.error:
            continue
    if best is None:
        return True, None
    allowed = best[1] == "allow"
    return allowed, (best[1], best[2])


def check_ai_crawlers(s: Site) -> CheckResult:
    if s.robots_text is None:
        return CheckResult("ai_crawlers_allowed", "llm", INFO,
                           "no robots.txt — defaults to allow-all")
    groups = _parse_robots_groups(s.robots_text)
    star_blocked = _bot_allowed("*", groups) is False
    blocked = []
    for bot in AI_BOTS:
        v = _bot_allowed(bot, groups)
        if v is False:
            blocked.append(bot)
        elif v is None and star_blocked:
            blocked.append(f"{bot} (via *)")
    if blocked:
        return CheckResult("ai_crawlers_allowed", "llm", WARN,
                           f"blocked: {', '.join(blocked)}")
    return CheckResult("ai_crawlers_allowed", "llm", PASS,
                       f"{', '.join(AI_BOTS)} not blocked")


def check_citable_facts(s: Site) -> CheckResult:
    text = s.soup.get_text(" ", strip=True)
    patterns = [
        (r"\b\d{2,}\s?(kr|DKK|€|EUR|USD|\$)\b", "price"),
        (r"\b(\+?45[\s\-]?)?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b", "phone"),
        (r"\b\d{4}\s+[A-ZÆØÅ][a-zæøå]+\b", "postcode+city"),
        (r"\b\d{1,4}\s?(m²|m2|km|kvm|personer|gæster|værelser|rum)\b", "capacity"),
        (r"\b(19|20)\d{2}\b", "year"),
    ]
    hits = [label for pat, label in patterns if re.search(pat, text)]
    if len(hits) >= 2:
        return CheckResult("citable_facts", "llm", PASS, f"found: {', '.join(hits)}")
    if len(hits) == 1:
        return CheckResult("citable_facts", "llm", WARN,
                           f"only {hits[0]} — add more concrete numbers LLMs can cite")
    return CheckResult("citable_facts", "llm", WARN,
                       "no price/phone/address/year/capacity — reads as marketing copy")


def check_faq_schema(s: Site) -> CheckResult:
    has_details = bool(s.soup.find_all("details"))
    heading_faq = any(re.search(r"(?i)\bfaq\b|ofte stillede", h.get_text())
                      for h in s.soup.find_all(["h1", "h2", "h3"]))
    if not (has_details or heading_faq):
        return CheckResult("faq_schema_if_faq_visible", "llm", INFO, "no visible FAQ")
    scripts = s.soup.find_all("script", attrs={"type": "application/ld+json"})
    for sc in scripts:
        if not sc.string:
            continue
        try:
            data = json.loads(sc.string)
        except json.JSONDecodeError:
            continue
        for node in data if isinstance(data, list) else [data]:
            if isinstance(node, dict) and node.get("@type") == "FAQPage":
                n = len(node.get("mainEntity", []) or [])
                return CheckResult("faq_schema_if_faq_visible", "llm", PASS,
                                   f"FAQPage schema with {n} questions")
    return CheckResult("faq_schema_if_faq_visible", "llm", WARN,
                       "FAQ visible but no FAQPage JSON-LD")


def check_render_blocking(s: Site) -> CheckResult:
    head = s.soup.find("head")
    if not head:
        return CheckResult("render_blocking_assets", "perf", WARN, "no <head>")
    bad = []
    for sc in head.find_all("script", src=True):
        src = sc["src"]
        if "cdn.tailwindcss.com" in src or "/cdn/" in src.lower():
            bad.append(src)
    if bad:
        return CheckResult("render_blocking_assets", "perf", FAIL,
                           f"dev CDN in <head>: {bad[0]}")
    return CheckResult("render_blocking_assets", "perf", PASS, "no dev CDNs in <head>")


def check_lcp_hints(s: Site) -> CheckResult:
    first_img = s.soup.find("img")
    preloads = s.soup.find_all("link", rel=lambda v: v and "preload" in v,
                               attrs={"as": "image"})
    if preloads:
        return CheckResult("lcp_image_hints", "perf", PASS,
                           f"<link rel=preload as=image>: {preloads[0].get('href')}")
    if not first_img:
        return CheckResult("lcp_image_hints", "perf", INFO, "no <img> on page")
    fp = (first_img.get("fetchpriority") or "").lower()
    loading = (first_img.get("loading") or "").lower()
    if fp == "high" or loading == "eager":
        return CheckResult("lcp_image_hints", "perf", PASS,
                           f"first img has fetchpriority={fp!r} loading={loading!r}")
    return CheckResult("lcp_image_hints", "perf", WARN,
                       "first <img> missing fetchpriority=high / preload — LCP risk")


# --------- runner ---------

# ---------- Google Search Console "why pages aren't indexed" translations ----------

def check_url_status(s: Site) -> CheckResult:
    """Flag the HTTP status class of the audited URL (404/5xx/403 prevent indexing)."""
    code = s.response.status_code
    if code == 200:
        return CheckResult("url_status", "shared", PASS, f"200 {s.final_url}")
    if code == 403:
        return CheckResult("url_status", "shared", FAIL,
                           f"403 Forbidden — GSC will show 'Blocked due to access forbidden'")
    if code == 404:
        return CheckResult("url_status", "shared", FAIL,
                           f"404 Not Found — GSC will show 'Not found (404)'")
    if 500 <= code < 600:
        return CheckResult("url_status", "shared", FAIL,
                           f"{code} Server Error — GSC will show 'Server error (5xx)'")
    if 400 <= code < 500:
        return CheckResult("url_status", "shared", FAIL,
                           f"{code} — GSC will show 'Blocked due to other 4xx issue'")
    return CheckResult("url_status", "shared", WARN, f"{code} {s.final_url}")


def check_url_not_redirected(s: Site) -> CheckResult:
    """If input URL redirected, flag it — Google indexes the target, not the input URL."""
    if not s.response.history:
        return CheckResult("url_not_redirected", "shared", PASS,
                           "audited URL returned final content directly")
    hops = len(s.response.history)
    first = s.response.history[0]
    return CheckResult("url_not_redirected", "shared", INFO,
                       f"{hops} redirect hop(s): {first.url} → … → {s.final_url}")


def check_redirect_chain(s: Site) -> CheckResult:
    """Flag redirect chains — Google gives up after too many hops."""
    history = s.response.history
    if len(history) == 0:
        return CheckResult("redirect_chain", "shared", PASS, "no redirect")
    if len(history) == 1:
        return CheckResult("redirect_chain", "shared", PASS, "1 redirect hop")
    if len(history) >= 5:
        return CheckResult("redirect_chain", "shared", FAIL,
                           f"{len(history)} hops — GSC 'Redirect error'")
    if len(history) >= 3:
        return CheckResult("redirect_chain", "shared", WARN,
                           f"{len(history)} hops — reduce to 1 if possible")
    return CheckResult("redirect_chain", "shared", WARN,
                       f"{len(history)} hops")


def check_googlebot_allowed(s: Site) -> CheckResult:
    """Can Googlebot crawl THIS URL per robots.txt? (Path-aware, not blanket)."""
    if s.robots_text is None:
        return CheckResult("googlebot_allowed", "shared", INFO,
                           "no robots.txt — defaults to allow-all")
    path = urlparse(s.final_url).path or "/"
    groups = _parse_robots_groups(s.robots_text)
    allowed, matched = _path_allowed_for("Googlebot", path, groups)
    if allowed:
        if matched:
            return CheckResult("googlebot_allowed", "shared", PASS,
                               f"Googlebot allowed ({matched[0]}: {matched[1]})")
        return CheckResult("googlebot_allowed", "shared", PASS,
                           "Googlebot allowed (no matching rule)")
    return CheckResult("googlebot_allowed", "shared", FAIL,
                       f"Googlebot blocked by robots.txt ({matched[0]}: {matched[1]}) — "
                       f"GSC 'Blocked by robots.txt'")


def check_soft_404(s: Site) -> CheckResult:
    """200 response with 404-like content — GSC 'Soft 404'."""
    if s.response.status_code != 200:
        return CheckResult("soft_404", "seo", INFO,
                           f"status {s.response.status_code} (not 200)")
    copy = BeautifulSoup(s.response.text, "html.parser")
    for t in copy(["script", "style", "noscript"]):
        t.decompose()
    text = copy.get_text(" ", strip=True)
    words = len(text.split())
    title = s.soup.title.string.lower() if s.soup.title and s.soup.title.string else ""
    h1 = s.soup.find("h1")
    h1_text = h1.get_text(" ", strip=True).lower() if h1 else ""
    body = text.lower()
    indicators = [
        "404", "page not found", "not found",
        "siden findes ikke", "siden kunne ikke findes", "ikke fundet",
        "sidan finns inte", "ikke eksisterer",
        "the page you are looking for",
    ]
    hot_fields = f"{title} {h1_text}"
    title_hit = any(ind in hot_fields for ind in indicators)
    body_hit = any(ind in body for ind in indicators)
    if title_hit and words < 300:
        return CheckResult("soft_404", "seo", FAIL,
                           f"title/h1 says 'not found' + {words} words — looks like soft 404")
    if body_hit and words < 80:
        return CheckResult("soft_404", "seo", WARN,
                           f"'not found'-style text + only {words} words")
    return CheckResult("soft_404", "seo", PASS, f"{words} words, no soft-404 indicators")


def check_indexability_composite(s: Site) -> CheckResult:
    """Roll-up: is this URL eligible to be indexed by Google?"""
    blockers: list[str] = []
    if s.response.status_code != 200:
        blockers.append(f"status {s.response.status_code}")
    # meta robots noindex / X-Robots-Tag
    m = s.soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    content = (m.get("content") or "").lower() if m else ""
    header = s.response.headers.get("X-Robots-Tag", "").lower()
    if "noindex" in content or "noindex" in header:
        blockers.append("noindex directive")
    # canonical pointing elsewhere
    link = s.soup.find("link", rel=lambda v: v and "canonical" in v)
    href = (link.get("href") or "").strip() if link else ""
    if href:
        normalized = percent_encode_path(href).rstrip("/")
        current = percent_encode_path(s.final_url).rstrip("/")
        if normalized != current:
            blockers.append(f"canonical points to {href}")
    # robots.txt
    if s.robots_text:
        path = urlparse(s.final_url).path or "/"
        groups = _parse_robots_groups(s.robots_text)
        allowed, matched = _path_allowed_for("Googlebot", path, groups)
        if not allowed:
            blockers.append(f"robots.txt {matched[0]}:{matched[1]}")
    if not blockers:
        return CheckResult("page_indexable_by_google", "seo", PASS,
                           "no noindex, canonical=self, robots allows, status 200")
    if any("noindex" in b or "status" in b or "robots.txt" in b for b in blockers):
        return CheckResult("page_indexable_by_google", "seo", FAIL,
                           f"won't be indexed: {'; '.join(blockers)}")
    return CheckResult("page_indexable_by_google", "seo", WARN,
                       f"alternate/canonical elsewhere: {'; '.join(blockers)}")


# ---------- new checks (Ahrefs / Screaming Frog / Sitebulb / Lighthouse coverage) ----------

def check_doctype(s: Site) -> CheckResult:
    head = s.response.text[:200].lstrip()
    if re.match(r"(?i)<!doctype\s+html\s*>", head):
        return CheckResult("doctype_present", "shared", PASS, "<!DOCTYPE html>")
    m = re.match(r"(?i)<!doctype[^>]+>", head)
    if m:
        return CheckResult("doctype_present", "shared", WARN,
                           f"non-HTML5 doctype: {m.group(0)}")
    return CheckResult("doctype_present", "shared", FAIL, "no doctype declaration")


def check_meta_charset_early(s: Site) -> CheckResult:
    head_bytes = s.response.content[:2048]
    m = re.search(rb"(?i)<meta[^>]+charset", head_bytes)
    if not m:
        # might be in HTTP header instead, which is acceptable
        if "charset" in s.response.headers.get("Content-Type", "").lower():
            return CheckResult("meta_charset_early", "shared", PASS,
                               "declared in Content-Type header")
        return CheckResult("meta_charset_early", "shared", FAIL,
                           "no charset in HTML or Content-Type header")
    offset = m.start()
    if offset > 1024:
        return CheckResult("meta_charset_early", "shared", WARN,
                           f"declared at byte {offset} (>1024)")
    return CheckResult("meta_charset_early", "shared", PASS, f"declared at byte {offset}")


def check_mixed_content(s: Site) -> CheckResult:
    if not s.final_url.startswith("https://"):
        return CheckResult("mixed_content", "shared", INFO, "page not served over https")
    bad: list[str] = []
    selectors = [("img", "src"), ("script", "src"), ("iframe", "src"),
                 ("video", "src"), ("audio", "src"), ("source", "src"),
                 ("link", "href")]
    for tag, attr in selectors:
        for el in s.soup.find_all(tag):
            v = (el.get(attr) or "").strip()
            if v.startswith("http://"):
                bad.append(f"<{tag} {attr}={v}>")
                if len(bad) >= 5:
                    break
        if len(bad) >= 5:
            break
    if bad:
        return CheckResult("mixed_content", "shared", FAIL,
                           f"{len(bad)} http:// resource(s): {bad[0]}")
    return CheckResult("mixed_content", "shared", PASS, "no http:// resources")


def check_security_headers(s: Site) -> CheckResult:
    h = s.response.headers
    checks = {
        "X-Content-Type-Options": "nosniff" in (h.get("X-Content-Type-Options", "")).lower(),
        "Referrer-Policy": bool(h.get("Referrer-Policy")),
        "Content-Security-Policy": bool(h.get("Content-Security-Policy")),
        "Permissions-Policy": bool(h.get("Permissions-Policy")),
    }
    missing = [k for k, ok in checks.items() if not ok]
    if not missing:
        return CheckResult("security_headers", "shared", PASS, "all four present")
    if len(missing) <= 2:
        return CheckResult("security_headers", "shared", WARN,
                           f"missing: {', '.join(missing)}")
    return CheckResult("security_headers", "shared", FAIL,
                       f"missing: {', '.join(missing)}")


def check_meta_refresh(s: Site) -> CheckResult:
    m = s.soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
    if not m:
        return CheckResult("meta_refresh_redirect", "shared", PASS, "no meta refresh")
    content = (m.get("content") or "")
    if re.search(r"url\s*=", content, re.I):
        return CheckResult("meta_refresh_redirect", "shared", FAIL,
                           f"client-side redirect: {content}")
    return CheckResult("meta_refresh_redirect", "shared", WARN,
                       f"meta refresh present: {content}")


def check_meta_robots_indexable(s: Site) -> CheckResult:
    m = s.soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    content = (m.get("content") or "").lower() if m else ""
    header = s.response.headers.get("X-Robots-Tag", "").lower()
    combined = f"{content} {header}"
    if "noindex" in combined:
        return CheckResult("meta_robots_indexable", "seo", FAIL,
                           f"noindex set: meta={content!r} header={header!r}")
    if "nofollow" in combined:
        return CheckResult("meta_robots_indexable", "seo", WARN,
                           f"nofollow set: meta={content!r} header={header!r}")
    return CheckResult("meta_robots_indexable", "seo", PASS,
                       content or "(default indexable)")


def check_viewport_scalable(s: Site) -> CheckResult:
    m = s.soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)})
    c = (m.get("content") or "").lower().replace(" ", "") if m else ""
    if not c:
        return CheckResult("viewport_accessible", "seo", INFO,
                           "no viewport (covered by viewport_meta)")
    if "user-scalable=no" in c or re.search(r"maximum-scale=1(?:\.0)?\b", c):
        return CheckResult("viewport_accessible", "seo", WARN,
                           f"zoom disabled (a11y issue): {c}")
    return CheckResult("viewport_accessible", "seo", PASS, "zoom not disabled")


def check_external_link_safety(s: Site) -> CheckResult:
    host = urlparse(s.final_url).netloc
    unsafe: list[str] = []
    total_external_blank = 0
    for a in s.soup.find_all("a", href=True, target="_blank"):
        href = urljoin(s.final_url, a["href"])
        if urlparse(href).netloc and urlparse(href).netloc != host:
            total_external_blank += 1
            rel = " ".join(a.get("rel", []) if isinstance(a.get("rel"), list)
                           else [a.get("rel", "")])
            if "noopener" not in rel.lower():
                unsafe.append(href)
    if total_external_blank == 0:
        return CheckResult("external_link_rel_safety", "seo", INFO,
                           "no external target=_blank links")
    if unsafe:
        return CheckResult("external_link_rel_safety", "seo", FAIL,
                           f"{len(unsafe)}/{total_external_blank} missing rel=noopener: {unsafe[0]}")
    return CheckResult("external_link_rel_safety", "seo", PASS,
                       f"{total_external_blank} external _blank links all safe")


def check_descriptive_link_text(s: Site) -> CheckResult:
    links = s.soup.find_all("a", href=True)
    if len(links) < 5:
        return CheckResult("descriptive_link_text", "seo", INFO,
                           f"only {len(links)} links — skipping")
    generic = 0
    total = 0
    for a in links:
        txt = a.get_text(" ", strip=True).lower()
        if not txt:
            # skip icon-only links (should ideally have aria-label but checked elsewhere)
            continue
        total += 1
        if txt in GENERIC_ANCHOR_TEXT or re.fullmatch(r"https?://\S+", txt):
            generic += 1
    if total == 0:
        return CheckResult("descriptive_link_text", "seo", WARN,
                           "all links have empty text")
    pct = generic * 100 // total
    if pct > 40:
        return CheckResult("descriptive_link_text", "seo", FAIL,
                           f"{generic}/{total} generic ({pct}%)")
    if pct > 20:
        return CheckResult("descriptive_link_text", "seo", WARN,
                           f"{generic}/{total} generic ({pct}%)")
    return CheckResult("descriptive_link_text", "seo", PASS,
                       f"{generic}/{total} generic ({pct}%)")


def check_text_to_html_ratio(s: Site) -> CheckResult:
    html_len = len(s.response.text)
    if html_len == 0:
        return CheckResult("text_to_html_ratio", "seo", FAIL, "empty HTML")
    # strip scripts + styles before measuring visible text
    copy = BeautifulSoup(s.response.text, "html.parser")
    for tag in copy(["script", "style", "noscript"]):
        tag.decompose()
    text = copy.get_text(" ", strip=True)
    ratio = len(text) / html_len
    words = len(text.split())
    if words < 50:
        return CheckResult("text_to_html_ratio", "seo", FAIL,
                           f"only {words} visible words — thin content")
    if ratio < TEXT_RATIO_FAIL:
        return CheckResult("text_to_html_ratio", "seo", FAIL,
                           f"ratio {ratio:.1%} ({words} words)")
    if ratio < TEXT_RATIO_WARN:
        return CheckResult("text_to_html_ratio", "seo", WARN,
                           f"ratio {ratio:.1%} ({words} words)")
    return CheckResult("text_to_html_ratio", "seo", PASS,
                       f"ratio {ratio:.1%} ({words} words)")


def check_inline_asset_size(s: Site) -> CheckResult:
    total = 0
    for t in s.soup.find_all(["script", "style"]):
        if t.name == "script" and t.get("src"):
            continue
        total += len(t.string or "")
    kb = total / 1024
    if total >= INLINE_ASSET_FAIL:
        return CheckResult("inline_asset_size", "perf", FAIL, f"{kb:.0f} KB inline")
    if total >= INLINE_ASSET_WARN:
        return CheckResult("inline_asset_size", "perf", WARN, f"{kb:.0f} KB inline")
    return CheckResult("inline_asset_size", "perf", PASS, f"{kb:.0f} KB inline")


def check_dom_size(s: Site) -> CheckResult:
    elements = s.soup.find_all()
    count = len(elements)
    # max nesting depth — walk the tree
    def depth(node, d: int = 0) -> int:
        children = [c for c in getattr(node, "children", []) if getattr(c, "name", None)]
        if not children:
            return d
        return max(depth(c, d + 1) for c in children)
    max_depth = depth(s.soup)
    if count >= DOM_ELEMENTS_FAIL or max_depth >= DOM_DEPTH_FAIL:
        return CheckResult("dom_size", "perf", FAIL,
                           f"{count} elements, depth {max_depth}")
    if count >= DOM_ELEMENTS_WARN or max_depth >= DOM_DEPTH_WARN:
        return CheckResult("dom_size", "perf", WARN,
                           f"{count} elements, depth {max_depth}")
    return CheckResult("dom_size", "perf", PASS,
                       f"{count} elements, depth {max_depth}")


def check_image_modern_format(s: Site) -> CheckResult:
    imgs = s.soup.find_all("img")
    if len(imgs) < 3:
        return CheckResult("image_modern_format", "perf", INFO,
                           f"only {len(imgs)} images")
    modern_exts = (".webp", ".avif")
    modern = 0
    legacy: list[str] = []
    for img in imgs:
        src = (img.get("src") or "").lower()
        srcset = (img.get("srcset") or "").lower()
        picture = img.find_parent("picture")
        has_modern_source = False
        if picture:
            for src_el in picture.find_all("source"):
                stype = (src_el.get("type") or "").lower()
                if "webp" in stype or "avif" in stype:
                    has_modern_source = True
                    break
        if src.endswith(modern_exts) or any(e in srcset for e in modern_exts) or has_modern_source:
            modern += 1
        else:
            legacy.append(src.split("/")[-1][:40])
    pct = modern * 100 // len(imgs)
    if pct >= 80:
        return CheckResult("image_modern_format", "perf", PASS,
                           f"{modern}/{len(imgs)} modern ({pct}%)")
    if pct >= 50:
        return CheckResult("image_modern_format", "perf", WARN,
                           f"{modern}/{len(imgs)} modern ({pct}%) — example: {legacy[0]}")
    return CheckResult("image_modern_format", "perf", FAIL,
                       f"{modern}/{len(imgs)} modern ({pct}%) — convert to webp/avif")


CheckFn = Callable[[Site], CheckResult]

# ---------- Ads / tracking / martech detection (HTML signature scan) ----------

# Each entry: { name, label, patterns (any-of, regex, case-insensitive), id_regex (optional),
#               warn_on_found (optional), warn_msg (optional) }

ADS_PIXEL_SIGNATURES: list[dict] = [
    {"name": "meta_pixel", "label": "Meta (Facebook) Pixel",
     "patterns": [r"connect\.facebook\.net/[^/]+/fbevents\.js", r"\bfbq\s*\("],
     "id_regex": r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{6,})['\"]"},
    {"name": "google_ads", "label": "Google Ads",
     "patterns": [r"googletagmanager\.com/gtag/js\?id=AW-", r"\bgoogle_conversion_id\b", r"\bAW-\d{6,}\b"],
     "id_regex": r"(AW-\d{6,})"},
    {"name": "google_tag_manager", "label": "Google Tag Manager",
     "patterns": [r"googletagmanager\.com/gtm\.js\?id=GTM-"],
     "id_regex": r"(GTM-[A-Z0-9]+)"},
    {"name": "linkedin_insight", "label": "LinkedIn Insight",
     "patterns": [r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js",
                  r"_linkedin_data_partner_ids"],
     "id_regex": r"_linkedin_data_partner_ids\s*=\s*\[\s*['\"]?(\d+)"},
    {"name": "tiktok_pixel", "label": "TikTok Pixel",
     "patterns": [r"analytics\.tiktok\.com/i18n/pixel/events\.js", r"\bttq\.load\s*\("],
     "id_regex": r"ttq\.load\s*\(\s*['\"]([A-Z0-9]+)['\"]"},
    {"name": "pinterest_tag", "label": "Pinterest Tag",
     "patterns": [r"s\.pinimg\.com/ct/core\.js", r"\bpintrk\s*\(\s*['\"]load['\"]"],
     "id_regex": r"pintrk\s*\(\s*['\"]load['\"]\s*,\s*['\"](\d+)['\"]"},
    {"name": "snapchat_pixel", "label": "Snapchat Pixel",
     "patterns": [r"sc-static\.net/scevent\.min\.js", r"\bsnaptr\s*\(\s*['\"]init['\"]"],
     "id_regex": r"snaptr\s*\(\s*['\"]init['\"]\s*,\s*['\"]([a-f0-9-]+)['\"]"},
    {"name": "reddit_pixel", "label": "Reddit Pixel",
     "patterns": [r"redditstatic\.com/ads/pixel\.js", r"\brdt\s*\(\s*['\"]init['\"]"],
     "id_regex": r"rdt\s*\(\s*['\"]init['\"]\s*,\s*['\"]([a-z0-9_]+)['\"]"},
    {"name": "bing_uet", "label": "Microsoft Ads (Bing UET)",
     "patterns": [r"bat\.bing\.com/bat\.js", r"\b(?:UET|uetq)\b"],
     "id_regex": r"['\"]ti['\"]\s*:\s*['\"](\d+)['\"]"},
    {"name": "x_twitter_pixel", "label": "X (Twitter) Pixel",
     "patterns": [r"static\.ads-twitter\.com/uwt\.js", r"\btwq\s*\(\s*['\"]config['\"]"],
     "id_regex": r"twq\s*\(\s*['\"]config['\"]\s*,\s*['\"]([a-z0-9]+)['\"]"},
]

TRACKING_SIGNATURES: list[dict] = [
    {"name": "google_analytics_4", "label": "Google Analytics 4",
     "patterns": [r"googletagmanager\.com/gtag/js\?id=G-",
                  r"gtag\s*\(\s*['\"]config['\"]\s*,\s*['\"]G-"],
     "id_regex": r"(G-[A-Z0-9]+)"},
    {"name": "universal_analytics", "label": "Universal Analytics (legacy)",
     "patterns": [r"\bUA-\d+-\d+\b"],
     "id_regex": r"(UA-\d+-\d+)",
     "warn_on_found": True,
     "warn_msg": "sunset July 2024 — migrate to GA4"},
    {"name": "segment", "label": "Segment",
     "patterns": [r"cdn\.segment\.com/analytics\.js", r"\banalytics\.load\s*\("]},
    {"name": "mixpanel", "label": "Mixpanel",
     "patterns": [r"cdn\.mxpnl\.com", r"\bmixpanel\.init\s*\("]},
    {"name": "hotjar", "label": "Hotjar",
     "patterns": [r"static\.hotjar\.com/c/hotjar-", r"\bhjid\s*:"],
     "id_regex": r"hjid\s*:\s*(\d+)"},
    {"name": "microsoft_clarity", "label": "Microsoft Clarity",
     "patterns": [r"www\.clarity\.ms/tag/", r"\bclarity\s*\(\s*['\"]set['\"]"]},
    {"name": "plausible", "label": "Plausible Analytics",
     "patterns": [r"plausible\.io/js/script", r"data-domain\s*="]},
    {"name": "fathom", "label": "Fathom Analytics",
     "patterns": [r"cdn\.usefathom\.com/script\.js"]},
    {"name": "simple_analytics", "label": "Simple Analytics",
     "patterns": [r"scripts\.simpleanalyticscdn\.com"]},
    {"name": "cloudflare_analytics", "label": "Cloudflare Web Analytics",
     "patterns": [r"static\.cloudflareinsights\.com/beacon\.min\.js"]},
    {"name": "matomo", "label": "Matomo",
     "patterns": [r"matomo\.js", r"\b_paq\.push\s*\(", r"piwik\.js"]},
    {"name": "amplitude", "label": "Amplitude",
     "patterns": [r"cdn\.amplitude\.com", r"amplitude\.getInstance"]},
    {"name": "fullstory", "label": "FullStory",
     "patterns": [r"fullstory\.com/s/fs\.js", r"\bFS\.identify\s*\("]},
]

MARTECH_SIGNATURES: list[dict] = [
    # Consent Management Platforms (CMPs)
    {"name": "cookiebot", "label": "Cookiebot CMP",
     "patterns": [r"consent\.cookiebot\.com", r"data-cbid\s*="],
     "id_regex": r"data-cbid\s*=\s*['\"]([a-f0-9-]+)"},
    {"name": "onetrust", "label": "OneTrust CMP",
     "patterns": [r"cdn\.cookielaw\.org", r"OneTrust\.AllowAll"]},
    {"name": "usercentrics", "label": "Usercentrics CMP",
     "patterns": [r"app\.usercentrics\.eu", r"usercentrics-root"]},
    {"name": "didomi", "label": "Didomi CMP",
     "patterns": [r"sdk\.privacy-center\.org", r"\bwindow\.didomiOnReady\b"]},
    {"name": "iubenda", "label": "Iubenda CMP",
     "patterns": [r"cs\.iubenda\.com", r"iubenda-cs-"]},
    # Chat widgets
    {"name": "intercom", "label": "Intercom",
     "patterns": [r"widget\.intercom\.io", r"\bwindow\.Intercom\b"]},
    {"name": "drift", "label": "Drift",
     "patterns": [r"js\.driftt\.com/include", r"\bwindow\.drift\b"]},
    {"name": "zendesk_chat", "label": "Zendesk Chat / Web Widget",
     "patterns": [r"static\.zdassets\.com", r"zendeskChat", r"\bzE\s*\("]},
    {"name": "crisp", "label": "Crisp Chat",
     "patterns": [r"client\.crisp\.chat", r"\bCRISP_WEBSITE_ID\b"]},
    {"name": "tawk", "label": "Tawk.to",
     "patterns": [r"embed\.tawk\.to", r"\bTawk_API\b"]},
    {"name": "hubspot_chat", "label": "HubSpot Chat",
     "patterns": [r"js\.hs-scripts\.com", r"js\.hsadspixel\.net", r"hbspt\.forms"],
     "id_regex": r"hs-scripts\.com/(\d+)\.js"},
    # CRM / marketing automation scripts
    {"name": "marketo", "label": "Marketo",
     "patterns": [r"munchkin\.marketo\.net", r"\bMunchkin\.init\s*\("]},
    {"name": "pardot", "label": "Pardot",
     "patterns": [r"pi\.pardot\.com"]},
    {"name": "activecampaign", "label": "ActiveCampaign",
     "patterns": [r"trackcmp\.net", r"activehosted\.com"]},
    {"name": "klaviyo", "label": "Klaviyo",
     "patterns": [r"static\.klaviyo\.com", r"\bklaviyo\.init\s*\("]},
    # CDPs
    {"name": "rudderstack", "label": "RudderStack CDP",
     "patterns": [r"cdn\.rudderlabs\.com"]},
    {"name": "mparticle", "label": "mParticle CDP",
     "patterns": [r"jssdkcdns\.mparticle\.com"]},
]


def _make_signature_check(sig: dict, category: str) -> CheckFn:
    name = sig["name"]
    label = sig["label"]
    patterns = sig["patterns"]
    id_regex = sig.get("id_regex")
    warn_on_found = sig.get("warn_on_found", False)
    warn_msg = sig.get("warn_msg", "")

    def check(s: Site) -> CheckResult:
        html = s.response.text
        if not any(re.search(p, html, re.I) for p in patterns):
            return CheckResult(name, category, INFO, f"{label} not detected")
        id_str = ""
        if id_regex:
            # IDs are case-sensitive in their canonical form (G-XXXXXX, AW-XXXXX,
            # GTM-XXX, UA-XXXX-Y, etc.) — don't use re.I or we match JS-bundle hashes
            m = re.search(id_regex, html)
            if m:
                id_str = f" ({m.group(1)})"
        if warn_on_found:
            return CheckResult(name, category, WARN,
                               f"{label}{id_str}" + (f" — {warn_msg}" if warn_msg else ""))
        return CheckResult(name, category, PASS, f"{label}{id_str}")

    check.__name__ = f"check_{name}"
    return check


_ADS_PIXEL_CHECKS: list[CheckFn] = [_make_signature_check(s, "ads") for s in ADS_PIXEL_SIGNATURES]
_TRACKING_CHECKS: list[CheckFn] = [_make_signature_check(s, "tracking") for s in TRACKING_SIGNATURES]
_MARTECH_CHECKS: list[CheckFn] = [_make_signature_check(s, "martech") for s in MARTECH_SIGNATURES]


def check_ads_pixels_summary(s: Site) -> CheckResult:
    html = s.response.text
    found = [sig["label"] for sig in ADS_PIXEL_SIGNATURES
             if any(re.search(p, html, re.I) for p in sig["patterns"])]
    if not found:
        return CheckResult("ads_pixels_summary", "ads", INFO, "no ads pixels detected")
    return CheckResult("ads_pixels_summary", "ads", PASS,
                       f"{len(found)} ads pixel(s): {', '.join(found)}")


def check_tracking_summary(s: Site) -> CheckResult:
    html = s.response.text
    found = [sig["label"] for sig in TRACKING_SIGNATURES
             if any(re.search(p, html, re.I) for p in sig["patterns"])]
    if not found:
        return CheckResult("tracking_summary", "tracking", INFO, "no analytics detected")
    return CheckResult("tracking_summary", "tracking", PASS,
                       f"{len(found)} analytics tool(s): {', '.join(found)}")


def check_martech_summary(s: Site) -> CheckResult:
    html = s.response.text
    found = [sig["label"] for sig in MARTECH_SIGNATURES
             if any(re.search(p, html, re.I) for p in sig["patterns"])]
    if not found:
        return CheckResult("martech_summary", "martech", INFO, "no martech detected")
    return CheckResult("martech_summary", "martech", PASS,
                       f"{len(found)} martech tool(s): {', '.join(found)}")


# ---------- Authority / rank signals (free, no API keys) ----------

WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"


def _registered_domain(host: str) -> str:
    """Strip leading www. — not a full public-suffix resolver."""
    return host[4:] if host.startswith("www.") else host


def check_domain_age_wayback(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    try:
        r = s.session.get(WAYBACK_CDX_URL, params={
            "url": domain, "output": "json", "limit": 1, "from": "19960101"
        }, timeout=10, headers={"User-Agent": UA})
        data = r.json()
        if not data or len(data) < 2:
            return CheckResult("domain_age_wayback", "authority", INFO,
                               f"no Wayback snapshots for {domain}")
        header, row = data[0], data[1]
        ts_idx = header.index("timestamp") if "timestamp" in header else 1
        ts = row[ts_idx]
        year, month, day = int(ts[:4]), int(ts[4:6]), int(ts[6:8])
        first_date = datetime(year, month, day, tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - first_date).days
        age_years = age_days / 365.25
        label = f"first archived {first_date:%Y-%m-%d}"
        if age_days < 180:
            return CheckResult("domain_age_wayback", "authority", WARN,
                               f"{label} ({age_days}d ago) — new/unknown domain")
        return CheckResult("domain_age_wayback", "authority", INFO,
                           f"{label} (~{age_years:.1f} years)")
    except Exception as e:
        return CheckResult("domain_age_wayback", "authority", INFO,
                           f"Wayback lookup failed: {type(e).__name__}")


def check_wayback_snapshot_count(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    try:
        r = s.session.get(WAYBACK_CDX_URL, params={
            "url": domain, "output": "json",
            "collapse": "timestamp:8", "limit": 2000,
        }, timeout=15, headers={"User-Agent": UA})
        data = r.json()
        if len(data) < 2:
            return CheckResult("wayback_snapshot_count", "authority", INFO,
                               f"0 archived days for {domain}")
        rows = data[1:]
        first_ts = rows[0][1]
        last_ts = rows[-1][1]
        return CheckResult("wayback_snapshot_count", "authority", INFO,
                           f"{len(rows)} archived day(s), "
                           f"{first_ts[:4]}-{first_ts[4:6]}..{last_ts[:4]}-{last_ts[4:6]}")
    except Exception as e:
        return CheckResult("wayback_snapshot_count", "authority", INFO,
                           f"Wayback count failed: {type(e).__name__}")


def check_wikipedia_presence(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    short = domain.split(".")[0]
    results: list[str] = []
    for lang in ("en", "da"):
        try:
            r = s.session.get(f"https://{lang}.wikipedia.org/w/api.php",
                              params={"action": "query", "list": "search",
                                      "srsearch": short, "format": "json", "srlimit": 3},
                              timeout=10, headers={"User-Agent": UA})
            data = r.json()
            for h in data.get("query", {}).get("search", []):
                title = h.get("title", "")
                snippet = h.get("snippet", "")
                # match if title or snippet contains the root label or full domain
                combined = f"{title} {snippet}".lower()
                if short.lower() in combined or domain.lower() in combined:
                    results.append(f"{lang}:{title}")
                    break
        except Exception:
            continue
    if results:
        return CheckResult("wikipedia_presence", "authority", PASS,
                           f"Wikipedia article: {', '.join(results)}")
    return CheckResult("wikipedia_presence", "authority", INFO,
                       "no Wikipedia article found")


def check_commoncrawl_presence(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    try:
        info = s.session.get("https://index.commoncrawl.org/collinfo.json",
                             timeout=10, headers={"User-Agent": UA})
        crawls = info.json()
        if not crawls:
            return CheckResult("commoncrawl_presence", "authority", INFO,
                               "no crawls available")
        latest = crawls[0]
        cdx = latest.get("cdx-api")
        name = latest.get("name", "?")
        if not cdx:
            return CheckResult("commoncrawl_presence", "authority", INFO,
                               f"no CDX API on {name}")
        r = s.session.get(cdx, params={
            "url": f"{domain}/*", "output": "json", "limit": 500,
        }, timeout=15, headers={"User-Agent": UA})
        lines = [l for l in r.text.splitlines() if l.strip()]
        count = len(lines)
        if count == 0:
            return CheckResult("commoncrawl_presence", "authority", INFO,
                               f"not in {name}")
        suffix = "+ pages" if count >= 500 else " pages"
        return CheckResult("commoncrawl_presence", "authority", INFO,
                           f"{count}{suffix} in {name}")
    except Exception as e:
        return CheckResult("commoncrawl_presence", "authority", INFO,
                           f"CC lookup failed: {type(e).__name__}")


KNOWN_HOSTERS = {
    "Cloudflare": ["cloudflare.com", "cloudflare.net"],
    "AWS": ["amazonaws.com"],
    "Google Cloud": ["googleusercontent.com", "googleapis.com", "1e100.net"],
    "Azure": ["azurewebsites.net", "cloudapp.net", "azureedge.net"],
    "Hetzner": ["hetzner.com", "your-server.de", "static.hetzner.com"],
    "DigitalOcean": ["digitalocean.com"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "Netlify": ["netlify.com", "netlify.app"],
    "Vercel": ["vercel.com", "vercel-dns.com"],
    "Heroku": ["herokudns.com", "herokuapp.com"],
    "GitHub Pages": ["github.io"],
    "Akamai": ["akamai.net", "akamaiedge.net"],
}


def check_dns_popularity_signals(s: Site) -> CheckResult:
    host = urlparse(s.final_url).hostname or ""
    signals: list[str] = []
    # reverse-DNS of first A record
    try:
        infos = socket.getaddrinfo(host, 443, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
        if infos:
            ip = infos[0][4][0]
            try:
                rdns = socket.gethostbyaddr(ip)[0]
                hoster = None
                for hname, domains in KNOWN_HOSTERS.items():
                    if any(d in rdns.lower() for d in domains):
                        hoster = hname
                        break
                signals.append(f"host: {hoster} ({rdns})" if hoster else f"rDNS: {rdns}")
            except (socket.herror, OSError):
                signals.append(f"A={ip} (no PTR)")
    except (socket.gaierror, OSError):
        pass
    # MX presence
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = 4.0
        answer = resolver.resolve(_registered_domain(host), "MX",
                                  raise_on_no_answer=False)
        if answer.rrset is not None and len(answer):
            signals.append(f"{len(list(answer))} MX")
    except Exception:
        pass
    if not signals:
        return CheckResult("dns_popularity_signals", "authority", INFO, "no signals gathered")
    return CheckResult("dns_popularity_signals", "authority", INFO, "; ".join(signals))


# ---------- Browser-based Meta / Google ad-library scrapes (behind --ads-deep) ----------

def _find_facebook_page(s: Site) -> Optional[str]:
    for a in s.soup.find_all("a", href=True):
        href = a["href"]
        m = re.search(r"https?://(?:www\.)?facebook\.com/([^/?#]+)", href)
        if m:
            slug = m.group(1)
            if slug.lower() not in ("sharer", "share", "tr", "pages", "plugins", "dialog"):
                return slug
    return None


def check_meta_ad_library(s: Site) -> CheckResult:
    if not s.ads_deep:
        return CheckResult("meta_ad_library", "ads", INFO,
                           "skipped (pass --ads-deep to scrape Meta Ad Library)")
    pool = s.browser_pool_ref
    if pool is None or pool.context is None:
        return CheckResult("meta_ad_library", "ads", INFO,
                           "--ads-deep needs --browser (Chromium unavailable)")
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    query = _find_facebook_page(s) or domain.split(".")[0]
    url = ("https://www.facebook.com/ads/library/"
           "?active_status=active&ad_type=all&country=ALL"
           f"&q={quote(query, safe='')}&search_type=keyword_unordered")
    with pool._lock:
        page = pool.context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)  # let Facebook's JS settle
            content = page.content()
        except Exception as e:
            page.close()
            return CheckResult("meta_ad_library", "ads", INFO,
                               f"scrape failed: {type(e).__name__}")
        finally:
            try:
                page.close()
            except Exception:
                pass
    m = re.search(r"~?(\d{1,3}(?:[,.]\d{3})*)\s*(?:result|ads?\b)", content, re.I)
    if m:
        return CheckResult("meta_ad_library", "ads", PASS,
                           f"~{m.group(1)} active Meta ad(s) for '{query}'")
    if re.search(r"no results|not running ads|0 results", content, re.I):
        return CheckResult("meta_ad_library", "ads", INFO,
                           f"no active Meta ads for '{query}'")
    return CheckResult("meta_ad_library", "ads", INFO,
                       f"Meta Ad Library inconclusive for '{query}' "
                       "(scrape is best-effort; JS rendering may vary)")


def check_google_ads_transparency(s: Site) -> CheckResult:
    if not s.ads_deep:
        return CheckResult("google_ads_transparency", "ads", INFO,
                           "skipped (pass --ads-deep to scrape Google Ads Transparency)")
    pool = s.browser_pool_ref
    if pool is None or pool.context is None:
        return CheckResult("google_ads_transparency", "ads", INFO,
                           "--ads-deep needs --browser")
    host = urlparse(s.final_url).hostname or ""
    domain = _registered_domain(host)
    query = domain.split(".")[0]
    url = f"https://adstransparency.google.com/?region=anywhere&q={quote(query, safe='')}"
    with pool._lock:
        page = pool.context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)
            content = page.content()
        except Exception as e:
            page.close()
            return CheckResult("google_ads_transparency", "ads", INFO,
                               f"scrape failed: {type(e).__name__}")
        finally:
            try:
                page.close()
            except Exception:
                pass
    m = re.search(r"(\d{1,3}(?:,\d{3})*)\s*(?:ads?\b|advertisers)", content, re.I)
    if m:
        return CheckResult("google_ads_transparency", "ads", PASS,
                           f"~{m.group(1)} active Google ads/advertisers for '{query}'")
    if re.search(r"no (?:ads|advertisers)\s+(?:found|match)", content, re.I):
        return CheckResult("google_ads_transparency", "ads", INFO,
                           f"no Google ads for '{query}'")
    return CheckResult("google_ads_transparency", "ads", INFO,
                       f"Google Ads Transparency inconclusive for '{query}' "
                       "(scrape is best-effort)")


CHECKS: list[CheckFn] = [
    # shared
    check_https_reachable, check_url_status, check_url_not_redirected, check_redirect_chain,
    check_http_to_https, check_www_apex, check_hsts,
    check_dual_stack_host, check_dual_stack_assets,
    check_content_type, check_x_robots, check_doctype, check_meta_charset_early,
    check_mixed_content, check_security_headers, check_meta_refresh,
    check_robots_txt, check_googlebot_allowed,
    # seo
    check_title, check_meta_description, check_canonical, check_canonical_not_redirect,
    check_meta_robots_indexable, check_indexability_composite, check_soft_404,
    check_h1, check_html_lang,
    check_viewport, check_viewport_scalable,
    check_favicon, check_apple_touch_icon, check_images_alt, check_open_graph,
    check_twitter_card, check_json_ld, check_hreflang,
    check_outgoing_links_present, check_external_link_safety,
    check_descriptive_link_text, check_text_to_html_ratio,
    check_breadcrumb_schema, check_product_schema,
    # llm
    check_llms_txt, check_llms_full_txt, check_ai_crawlers,
    check_citable_facts, check_faq_schema,
    # security
    check_tls_cert_expiry, check_tls_cert_hostname, check_tls_protocol_version,
    check_tls_chain_completeness, check_hsts_preload_ready,
    check_caa_record, check_dnssec,
    check_csp_unsafe_inline, check_cross_origin_isolation, check_subresource_integrity,
    # a11y
    check_heading_hierarchy, check_form_inputs_labeled,
    check_landmark_regions, check_button_accessible_name,
    # privacy
    check_cookie_flags,
    # email
    check_mx_records, check_spf_record, check_dmarc_record,
    check_dkim_record, check_mta_sts,
    # perf
    check_page_response_time, check_html_size,
    check_images_dimensions, check_image_sizes, check_image_modern_format,
    check_css_sizes, check_js_assets_reachable,
    check_inline_asset_size, check_dom_size,
    check_render_blocking, check_lcp_hints,
    check_http2_http3, check_compression,
    check_mobile_content_parity, check_responsive_images_srcset,
    # browser (opt-in via --browser; returns INFO when off)
    check_browser_js_errors, check_browser_console_errors,
    check_browser_failed_requests, check_browser_load_time,
    check_browser_fcp, check_browser_lcp, check_browser_cls,
    # ads pixels (HTML scan) + aggregated summary + deep scrapes
    *_ADS_PIXEL_CHECKS, check_ads_pixels_summary,
    check_meta_ad_library, check_google_ads_transparency,
    # tracking / analytics
    *_TRACKING_CHECKS, check_tracking_summary,
    # martech (CMPs, chat widgets, CRM scripts, CDPs)
    *_MARTECH_CHECKS, check_martech_summary,
    # authority / rank signals (free, no API keys)
    check_domain_age_wayback, check_wayback_snapshot_count,
    check_wikipedia_presence, check_commoncrawl_presence,
    check_dns_popularity_signals,
]


def build_site(url: str, session: Optional[requests.Session] = None,
               browser_pool: Optional[BrowserPool] = None,
               ads_deep: bool = False) -> Site:
    """Build a Site for one URL. TLS probe and robots.txt are cached per host.

    Pass `session` to reuse a requests.Session (keep-alive) across many URLs.
    Pass `browser_pool` to run a headless-browser audit for this URL.
    """
    if session is None:
        session = requests.Session()
    r = fetch(session, url)
    soup = BeautifulSoup(r.text, "html.parser")
    host = urlparse(r.url).hostname or ""
    # host-cached robots.txt (thread-safe: check-set around the slow fetch)
    with _CACHE_LOCK:
        cached = _ROBOTS_CACHE.get(host)
    if cached is not None:
        robots, robots_ct, robots_status, robots_url = cached
    else:
        robots_url = urljoin(root_url(r.url), "/robots.txt")
        robots, robots_ct, robots_status = None, None, None
        try:
            rr = fetch(session, robots_url)
            robots_status = rr.status_code
            robots_ct = rr.headers.get("Content-Type")
            if rr.status_code == 200:
                robots = rr.text
        except requests.RequestException:
            pass
        with _CACHE_LOCK:
            _ROBOTS_CACHE.setdefault(host, (robots, robots_ct, robots_status, robots_url))
            robots, robots_ct, robots_status, robots_url = _ROBOTS_CACHE[host]
    # host-cached TLS probe
    tls_info: Optional[dict] = None
    parsed = urlparse(r.url)
    if parsed.scheme == "https" and parsed.hostname:
        tls_info = _tls_probe_cached(parsed.hostname, parsed.port or 443)
    # optional headless-browser audit (one navigation per URL)
    browser_result: Optional[dict] = None
    if browser_pool is not None:
        browser_result = browser_pool.audit(r.url)
    return Site(url=url, final_url=r.url, response=r, soup=soup,
                robots_text=robots, robots_content_type=robots_ct,
                robots_status=robots_status, robots_url=robots_url, session=session,
                tls_info=tls_info, browser_result=browser_result,
                ads_deep=ads_deep, browser_pool_ref=browser_pool)


# Checks whose result doesn't change per URL on the same host — run once.
# Names match `check_<name>` function stripped of the `check_` prefix.
SITE_WIDE_CHECKS = {
    "http_to_https", "www_apex", "hsts", "hsts_preload_ready",
    "dual_stack_host",
    "robots_txt",
    "tls_cert_expiry", "tls_cert_hostname", "tls_protocol_version",
    "tls_chain_completeness",
    "caa_record", "dnssec",
    "llms_txt", "llms_full_txt", "ai_crawlers",
    "mx_records", "spf_record", "dmarc_record", "dkim_record", "mta_sts",
    # ads/tracking/martech pixels are the same signatures for every page
    "ads_pixels_summary", "tracking_summary", "martech_summary",
    "meta_ad_library", "google_ads_transparency",
    *(sig["name"] for sig in ADS_PIXEL_SIGNATURES),
    *(sig["name"] for sig in TRACKING_SIGNATURES),
    *(sig["name"] for sig in MARTECH_SIGNATURES),
    # authority / rank signals are domain-level
    "domain_age_wayback", "wayback_snapshot_count", "wikipedia_presence",
    "commoncrawl_presence", "dns_popularity_signals",
}


def _discover_urls(site: Site, max_urls: int) -> list[str]:
    """Find URLs to audit. Prefer sitemap; fall back to internal links on homepage."""
    # 1. sitemap
    sm_result, locs = check_sitemap(site)
    if locs:
        # dedupe + cap; include homepage up front if not present
        seen: set[str] = set()
        out: list[str] = []
        for u in [site.final_url, *locs]:
            if u not in seen:
                seen.add(u)
                out.append(u)
            if len(out) >= max_urls:
                break
        return out
    # 2. fallback: crawl <a href> from homepage
    host = urlparse(site.final_url).hostname or ""
    out = [site.final_url]
    seen = {site.final_url}
    for a in site.soup.find_all("a", href=True):
        u = urljoin(site.final_url, a["href"].split("#")[0])
        p = urlparse(u)
        if p.hostname == host and p.scheme in ("http", "https"):
            clean = urlunparse(p._replace(fragment=""))
            if clean not in seen:
                seen.add(clean)
                out.append(clean)
        if len(out) >= max_urls:
            break
    return out


class ProgressBar:
    """Tiny stderr progress bar. Disables itself when stderr isn't a TTY."""

    def __init__(self, total: int, enabled: bool = True, width: int = 28):
        self.total = total
        self.width = width
        self.done = 0
        self.enabled = enabled and sys.stderr.isatty()
        self._lock = threading.Lock()

    def tick(self, result: CheckResult) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.done += 1
            filled = int(self.width * self.done / self.total)
            bar = "█" * filled + "░" * (self.width - filled)
            pct = int(100 * self.done / self.total)
            icon = ICON.get(result.status, " ")
            label = f"{icon} {result.check}"[:40]
            line = f"\r[{bar}] {self.done:>2}/{self.total} {pct:>3}%  {label}"
            sys.stderr.write(line.ljust(80))
            sys.stderr.flush()

    def close(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 80 + "\r")
            sys.stderr.flush()


def _sort_results(results: list[CheckResult]) -> list[CheckResult]:
    order = {"shared": 0, "security": 1, "seo": 2, "llm": 3, "perf": 4,
             "browser": 5, "a11y": 6, "privacy": 7, "email": 8,
             "ads": 9, "tracking": 10, "martech": 11, "authority": 12}
    return sorted(results, key=lambda r: (order.get(r.category, 9), r.check))


def _check_name(fn: Callable) -> str:
    return fn.__name__.replace("check_", "", 1)


def run_site_audit(url: str, progress: bool = True, browser: bool = True,
                   single: bool = False, max_urls: int = 50,
                   ads_deep: bool = False
                   ) -> tuple[list[CheckResult], dict[str, list[CheckResult]], list[str]]:
    """Audit a site: one pass of site-wide checks + per-URL checks over discovered URLs.

    Returns (site_wide_results, per_url_results, urls_audited).
    """
    session = requests.Session()

    # homepage = first URL we audit + source of discovery
    homepage = build_site(url, session=session, ads_deep=ads_deep)

    # discover URLs
    if single:
        urls = [homepage.final_url]
    else:
        urls = _discover_urls(homepage, max_urls)

    # optional browser pool, reused across navigations
    pool: Optional[BrowserPool] = None
    browser_error: Optional[str] = None
    if browser:
        pool = BrowserPool()
        browser_error = pool.start()
        if browser_error:
            pool = None
    # Now that we know if the pool exists, attach it to the homepage so the
    # site-wide ads-library checks can use it.
    homepage.browser_pool_ref = pool

    # total ticks for progress bar
    #   site-wide checks: len(SITE_WIDE_CHECKS intersecting CHECKS)
    #   per-URL checks (len(CHECKS) - site-wide count - browser-off count) × len(urls)
    active_per_url = [fn for fn in CHECKS
                      if _check_name(fn) not in SITE_WIDE_CHECKS
                      and (pool is not None or not fn.__name__.startswith("check_browser_"))]
    site_wide_fns = [fn for fn in CHECKS if _check_name(fn) in SITE_WIDE_CHECKS]
    total_ticks = len(site_wide_fns) + len(active_per_url) * len(urls) + 2 * len(urls)
    bar = ProgressBar(total=total_ticks, enabled=progress)

    def _run_checks_sequential(site: Site, fns: list[CheckFn]) -> list[CheckResult]:
        """Run check functions one at a time (some checks fan out their own parallel
        HEAD/DNS internally — a single shared session keeps connection reuse good)."""
        out: list[CheckResult] = []
        for fn in fns:
            try:
                r = fn(site)
            except Exception as e:
                r = CheckResult(_check_name(fn), "shared", FAIL,
                                f"check crashed: {type(e).__name__}: {e}")
            out.append(r)
            bar.tick(r)
        return out

    # ── site-wide checks on homepage ──
    site_wide_results = _run_checks_sequential(homepage, site_wide_fns)
    sm_result, locs = check_sitemap(homepage)
    site_wide_results.append(sm_result)
    bar.tick(sm_result)
    su = check_sitemap_urls_reachable(homepage, locs)
    site_wide_results.append(su)
    bar.tick(su)

    # ── per-URL checks — PARALLEL across URLs ──
    # The big win is running many URLs concurrently; each URL's own checks stay
    # sequential so we don't fight nested thread pools inside dkim/dual_stack/etc.
    per_url_results: dict[str, list[CheckResult]] = {}

    def _audit_one_url(i: int, u: str) -> tuple[str, list[CheckResult]]:
        if u == homepage.final_url and i == 0:
            site = homepage
            if pool is not None:
                site.browser_result = pool.audit(u)
        else:
            try:
                # each thread needs its own Session to avoid urllib3 contention
                site = build_site(u, session=requests.Session(), browser_pool=pool,
                                  ads_deep=ads_deep)
            except requests.RequestException as e:
                return u, [CheckResult("fetch_failed", "shared", FAIL, str(e))]
        res = _run_checks_sequential(site, active_per_url)
        link_results, _ = _probe_internal_links(site)
        res.extend(link_results)
        return u, _sort_results(res)

    # concurrency cap — 4 URLs at a time keeps nested fanout manageable on macOS
    max_url_workers = min(4, max(1, len(urls)))
    if max_url_workers == 1 or len(urls) == 1:
        for i, u in enumerate(urls):
            key, res = _audit_one_url(i, u)
            per_url_results[key] = res
    else:
        with ThreadPoolExecutor(max_workers=max_url_workers) as ex:
            futures = [ex.submit(_audit_one_url, i, u) for i, u in enumerate(urls)]
            for fut in as_completed(futures):
                key, res = fut.result()
                per_url_results[key] = res

    bar.close()
    if pool is not None:
        pool.stop()
    if browser_error:
        site_wide_results.append(CheckResult("browser_pool", "browser", FAIL, browser_error))

    return _sort_results(site_wide_results), per_url_results, urls


# back-compat shim for any external caller
def run_all(url: str, progress: bool = True, browser: bool = False) -> list[CheckResult]:
    site_wide, per_url, _ = run_site_audit(url, progress=progress, browser=browser, single=True)
    first = next(iter(per_url.values())) if per_url else []
    return _sort_results(site_wide + first)


CATEGORIES = [("shared", "Shared / Transport"), ("security", "Security / TLS / DNS"),
              ("seo", "SEO"), ("llm", "LLM-readiness"),
              ("perf", "Performance"), ("browser", "Runtime (headless browser)"),
              ("a11y", "Accessibility"), ("privacy", "Privacy"),
              ("email", "Email / DNS"),
              ("ads", "Ads pixels & ad libraries"),
              ("tracking", "Analytics / tracking"),
              ("martech", "Marketing stack (CMPs, chat, CRM)"),
              ("authority", "Authority signals (free, no API keys)")]


def _render_table(results: list[CheckResult]) -> list[str]:
    out: list[str] = []
    for cat, label in CATEGORIES:
        rows = [r for r in results if r.category == cat]
        if not rows:
            continue
        out.append(f"### {label}")
        out.append("| Check | Status | Detail |")
        out.append("|---|---|---|")
        for r in rows:
            detail = r.message.replace("|", "\\|")
            out.append(f"| {r.check} | {ICON.get(r.status, '?')} {r.status} | {detail} |")
        out.append("")
    return out


def _counts(results: list[CheckResult]) -> dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in (PASS, WARN, FAIL, INFO)}


def _summary_line(results: list[CheckResult]) -> str:
    c = _counts(results)
    return (f"{ICON[PASS]} {c[PASS]} pass · {ICON[WARN]} {c[WARN]} warn · "
            f"{ICON[FAIL]} {c[FAIL]} fail · {ICON[INFO]} {c[INFO]} info")


def render_markdown(url: str, site_wide: list[CheckResult],
                    per_url: dict[str, list[CheckResult]], urls: list[str]) -> str:
    lines: list[str] = [f"# Site audit: {url}", ""]
    lines.append(f"Audited **{len(urls)}** URL(s).  ")
    lines.append(f"Site-wide: **{_summary_line(site_wide)}**")
    lines.append("")

    # ── site-wide section ──
    lines.append("## Site-wide checks")
    lines.append("_Run once on the homepage; results apply to the whole host._")
    lines.append("")
    lines.extend(_render_table(site_wide))

    # build aligned, short URL paths for per-URL tables
    base = url.rstrip("/")
    shorts = {u: (u.replace(base, "") or "/") for u in urls}
    url_w = max((len(s) for s in shorts.values()), default=3)

    # ── per-URL issue digest (fixed-width monospace) ──
    lines.append("## Per-URL issues (WARN + FAIL only)")
    lines.append("")
    lines.append("```")
    header = f"{'URL'.ljust(url_w)}  {'Status'.ljust(6)}  {'Check'.ljust(32)}  Detail"
    lines.append(header)
    lines.append("-" * min(len(header), 120))
    any_issues = False
    for u in urls:
        short = shorts[u]
        for r in per_url.get(u, []):
            if r.status in (WARN, FAIL):
                any_issues = True
                icon = ICON[r.status]
                detail = r.message.replace("\n", " ")[:100]
                lines.append(f"{short.ljust(url_w)}  {icon} {r.status.ljust(4)}  {r.check.ljust(32)}  {detail}")
    if not any_issues:
        lines.append("(none)")
    lines.append("```")
    lines.append("")

    # ── per-URL pass/warn/fail summary (fixed-width monospace) ──
    by_page: list[tuple[str, dict[str, int]]] = [(u, _counts(per_url.get(u, []))) for u in urls]
    worst = sorted(by_page, key=lambda x: (-x[1][FAIL], -x[1][WARN]))[:10]
    lines.append("## Per-URL summary")
    lines.append("")
    lines.append("```")
    lines.append(f"{'URL'.ljust(url_w)}   ✅   🟡   🔴   ℹ️")
    lines.append("-" * (url_w + 24))
    for u, c in worst:
        short = shorts[u]
        lines.append(f"{short.ljust(url_w)}  {c[PASS]:>3}  {c[WARN]:>3}  {c[FAIL]:>3}  {c[INFO]:>3}")
    if len(urls) > 10:
        lines.append(f"… {len(urls) - 10} more URL(s) …")
    lines.append("```")
    lines.append("")

    # ── aggregate ──
    all_results = list(site_wide)
    for rs in per_url.values():
        all_results.extend(rs)
    lines.append(f"**Aggregate:** {_summary_line(all_results)} across "
                 f"site-wide + {len(urls)} URL(s)")
    return "\n".join(lines)


def render_single(url: str, site_wide: list[CheckResult],
                  per_url: dict[str, list[CheckResult]]) -> str:
    """Compatible with --single: flatten site-wide + the one page into one report."""
    lines = [f"# SEO + LLM check: {url}", ""]
    one_page = next(iter(per_url.values())) if per_url else []
    combined = _sort_results(site_wide + one_page)
    # reuse existing single-page renderer style (## headers, not ### from table helper)
    for cat, label in CATEGORIES:
        rows = [r for r in combined if r.category == cat]
        if not rows:
            continue
        lines.append(f"## {label}")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---|---|")
        for r in rows:
            detail = r.message.replace("|", "\\|")
            lines.append(f"| {r.check} | {ICON.get(r.status, '?')} {r.status} | {detail} |")
        lines.append("")
    lines.append(f"**Summary:** {_summary_line(combined)}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="SEO + LLM-readiness website checker")
    ap.add_argument("url", help="URL to check (e.g. https://example.com)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    ap.add_argument("--fail-on", choices=["warn", "fail"], default=None,
                    help="exit non-zero if any check at or above this severity")
    ap.add_argument("--no-progress", action="store_true",
                    help="suppress the stderr progress bar")
    ap.add_argument("--no-browser", action="store_true",
                    help="disable the headless-browser audit (it is ON by default; "
                         "needs `pip install -r requirements-browser.txt && "
                         "playwright install chromium` the first time)")
    ap.add_argument("--single", action="store_true",
                    help="audit only the input URL (skip sitemap/link crawl)")
    ap.add_argument("--max-urls", type=int, default=50,
                    help="max URLs to audit when crawling (default 50)")
    ap.add_argument("--ads-deep", action="store_true",
                    help="scrape Meta Ad Library + Google Ads Transparency Center "
                         "for active-ad counts (best-effort; requires --browser)")
    args = ap.parse_args(argv)

    url = args.url
    if not urlparse(url).scheme:
        url = "https://" + url

    try:
        site_wide, per_url, urls = run_site_audit(
            url,
            progress=not args.no_progress,
            browser=not args.no_browser,
            single=args.single,
            max_urls=args.max_urls,
            ads_deep=args.ads_deep,
        )
    except requests.RequestException as e:
        print(f"fatal: could not fetch {url}: {e}", file=sys.stderr)
        return 2

    if args.json:
        out = {
            "url": url,
            "urls_audited": urls,
            "site_wide": [asdict(r) for r in site_wide],
            "per_url": {u: [asdict(r) for r in rs] for u, rs in per_url.items()},
        }
        print(json.dumps(out, indent=2))
    elif args.single:
        print(render_single(url, site_wide, per_url))
    else:
        print(render_markdown(url, site_wide, per_url, urls))

    all_results = list(site_wide)
    for rs in per_url.values():
        all_results.extend(rs)
    if args.fail_on == "fail" and any(r.status == FAIL for r in all_results):
        return 1
    if args.fail_on == "warn" and any(r.status in (WARN, FAIL) for r in all_results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
