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
from concurrent.futures import ThreadPoolExecutor
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
    """True if the server accepts a connection restricted to exactly this TLS version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
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
    """HTML served with gzip / br / zstd when encoded."""
    enc = s.response.headers.get("Content-Encoding", "").lower()
    size = len(s.response.content)
    if size < 10 * 1024:
        return CheckResult("compression", "perf", INFO,
                           f"HTML {size // 1024} KB — too small to matter")
    if enc in ("br", "zstd"):
        return CheckResult("compression", "perf", PASS,
                           f"Content-Encoding={enc} (modern)")
    if enc == "gzip":
        return CheckResult("compression", "perf", WARN,
                           f"Content-Encoding=gzip — consider br/zstd (~15-20% smaller)")
    return CheckResult("compression", "perf", FAIL,
                       f"HTML {size // 1024} KB served uncompressed — enable gzip/brotli")


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

KNOWN_TRACKERS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Ads / DoubleClick",
    "facebook.net": "Facebook Pixel",
    "connect.facebook.net": "Facebook Pixel",
    "hotjar.com": "Hotjar",
    "static.hotjar.com": "Hotjar",
    "clarity.ms": "Microsoft Clarity",
    "mixpanel.com": "Mixpanel",
    "segment.com": "Segment",
    "analytics.tiktok.com": "TikTok Pixel",
    "snap.licdn.com": "LinkedIn Insight",
    "ads.linkedin.com": "LinkedIn Ads",
    "pinimg.com": "Pinterest Tag",
    "amplitude.com": "Amplitude",
    "fullstory.com": "FullStory",
}


def check_third_party_trackers(s: Site) -> CheckResult:
    """Third-party hosts + known trackers on the page. Flag trackers that load
    before any cookie-consent UI (heuristic)."""
    host = urlparse(s.final_url).hostname or ""
    third_party_hosts: set[str] = set()
    for tag, attr in [("script", "src"), ("img", "src"), ("iframe", "src"), ("link", "href")]:
        for el in s.soup.find_all(tag, attrs={attr: True}):
            url = urljoin(s.final_url, el[attr])
            h = urlparse(url).hostname
            if h and h != host:
                third_party_hosts.add(h)
    # match known trackers
    trackers_found: list[str] = []
    for h in third_party_hosts:
        for domain, name in KNOWN_TRACKERS.items():
            if h == domain or h.endswith("." + domain):
                trackers_found.append(name)
                break
    trackers_found = sorted(set(trackers_found))
    # heuristic: does the page mention a cookie banner?
    page_text = s.soup.get_text(" ", strip=True).lower()
    has_banner = any(s in page_text for s in
                     ("cookie", "consent", "accepter", "samtykke", "privatliv"))
    if trackers_found and not has_banner:
        return CheckResult("third_party_trackers", "privacy", FAIL,
                           f"{len(trackers_found)} tracker(s) + no cookie banner detected: "
                           f"{', '.join(trackers_found)} (GDPR/ePrivacy requires consent)")
    if len(third_party_hosts) > 10:
        return CheckResult("third_party_trackers", "privacy", WARN,
                           f"{len(third_party_hosts)} third-party hosts; "
                           f"trackers: {', '.join(trackers_found) or 'none known'}")
    if trackers_found:
        return CheckResult("third_party_trackers", "privacy", WARN,
                           f"{len(trackers_found)} tracker(s) present (consent banner detected): "
                           f"{', '.join(trackers_found)}")
    return CheckResult("third_party_trackers", "privacy", PASS,
                       f"{len(third_party_hosts)} third-party host(s), no known trackers")


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
    check_third_party_trackers, check_cookie_flags,
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
]


def build_site(url: str) -> Site:
    session = requests.Session()
    r = fetch(session, url)
    soup = BeautifulSoup(r.text, "html.parser")
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
    # one TLS probe, reused by every security check
    tls_info: Optional[dict] = None
    parsed = urlparse(r.url)
    if parsed.scheme == "https" and parsed.hostname:
        tls_info = _tls_probe(parsed.hostname, parsed.port or 443)
    return Site(url=url, final_url=r.url, response=r, soup=soup,
                robots_text=robots, robots_content_type=robots_ct,
                robots_status=robots_status, robots_url=robots_url, session=session,
                tls_info=tls_info)


class ProgressBar:
    """Tiny stderr progress bar. Disables itself when stderr isn't a TTY."""

    def __init__(self, total: int, enabled: bool = True, width: int = 28):
        self.total = total
        self.width = width
        self.done = 0
        self.enabled = enabled and sys.stderr.isatty()

    def tick(self, result: CheckResult) -> None:
        if not self.enabled:
            return
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


def run_all(url: str, progress: bool = True) -> list[CheckResult]:
    site = build_site(url)
    # total = simple checks + sitemap + sitemap_urls + 2 link probes
    bar = ProgressBar(total=len(CHECKS) + 4, enabled=progress)
    results: list[CheckResult] = []
    for fn in CHECKS:
        r = fn(site)
        results.append(r)
        bar.tick(r)
    sm_result, locs = check_sitemap(site)
    results.append(sm_result)
    bar.tick(sm_result)
    su = check_sitemap_urls_reachable(site, locs)
    results.append(su)
    bar.tick(su)
    link_results, _ = _probe_internal_links(site)
    for r in link_results:
        results.append(r)
        bar.tick(r)
    bar.close()
    order = {"shared": 0, "security": 1, "seo": 2, "llm": 3, "perf": 4,
             "a11y": 5, "privacy": 6, "email": 7}
    results.sort(key=lambda r: (order.get(r.category, 9), r.check))
    return results


def render_markdown(url: str, results: Iterable[CheckResult]) -> str:
    results = list(results)
    lines = [f"# SEO + LLM check: {url}\n"]
    categories = [("shared", "Shared / Transport"), ("security", "Security / TLS / DNS"),
                  ("seo", "SEO"), ("llm", "LLM-readiness"),
                  ("perf", "Performance"), ("a11y", "Accessibility"),
                  ("privacy", "Privacy"), ("email", "Email / DNS")]
    for cat, label in categories:
        rows = [r for r in results if r.category == cat]
        if not rows:
            continue
        lines.append(f"## {label}")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---|---|")
        for r in rows:
            detail = r.message.replace("|", "\\|")
            lines.append(f"| {r.check} | {ICON.get(r.status, '?')} {r.status} | {detail} |")
        lines.append("")
    summary = {s: sum(1 for r in results if r.status == s) for s in (PASS, WARN, FAIL, INFO)}
    lines.append(f"**Summary:** "
                 f"{ICON[PASS]} {summary[PASS]} pass · "
                 f"{ICON[WARN]} {summary[WARN]} warn · "
                 f"{ICON[FAIL]} {summary[FAIL]} fail · "
                 f"{ICON[INFO]} {summary[INFO]} info")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="SEO + LLM-readiness website checker")
    ap.add_argument("url", help="URL to check (e.g. https://example.com)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    ap.add_argument("--fail-on", choices=["warn", "fail"], default=None,
                    help="exit non-zero if any check at or above this severity")
    ap.add_argument("--no-progress", action="store_true",
                    help="suppress the stderr progress bar")
    args = ap.parse_args(argv)

    url = args.url
    if not urlparse(url).scheme:
        url = "https://" + url

    try:
        results = run_all(url, progress=not args.no_progress)
    except requests.RequestException as e:
        print(f"fatal: could not fetch {url}: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"url": url, "results": [asdict(r) for r in results]}, indent=2))
    else:
        print(render_markdown(url, results))

    if args.fail_on == "fail" and any(r.status == FAIL for r in results):
        return 1
    if args.fail_on == "warn" and any(r.status in (WARN, FAIL) for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
