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
import sys
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse, quote
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (compatible; SEOLLMChecker/1.0; +https://github.com/)"
TIMEOUT = 15
AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot"]

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
    session: requests.Session


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
    t = s.soup.title.string.strip() if s.soup.title and s.soup.title.string else ""
    if not t:
        return CheckResult("title_tag", "seo", FAIL, "no <title>")
    if not (15 <= len(t) <= 65):
        return CheckResult("title_tag", "seo", WARN, f"length {len(t)}: {t!r}")
    return CheckResult("title_tag", "seo", PASS, f"{len(t)} chars: {t!r}")


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


def check_favicon(s: Site) -> CheckResult:
    link = s.soup.find("link", rel=lambda v: v and ("icon" in v and "apple" not in v))
    href = link.get("href") if link else "/favicon.ico"
    url = urljoin(s.final_url, href)
    try:
        r = _head_or_get(s.session, url)
    except requests.RequestException as e:
        return CheckResult("favicon", "seo", WARN, f"{url}: {e}")
    ok = r.status_code == 200
    return CheckResult("favicon", "seo", PASS if ok else WARN, f"{r.status_code} {url}")


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


def check_robots_txt(s: Site) -> CheckResult:
    if s.robots_text is None:
        return CheckResult("robots_txt_present", "shared", FAIL,
                           "GET /robots.txt failed or non-200")
    if s.robots_content_type and not s.robots_content_type.lower().startswith("text/plain"):
        return CheckResult("robots_txt_present", "shared", WARN,
                           f"served as {s.robots_content_type!r} (want text/plain) — crawlers may ignore")
    # must parse into at least one group with a User-agent
    groups = _parse_robots_groups(s.robots_text)
    if not any(agents for agents, _ in groups):
        return CheckResult("robots_txt_present", "shared", FAIL,
                           "robots.txt has no User-agent lines — unparseable")
    has_sitemap = bool(re.search(r"(?im)^\s*sitemap\s*:", s.robots_text))
    if not has_sitemap:
        return CheckResult("robots_txt_present", "shared", WARN,
                           f"parses ({len(groups)} groups) but no Sitemap: line")
    return CheckResult("robots_txt_present", "shared", PASS,
                       f"parses ({len(groups)} groups), has Sitemap:")


def _sitemap_url(s: Site) -> str:
    if s.robots_text:
        for line in s.robots_text.splitlines():
            m = re.match(r"(?i)\s*sitemap\s*:\s*(\S+)", line)
            if m:
                return m.group(1).strip()
    return urljoin(root_url(s.final_url), "/sitemap.xml")


SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def _parse_sitemap(session: requests.Session, url: str,
                   depth: int = 0) -> tuple[Optional[ET.Element], Optional[str]]:
    try:
        r = fetch(session, url)
    except requests.RequestException as e:
        return None, f"{url}: {e}"
    if r.status_code != 200:
        return None, f"{r.status_code} {url}"
    ct = r.headers.get("Content-Type", "").lower()
    if not ("xml" in ct or "text/plain" in ct):
        return None, f"{url} served as {ct!r} (expected xml)"
    try:
        return ET.fromstring(r.text), None
    except ET.ParseError as e:
        return None, f"{url} invalid XML: {e}"


def check_sitemap(s: Site) -> tuple[CheckResult, list[str]]:
    url = _sitemap_url(s)
    root, err = _parse_sitemap(s.session, url)
    if err or root is None:
        return CheckResult("sitemap_xml", "seo", FAIL, err or "parse failed"), []

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
            sub_root, sub_err = _parse_sitemap(s.session, child_url, depth=1)
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
    status = WARN if issues else PASS
    msg = f"{prefix}{len(locs)} URLs" + (f"; {', '.join(issues)}" if issues else "")
    return CheckResult("sitemap_xml", "seo", status, msg, url), locs


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


def check_internal_links(s: Site) -> CheckResult:
    host = urlparse(s.final_url).netloc
    links = []
    for a in s.soup.find_all("a", href=True):
        u = urljoin(s.final_url, a["href"])
        if urlparse(u).netloc == host and u not in links:
            links.append(u)
    sample = links[:10]
    if not sample:
        return CheckResult("internal_links_reachable", "seo", INFO, "no internal links")
    broken = []
    for u in sample:
        try:
            r = s.session.head(u, timeout=TIMEOUT, allow_redirects=True,
                               headers={"User-Agent": UA})
            if r.status_code == 405:
                r = fetch(s.session, u)
            if r.status_code >= 400:
                broken.append(f"{u} [{r.status_code}]")
        except requests.RequestException as e:
            broken.append(f"{u} [{e}]")
    if broken:
        return CheckResult("internal_links_reachable", "seo", WARN,
                           f"{len(broken)}/{len(sample)} broken: {broken[0]}")
    return CheckResult("internal_links_reachable", "seo", PASS, f"{len(sample)} links OK")


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

CheckFn = Callable[[Site], CheckResult]

CHECKS: list[CheckFn] = [
    check_https_reachable, check_http_to_https, check_www_apex, check_hsts,
    check_content_type, check_x_robots,
    check_title, check_meta_description, check_canonical, check_h1, check_html_lang,
    check_viewport, check_favicon, check_apple_touch_icon, check_images_alt, check_open_graph,
    check_twitter_card, check_json_ld, check_hreflang,
    check_robots_txt, check_internal_links,
    check_llms_txt, check_llms_full_txt, check_ai_crawlers,
    check_citable_facts, check_faq_schema,
    check_images_dimensions, check_render_blocking, check_lcp_hints,
]


def build_site(url: str) -> Site:
    session = requests.Session()
    r = fetch(session, url)
    soup = BeautifulSoup(r.text, "html.parser")
    robots_url = urljoin(root_url(r.url), "/robots.txt")
    robots, robots_ct = None, None
    try:
        rr = fetch(session, robots_url)
        if rr.status_code == 200:
            robots = rr.text
            robots_ct = rr.headers.get("Content-Type")
    except requests.RequestException:
        pass
    return Site(url=url, final_url=r.url, response=r, soup=soup,
                robots_text=robots, robots_content_type=robots_ct, session=session)


def run_all(url: str) -> list[CheckResult]:
    site = build_site(url)
    results = [fn(site) for fn in CHECKS]
    sm_result, locs = check_sitemap(site)
    results.append(sm_result)
    results.append(check_sitemap_urls_reachable(site, locs))
    order = {"shared": 0, "seo": 1, "llm": 2, "perf": 3}
    results.sort(key=lambda r: (order.get(r.category, 9), r.check))
    return results


def render_markdown(url: str, results: Iterable[CheckResult]) -> str:
    results = list(results)
    lines = [f"# SEO + LLM check: {url}\n"]
    categories = [("shared", "Shared / Transport"), ("seo", "SEO"),
                  ("llm", "LLM-readiness"), ("perf", "Performance")]
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
    args = ap.parse_args(argv)

    url = args.url
    if not urlparse(url).scheme:
        url = "https://" + url

    try:
        results = run_all(url)
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
