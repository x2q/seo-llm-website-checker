# seo-llm-website-checker

Single-file Python CLI that runs ~60 checks on a live website and reports SEO + LLM-readiness issues as a markdown table (or JSON). Covers the same ground as a single-page Ahrefs / Screaming Frog / Sitebulb / Lighthouse / Google Search Console audit — slow pages, broken links, redirect chains, canonical/sitemap hygiene, oversized assets, mixed content, security headers, DOM size, modern image formats, Googlebot crawlability, soft-404 detection, plus LLM-specific signals (`llms.txt`, AI crawler access, citable facts). No headless browser — just HTTP + HTML parsing.

## Install

```sh
pip install -r requirements.txt
```

Deps: `requests`, `beautifulsoup4`.

## Usage

```sh
python check.py https://example.com              # markdown table
python check.py https://example.com --json       # JSON for scripting/CI
python check.py https://example.com --fail-on fail   # exit 1 on any FAIL
python check.py https://example.com --fail-on warn   # exit 1 on any WARN or FAIL
```

## What it checks

### Shared / transport

- HTTPS reachable, HTTP → HTTPS redirect, HSTS header
- **URL status class** — explicitly flag 404, 403, 5xx, 4xx (GSC will refuse to index)
- **URL not redirected** — if the input URL itself 30xs, say so (Google indexes the target)
- **Redirect chain length** — WARN >1 hop, FAIL >4 (GSC "Redirect error")
- **Googlebot allowed** — path-aware robots.txt matching (longest-pattern-wins, `$` end-anchor, `*` wildcard) for the audited URL (GSC "Blocked by robots.txt")
- www ↔ apex canonicalization (redirect direction must match the `<link rel=canonical>`)
- `Content-Type` + charset, no `X-Robots-Tag: noindex`
- **`<!DOCTYPE html>` present** (Lighthouse, Screaming Frog)
- **Charset declared in first 1 KB of HTML** (or in `Content-Type` header)
- **No mixed content** — no `http://` resources on an `https://` page (Screaming Frog, SEMrush)
- **Security headers** — `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`
- **No `<meta http-equiv="refresh">`** client-side redirect (SEO anti-pattern)
- `robots.txt` reachable, served as `text/plain`, parses, contains a `Sitemap:` line

### SEO

- `<title>` (15–65 chars), `<meta name=description>` (50–160 chars)
- `<link rel=canonical>` present, absolute https, matches the fetched URL (path percent-encoded)
- **Canonical URL itself returns 200 directly** (doesn't redirect — the Ahrefs "canonical points to redirect" check)
- **`<meta name="robots">` + `X-Robots-Tag` — page is indexable** (FAIL on `noindex`, WARN on `nofollow`)
- **Page indexable by Google (composite)** — rolls up status, robots meta/header, canonical direction, and robots.txt into one "will Google index this?" verdict
- **Soft 404 detection** — 200 response whose title/H1 says "not found"/"ikke fundet" with thin content
- Single non-empty `<h1>`, `<html lang>` (warns if `.dk` site isn't `da`)
- `<meta name=viewport>` with `width=device-width`
- **Viewport doesn't disable zoom** (`user-scalable=no` / `maximum-scale=1` — accessibility issue)
- **favicon** and **apple-touch-icon** both resolve 200 (apple-touch-icon drives iMessage/iOS share previews)
- `<img>` elements have `alt`
- Open Graph (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`) all present, `og:image` reachable
- Twitter card (prefers `summary_large_image`)
- JSON-LD structured data parses, traverses `@graph`, contains at least one useful type (Organization, WebSite, LocalBusiness, Article, FAQPage, Product, …), rejects JSON-LD loaded via `src=`
- `hreflang` reciprocity + `x-default` when present
- `sitemap.xml`: valid XML, follows `<sitemapindex>` one level, all URLs https + percent-encoded, `<lastmod>` present, sampled URLs return 200 and self-canonical
- **Page has outgoing links** (FAIL if zero — dead-end for crawlers)
- **Internal links not broken** (sample of 10 — FAIL on 4xx/5xx)
- **Internal links not going through redirects** (sample of 10 — WARN on 3xx, the Ahrefs "page has links to redirect" check)
- **External `target="_blank"` links have `rel="noopener"`** (security — Lighthouse, Screaming Frog)
- **Descriptive link text** — fewer than 20% of anchors are "click here" / "read more" / "læs mere" / bare URLs (Lighthouse `link-text`)
- **Text-to-HTML ratio** — ≥10% visible text and ≥50 words (thin-content guard)

### LLM-readiness

- `/llms.txt` reachable, served as `text/plain`, non-empty, has at least one markdown heading and one link
- `/llms-full.txt` (optional) reachable with `text/*` Content-Type
- `robots.txt` doesn't block `GPTBot`, `ClaudeBot`, `PerplexityBot`, `Google-Extended`, `CCBot` (direct `Disallow: /` or inherited from `User-agent: *`)
- Citable facts: homepage text contains concrete numbers — price, phone, postcode, capacity, year — so LLMs have something to cite instead of marketing copy
- `FAQPage` JSON-LD present when the page has a visible FAQ section

### Performance hints (static)

- **Page response time** (WARN >2s, FAIL >5s — Ahrefs "slow page" proxy)
- **HTML payload size** (WARN >500 KB, FAIL >2 MB)
- All `<img>` have `width` + `height` (CLS)
- **Image file sizes** — samples up to 10 images; WARN on any >200 KB, FAIL on >500 KB
- **Modern image formats** — ≥80% WebP/AVIF across the sample (Lighthouse `modern-image-formats`)
- **CSS file sizes** — WARN on any stylesheet >100 KB
- **JS assets reachable** — HEAD on referenced `<script src>` files; FAIL on 4xx/5xx (closest static approximation of Ahrefs "broken JavaScript")
- **Inline `<script>` + `<style>` size** — WARN >50 KB, FAIL >150 KB (un-cacheable bloat)
- **DOM size + depth** — WARN >1500 elements or depth >32, FAIL >3000 or depth >60 (Lighthouse `dom-size`)
- No dev CDNs (e.g. `cdn.tailwindcss.com`) in `<head>`
- First `<img>` has `fetchpriority=high`/`loading=eager`, or a `<link rel=preload as=image>` is set (LCP)

## Output

Default is a markdown table grouped by category with ✅ / 🟡 / 🔴 / ℹ️ icons and a one-line summary. `--json` emits `{url, results: [{check, category, status, message, evidence}]}` for programmatic consumption.

## Example

```
# SEO + LLM check: https://example.com

## Shared / Transport
| Check | Status | Detail |
|---|---|---|
| https_reachable | ✅ PASS | 200 on https://www.example.com/ |
| www_apex_canonicalization | ✅ PASS | https://example.com/ → https://www.example.com/ (matches canonical) |
| robots_txt_present | ✅ PASS | parses (1 groups), has Sitemap: |

## SEO
| Check | Status | Detail |
|---|---|---|
| canonical | ✅ PASS | https://www.example.com/ |
| apple_touch_icon | 🟡 WARN | no apple-touch-icon — iMessage/iOS bookmark preview will be generic |

...

**Summary:** ✅ 20 pass · 🟡 5 warn · 🔴 1 fail · ℹ️ 5 info
```
