# seo-llm-website-checker

A single-file Python CLI that audits one live URL against **86 static checks** (plus 7 optional runtime checks via headless Chromium) across SEO, performance, security, accessibility, privacy, email DNS, and LLM-readiness — in one command, in ~5 seconds (plus ~3 s if `--browser`).

Covers the ground an Ahrefs / Screaming Frog / Sitebulb / Lighthouse / Google Search Console / PageSpeed audit would, for a single page. No headless browser, no multi-page crawl, no paid APIs — just `requests`, `BeautifulSoup`, `dnspython`, and stdlib `ssl` / `socket`.

## Install

```sh
pip install -r requirements.txt
```

Three deps: `requests`, `beautifulsoup4`, `dnspython`.

**Optional — headless-browser mode** (adds 7 runtime checks: JS errors, console errors, failed requests, load time, FCP, LCP, CLS):

```sh
pip install -r requirements-browser.txt
playwright install chromium
```

## Run

```sh
python check.py https://example.com                  # markdown report
python check.py https://example.com --json           # JSON for CI
python check.py https://example.com --fail-on fail   # exit 1 on any 🔴
python check.py https://example.com --fail-on warn   # exit 1 on any 🟡 or 🔴
python check.py https://example.com --no-progress    # silence stderr bar
python check.py https://example.com --browser        # add headless-Chromium runtime checks
```

While running, a live progress bar renders on stderr:

```
[████████░░░░░░░░░░░░░░░░░░░░] 18/86  21%  ✅ viewport_meta
```

Auto-disables when stderr isn't a TTY, so piped output stays clean.

## Output

Markdown table grouped by category (`Shared` · `Security` · `SEO` · `LLM` · `Performance` · `Accessibility` · `Privacy` · `Email`), ending in a one-line summary:

```
**Summary:** ✅ 51 pass · 🟡 18 warn · 🔴 6 fail · ℹ️ 10 info
```

`--json` emits `{url, results: [{check, category, status, message, evidence}]}`.

## What it checks

### Shared / transport (18)

| Check | What |
|---|---|
| `https_reachable` | URL returns 200 over HTTPS |
| `url_status` | explicit status class — 404 / 403 / 5xx / 4xx are flagged separately (GSC reasons) |
| `url_not_redirected` | INFO when the input URL itself 30xs (Google indexes the target) |
| `redirect_chain` | WARN >1 hop, FAIL >4 (GSC "Redirect error") |
| `http_to_https_redirect` | port 80 redirects to HTTPS with 301/308 |
| `www_apex_canonicalization` | one direction redirects to the other, matching `<link rel=canonical>` |
| `hsts_header` | `Strict-Transport-Security` with `max-age≥15552000` |
| `dual_stack_host` | primary host has A + AAAA records *and* TCP-connects on both |
| `dual_stack_assets` | every referenced third-party asset host resolves via IPv4 + IPv6 |
| `content_type_charset` | `text/html; charset=utf-8` |
| `x_robots_tag` | no `noindex` in response header |
| `doctype_present` | `<!DOCTYPE html>` at the top |
| `meta_charset_early` | `<meta charset>` in first 1 KB, or charset in `Content-Type` |
| `mixed_content` | no `http://` resources on an `https://` page |
| `security_headers` | `X-Content-Type-Options`, `Referrer-Policy`, CSP, Permissions-Policy |
| `meta_refresh_redirect` | no client-side `<meta http-equiv=refresh>` redirect |
| `robots_txt` | status + Content-Type (`text/plain`) + parses + `Sitemap:` line + syntax (BOM, CRLF, unknown directives) |
| `googlebot_allowed` | path-aware robots.txt match for the audited URL (longest-match, `$` end-anchor, `*` wildcard) |

### Security / TLS (10)

| Check | What |
|---|---|
| `tls_cert_expiry` | days until `notAfter`: FAIL <15, WARN <30 |
| `tls_cert_hostname_match` | hostname in `subjectAltName`; CN-only is WARN |
| `tls_protocol_version` | FAIL if server still accepts TLS 1.0/1.1; WARN if TLS 1.3 unsupported |
| `tls_chain_completeness` | server sent intermediate certs (needs Python 3.13+) |
| `hsts_preload_ready` | meets [hstspreload.org](https://hstspreload.org) criteria |
| `caa_record` | domain publishes CAA DNS record restricting CAs |
| `dnssec` | parent zone returns DS record (zone is signed) |
| `csp_unsafe_inline` | CSP disallows `'unsafe-inline'`/`'unsafe-eval'` unless nonce/hash/strict-dynamic |
| `cross_origin_isolation` | COOP `same-origin` + COEP `require-corp` (SharedArrayBuffer / XS-Leak defence) |
| `subresource_integrity` | every cross-origin `<script>`/`<link rel=stylesheet>` has `integrity="sha…"` |

### SEO (28)

Head / indexability:

- `title_tag` — 15–65 chars after whitespace collapse; WARN on stray newlines/indent in the source
- `meta_description` — 50–160 chars
- `canonical` — single `<link rel=canonical>`, absolute https, matches fetched URL (percent-encoded)
- `canonical_not_redirect` — the canonical URL itself returns 200 (Ahrefs "canonical points to redirect")
- `meta_robots_indexable` — no `noindex` in meta or `X-Robots-Tag`
- `page_indexable_by_google` — composite: status + robots + canonical direction + robots.txt
- `soft_404` — 200 body whose title/H1 says "not found"/"ikke fundet" with thin content
- `h1_single` — exactly one non-empty `<h1>`
- `html_lang` — `<html lang>` present (WARN if `.dk` site isn't `da`)
- `viewport_meta` / `viewport_accessible` — `width=device-width` and no `user-scalable=no`
- `favicon` — Google Search spec: crawlable by Googlebot, `image/*` Content-Type, valid format (PNG / ICO / SVG / JPEG / GIF / WebP), SVG always passes, raster must be square and a multiple of 48 (48 / 96 / 144 / 192)
- `apple_touch_icon` — for iMessage and iOS bookmark previews

Metadata / social / structured data:

- `images_alt` — every `<img>` has `alt`
- `open_graph` — `og:title`/`description`/`image`/`url`/`type` + `og:image` resolves
- `twitter_card` — prefers `summary_large_image`
- `json_ld_structured_data` — parses, traverses `@graph`, has a useful `@type`, rejects `<script src=>` JSON-LD
- `hreflang` — reciprocity + `x-default`
- `breadcrumb_schema` — `BreadcrumbList` well-formed (≥2 items with `position`/`name`/`item`)
- `product_schema` — `Product` has `name` + `image` + one of `offers`/`aggregateRating`/`review`; `offers` has `price` + `priceCurrency` + `availability`

Crawlability:

- `sitemap_xml` — status + Content-Type (`application/xml`) + content; follows `<sitemapindex>` one level
- `sitemap_urls_reachable` — sample 10 URLs return 200 self-canonical
- `internal_links_not_broken` — sample 10 internal links FAIL on 4xx/5xx
- `internal_links_not_redirecting` — WARN on 3xx (Ahrefs "page has links to redirect")
- `outgoing_links_present` — page has ≥1 outgoing link
- `external_link_rel_safety` — external `target=_blank` has `rel=noopener`
- `descriptive_link_text` — <20% "click here" / "læs mere" / bare URLs
- `text_to_html_ratio` — ≥10% visible text, ≥50 words

### LLM-readiness (5)

- `llms_txt` — `/llms.txt` 200, `text/plain`, has a markdown heading and a link
- `llms_full_txt` — `/llms-full.txt` optional
- `ai_crawlers_allowed` — robots.txt doesn't block `GPTBot`/`ClaudeBot`/`PerplexityBot`/`Google-Extended`/`CCBot`
- `citable_facts` — page has concrete numbers (price, phone, postcode, year, capacity) LLMs can cite
- `faq_schema_if_faq_visible` — `FAQPage` JSON-LD when a FAQ section is visible

### Performance (15)

| Check | Rule |
|---|---|
| `page_response_time` | WARN >2 s, FAIL >5 s |
| `html_size` | WARN >500 KB, FAIL >2 MB |
| `images_dimensions` | every `<img>` has `width`+`height` (CLS) |
| `image_sizes` | WARN any image >200 KB, FAIL >500 KB |
| `image_modern_format` | ≥80% WebP / AVIF |
| `responsive_images_srcset` | ≥70% of `<img>` use `srcset` or `<picture>` |
| `css_sizes` | WARN any stylesheet >100 KB |
| `js_assets_reachable` | `<script src>` returns 200 |
| `inline_asset_size` | WARN inline `<script>`+`<style>` >50 KB |
| `dom_size` | WARN >1500 elements or depth >32 |
| `render_blocking_assets` | no dev CDNs in `<head>` |
| `lcp_image_hints` | first `<img>` has `fetchpriority=high`/`loading=eager` or `<link rel=preload as=image>` |
| `http2_http3` | ALPN negotiates `h2`; `Alt-Svc` advertises `h3` |
| `compression` | probes `br` / `zstd` / `gzip` / `deflate` with `Accept-Encoding`, measures wire bytes, reports savings |
| `mobile_content_parity` | refetches with iPhone Safari UA; flags blocks, m./mobile redirects, HTML-size divergence |

### Runtime — headless browser (7, opt-in via `--browser`)

One navigation in Chromium (Playwright) reused by all seven checks:

| Check | Rule |
|---|---|
| `browser_js_errors` | no uncaught JS exceptions (`pageerror` events) |
| `browser_console_errors` | FAIL on any `console.error`; WARN if >5 warnings |
| `browser_failed_requests` | FAIL on any `requestfailed` event (network errors, CORS blocks) |
| `browser_load_time` | WARN `load` event >3 s, FAIL >5 s |
| `browser_fcp` | First Contentful Paint: good <1800 ms, poor >3000 ms |
| `browser_lcp` | Largest Contentful Paint (Core Web Vital): good <2500 ms, poor >4000 ms |
| `browser_cls` | Cumulative Layout Shift (Core Web Vital): good <0.1, poor >0.25 |

### Accessibility (4)

- `heading_hierarchy` — exactly one `<h1>`, no skipped levels
- `form_inputs_labeled` — every input has `<label for>`, wrapping `<label>`, `aria-label`, or `aria-labelledby`
- `landmark_regions` — exactly one `<main>`, `<nav>` present
- `button_accessible_name` — every `<button>` / `<a href>` has visible text, `aria-label`, or nested `<img alt>`

### Privacy (1)

- `cookie_flags` — every `Set-Cookie` on HTTPS has `Secure` + `HttpOnly` + `SameSite`

### Email / DNS (5)

- `mx_records` — domain has MX records
- `spf_record` — single `v=spf1` TXT with `-all`/`~all` (FAIL on `+all` or duplicates)
- `dmarc_record` — `v=DMARC1` at `_dmarc.<domain>`; PASS on `p=reject`/`p=quarantine`, WARN on `p=none`
- `dkim_record` — probes 24 common selectors in parallel (`default`, `google`, `selector1/2`, `mandrill`, `sendgrid`, `mailgun`, `k1/k2`, `zoho`, `protonmail`, …)
- `mta_sts` — optional `v=STSv1` at `_mta-sts.<domain>`

## Limitations

Even with `--browser`, this tool still can't measure:

- **Core Web Vitals from field data** (the `--browser` LCP/CLS are synthetic — from this one load, not real users). For field data, use CrUX or PageSpeed Insights API.
- **Multi-page signals**: duplicate content across pages, orphan pages, internal PageRank
- **Colour contrast, tap-target size** (needs rendering geometry + DOM traversal)
- **INP** — needs user interaction; only available from field data

For those, reach for Lighthouse or a real crawler. This tool gives you the other ~80% in one command.

## Exit codes

| Mode | Exit |
|---|---|
| default | `0` always (unless network fatal, which is `2`) |
| `--fail-on warn` | `1` if any check is 🟡 or 🔴 |
| `--fail-on fail` | `1` if any check is 🔴 |
| network fetch failed | `2` |

Suitable for CI — run against staging before a deploy and fail the pipeline on regressions.
