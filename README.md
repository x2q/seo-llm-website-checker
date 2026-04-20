# seo-llm-website-checker

One command, one URL → full-site audit of **~140 checks** across SEO, security, performance, accessibility, privacy, email DNS, LLM-readiness, ad-pixel / tracking / martech detection, and free authority signals. Crawls up to 50 URLs via `sitemap.xml` (or homepage link fallback), runs site-wide checks once, per-URL checks for each page, outputs markdown or JSON.

**No API keys. Ever.** Every data source is publicly accessible without registration — Wayback CDX, Wikipedia API, Common Crawl index, DNS, and direct scraping of public ad-transparency pages.

Built on `requests`, `beautifulsoup4`, `dnspython`, stdlib `ssl`/`socket`, and (optionally) Playwright Chromium for runtime checks like LCP, CLS, JS errors.

## Quick start

```sh
git clone https://github.com/x2q/seo-llm-website-checker
cd seo-llm-website-checker
pip install -r requirements.txt -r requirements-browser.txt
playwright install chromium
python check.py https://example.com
```

Skip the second install line and add `--no-browser` if you don't want the headless-Chromium runtime checks — the other 86 still work.

## What you get

```
# Site audit: https://example.com
Audited **50** URL(s).
Site-wide: ✅ 13 pass · 🟡 4 warn · 🔴 1 fail · ℹ️ 4 info

## Site-wide checks
[markdown tables per category — TLS, DNS, robots.txt, email, sitemap, …]

## Per-URL issues (WARN + FAIL only)
URL                                    Status   Check                  Detail
-----------------------------------------------------------------------------------
https://www.example.com/               🔴 FAIL  images_alt             4/9 missing alt (44%)
https://www.example.com/               🔴 FAIL  compression            HTML 45 KB served uncompressed
https://www.example.com/about          🟡 WARN  meta_description       length 210 (>160)
https://www.example.com/blog/post-1    🔴 FAIL  images_alt             3/8 missing alt (37%)
...

## Per-URL summary
URL                                      ✅   🟡   🔴   ℹ️
----------------------------------------------------------
https://www.example.com/                 45   13    7    6
https://www.example.com/about            47   13    6    5
https://www.example.com/blog/post-1      48   12    5    5
...

**Aggregate:** ✅ 2415 pass · 🟡 210 warn · 🔴 85 fail · ℹ️ 100 info across site-wide + 50 URL(s)
```

Per-URL tables use fixed-width monospace blocks (URL column padded to the longest URL, counts right-aligned) so everything lines up in any renderer.

Live progress bar on stderr while running (auto-hides for pipes/CI):

```
[█████████████░░░░░░░░░░░░░░░] 128/320 40%  ✅ canonical
```

## Flags

| Flag | Effect |
|---|---|
| `--single` | audit only the input URL (no crawl) |
| `--max-urls N` | cap the crawl (default 50) |
| `--no-browser` | skip headless-Chromium checks (saves ~3s per URL) |
| `--ads-deep` | scrape Meta Ad Library + Google Ads Transparency (needs `--browser`) |
| `--no-progress` | silence the stderr bar |
| `--json` | emit `{url, urls_audited, site_wide, per_url}` instead of markdown |
| `--fail-on warn\|fail` | exit 1 on any 🟡 or 🔴 (for CI) |

## Checks

Checks are partitioned into **site-wide** (run once on the homepage — results apply to the whole host) and **per-URL** (run for every crawled page).

### Site-wide (22 + 10 ads + 13 tracking + 17 martech + 5 authority + 2 ad libraries = 69)

**Transport:** `http_to_https_redirect`, `www_apex_canonicalization`, `hsts_header`, `dual_stack_host`, `robots_txt`
**TLS / DNS:** `tls_cert_expiry`, `tls_cert_hostname_match`, `tls_protocol_version`, `tls_chain_completeness`, `hsts_preload_ready`, `caa_record`, `dnssec`
**Sitemap:** `sitemap_xml`, `sitemap_urls_reachable`
**LLM-readiness:** `llms_txt`, `llms_full_txt`, `ai_crawlers_allowed`
**Email DNS:** `mx_records`, `spf_record`, `dmarc_record`, `dkim_record`, `mta_sts`
**Ads pixels** (HTML signature scan, extracts pixel ID when present): `meta_pixel`, `google_ads`, `google_tag_manager`, `linkedin_insight`, `tiktok_pixel`, `pinterest_tag`, `snapchat_pixel`, `reddit_pixel`, `bing_uet`, `x_twitter_pixel`, plus aggregated `ads_pixels_summary`
**Ads libraries** (opt-in via `--ads-deep`, needs `--browser`): `meta_ad_library`, `google_ads_transparency`
**Analytics / tracking:** `google_analytics_4`, `universal_analytics` (WARN — sunset July 2024), `segment`, `mixpanel`, `hotjar`, `microsoft_clarity`, `plausible`, `fathom`, `simple_analytics`, `cloudflare_analytics`, `matomo`, `amplitude`, `fullstory`, plus aggregated `tracking_summary`
**Martech** (CMPs, chat, CRM, CDPs): `cookiebot`, `onetrust`, `usercentrics`, `didomi`, `iubenda`, `intercom`, `drift`, `zendesk_chat`, `crisp`, `tawk`, `hubspot_chat`, `marketo`, `pardot`, `activecampaign`, `klaviyo`, `rudderstack`, `mparticle`, plus aggregated `martech_summary`
**Authority signals** (free, no API keys): `domain_age_wayback`, `wayback_snapshot_count`, `wikipedia_presence`, `commoncrawl_presence`, `dns_popularity_signals`

### Per-URL (71)

#### Shared — per-URL (13)

`https_reachable`, `url_status`, `url_not_redirected`, `redirect_chain`, `content_type_charset`, `x_robots_tag`, `doctype_present`, `meta_charset_early`, `mixed_content`, `security_headers`, `meta_refresh_redirect`, `googlebot_allowed`, `dual_stack_assets`

#### SEO (28)

`title_tag`, `meta_description`, `canonical`, `canonical_not_redirect`, `meta_robots_indexable`, `page_indexable_by_google`, `soft_404`, `h1_single`, `html_lang`, `viewport_meta`, `viewport_accessible`, `favicon`, `apple_touch_icon`, `images_alt`, `open_graph`, `twitter_card`, `json_ld_structured_data`, `hreflang`, `outgoing_links_present`, `internal_links_not_broken`, `internal_links_not_redirecting`, `external_link_rel_safety`, `descriptive_link_text`, `text_to_html_ratio`, `breadcrumb_schema`, `product_schema`, `citable_facts`, `faq_schema_if_faq_visible`

#### Performance (15)

`page_response_time`, `html_size`, `images_dimensions`, `image_sizes`, `image_modern_format`, `responsive_images_srcset`, `css_sizes`, `js_assets_reachable`, `inline_asset_size`, `dom_size`, `render_blocking_assets`, `lcp_image_hints`, `http2_http3`, `compression`, `mobile_content_parity`

#### Runtime — headless browser (7, needs Playwright)

`browser_js_errors`, `browser_console_errors`, `browser_failed_requests`, `browser_load_time`, `browser_fcp`, `browser_lcp`, `browser_cls`

#### Accessibility (4)

`heading_hierarchy`, `form_inputs_labeled`, `landmark_regions`, `button_accessible_name`

#### Privacy (1)

`cookie_flags`

### Ads, tracking, martech — how they work

Each platform is a module-level signature dict with:
- `patterns`: any-of regex list (case-insensitive match against the HTML)
- `id_regex`: case-sensitive extraction of the pixel/tag ID when present

Adding a new platform is a 3-line edit: append a dict to the right `*_SIGNATURES` list in `check.py`.

A check returns `PASS` when the signature matches (with the ID in the message when extractable), `INFO` when not detected. `universal_analytics` uniquely returns `WARN` on match because GA legacy was sunset July 2024.

### Ads libraries — `--ads-deep`

Scrapes two public, auth-free pages:
- **Meta Ad Library** (`facebook.com/ads/library`) — searches for the site's FB page (discovered via `facebook.com/<name>` links on the page) or the domain root label
- **Google Ads Transparency** (`adstransparency.google.com`) — searches by domain root label

Both are **best-effort** — Meta and Google ship heavy JS rendering and change DOM structure regularly. These checks fail gracefully to `INFO` with an explanation when scraping can't extract an active-ad count. Use for a quick signal, not a source of truth.

### Authority signals — no API keys

| Check | Source | Auth? |
|---|---|---|
| `domain_age_wayback` | Wayback CDX API (`web.archive.org/cdx/search/cdx`) | none |
| `wayback_snapshot_count` | same, with `collapse=timestamp:8` for unique days | none |
| `wikipedia_presence` | MediaWiki action API (en + da) | none |
| `commoncrawl_presence` | Common Crawl CDX on the latest crawl (`collinfo.json` + per-crawl `cdx-api`) | none |
| `dns_popularity_signals` | stdlib `socket.gethostbyaddr` for reverse DNS + MX lookup; matches against known hoster domains (Cloudflare, AWS, GCP, Azure, Hetzner, Fastly, Netlify, Vercel, Heroku, GitHub Pages, Akamai, DigitalOcean) | none |

Every authority check has a short timeout (≤15 s) and returns `INFO` on any failure — no site audit is ever blocked by these external services.

### Notable rules

| Check | Rule |
|---|---|
| `favicon` | Google Search spec: `image/*` Content-Type, SVG or square raster multiple of 48×48 |
| `compression` | probes `br`/`zstd`/`gzip`/`deflate` separately, measures wire bytes |
| `tls_cert_expiry` | FAIL <15d, WARN <30d |
| `tls_protocol_version` | FAIL if server still accepts TLS 1.0/1.1 |
| `hsts_preload_ready` | meets [hstspreload.org](https://hstspreload.org) criteria |
| `dmarc_record` | PASS on `p=reject`/`p=quarantine`; WARN on `p=none` |
| `dkim_record` | probes 24 selectors in parallel (`default`, `google`, `k1`, `sendgrid`, …) |
| `googlebot_allowed` | path-aware robots.txt match (longest-wins, `$` anchor, `*` wildcard) |
| `soft_404` | 200 response whose title/H1 says "not found" / "ikke fundet" with thin body |
| `page_indexable_by_google` | composite: status + robots + canonical direction + robots.txt |
| `mobile_content_parity` | refetches with iPhone UA; flags blocks, m.* redirects, HTML divergence |
| `browser_lcp` / `browser_cls` | Core Web Vitals from `PerformanceObserver` (synthetic, one load) |

## How URLs are discovered

1. **`sitemap.xml`** first (via `robots.txt` `Sitemap:` line, else `/sitemap.xml`). Follows `<sitemapindex>` one level.
2. **Fallback:** internal `<a href>` links on the homepage.
3. Capped at `--max-urls` (default 50). Homepage is always first.

## Shared state across URLs

To keep multi-URL runs fast:

- **TLS probe** — one SSL handshake per host (cert, protocol, ALPN, chain reused across all per-URL TLS checks).
- **`robots.txt`** — one fetch per host.
- **Email/CAA/DNSSEC DNS** — cached per host by `dnspython`.
- **Sitemap** — fetched and sampled once as a site-wide check.
- **Browser** — one Chromium instance stays open; each URL is `page.goto()` on a reused context with `PerformanceObserver` pre-installed.

## Limitations

Even with `--browser`:

- **Core Web Vitals from field data** — the `--browser` LCP/CLS are synthetic (this load), not real-user CrUX data.
- **Multi-page signals** — no duplicate-content detection across pages, no internal PageRank / orphan detection. (The crawl audits each URL independently.)
- **Colour contrast, tap-target size** — needs rendering geometry.
- **INP** — needs user interaction.

For those, use Lighthouse or a real crawler.

## Exit codes

| Mode | Exit |
|---|---|
| default | `0` |
| `--fail-on warn` | `1` on any 🟡 or 🔴 |
| `--fail-on fail` | `1` on any 🔴 |
| fatal network error on homepage | `2` |

## License / contributing

MIT. PRs welcome — each check is a self-contained function returning `CheckResult(name, category, status, message)`; add it to `CHECKS` (and, if site-wide, to `SITE_WIDE_CHECKS`).
