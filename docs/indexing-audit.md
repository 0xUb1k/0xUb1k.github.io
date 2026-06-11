**Executive Summary**

This document summarizes a technical SEO and indexing audit for the Astro-based site at https://blog.davidherm.es. It is intended to be consumed by downstream research tools or engineers and contains: evidence, a prioritized remediation plan, reproducible commands, and a list of files and artifacts to ingest.

**Scope**: infrastructure availability, canonicalization, sitemap and robots, social card (Satori) generation, trailing slash normalization, template (MultiTerm) configuration, and content/frontmatter quality.

**Evidence & Quick Findings**

- Live checks (performed 2026-06-11): `/robots.txt` returns HTTP 200 and contains `Sitemap: https://blog.davidherm.es/sitemap-index.xml`.
- Homepage returns HTTP 200 and includes canonical and JSON-LD meta output.
- Local `npm run build` completed; `dist/` produced `robots.txt`, `sitemap-index.xml`, `sitemap-0.xml`, `posts/*.html`, and `social-cards/` assets.
- Notable issue: generated canonicals and social-card paths include `.html` suffix (e.g. canonical -> `https://blog.davidherm.es/posts/hof.html`) which may mismatch hosting pretty-URL behavior.

**Files of interest (ingest these)**

- [astro.config.mjs](astro.config.mjs)
- [src/site.config.ts](src/site.config.ts)
- [src/layouts/Layout.astro](src/layouts/Layout.astro)
- [src/pages/robots.txt.ts](src/pages/robots.txt.ts)
- [src/pages/social-cards/[slug].png.ts](src/pages/social-cards/[slug].png.ts)
- [package.json](package.json)
- [src/content/posts/hof/index.md](src/content/posts/hof/index.md) (representative post)
- `dist/` artifacts: `dist/robots.txt`, `dist/sitemap-index.xml`, `dist/sitemap-0.xml`, `dist/posts/hof.html`, `dist/social-cards/*`

**Architecture notes for a research tool**

- Framework: Astro (SSG) using MultiTerm theme (site config centralized in `src/site.config.ts`).
- Canonical generation: `Layout.astro` computes `pageUrl` via `new URL(Astro.url.pathname, Astro.site)` then strips trailing slash with `.replace(/\/$/, '')`.
- Site base URL is provided from `siteConfig.site` (correctly set to `https://blog.davidherm.es`). Astro uses `site: siteConfig.site` in `astro.config.mjs` so build-time FQDN injection is already wired.
- Sitemap: `@astrojs/sitemap` integration is enabled in `astro.config.mjs` and produces `sitemap-index.xml` that references `sitemap-0.xml`.
- robots.txt: dynamic endpoint at `src/pages/robots.txt.ts` builds the sitemap URL from `Astro.site` (works when server supports function routes). A `dist/robots.txt` is produced by the static build.
- Social cards: `src/pages/social-cards/[slug].png.ts` uses Satori + Resvg and a local JetBrains font from `node_modules` — failures here can make head generation fail or slow builds.
- Comments/engagement: site uses Giscus client-side comments; these are not visible to the initial static HTML parsed by crawlers and therefore do not contribute to immediate engagement signals.

**Primary risk vectors and why indexing can fail**

1. Infrastructure downtime (DNS, SSL, hosting): if the domain was unreachable for prolonged periods, crawlers will drop URLs. This is the single highest-impact failure.
2. robots.txt/sitemap unreachable: search engines halt or deprioritize crawling when these are missing or return server errors. Confirmed reachable now, but ensure host mapping never breaks these endpoints.
3. Canonical mismatch (.html vs pretty URLs): generated `<link rel="canonical">` values include `.html` suffix; if hosting serves pretty URLs (`/posts/hof`) or redirects inconsistently, this produces conflicting canonical signals and redirect loops.
4. Trailing slash normalization: `siteConfig.trailingSlashes = false` (no trailing slash) — the host must not enforce the opposite normalization.
5. Satori/build-time failures: social card generation depends on local font and Resvg; in some platforms this causes timeouts or build errors which can produce bad head HTML.
6. Content quality signals: niche CTF writeups produce low traffic; without strong schema, evergreen signals, and author verification JSON-LD, modern algorithmic filters may deprioritize very low-engagement pages.

**Immediate remediation (prioritized)**

1. Infrastructure: verify DNS, TLS/SSL, and hosting account are active and healthy. Confirm uptime and no edge-network misconfiguration. (Critical)
2. Canonical sanitization (code change): change `Layout.astro` canonical generation to strip `.html` suffixes so canonical URLs use pretty paths (example logic provided below). (High)
3. Social-card paths: ensure `social-cards` route and generated filenames do not include `.html` in slug names (strip when building image filename). (High)
4. Hosting rewrites/redirects: ensure the host rewrites `/posts/hof` -> `/posts/hof.html` or serves the `dist/` file for pretty paths, and that it enforces the same trailing-slash policy as `site.config.ts`. (High)
5. Add static `public/robots.txt` fallback if the platform requires static mapping. Currently dynamic `robots.txt` works and `dist/robots.txt` is produced. (Medium)
6. Schema & frontmatter: ensure every post includes `title`, `description`, `published` (ISO), and author fields; generate `Article`/`TechArticle` JSON-LD in `Layout.astro` (already present) and ensure accurate `datePublished`. (Medium)

**Suggested code snippets**

- Canonical normalization (update in `src/layouts/Layout.astro`):

```js
// After computing pageUrl, normalize to remove `.html` suffix
const canonicalUrl = pageUrl.replace(/\.html$/, '')
// then use canonicalUrl in link rel="canonical"
```

- Social-card filename normalization (in `src/pages/social-cards/[slug].png.ts`): remove `.html` from slug when constructing paths.

**Reproduction / validation commands**

Run locally:

```bash
npm ci
npm run build
ls -la dist
curl -I -A "Googlebot" https://blog.davidherm.es/robots.txt
curl -I -A "Googlebot" https://blog.davidherm.es/
sed -n '1,80p' dist/posts/hof.html
```

Google Search Console steps (after fixes):

1. Verify site ownership in Search Console.
2. Submit `https://blog.davidherm.es/sitemap-index.xml` in Sitemaps.
3. Use URL Inspection on homepage and representative post; request indexing and monitor coverage reports.

**Artifacts to attach to a deep research tool**

- `astro.config.mjs`, `src/site.config.ts`, `src/layouts/Layout.astro`, `src/pages/robots.txt.ts`, `src/pages/social-cards/[slug].png.ts`, `package.json`, `dist/sitemap-index.xml`, `dist/sitemap-0.xml`, `dist/robots.txt`, `dist/posts/hof.html`, and the build log (`npm run build` output).

**Next steps I can execute for you**

- Apply the canonical and social-card filename fixes and run a clean build to demonstrate outputs. (I can patch files and run `npm run build`.)
- Produce a small PR with the changes and tests verifying `dist/posts/hof.html` canonical and `dist/social-cards/hof.png` naming.

**Contact-style summary**

Short version for a non-technical recipient: the site is currently reachable and the codebase is mostly correct, but the generated canonical links include `.html` which can confuse search engines if the hosting URL normalization differs; also social-card generation and hosting rewrites are common failure points — fix canonicals, confirm host rewrites, then resubmit the sitemap.

---

Generated by: audit run 2026-06-11
