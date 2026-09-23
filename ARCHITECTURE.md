# Aegis v0.9 Guardian Architecture

## Trust boundaries

**Main process (`src/main.js`)** owns the browser lifecycle, BrowserWindow/WebContentsView creation, private Chromium sessions, navigation policy, settings/bookmarks/downloads, permission prompts, network diagnostics, SponsorBlock orchestration, cleanup and New Identity.

**Trusted UI renderer (`src/ui/`)** is delivered only through `aegis://app/`. It has no Node integration, cannot directly access local files or Electron APIs, cannot navigate the trusted shell onto the public web, and reaches privileged operations only through the narrow preload bridge.

**Remote web renderers** are separate `WebContentsView` instances. Every normal tab receives its own non-persistent Chromium partition. The renderer is sandboxed, context isolated, has Node disabled, and receives no trusted preload bridge.

## Core modules

- `core/settings.js` — schema v7, hardened defaults, profile application, migration and validation.
- `core/network.js` — System/Direct/fixed routing, fresh-session reliability, fail-closed fixed proxies and disposable-session diagnostics.
- `core/privacy.js` — request filtering, cookie/referrer/ETag/CDN defenses, permissions, downloads and privacy statistics.
- `core/fingerprint.js` — tiered environment normalization and deterministic perturbation.
- `core/url.js` — input/search normalization, HTTPS-first rules, tracking cleanup, redirect unwrapping and party classification.
- `core/navigation.js` — current Electron navigation-details adapter and safe internal-navigation rules.
- `core/blocklist.js` — compact high-confidence tracker/ad/social/cryptominer/fingerprinting/CDN knowledge.
- `core/filter-rules.js` — bounded local hostname block/allow rules plus a safe cosmetic-rule subset.
- `core/content-filter.js` — cosmetic CSS, known ad/SDK classification, first-party analytics patterns, privacy-API and tracking-transport guards.
- `core/security-suite.js` — behavioral verification for session isolation, WebRTC host candidates, renderer privacy surfaces, routing posture and public-IP evidence.
- `core/tracker-learning.js` — memory-only cross-site behavioral tracker learner.
- `core/safety.js` — local destination-risk heuristics.
- `core/sponsor.js` — privacy-preserving SponsorBlock lookup and page-side skipping logic.

## First-tab lifecycle

1. Create a non-persistent Chromium partition.
2. Register `aegis://` on that session.
3. Create a hardened WebContentsView.
4. Attach permission, request-filter, download and navigation handlers.
5. Attach the view to the already-visible browser shell and activate it.
6. Start the fingerprint/privacy new-document preload and wait up to a bounded 5 seconds before the first remote navigation; failures remain fail-soft and visible in diagnostics.
7. If the route is **System**, inherit Chromium/macOS platform networking and begin navigation without a `setProxy()` race.
8. If the route is Direct/SOCKS/HTTP/HTTPS, apply the requested route first; fixed routes may fail closed.
9. Navigate to DuckDuckGo or the configured home page.
10. If navigation fails, show a local recovery page while keeping the browser shell operational.

Normal application startup never waits for the public page to finish loading. The external smoke test is intentionally stricter and does wait for DuckDuckGo to complete.

## Diagnostics

Diagnostics do not depend on the active tab. A new disposable Chromium session is created with the same route settings, then proxy resolution, DNS resolution and HTTPS fetch are run concurrently with bounded timeouts. The diagnostic session is cleared and its connections are closed afterward.

This separates **network failure** from **tab/privacy-policy failure** and avoids interrupting an active page with a proxy reset.

## Request-policy pipeline

For each private tab:

1. Record the current top-level site.
2. Apply local block/allow rules.
3. Classify high-confidence known trackers by category.
4. Consult memory-only cross-site learner when enabled.
5. Apply third-party and Compatibility Mode policy.
6. Cancel blocked requests before they reach the renderer.
7. Block high-confidence first-party analytics paths when heuristic protection is enabled.
8. Reduce request headers: GPC/DNT, Client Hints, referrers, validators, cookies, public-CDN state.
9. Reduce response persistence: reporting headers, tracker validators and third-party Set-Cookie.
10. Apply browser-owned user-origin cosmetic CSS after document load, plus new-document privacy API/beacon guards before page script execution.

## Identity lifecycle

**Close tab** clears the tab session's data/cache/connections and destroys its view.

**Cookie AutoDelete** can additionally clear the origin left behind within an open tab after a configurable delay unless the origin is fireproofed.

**New Identity** closes all public renderers, clears every private session, resets the behavioral learner, rotates fingerprint/identity seeds and creates a fresh tab.

## Persistence

Aegis intentionally persists only:

- sanitized local settings;
- explicit bookmarks;
- in-session download metadata / downloaded files;
- launcher/runtime/diagnostic artifacts.

Aegis does not create a browsing-history database, cloud profile or sync account.


## Sentinel privacy intelligence plane

Sentinel is intentionally split across trust boundaries:

1. The main process request interceptor records hostname-only third-party network metadata and block/allow outcomes. Full third-party request URLs are never exposed to the browser chrome.
2. A bounded DevTools Runtime binding accepts a small allowlisted set of page-observation events from an injected audit script.
3. The audit script wraps selected browser APIs and detects sensitive form *types* without reading field values.
4. The main process normalizes and bounds every event before publishing it to the Aegis-owned chrome.
5. The renderer computes presentation-only posture/exposure summaries. No Sentinel data is uploaded or persisted as browsing history.

The audit plane is explanatory rather than authoritative security telemetry. A malicious page may avoid or alter observable JavaScript API usage, and browser-engine behavior can change. Protection enforcement remains in the main-process session/request/permission layers rather than relying on the audit script.
