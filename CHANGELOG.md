# Aegis Privacy Browser — Changelog

## v1.0.0-beta.1 — Sentinel 2.0 / Extension Runtime

- Added Simple and Advanced Sentinel views with routed IP, third-party/tracker, fingerprint and permission intelligence.
- Added a privacy-control enforcement registry with ENFORCED / DEGRADED / DISABLED evidence.
- Fixed privacy preload initialization so an optional CDP/Sentinel step cannot abort GPC, API guard, screen normalization and fingerprint preloads.
- Privacy-preload-affecting setting changes now rebuild active tab renderers so changes apply immediately rather than only to new tabs.
- Added Firefox-style XPI inspection/install flow with explicit permission review and compatibility reporting.
- Added per-extension isolated worlds and an identity-bound extension bridge with no Node.js exposure.
- Added supported runtime/storage/tabs/permissions/i18n WebExtension compatibility surfaces.
- Unsupported background/privileged extension APIs are explicitly reported instead of silently ignored.
- Added cryptominer control to the UI and fixed independent category blocking semantics.
- Increased Sentinel/add-on/enforcement-detail typography and responsive layout.
- Added extension, isolation-world, privacy-control and Sentinel UI regression tests.

### Release boundary

This remains a beta until native macOS end-to-end verification, BrowserLeaks/EFF reruns, extension package testing, signing/notarization and external security review are complete. Universal Firefox XPI compatibility is not claimed on the Electron engine.

## v0.9.0 — Guardian

- Added first-party cosmetic ad filtering with user-origin CSS and custom cosmetic-rule support.
- Expanded native network coverage for video/mobile/programmatic ads, social pixels, verification vendors, and tracking SDKs.
- Added Privacy API Guard for Local Font Access, device APIs, Protected Audience, selected Private State Token surfaces, and third-party Storage Access requests.
- Added tracking beacon/ping suppression for known tracker destinations.
- Added behavioral WebRTC ICE candidate verification and explicit route/IP posture warnings.
- Security Suite now separates PASS, WARNING, INFO, FAIL, and NOT TESTED.
- Added live GPC verification, screen normalization inspection, WebGL debug-renderer inspection, and page-visible product-token checks.
- Increased default UI text size and added Standard/Large/Extra Large scaling.
- Added production SVG mark/wordmark, brand system, PRD, and sanitized benchmark baseline.
- Updated macOS launch/runtime versioning to 0.9.0.
- Added Guardian regression tests for filtering, privacy APIs, fingerprinting, security-suite semantics, branding, and PRD assets.
- Ensured bounded anti-fingerprint/privacy new-document preloads are installed before the first remote navigation whenever Chromium exposes the required debugger path.
- Added conservative video/native ad cosmetics and fixed generated preload syntax validation discovered during release verification.


## Verification, native context controls, and temporary permissions

- Added a Security Suite that reports PASS, FAIL, or NOT TESTED with evidence and scope for every check.
- Added a real behavioral cookie-isolation proof using two disposable Chromium sessions.
- Added on-demand “What’s my IP” verification through the configured Chromium route plus disposable DNS/HTTPS checks.
- Added runtime evidence for renderer isolation, permission handlers, anti-fingerprinting readiness, HTTPS-first posture, tracker defense, and third-party-cookie defense.
- Added tab-scoped temporary 10-minute permission grants kept only in memory; New Identity, site hardening, site-permission changes, and data clearing revoke them.
- Rebuilt permission prompts to explain exactly what data each requested capability can expose and the practical risk.
- Added a native Electron right-click menu for isolated-link opening, clean-link copying, Site Privacy Inspector, Harden This Site, clear-tab-data, and Security Suite access.
- Kept external verification opt-in: no public-IP service is contacted until the user runs full verification.

# Aegis Privacy Browser v0.7.0

## Native view layering and viewport reliability

- Fixed the Electron `WebContentsView` stacking issue that caused remote websites to cover Settings and browser-owned menus regardless of CSS `z-index`.
- Settings, command palette, and permission prompts now temporarily occlude the active remote renderer so Aegis controls are always visible and interactive.
- Privacy Report and Library panels now reserve real right-side viewport space; the website remains live beside the panel instead of painting over it.
- Closing browser-owned UI restores the active page renderer to its full content viewport.
- Centered and widened the Settings control center for large displays while preserving responsive layouts on smaller windows.
- Added regression coverage for modal occlusion, docked panel viewport reservation, and IPC layering contracts.

# Changelog

## 0.7.0 — 2026-09-22

- Rebuilt the Settings Control Center around a fixed three-region layout: header, independently scrolling content, and non-overlapping action footer.
- Added responsive settings navigation, larger content width, grouped protection cards, consistent spacing, and accessible scrollbars.
- Added Settings search with jump-to-control behavior across all categories.
- Added explicit unsaved-change state plus Cancel/Save actions.
- Fixed the v0.5.x footer overlay that could cover privacy controls and make the settings layout appear clipped.
- Preserved native WebContentsView occlusion so settings remain above website content.

## 0.5.1 — 2026-09-22

- Rebuilt first-tab startup so the private view is attached and usable before slow network/fingerprint stages complete; normal startup no longer treats a remote page-load timeout as browser startup failure.
- Changed the default home page and external smoke-test target to `https://duckduckgo.com/`.
- Eliminated the fresh-System-session proxy race: new sessions inherit Chromium/macOS platform routing without calling `setProxy()` during first navigation. Explicit Direct and fixed proxy routes are applied before navigation.
- Rebuilt Diagnostics around a disposable Chromium session so connectivity tests still work when the active tab is unhealthy and cannot interrupt a page by resetting its connections. Proxy, DNS and HTTPS checks run concurrently with bounded timeouts.
- Added native high-confidence ad/social/cryptominer/fingerprinting blocking, local hostname filter rules and per-category statistics.
- Added memory-only Privacy-Badger-style cross-site tracker learning that resets on New Identity.
- Added ClearURLs-style tracking-parameter cleaning and known redirect-wrapper unwrapping.
- Added Cookie AutoDelete-style origin cleanup with configurable delay and fireproof-site exceptions.
- Added ETag tracking defenses and common public-CDN cookie/referrer isolation.
- Added local safety intelligence for embedded credentials, raw-IP destinations, punycode, unusual ports and simple brand-lookalike hostnames.
- Added optional SponsorBlock integration using a four-character SHA-256 prefix lookup, local exact matching and selectable sponsor categories.
- Added fail-closed fixed-proxy configuration while keeping System routing fail-soft for browser availability.
- Expanded Settings across Privacy, Security, Permissions, Network, Search, Appearance and Diagnostics, including home page, filter rules, fireproof sites, SponsorBlock categories, proxy safety and Nebula/Graphite/Arctic themes.
- Added renderer-health visibility to Diagnostics and more detailed privacy/safety state in the browser UI.
- Expanded source preflight so every core module and UI script is syntax-checked before Electron starts.
- Added network-resilience regression tests for fresh System routing, explicit Direct routing and Chromium-session connectivity checks.
- v0.5 intentionally does not claim full uBlock Origin cosmetic/scriptlet parity, full Decentraleyes local-library replacement, or literal fingerprint invisibility.

## 0.4.0 — 2026-09-22

- Fixed website navigation for Electron 44 by consuming the current navigation-details event object for `will-navigate`, `will-frame-navigate`, and `will-redirect`; retained legacy positional-signature compatibility.
- Changed untouched legacy `direct` routing to macOS `system` proxy/PAC routing, while preserving explicit Direct/HTTP/HTTPS/SOCKS5 choices.
- Removed the asynchronous proxy-configuration race during private-tab creation; routing is now awaited once before initial navigation and stale connections are closed.
- Added a real external-web smoke test: `Smoke-Test-Aegis.command` must load `https://example.com/` through an isolated tab before reporting success.
- Added local-only active-session Diagnostics for proxy resolution, DNS and HTTPS.
- Added a private local error page for failed website loads with secure retry and explicit-only HTTP recovery for selected connection errors.
- Changed Strict mode to keep service workers available for modern website compatibility; Maximum mode retains the aggressive service-worker control.
- Added per-tab Compatibility mode that relaxes third-party cookie stripping and heuristic tracker blocking while retaining explicit tracker blocking and core sandbox/security controls.
- Reworked new-tab search to use a packaged CSP-safe script instead of a form action blocked by the hardened internal Content Security Policy.
- Added local bookmarks with `Cmd/Ctrl+D`, a browser Library, and owner-only bookmark persistence.
- Added a local download center with progress, cancel, reveal-in-Finder and completed-item cleanup.
- Added Aurora Glass as the default modern color system, with Graphite and Arctic Light themes, improved browser chrome, settings layouts, diagnostics and responsive library surfaces.
- Expanded Settings to Privacy, Security, Permissions, Network, Search, Appearance, Diagnostics and About.
- Extended preflight to syntax-check browser chrome, start page, error page and navigation-core scripts before launching Electron.
- Added regression coverage for network navigation, proxy migration, internal start/error flows, diagnostics surfaces and external-web smoke-test requirements.

## 0.3.1 — 2026-09-22

- Fixed the v0.3 smoke-test blocker where `codesign --verify --deep --strict` could reject the pristine official Electron bundle and prevent startup.
- Changed engine trust to a layered model: the exact official Electron release SHA-256 is the primary trust anchor; standard deep code-signature verification is secondary; strict verification is diagnostic.
- If standard macOS signature verification fails, Aegis now restores Electron from the already SHA-256-verified official archive before launch, preventing a modified installed engine from being reused.
- Added a local trust marker plus detailed `codesign.log`, Gatekeeper diagnostics, archive-hash reporting, and trust-mode reporting.
- Fixed the silent startup hang caused by registering `aegis://` only on Electron's default session. Every ephemeral private-tab session now registers the internal protocol before loading its start page.
- Browser chrome is shown and focused before first-tab initialization, so a tab failure can no longer leave Aegis running invisibly.
- Added explicit startup milestones for engine version, protocol registration, browser-window visibility, and private-tab initialization.
- Added a 10-second startup watchdog around browser chrome and first-tab initialization.
- Added `Smoke-Test-Aegis.command`, which opens Aegis, initializes a private tab, and exits automatically when startup succeeds.
- Removed npm/Node from the normal launch path. The launcher downloads the exact official Electron 44.4.3 ZIP for Apple Silicon or Intel directly into Aegis Application Support.
- Added pinned SHA-256 verification for both macOS Electron architectures before extraction.
- Added code-signature verification for the extracted Electron.app without making host-specific strict verification the sole launch gate.
- Added process/startup-marker reporting to `Diagnose-Aegis.command`.
- Moved zoom isolation to Electron 44's supported `webContents.setZoomMode('isolated')` API.
- Added a stricter CSP to Aegis's internal UI protocol responses.
- Hardened internal UI path resolution against traversal outside the packaged UI directory.
- Added single-instance handling and macOS activation/focus recovery.
- Added five startup/API regression tests; total test suite now covers 32 checks.
- Retains the v0.2.1 JavaScript-policy fix: `webPreferences.javascript` is used instead of the nonexistent `setJavaScriptEnabled()` API.

## 0.2.0 — 2026-09-22

- Fixed macOS Downloads sandbox startup failure by bootstrapping Electron into Application Support.
- Updated Electron from 44.4.0 to 44.4.3.
- Rebuilt UI using Midnight Aurora design system plus Graphite and Arctic Light themes.
- Added complete settings center with seven categories.
- Added Standard, Strict, and Maximum privacy profiles.
- Added cache-disabled in-memory sessions per tab.
- Added third-party Cookie/Set-Cookie stripping.
- Added per-site permission exceptions and global permission defaults.
- Added TLS 1.2 minimum configuration.
- Added enhanced canvas, WebGL, audio, media-device, Client Hint, and timezone fingerprint defenses.
- Added service-worker control and Maximum-mode font-enumeration reduction.
- Added direct/HTTP/HTTPS/SOCKS5 proxy controls and Tor preset.
- Added configurable private search engines.
- Added command palette and expanded keyboard shortcuts.
- Added local appearance controls and privacy score.
- Added active-session data clearing and optional clipboard clearing on identity rotation.
- Expanded executable download blocking.
- Added UI contract tests and settings/permission tests.
- Added `Diagnose-Aegis.command` for private, local-only startup diagnostics.
