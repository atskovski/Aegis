<p align="center"><img src="assets/brand/aegis-lockup.svg" alt="Aegis Privacy Browser" width="430"></p>

# Aegis Privacy Browser v1.0 — Runtime Guardian

Aegis 1.0 is a local-first privacy and security browser for macOS built on Electron/Chromium. The 1.0 architecture treats security controls as enforceable contracts: browser policy, backend enforcement, behavioral runtime probes and user-visible evidence must agree before a protection is presented as working.

Aegis does **not** claim anonymity or “zero fingerprint.” A direct/system route can expose a public IP, Chromium transport characteristics remain observable, and sophisticated fingerprinting can still distinguish a browser. Aegis instead reduces tracking and attack surface, isolates high-risk browsing contexts, verifies important protections at runtime, and reports residual exposure explicitly.

## Aegis 1.0 security architecture

- Per-tab **ephemeral session isolation** with a behavioral cookie-separation proof.
- Native main-process **ad/tracker filtering** plus conservative **cosmetic filtering**.
- Coverage for video/mobile/programmatic ad SDKs, social pixels, analytics and verification providers.
- **Tracking transport guard** for known `sendBeacon` and anchor-ping tracker destinations.
- **Privacy API guard** for local fonts, device APIs, Protected Audience and selected private-token/storage surfaces.
- Strict/Maximum **fingerprint resistance** for UA/Client Hints, timezone, language, screen metrics, hardware values, Canvas, WebGL, media devices, audio/font surfaces and timer precision.
- Startup WebRTC policy plus a live **ICE-candidate local-IP test**.
- Explicit public-IP route verification labeled as information—not as proof of anonymity.
- Permission firewall with **Allow once**, **Allow 10 minutes**, persistent allow/block, and risk explanations.
- Native right-click security actions and per-site hardening.
- Aegis Sentinel site privacy inspector with local third-party, sensitive API, identity-surface and activity evidence.
- Larger default typography with **Standard / Large / Extra Large** text scales.
- New production SVG brand system, PRD, threat model, security model and benchmark baseline.

## Why v0.9 exists

The supplied v0.8 benchmark evidence showed that raw network interception was substantially stronger than cosmetic filtering and privacy-API/fingerprint protection. Guardian specifically targets those gaps. See [`docs/BENCHMARK_BASELINE.md`](docs/BENCHMARK_BASELINE.md) and [`docs/PRD.md`](docs/PRD.md).

## Start on macOS

1. Extract the release into a fresh folder.
2. Double-click **`Smoke-Test-Aegis.command`** first. It launches the real browser, creates an isolated tab, attempts an external HTTPS navigation, and exits after the smoke result.
3. Double-click **`Run-Aegis.command`** for normal use.
4. Use **Settings → Diagnostics → Run Security Suite** to verify the active runtime.
5. Use **`Diagnose-Aegis.command`** for engine integrity, routing/startup markers, quarantine/code-sign diagnostics, and the local launch log.

Normal launch does not require npm or Node. The launcher copies Aegis to `~/Library/Application Support/Aegis Privacy Browser/runtime-v1.0.0`, installs the pinned Electron 44.4.3 runtime for Apple Silicon or Intel, validates the expected release archive, runs local preflight checks, and starts the browser from Application Support.

## Security Suite evidence model

Aegis does not turn every enabled preference into a green check. Results are separated into:

- **PASS** — the configured control or behavioral test succeeded.
- **WARNING** — usable, but the current posture has a meaningful caveat.
- **INFO** — evidence or a known limitation that is not pass/fail.
- **FAIL** — the expected control or behavioral result failed.
- **NOT TESTED** — the test could not be run in the current state.

Current verification covers renderer isolation, permission handlers, fingerprint preload readiness, cosmetic filtering, HTTPS-first behavior, privacy-API exposure, GPC, screen normalization, WebGL debug renderer exposure, browser product-token leakage, WebRTC host candidates, startup WebRTC policy, site isolation, third-party cookie defense, network tracker filtering, beacon filtering, TLS fingerprint visibility, disposable session isolation, route posture, DNS/HTTPS reachability, and observed public IP.

## Privacy architecture

Every ordinary tab receives a unique non-persistent Chromium partition. Disk cache is disabled for private browsing sessions, closing a tab clears its session data/cache/connections, and **New Identity** destroys all active tab sessions, rotates ephemeral identity state, clears memory-only tracker learning, and opens a fresh tab.

Aegis intentionally persists only settings, explicit bookmarks, download metadata and local launcher/runtime diagnostics. It does not implement an Aegis browsing-history database, cloud sync, account system, or browser telemetry service.

## Filtering stack

Aegis implements its protections directly rather than depending on privileged browser extensions:

- High-confidence local domain/category blocking for ads, analytics, social, marketing, attribution, telemetry, fingerprinting scripts and cryptomining.
- Cross-site context checks and memory-only behavioral tracker learning.
- Local custom hostname allow/block rules.
- Tracking-parameter stripping and redirect-wrapper cleanup.
- Third-party cookie/header restrictions and referrer reduction.
- Conservative user-origin cosmetic CSS filtering.
- Known tracker `sendBeacon` and anchor-ping suppression.
- ETag reduction and public-CDN isolation controls.
- Optional SponsorBlock integration for YouTube sponsor segments.

Aegis is **not yet a full uBlock Origin-compatible filter language/scriptlet engine**. That remains a roadmap item.

## Fingerprint resistance

**Standard** minimizes compatibility-sensitive spoofing. **Strict** is the recommended default. **Maximum** applies more aggressive controls and can break sites.

Strict/Maximum standardize or reduce selected UA/Client Hints, locale/timezone, screen dimensions, hardware concurrency/device memory, Canvas outputs, WebGL debug identity, device identifiers, local fonts, audio surfaces, speech voices and timing precision. Maximum can disable additional rendering/execution surfaces.

A one-time fingerprinting test may still call an Aegis instance “unique.” The design target is to reduce entropy and linkability, not promise mathematical invisibility.

## Network and IP privacy

Aegis supports System, Direct, SOCKS5, HTTP and HTTPS proxy modes. Fixed proxy modes can fail closed. The Security Suite performs route/connectivity checks in a disposable session.

A successful public-IP lookup is intentionally reported as **INFO**. It tells you which address destination sites can observe through the configured route. If IP masking is required, use a trusted VPN, Tor, or proxy configuration appropriate to your threat model.

## Permissions

Camera, microphone, location, notifications, clipboard read, screen capture, MIDI, USB, Serial and HID are mediated through explicit Electron permission handlers. The prompt explains what the site is asking for and offers:

- Allow once
- Allow for 10 minutes (tab-scoped, memory-only)
- Always allow for this origin
- Block once
- Always block for this origin

## Aegis Sentinel

The toolbar Sentinel beacon opens a local Site Privacy Inspector showing:

- What sensitive capabilities the page is using or requesting.
- Third-party hostnames contacted or blocked.
- Identity/fingerprint surfaces observed.
- Current protection layers and posture.
- Recent privacy/network activity.
- Per-site permission controls.
- One-click **Harden This Site**.

Sentinel activity is per-tab and ephemeral. It is intended as an explanatory instrument, not a guarantee that a site is safe.

## UI and brand

Guardian defaults to larger text and supports Standard/Large/Extra Large scaling. The Aegis shield mark represents protection; the central mint node represents **verification**—the idea that protection should be inspectable.

Brand assets and usage guidance live in [`assets/brand/`](assets/brand/) and [`docs/BRAND.md`](docs/BRAND.md).

## Keyboard shortcuts

- `Cmd/Ctrl + L` — address bar
- `Cmd/Ctrl + T` — new isolated tab
- `Cmd/Ctrl + W` — close tab
- `Cmd/Ctrl + D` — bookmark current page
- `Cmd/Ctrl + K` — command palette
- `Cmd/Ctrl + ,` — settings
- `Cmd/Ctrl + Shift + N` — New Identity

## Verification for contributors

```sh
npm install
npm run verify
```

The repository includes core logic tests, UI/IPC contract tests, startup harness tests, privacy/security-suite tests, and Guardian-specific regression tests. The final native macOS GUI/network smoke test must still run on macOS because CI or Linux test environments cannot prove the exact macOS Chromium rendering/network path.

## Documentation

- [`docs/PRD.md`](docs/PRD.md) — complete product requirements and acceptance criteria.
- [`docs/BRAND.md`](docs/BRAND.md) — logo, color, typography, iconography and voice.
- [`docs/BENCHMARK_BASELINE.md`](docs/BENCHMARK_BASELINE.md) — sanitized v0.8 baseline and v0.9 targets.
- [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md) — automated, native macOS, external-regression, and distribution release gates.
- [`SECURITY.md`](SECURITY.md) — security model.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversaries, protected assets and limits.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component/system architecture.
- [`FEATURES.md`](FEATURES.md) — implementation matrix.

## Release status

v0.9.0 is a **hardened local macOS development/release-candidate build**, not yet a fully public Apple distribution. A production v1.0 still requires signed/notarized app packaging, signed updates, reproducible release provenance, broad native macOS compatibility testing, an accessibility audit, and independent security review.
