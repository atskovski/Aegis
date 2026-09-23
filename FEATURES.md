# Aegis v0.9 Guardian Privacy & Safety Feature Matrix

## v0.9 Guardian hardening

| Area | Implementation | Evidence |
|---|---|---|
| Cosmetic filtering | Browser-owned user-origin CSS plus local custom cosmetic rules | Security Suite runtime state + regression tests |
| Beacon/ping defense | Page preload suppresses known tracker `sendBeacon` and anchor `ping` destinations | Runtime policy + source tests |
| Privacy API guard | Reduces local-font, hardware-device, Protected Audience, token and third-party storage access surfaces | Live renderer inspection |
| WebRTC | Non-proxied UDP startup policy + behavioral ICE candidate check | Behavioral Security Suite test |
| IP routing | System/direct/fixed proxy posture with fail-closed fixed route support | Disposable routed session + observed public-IP INFO |
| Fingerprinting | UA/CH, locale/timezone, screen, Canvas, WebGL, media, audio/font and timing defenses | Live surface inspection + BrowserLeaks regression target |
| Readability | Large default type plus three text scales | UI contract/regression tests |
| Product definition | PRD, brand guide, benchmark baseline, SVG mark/wordmark | Versioned repository documents |

| Inspiration / capability | Native Aegis implementation | Scope / limitation |
|---|---|---|
| uBlock Origin | Main-process network blocking for ads, known trackers, social pixels, cryptominers, fingerprint endpoints + bounded hostname block/allow rules | v0.9 includes conservative cosmetic CSS filtering, but not the full uBO procedural-filter/scriptlet ecosystem |
| ClearURLs | High-confidence tracking-parameter removal and known redirect-wrapper unwrapping | Conservative to preserve functional query parameters |
| Privacy Badger | Memory-only cross-site recurrence learner, optionally strengthened by cookie evidence | No persistent learning profile; resets with New Identity |
| Cookie AutoDelete | Per-tab ephemeral sessions + site-leave cleanup with delay and fireproof exceptions | Does not reproduce every extension expression/list feature |
| DuckDuckGo protections | Known-tracker/cookie controls, GPC, DNT, link cleaning, referrer reduction, HTTPS-first and fingerprint defenses | No claim of full proprietary tracker/CNAME-rule parity |
| Decentraleyes | Cookie/referrer isolation for common public CDN requests | No bundled local CDN library replacements yet |
| SponsorBlock | Four-character SHA-256 prefix lookup, local exact video match, selectable segment categories | Optional and network-dependent; disabled by default |
| HTTPS Everywhere | Native HTTPS-first top-level navigation | Explicit one-tab HTTP exception can be chosen by the user |
| Privacy Possum | ETag/cache-validator reduction plus environment normalization and deterministic anti-correlation | Not an exact extension implementation |
| Browser safety | Local checks for credentials-in-URL, raw IPs, punycode, unusual ports and simple brand lookalikes | No cloud malware/phishing reputation feed |
| Proxy leak protection | System/Direct/fixed routing, fail-closed fixed proxies, non-proxied WebRTC UDP disabled | Tor/VPN/proxy service is external to Aegis |
| Disposable diagnostics | Separate private Chromium session tests proxy, DNS and HTTPS concurrently | Confirms route/connectivity, not that every remote website is healthy |
| State minimization | Non-persistent per-tab partitions, disabled disk cache, tab-close cleanup and New Identity | Explicit bookmarks/settings/downloads intentionally persist |


## Sentinel Deep Inspector
- Live toolbar posture score and blocked-action counter.
- Sensitive API ledger covering permissions, storage, fingerprint surfaces, WebRTC, battery/network metadata, gamepads, and identity surfaces.
- Sensitive-form intent detection (email/password/payment/address/phone/file-upload presence only; never field values).
- Hostname-only third-party connection ledger with blocked/contacted status and resource categories.
- Identity Shield explanation for timezone, language, screen, hardware, Canvas/GPU, WebRTC, storage, and Client Hints.
- Local recent-event timeline; nothing in the Sentinel ledger is uploaded by Aegis.


## v0.8 Verification & control layer (carried forward)
- Security Suite foundation with explicit PASS / FAIL / NOT TESTED evidence; v0.9 adds WARNING and INFO so route/public-IP/TLS caveats are not mislabeled as failures.
- Behavioral proof of per-session cookie isolation using two disposable Chromium sessions.
- On-demand routed public-IP proof through the configured Chromium route; never runs automatically.
- DNS + HTTPS connectivity proof in a disposable session.
- Runtime/startup policy evidence for renderer sandboxing, permission firewall, WebRTC leak guard and site-per-process.
- Native right-click menu with Site Privacy Inspector, Harden This Site, clear-tab-data, clean-link copy, isolated-tab opening, and Security Suite access.
- Permission prompts explain the data requested and practical risk, with Allow once, Allow 10 minutes, Always allow, Block once, and Always block.
