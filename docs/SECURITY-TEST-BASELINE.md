# Security & Privacy Test Baseline — 2026-09-23

This document records the supplied pre-v0.9 test results as an engineering baseline. Raw BrowserLeaks screenshots are intentionally **not** committed because one of them contains the user's real public IP/ISP information.

## AdBlockBench

- Overall: **39**
- Network: **79**
- Cosmetic: **10**
- Scriptlet: **0**
- API: **0**
- Tracking category: **71**
- Fingerprinting category: **21**
- Privacy API category: **0**
- Advanced category: **38**

Observed gaps included Google IMA requests, first-party Matomo-style analytics, some beacon/ping transports, visible cosmetic ad containers, and exposed fingerprint/privacy APIs.

## Ad-network test

- Overall: **66**
- Weighted: **68**
- Networks blocked: **52 / 79**
- Audio ads: 86%
- Video ads: 67%
- Display ads: 64%
- Programmatic: 50%
- Mobile ads: 30%
- Analytics: 91%
- Social tracking: 60%
- Cross-site tracking: 82%

v0.9 adds broader high-confidence network rules, first-party analytics heuristics, generic cosmetic filtering, and tracking-beacon suppression.

## BrowserLeaks observations

- **WebRTC:** test reported no local-IP leak; public candidate matched the route's visible public IP.
- **Canvas:** the tested signature was unique in the BrowserLeaks database. Aegis should interpret this as a correlation risk, not claim that randomization alone makes the user anonymous.
- **WebGL:** renderer APIs/hashes remained observable; v0.9 strengthens debug-info normalization/readback perturbation and Maximum mode can disable WebGL contexts.
- **JavaScript:** hardware, audio, local-font, screen, and multiple privacy-related APIs were observable. v0.9 expands the Privacy API Guard and adds explicit behavioral verification.
- **TLS:** TLS 1.3 and 1.2 were enabled, TLS 1.1/1.0 disabled, active mixed content blocked and passive content upgraded. JA3/JA4-style transport fingerprints remain a known Chromium-level visibility surface.
- **Public IP:** the test showed the system route's public IP. This is expected when no trusted VPN/proxy/Tor route is configured. v0.9 reports this as routing evidence and warning rather than a false anonymity pass.

## Performance baseline

The supplied Speedometer 3 export reported:

- Score mean: **38.2157**
- Geomean: **26.2709 ms**

Performance comparisons must be run on the same hardware/OS/runtime build to be meaningful.

## v0.9 verification targets

- No `Aegis` product token in page-visible User-Agent.
- `navigator.globalPrivacyControl === true` when GPC is enabled.
- Local Font Access and high-entropy device APIs suppressed when Privacy API Guard is enabled.
- Protected Audience / Private State Token / Storage Access entry points suppressed by the guard.
- WebRTC behavioral test exposes no numeric local host ICE candidate.
- Cosmetic filter active in remote pages with Shields enabled.
- Public-IP test clearly labels system/direct routing as exposed rather than anonymous.
