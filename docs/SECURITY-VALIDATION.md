# Security Validation — 2026-09-23

This document summarizes the user-provided BrowserLeaks and benchmark runs. Raw screenshots containing a public IP/ISP/location are intentionally not committed to the public repository.

## BrowserLeaks observations
- WebRTC: no secondary WebRTC leak was reported in the supplied run; the WebRTC public address matched the remote address and no local address was shown.
- TLS: TLS 1.3 and TLS 1.2 were enabled; TLS 1.1 and TLS 1.0 were disabled; mixed active content was blocked and passive mixed content was upgraded.
- Canvas: the supplied test reported a unique canvas signature. This is a warning that per-session/per-site perturbation alone does not guarantee membership in a large anonymity set.
- WebGL: vendor/renderer exposure was masked to generic WebKit values in the supplied report, but the rendered image/hash still represents a fingerprinting surface.
- JavaScript/browser information: several high-entropy APIs remain exposed for web compatibility; Maximum mode should reduce more of these surfaces.

## Ad blocking benchmark observations
The supplied AdBlockBench run reported overall score 39, network score 79, cosmetic score 10, scriptlet score 0, and API score 0. Tracking scored 71 while fingerprinting scored 21. This indicates Aegis was substantially stronger at network blocking than cosmetic/API-surface mitigation.

The separate adblocker test reported 52 of 79 networks blocked (66% overall / 68% weighted), with 91% analytics and 82% cross-site tracking blocking, but weaker mobile/programmatic/display coverage.

## v0.9 response
- Added safe generic cosmetic filtering in Strict mode.
- Added broader cosmetic selectors only in Maximum mode.
- Added additional Maximum-mode privacy API reduction for local font access and selected device APIs.
- Added WebGL readPixels perturbation and quantized canvas text metrics in Maximum mode.
- Increased UI text sizing across security/settings surfaces.
- Kept `eval` and other fundamental JavaScript primitives available by default to avoid severe compatibility breakage and an unusual browser fingerprint.

## Validation caveat
Third-party benchmark scores are useful signals, not security guarantees. A higher score can sometimes be achieved by breaking APIs globally; Aegis instead treats compatibility impact and fingerprint uniqueness as part of the security decision.
