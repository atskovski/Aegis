# Aegis v0.8 → v0.9 Benchmark Baseline

Baseline captured from the user-supplied 2026-09-23 test exports and BrowserLeaks screenshots. This document intentionally excludes the raw public IP, ISP, street/registry details, and geolocation visible in the screenshots because the repository is public.

## AdblockBench baseline
- Control healthy: yes
- Overall score: 39
- Network: 79
- Cosmetic: 10
- Scriptlet: 0
- API: 0
- Tracking category: 71
- Fingerprinting category: 21
- Privacy API category: 0
- Advanced category: 38

Observed gaps included visible generic ad containers, exposed canvas/WebGL/audio/font/screen APIs, Protected Audience/Private State Token surfaces, Storage Access API exposure, and background beacon transports.

## Network-focused blocker baseline
- Overall: 66
- Weighted: 68
- Networks: 52 blocked / 79 tested
- Audio: 86%
- Video: 67%
- Display: 64%
- Programmatic: 50%
- Mobile: 30%
- Analytics: 91%
- Social: 60%
- Cross-site tracking: 82%

## BrowserLeaks observations
- Canvas: test reported a signature unique to its database sample.
- WebGL: renderer/vendor were partially standardized but stable hashes remained observable.
- WebRTC: no local IP leak was reported in the supplied test; the public route IP remained visible.
- TLS: TLS 1.2/1.3 were available and 1.0/1.1 disabled, but Chromium TLS fingerprints remained observable.
- JavaScript: multiple high-entropy browser/device APIs remained visible.

## Speedometer 3
- Mean supplied score: ~38.2
- Geomean test time: ~26.27 ms

Performance is a guardrail, not a security score. Future releases should compare privacy gains against regressions in page responsiveness and compatibility.

## v0.9 goals
1. Raise cosmetic filtering coverage without broad false positives.
2. Block known video/mobile/programmatic escape domains seen in the supplied tests.
3. Suppress beacon/ping tracker transports.
4. Reduce high-entropy browser/device/ad-tech API exposure.
5. Add behavioral WebRTC verification rather than relying only on launch policy.
6. Increase UI legibility and separate PASS/WARNING/INFO/FAIL/NOT TESTED.
7. Preserve performance by keeping filtering local and avoiding heavyweight always-on DOM scanning.
