# Trackability Findings and v1 Response

## Evidence supplied during v1 hardening

The Cover Your Tracks result supplied by the project owner reported:
- tracking ads were not blocked by the test;
- invisible trackers were not blocked by the test;
- the tested browser fingerprint appeared unique;
- the report estimated at least 18.31 bits of identifying information;
- the reported user agent contained an Aegis/Electron product token in the older tested build;
- canvas and AudioContext were reported as randomized by first-party domain;
- WebGL remained a high-value fingerprint surface;
- system fonts, screen metrics, timezone, hardware concurrency and device memory contributed identifying information.

These results are treated as evidence that a configured privacy control is not enough. Aegis must verify the running document and distinguish network tracking protection from fingerprint resistance.

## v1 engineering response

1. **Generic network identity**
   - remote sessions use a generic Chromium-style User-Agent rather than an Aegis product token.
   - browser branding belongs in browser chrome, not the site-visible HTTP identity.

2. **Independent privacy bootstrap**
   - timezone, locale, anti-fingerprint preload, API guard and Sentinel preload install independently.
   - one failed CDP command no longer prevents unrelated protections from installing.
   - component failures are retained as evidence.

3. **Policy replacement**
   - old document-start scripts are explicitly removed before replacement.
   - settings that affect document-start behavior cause remote tabs to reload after the new policy is installed.
   - this prevents a saved setting from silently leaving the old runtime policy active.

4. **Protection Registry**
   - every major privacy switch maps to a named enforcement layer and evidence source.
   - configured-but-not-enforced protections report **degraded**.

5. **Sentinel Simple / Advanced**
   - Simple answers: protection state, blocks, third parties, route, observed public IP and what that IP means.
   - Advanced exposes network hosts, privacy events, fingerprint surfaces, storage, runtime evidence, session type and component status.

6. **Extension security**
   - XPI install is capability-gated.
   - a package requiring APIs unavailable in the Chromium edition is rejected as **Requires Gecko**.
   - compatible static content scripts execute in a dedicated Chromium isolated world rather than the website's main JavaScript world.

## Remaining production gates

Aegis cannot claim production anonymity from these changes alone. Before a 1.0 security claim, the release process must rerun Cover Your Tracks, BrowserLeaks, WebRTC, TLS, canvas/WebGL/audio, storage, cookie, ad-block and performance tests on the signed macOS build. Results need to be recorded by version and compared against the previous baseline.

Full Firefox XPI parity requires a Gecko/Firefox-derived edition. Electron's extension implementation is not a drop-in implementation of Firefox WebExtensions.
