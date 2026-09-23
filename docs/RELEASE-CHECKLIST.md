# Aegis Release Checklist

Aegis uses a proof-oriented release gate. A release is not considered production-ready merely because the UI opens.

## Automated gate

- `npm run verify` passes with no failures.
- Generated page-privacy and anti-fingerprint scripts parse successfully.
- Main/preload/UI/core JavaScript syntax checks pass.
- `scripts/self-check.js` confirms required sandbox, permission, network and cleanup hardening tokens.
- macOS `.command` launchers pass `zsh -n` on macOS CI.

## Native macOS gate

- Run `Smoke-Test-Aegis.command` on both Apple Silicon and Intel where available.
- Launch, open/close tabs, Settings, Sentinel, Library, command palette and permission prompt.
- Run the Security Suite and inspect PASS/WARNING/INFO/FAIL/NOT TESTED evidence rather than only the summary count.
- Confirm public-IP proof is never contacted until the user explicitly runs full verification.
- Confirm fixed proxy fail-closed behavior on a deliberately unreachable proxy.
- Confirm New Identity destroys active tabs and temporary permission grants.

## External regression suite

Use the same machine/profile for release-over-release comparisons where possible:

- BrowserLeaks: Canvas, WebGL, WebRTC, JavaScript, TLS, IP.
- AdBlockBench and the ad-network blocking harness.
- Speedometer 3.

Expected v0.9 direction: retain WebRTC local-IP protection and TLS baseline, materially improve cosmetic/API/privacy-surface results versus the captured v0.8 baseline, and avoid a severe repeatable performance regression.

## Distribution gate

Before calling a public binary release production-ready:

- Build a native `.app` artifact.
- Sign with an Aegis-controlled Apple Developer ID.
- Notarize and staple the ticket.
- Publish SHA-256 checksums from the release pipeline.
- Produce dependency/SBOM output and archive build provenance.
- Verify the release on a clean macOS account, not only a developer machine.

The source tree can be release-candidate quality before these publisher-controlled distribution steps are complete; documentation must keep that distinction explicit.
