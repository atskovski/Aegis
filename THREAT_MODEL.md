# Aegis Threat Model — v0.9.0

## Goals

Aegis is designed to reduce routine web tracking, persistent state, cross-site correlation, permission abuse, insecure navigation, link decoration, cache identifiers, common fingerprint inputs and accidental exposure through browser APIs while keeping ordinary modern websites usable.

The primary adversary is a website or third-party resource attempting to correlate browsing activity through cookies/storage, network requests, referrers, tracker endpoints, link decoration, Client Hints, canvas/audio/WebGL, screen/device characteristics, ETags, media-device metadata or powerful permissions.

## Defensive assumptions

- Web content is untrusted.
- The trusted Aegis UI and public web renderers must remain separated.
- Privacy controls can fail; failure should be observable and should not leave an invisible or unusable browser.
- Fixed proxy use may be anonymity-sensitive, so optional fail-closed behavior is appropriate.
- System-routing API failure should not brick ordinary browsing because Chromium already has a platform network stack.
- A persistent behavioral tracker profile can itself become sensitive state, so Aegis learning is memory-only and identity-scoped.

## Defenses

- Per-tab non-persistent Chromium sessions and disabled disk cache.
- Storage/cache/connection destruction on tab close and New Identity.
- Known tracker/ad/social/cryptominer/fingerprinting endpoint blocking.
- Local custom hostname block/allow rules.
- Memory-only cross-site tracker learning.
- Third-party cookie suppression outside Compatibility Mode.
- Tracking-parameter cleanup and known redirect-wrapper unwrapping.
- Cross-site referrer reduction.
- ETag/cache-validator reduction in tracking contexts.
- Public-CDN cookie/referrer isolation.
- Cookie AutoDelete with fireproof exceptions.
- Permission Block/Ask defaults and per-site exceptions.
- Renderer sandbox, context isolation, no Node in remote pages and site isolation.
- HTTPS-first navigation with explicit-only HTTP recovery.
- TLS 1.2 minimum.
- macOS System routing plus explicit Direct/SOCKS/HTTP/HTTPS proxy modes.
- Optional fail-closed fixed proxies.
- WebRTC non-proxied UDP blocking.
- Fingerprint normalization and deterministic perturbation by profile.
- WebGPU disabling.
- Local destination-risk heuristics.
- Optional privacy-preserving SponsorBlock lookup.
- Executable/script download blocking.
- Disposable-session connectivity diagnostics.
- No Aegis telemetry, cloud account, cloud sync or browsing-history database.

## Privacy versus compatibility

Privacy features can break legitimate sites. Aegis therefore separates protection into Standard, Strict and Maximum profiles. Strict keeps service workers available and is the default. Maximum enables more compatibility-sensitive controls.

Compatibility Mode is scoped to one tab and does not disable the renderer sandbox, context isolation, TLS policy, permission firewall, session isolation, unsafe-protocol restrictions, WebRTC policy or download controls.

The first tab is attached before slow hardening stages finish. Fingerprint setup is fail-soft. Fresh System sessions do not race a proxy mutation against initial navigation. This is an intentional reliability control: a privacy browser that cannot render websites pushes users toward disabling protections entirely.

## Out of scope / not guaranteed

Aegis does not guarantee anonymity against a destination that sees the connection's public IP, an ISP/employer network, VPN/proxy/Tor operator, global passive observer, compromised operating system, malicious administrator, hardware/firmware compromise, or browser/OS zero-day.

Logging into a personal account intentionally identifies that browsing session to the service.

Aegis does not provide Tor Browser's anonymity set or circuit isolation. A custom browser with a smaller population may be more distinguishable even if individual fingerprint surfaces are reduced.

Local URL heuristics are not a malware/phishing reputation feed and can miss malicious sites or flag unusual benign sites.

Download filtering is extension-based defense in depth, not antivirus or sandbox detonation.

SponsorBlock requires contacting its service when enabled. Decentraleyes-style local replacement libraries are not bundled in v0.5; Aegis only isolates common public-CDN cookies/referrers.
