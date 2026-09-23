# Aegis Privacy Browser

![Aegis wordmark](assets/brand/aegis-wordmark.svg)

**Aegis** is a local-first privacy and security browser focused on **visible, verifiable protection**. It combines isolated in-memory browsing sessions, native tracker/ad blocking, anti-fingerprinting controls, HTTPS-first navigation, explicit permission handling, safer downloads, proxy-aware diagnostics, and a browser-owned security intelligence layer called **Sentinel**.

## v0.9 direction

The v0.9 hardening work is driven by real BrowserLeaks and ad-block benchmark results rather than toggle counts. The supplied runs showed strong network blocking and WebRTC/TLS posture, but exposed gaps in cosmetic filtering and high-entropy browser API surfaces. The current branch adds:

- Safe generic cosmetic ad filtering, with more aggressive selectors only in Maximum mode.
- Stronger Maximum-mode privacy API reduction.
- Additional WebGL/canvas entropy reduction.
- Larger, more legible security/settings typography.
- A formal product requirements document and threat-aware product positioning.
- A complete Aegis/Sentinel visual system with original shield/A assets.
- A public security-validation summary that deliberately excludes screenshots exposing public IP/ISP/location data.

## Product model

Aegis separates four concepts that browsers often collapse into one switch:

1. **Configured** — a defense is enabled.
2. **Enforced** — the browser has installed the policy.
3. **Observed** — Sentinel saw the page attempt something.
4. **Verified** — a behavioral or external test produced evidence.

The Security Suite reports **PASS**, **FAIL**, or **NOT TESTED** and includes evidence instead of claiming that an enabled setting proves protection.

## Core architecture

- Sandboxed Electron/Chromium web renderers.
- Context isolation and Node integration disabled in remote content.
- Per-tab non-persistent Chromium partitions.
- Chromium site isolation.
- WebGPU disabled.
- Non-proxied WebRTC UDP disabled.
- TLS 1.2 minimum and HTTPS-first navigation.
- Third-party cookie restrictions and tracking-validator defenses.
- Native network blocking for trackers, ads, analytics, social trackers, crypto-miners, and fingerprinting endpoints.
- Local URL cleaning and cross-site referrer reduction.
- Permission firewall with tab-scoped, memory-only temporary grants.
- Sentinel site intelligence that records categories/hostnames rather than user-entered values.
- New Identity destroys active private sessions and transient grants.

## Important limits

Aegis is **not** a VPN, Tor client, malware sandbox, or endpoint-security replacement. If Aegis uses a normal system/direct route, websites can still see the public IP of that route. No browser can truthfully promise “zero fingerprint”: aggressively deleting or randomizing every API can itself make a user more unique or break websites.

The project therefore optimizes for lower stable cross-site entropy, isolation, explicit permissions, strong tracker defenses, and evidence users can inspect.

## Documentation

- [Product Requirements Document](PRD.md)
- [Brand System](docs/brand/BRAND-SYSTEM.md)
- [Security Validation](docs/SECURITY-VALIDATION.md)

## Brand

The name **Aegis** comes from the protective shield. The primary mark combines a geometric shield with an A-shaped negative space and a protected core. **Sentinel** is the page-intelligence subsystem; **Security Suite** is the verification subsystem; **New Identity** is the destructive privacy reset.

Primary palette: Aegis Ink `#07131B`, Sentinel Navy `#0D202C`, Aegis Mint `#62E6C3`, Signal Blue `#6F9EFF`, Clear White `#EEF9FB`.

## Development status

v0.9 is a hardened development release, not yet a notarized public macOS distribution. A production 1.0 still requires an Aegis-specific signed app bundle, Apple Developer ID signing/notarization, signed updates, broader native macOS testing, accessibility review, and independent security assessment.
