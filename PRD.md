# Aegis Privacy Browser — Product Requirements Document

**Product:** Aegis Privacy Browser  
**Release baseline:** v0.9  
**Category:** local-first privacy and security browser  
**Positioning:** a browser that makes protection visible, understandable, and verifiable.

## 1. Product summary
Aegis is a Chromium/Electron-based desktop browser shell designed around strong session isolation, privacy-preserving defaults, explicit permissions, tracker/ad defenses, anti-fingerprinting controls, HTTPS-first navigation, safer downloads, proxy-aware networking, and an evidence-driven Security Suite.

Aegis is not a VPN, anonymity network, malware sandbox, or substitute for endpoint security. When configured to use a system/direct connection, sites still see the public IP provided by that route. Aegis must never claim anonymity simply because browser-level protections are enabled.

## 2. Problem
Mainstream browsers expose large privacy/security surfaces while hiding most state behind settings. Users cannot easily answer: What did this page request? What was blocked? What identity information was exposed? Is my network route actually working? Did this protection pass a behavioral test or is it just enabled in settings?

## 3. Product principles
1. **Evidence over toggles.** “Enabled” and “verified” are different states.
2. **Local first.** Site intelligence stays on device unless the user explicitly invokes an external diagnostic.
3. **Least privilege.** Powerful APIs are blocked or prompted by default.
4. **Isolate by construction.** Browsing tabs use separate in-memory Chromium sessions.
5. **Fail visibly.** A broken proxy, failed security check, or compatibility downgrade must be explicit.
6. **Readable security.** Security UI uses plain language, legible type, and explains consequences.
7. **Compatibility is a mode, not a silent fallback.** A user may weaken protection for a site, but Aegis must show that state.

## 4. Target users
Privacy-conscious consumers; security practitioners; remote workers; people using untrusted sites; users who want browser-level visibility without learning dozens of extension interfaces.

## 5. Core experiences
### Browse privately
Each normal tab is backed by a non-persistent Chromium session. Closing/destroying the identity clears tab-local cookies, cache, storage, and connections.

### Understand a page
The Sentinel inspector reports tracker activity, third-party hosts, permission requests, sensitive browser surfaces, storage activity, and protection posture for the current tab.

### Verify protection
The Security Suite separates startup policy evidence, runtime configuration evidence, behavioral proofs, and network diagnostics. Checks report PASS, FAIL, or NOT TESTED with evidence text and timestamps.

### Control permissions
Camera, microphone, location, notifications, clipboard read, display capture, MIDI, USB, serial, and HID are treated as privileged surfaces. Temporary grants are tab-scoped and memory-only.

### Change identity
New Identity destroys active private sessions, rotates anti-fingerprinting identity state, and clears transient permission grants.

## 6. Security/privacy requirements
- Electron sandbox on; Node integration off in remote web content; context isolation on.
- Site-per-process and WebGPU disabled at startup.
- Non-proxied WebRTC UDP disabled.
- TLS 1.2 minimum; HTTPS-first upgrade behavior.
- Third-party tracker, ad, social tracker, crypto-miner, and fingerprinting-script blocking.
- Safe generic cosmetic filtering in Strict; broader cosmetic filtering only in Maximum.
- Third-party cookie stripping and ETag/validator defense for tracking contexts.
- GPC/DNT support.
- Local link-cleaning and tracking-parameter removal.
- Site intelligence without full third-party URL retention in the UI.
- Explicit risky-download handling.
- External protocol and remote DevTools restrictions.

## 7. Fingerprinting strategy
Fingerprinting defenses use a layered model: network-level fingerprinting-script blocking, standardized navigator/screen values, client-hint reduction, timezone/locale normalization, WebGL renderer masking, canvas/audio readout perturbation, device-label suppression, font-enumeration reduction, and optional stronger API-surface reduction in Maximum mode.

Aegis must document the tradeoff: blocking or randomizing every surface can itself create uniqueness or break sites. The goal is reducing stable cross-site entropy while keeping a coherent browser identity, not promising an impossible “zero fingerprint.”

## 8. Ad/tracker strategy
Aegis uses request blocking plus cosmetic filtering. The supplied benchmark showed strong network blocking but weak cosmetic/scriptlet/API results, so v0.9 adds browser-owned cosmetic filtering and treats API-surface exposure separately from ad-network blocking. Script execution primitives such as `eval` are not globally disabled because doing so would break ordinary web applications and could create a more identifiable browser profile.

## 9. UI/UX requirements
- Default body type 15 px; address bar 14 px; settings labels 14 px.
- Explanatory copy generally 11–12 px minimum.
- Security result states must include text, not color alone.
- Panels stay above web content and remain usable at smaller window sizes.
- Advanced controls include risk/compatibility explanations.
- Privacy score is explanatory, not a guarantee.

## 10. Branding
Brand: **Aegis**. Product descriptor: **Privacy Browser**. Security intelligence subsystem: **Sentinel**. Verification subsystem: **Security Suite**. Identity reset action: **New Identity**.

Primary visual language: Aegis Ink + Sentinel Navy with Aegis Mint/Signal Blue accents. The shield/A mark communicates protection and identity without copying mainstream browser branding.

## 11. Success metrics
- No silent permission grants for privileged APIs.
- Private tab storage does not leak to a separately created private tab in the behavioral proof.
- WebRTC leak test does not expose a second local/public address outside the configured route.
- Network tracker blocking remains high while false positives and page breakage are measured.
- Security Suite clearly distinguishes proof from policy.
- Settings and security panels meet the type-size floor and remain keyboard accessible.
- Regression suite passes before releases.

## 12. Non-goals
Aegis does not claim to hide an ISP-visible public IP without a proxy/VPN/Tor route, defeat all browser fingerprinting, detect all malware, replace endpoint protection, or make a compromised operating system safe.

## 13. Roadmap
v0.9: brand system, legibility pass, cosmetic filtering, stronger maximum fingerprint protection, benchmark-informed validation.  
v1.0: signed/notarized macOS build, reproducible release process, automatic filter-list updates with signature verification, certificate detail UI, download reputation integration with privacy-preserving design, accessibility audit, independent security review.  
Post-1.0: optional managed policy, enterprise deployment, privacy-preserving sync design, mobile feasibility research.
