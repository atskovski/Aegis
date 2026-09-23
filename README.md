<p align="center"><img src="assets/brand/aegis-lockup.svg" alt="Aegis Privacy Browser" width="430"></p>

# Aegis Privacy Browser 1.1.2 — Stable Security Kernel

Aegis 1.1 is a local-first macOS privacy, security and managed-browser platform built on Electron/Chromium. Its design rule is simple: a security setting is not treated as protection merely because a toggle is enabled. Aegis couples policy, browser-process enforcement, behavioral runtime checks and user-visible evidence.

Aegis does **not** promise anonymity, a zero fingerprint, malware immunity, or Tor Browser equivalence. It reduces attack surface and linkability, isolates high-risk activity, can fail closed for selected routes, and reports important residual exposure instead of converting limitations into green badges.

## 1.1.3 visibility and confirmation UX

- Replaced the small bottom toast with a large top-of-chrome confirmation banner that cannot be covered by the native webpage surface.
- Added clear success, warning, danger and informational treatments with larger typography, iconography and a dismiss button.
- Increased confirmation persistence to 6.5 seconds for normal/success messages, 8.5 seconds for warnings and 12 seconds for failures.
- Enlarged Settings, floating privacy/library panels, the command palette and permission dialogs.
- Raised and documented the UI stack so notifications remain above permission prompts, command palette, Settings and floating panels.
- Settings now show a prominent Unsaved / Saving / Saved ✓ state instead of immediately claiming a save before backend confirmation.
- Added regression tests that enforce notification placement, modal sizing and z-index ordering.

## 1.1.2 stability release

This release is a stabilization pass over the 1.1 Security Kernel and BrowserRuntime migration.

- Fixed the Security Suite cross-tab cohort crash caused by treating the tab `Map` as an Array.
- Removed a second latent Security Suite failure from the stale `createStats()` factory and routed probes through `makeTabStats()`.
- Security Suite IPC now returns structured failure evidence instead of surfacing an unhandled remote-method exception.
- Restored preload authorization for **Harden This Site** and **New Anonymous Tab** so those browser actions execute from the UI.
- Fixed Settings render/save symmetry for Bounce Tracking Protection.
- Profile and Reset Settings actions now preserve signed managed-policy locks, and Reset rebuilds active tab renderers so preload-based protections actually change at runtime.
- Consolidated request-header privacy enforcement into one deterministic `onBeforeSendHeaders` pipeline so User-Agent normalization, GPC/DNT, Client Hint reduction, referrer stripping and cookie isolation cannot silently replace one another.
- Security Suite network-identity verification now observes post-policy headers without replacing the privacy handler it is trying to test.
- Added stable-release health gates for UI/preload/main IPC parity, Settings control symmetry, Map/Array misuse, BrowserRuntime contract coverage, Security Suite runtime invariants and package/launcher version synchronization.
- Expanded the macOS launcher preflight to syntax-check BrowserRuntime, engine adapter, Security Suite, Security Kernel, compartment, extension and site-intelligence modules before starting the browser.

## What's new in 1.1

### Security Kernel and Runtime Guardian
- Centralized fail-closed policy broker for navigation, redirects, popups, requests, extensions, downloads, permissions, clipboard, screen capture, printing and developer tools.
- Kernel decisions carry explainable reason, enforcement layer and risk metadata rather than opaque allow/deny booleans.
- A tamper-evident SHA-256 decision chain records kernel evidence after secret redaction and continuously verifies chain integrity.
- A local adaptive risk engine correlates fingerprinting, phishing, TLS, private-network, permission, download and extension signals with time decay; successfully blocked activity contributes reduced residual risk.
- Unknown kernel actions and dangerous local/script URL schemes fail closed.
- Managed-policy runtime expiry enforcement, anti-rollback version comparison and signing-key identity support.
- Enterprise URL block rules now take precedence over allow rules.
- Fingerprint activity telemetry classifies bursts of high-entropy surface access as Low, Elevated or Aggressive without claiming anonymity.
- Identity-coherence evaluation compares observed browser identity with the active Aegis cohort policy.
- Filter subscriptions now support bounded streaming downloads, 24-hour cache TTLs, conditional ETag/Last-Modified refresh, parse-health validation, last-known-good retention and hosts-format conversion.

### Runtime Guardian and Security Suite
- Behavioral verification of renderer/Node isolation, session separation, storage cleanup, WebRTC exposure, network identity coherence and fingerprint cohort consistency.
- PASS / WARNING / INFO / FAIL / NOT TESTED evidence model.
- Disposable routed diagnostic sessions for DNS/HTTPS reachability and opt-in public-IP observation.
- Runtime security event ledger with bounded retention and secret redaction before evidence is retained.
- Exportable redacted `aegis.security-events.v1` JSON evidence.
- TLS certificate errors fail closed and are recorded as security evidence; Aegis does not claim to rewrite Chromium's TLS fingerprint.

### Privacy and fingerprint resistance
- A dedicated **Aegis Cohort v2** policy defines coherent Standard, Strict and Maximum identities instead of independently randomizing every surface.
- Strict/Maximum normalize timezone, locale, screen geometry, DPR, CPU concurrency, memory, User-Agent/Client Hints and related identity surfaces as a group.
- Maximum/Anonymous elevate WebGL to blocked, canvas extraction to a blank cohort behavior, WebRTC to blocked and timers to a coarser 10 ms quantum.
- Strict reduces local-font, plugin/MIME, media-device, speech-voice and selected high-entropy API exposure.
- Additional high-entropy surfaces such as installed-related-app discovery, gamepad/keyboard exposure, pressure APIs, detailed screen APIs and file-system picker surfaces are reduced in protected profiles.
- Selected preference media queries are normalized so OS theme/contrast/HDR preferences do not become an unnecessary identity signal.
- Fingerprint runtime evidence now carries the active cohort policy so Sentinel/Diagnostics can compare intended policy with observed behavior.
- Standard, Strict and Maximum privacy profiles.
- Cohort-oriented normalization for UA/Client Hints, locale, timezone, screen metrics, hardware concurrency and device memory.
- Canvas/audio perturbation, WebGL identity reduction and protected-profile WebGPU suppression.
- Local-font, plugin/MIME, battery/network and selected high-entropy API reduction.
- Letterboxing, timer reduction, service-worker controls and GPC/DNT.
- Startup WebRTC non-proxied UDP restrictions plus behavioral ICE-candidate testing.
- Maximum mode deliberately does **not** monkey-patch JavaScript `eval`; script shutdown belongs to the explicit anonymous/Safest-style compartment.

### Native Adblock Engine

Aegis now includes a browser-owned wide-spectrum content-blocking engine modeled on the strongest ideas from uBlock Origin, Brave adblock-rust, Ghostery and AdGuard rather than depending on a store extension.

- Default cached community sources: **uBlock filters, uBlock Privacy, uBlock Unbreak, EasyList, EasyPrivacy and Peter Lowe**.
- HTTPS filter-list updater with bounded downloads, atomic cache replacement, SHA-256 update evidence and manual/automatic refresh controls.
- Indexed hostname matcher to avoid scanning the full hostname-rule set on every request.
- ABP/uBO-style network patterns and exceptions.
- Resource-type options including script, image, stylesheet, font, media, XHR, subdocument, WebSocket, ping, document and popup.
- `third-party` / `first-party`, `domain=`, `important`, `match-case` and `removeparam=` handling.
- Domain-scoped cosmetic filters and cosmetic exceptions.
- Point-and-click **Pick page element** workflow that creates a local site-specific cosmetic rule.
- Popup filtering, tracker/ad/cryptominer categories, tracking-parameter stripping, beacon defense and per-tab blocked-request evidence.
- **My filters** editor for local custom rules.

Aegis does not execute arbitrary third-party uBO scriptlets/procedural JavaScript from filter subscriptions. Unsupported syntax is ignored rather than evaluated as trusted code. This is a deliberate security boundary; uBO has a substantially larger filter-language/runtime surface, so Aegis does not claim byte-for-byte uBO compatibility.

### Tracking and storage defense
- Native request filtering for ads, analytics, social trackers, attribution, telemetry, fingerprinting endpoints and cryptomining.
- Third-party request/cookie controls, tracking-parameter removal, redirect-wrapper cleanup and cross-site referrer reduction.
- ETag protection, tracking-beacon/anchor-ping defense and conservative cosmetic filtering.
- Cookie AutoDelete-style origin cleanup and bounce-tracker detection with intermediary storage purging.
- Memory-only tracker learning.
- Optional SponsorBlock integration.

### Isolated security compartments
- Unique non-persistent Chromium partitions for ordinary tabs.
- Harden This Site creates materially stronger per-site behavior rather than a cosmetic status change.
- Anonymous compartment requires the configured Tor SOCKS route to verify before remote browsing when Tor verification is required.
- Anonymous mode blocks local-network destinations, extensions and downloads and can disable JavaScript.
- New Identity destroys active browsing identities, clears ephemeral state and rotates identity seeds.
- Aegis explicitly does not claim that an Electron/Chromium anonymous compartment is equivalent to Tor Browser.

### Permissions and Site Privacy Intelligence
- Main-process permission mediation for camera, microphone, geolocation, notifications, clipboard read, display capture, local fonts, MIDI, USB, Serial and HID.
- Allow once, Allow 10 minutes, persistent per-origin decisions and explicit blocking.
- Sentinel Simple and Advanced views explain requested data, blocked/allowed activity, third parties, fingerprint surfaces, route posture, TLS observation and runtime evidence.
- Per-site privacy/security status and one-click hardening.

### Aegis Extension Runtime
- Installs inspected Firefox-style `.xpi` WebExtension packages into an Aegis-owned runtime.
- ZIP/path traversal and package-size validation, manifest validation, SHA-256 package identity and compatibility reporting.
- Dedicated isolated execution worlds for extension content scripts.
- Permission/host checks for exposed tab data and mutations.
- Hardened/anonymous tabs are excluded from extension access.
- Aegis reports unsupported APIs instead of pretending arbitrary Firefox compatibility. Background/service-worker parity, blocking webRequest, native messaging and several privileged Firefox APIs are not claimed.

### Enterprise Security Center
- Browser-process URL allowlists and blocklists.
- Extension allowlisting and block-unlisted-extension policy.
- Managed clipboard-read, display-capture and printing DLP restrictions.
- Signed administrator policy bundles verified with Ed25519.
- Set `AEGIS_POLICY_PUBLIC_KEY` to the administrator public key before importing a signed policy.
- Verified policy provenance and locked setting groups prevent ordinary UI patches from overriding administrator-managed controls.
- Invalid, modified or expired managed policies are rejected and recorded.
- Redacted security-evidence export for incident/compliance workflows.
- Site isolation remains part of the remote renderer security baseline.

Aegis local policy enforcement is not a substitute for an organization's MDM, EDR, SIEM, certificate deployment or OS-level DLP infrastructure.

## Engine architecture

Aegis is Chromium-based, but the product architecture is being separated from Electron. `src/core/engine-contract.js` defines the browser-engine boundary and `src/engine/electron-adapter.js` is the current Chromium/Electron implementation. Private-session creation, remote renderer construction/attachment, protocol registration, selected network operations, permission mediation, download interception, popup policy, certificate observation, JavaScript execution and DevTools-protocol fingerprint setup now route through that adapter.

This is an incremental migration: Electron remains the current desktop host and update vehicle, while privacy policy, ad blocking, enterprise controls, Sentinel evidence, fingerprint policy and compartment logic remain Aegis-owned core capabilities. The goal is to make a future direct Chromium host adapter possible without rewriting those security systems.

Chromium's sandbox and Site Isolation remain intentional security foundations; Aegis is reducing framework coupling, not reimplementing Chromium's renderer sandbox.

## Secure renderer baseline

Remote content runs with a deliberately restrictive Chromium/Electron policy: sandbox enabled, context isolation enabled, Node integration disabled, subframe Node integration disabled, web security enabled, insecure-content execution disabled, WebView disabled, plugins disabled, developer tools disabled, drag/drop navigation disabled, WebSQL disabled and media autoplay gated on user activation.

Aegis also enables site-per-process and disables or reduces selected background/speculative Chromium facilities at startup.

## Downloads

Downloads are isolated from anonymous mode, never described as malware-safe merely because they completed, and receive local integrity evidence after completion:
- SHA-256
- observed MIME type
- on-disk size verification
- basic MIME/extension mismatch warning
- explicit high-risk download handling

A SHA-256 digest proves file identity/integrity only; it is **not** a malware verdict.

## Appearance and accessibility

Browser chrome supports:
- Nebula Glass
- Graphite
- Arctic Light
- Deep Ocean
- Forest
- Ember
- High Contrast

Accent palettes include Electric Cyan, Ultraviolet, Emerald, Security Blue, Amber and Rose. Standard, Large and Extra Large text scales and multiple density options are available. These are browser-chrome preferences rather than deliberate webpage fingerprint attributes.

## Start on macOS

1. Clone or extract Aegis.
2. Double-click **`Smoke-Test-Aegis.command`** to run the native launch/network smoke path.
3. Double-click **`Run-Aegis.command`** for normal use.
4. Open **Settings → Diagnostics → Run Security Suite**.
5. Use **`Diagnose-Aegis.command`** for runtime/startup diagnostics.

For repository development:

```sh
npm install
npm run verify
npm start
```

Electron is pinned in `package.json`. The macOS launchers use zsh and keep the browser runtime under the user's Application Support directory.

## Security Suite evidence model

| State | Meaning |
| --- | --- |
| **PASS** | A configured enforcement path or behavioral test succeeded. |
| **WARNING** | Protection is active but a meaningful caveat exists. |
| **INFO** | Observed evidence or a known limitation; not a pass/fail claim. |
| **FAIL** | Required behavior failed. |
| **NOT TESTED** | A meaningful verification could not run in the current state. |

The suite covers renderer/process isolation, permission enforcement, privacy/fingerprint preload readiness, HTTPS-first posture, privacy API surfaces, GPC/DNT, WebGL/WebGPU-related exposure, WebRTC, site isolation, tracker/cookie/beacon defenses, storage resurrection cleanup, session isolation, fingerprint stability/cohort consistency, network/JavaScript identity coherence, route posture, DNS/HTTPS reachability and public-IP observation.

## Data model and secret handling

Aegis is local-first. It has no Aegis cloud account or browser telemetry service. Browsing compartments are ephemeral; Sentinel evidence is local and bounded. Settings, explicit bookmarks, download metadata and required local runtime diagnostics may persist.

Diagnostic/event data passes through defensive secret redaction. Credential-shaped keys, bearer values, API-key/password/token fields, private-key fields, secret URL parameters and proxy credentials are masked before relevant evidence is retained or exported. UI password masking alone is not treated as encryption.

## Network and anonymity

Aegis supports System, Direct, SOCKS5, HTTP and HTTPS proxy modes. Fixed proxy configurations can fail closed. Anonymous mode is designed around a verified Tor SOCKS route rather than silently falling back to a direct connection.

Destination sites can still observe the egress IP and Chromium transport characteristics. DNS behavior, endpoint software and network infrastructure remain part of the threat model. Use the route evidence in Sentinel/Diagnostics rather than assuming a proxy toggle proves anonymity.

## Keyboard shortcuts

- `Cmd/Ctrl + L` — address bar
- `Cmd/Ctrl + T` — new isolated tab
- `Cmd/Ctrl + W` — close tab
- `Cmd/Ctrl + D` — bookmark current page
- `Cmd/Ctrl + K` — command palette
- `Cmd/Ctrl + ,` — settings
- `Cmd/Ctrl + Shift + N` — New Identity

## Repository verification

```sh
npm run verify
```

The verification command runs the Node test suite, syntax-checks the browser/security modules, validates UI/IPC contracts and runs the repository self-check. GitHub Actions executes the supported CI matrix.

Native macOS GUI behavior, real-world fingerprint comparison populations, live leak services, Apple signing/notarization and independent penetration/security review cannot be proven by unit tests alone and remain separate release-assurance activities.

## Documentation

- [Product requirements](docs/PRD.md)
- [Architecture](ARCHITECTURE.md)
- [Feature matrix](FEATURES.md)
- [Security model](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Privacy-control contract](docs/PRIVACY-CONTROL-CONTRACT.md)
- [Extension runtime](docs/EXTENSIONS.md)
- [Benchmark baseline](docs/BENCHMARK_BASELINE.md)
- [Release checklist](docs/RELEASE-CHECKLIST.md)
- [Brand system](docs/BRAND.md)

## 1.1 status

The repository version is **1.1.0**. Aegis 1.1 now contains the Runtime Guardian architecture, isolated browsing compartments, enterprise policy engine, signed managed-policy verification, Aegis Extension Runtime, runtime Security Suite, Sentinel evidence model, tracking/storage defenses, fingerprint-reduction framework, download integrity evidence, secret-safe diagnostics and expanded appearance system.

The repository should still distinguish a feature-complete codebase from a publicly trusted binary release: broad native compatibility testing, Apple signing/notarization, signed update distribution, reproducible release provenance and independent security review are distribution/release-assurance steps rather than claims the source tree can make by itself.
