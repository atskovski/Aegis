# Aegis Privacy Browser — Product Requirements Document

**Product:** Aegis Privacy Browser  
**Release target:** v0.9 Guardian  
**Platform:** macOS first; architecture keeps portability to Windows/Linux possible  
**Runtime:** Electron + Chromium, sandboxed `WebContentsView` renderers  
**Product principle:** **Protection must be observable, explainable, and testable.**

## 1. Product definition

Aegis is a local-first privacy and security browser for people who want meaningful browser protections without having to assemble, configure, and trust a large stack of privileged extensions. The browser owns the privacy boundary: isolated tab sessions, network filtering, explicit permissions, anti-fingerprinting, HTTPS-first navigation, privacy diagnostics, and site-level intelligence are implemented in the application rather than represented as decorative toggles.

Aegis is not a VPN, Tor client, malware-scanning cloud service, or anonymity guarantee. Destination sites can still observe the public IP of the route Aegis uses unless the user supplies a trusted VPN/proxy/Tor route. Sites can also observe Chromium transport characteristics such as TLS fingerprints. The UI must state those limitations instead of implying otherwise.

## 2. Brand promise

**Aegis means a shield.** The product should feel like a professional protective instrument, not a hacker-themed novelty browser. The brand is built around three ideas:

1. **Shield** — Aegis actively limits tracking, dangerous capabilities, and cross-site correlation.
2. **Proof** — green states are backed by runtime, behavioral, or external evidence.
3. **Clarity** — the user can understand what a page is requesting, what is blocked, what remains visible, and what action to take.

Primary tagline: **Browse with proof.**  
Secondary line: **Private by default. Verifiable by design.**

## 3. Target users

Primary users are privacy-conscious consumers, security professionals, researchers, technical leaders, and users handling sensitive web workflows. Secondary users include ordinary users who want strong defaults but do not want to understand browser internals.

The default experience therefore needs to remain usable without configuration while exposing expert-grade evidence on demand.

## 4. Product goals

- Make every normal tab an isolated, non-persistent browsing identity.
- Reduce tracking and advertising requests before page execution.
- Reduce high-value fingerprinting surfaces without creating unstable per-call randomness.
- Block or explicitly prompt for powerful web permissions.
- Give users a readable Site Privacy Inspector showing what a page is attempting to access.
- Provide a Security Suite that distinguishes policy, behavior, external proof, warnings, and known limitations.
- Support explicit system/direct/SOCKS5/HTTP/HTTPS routing and fail-closed fixed proxy behavior.
- Keep browser chrome responsive even when network, privacy, or diagnostics subsystems fail.
- Maintain readable typography with a large default text scale.
- Never use a proprietary Aegis token in the page-visible or wire-level User-Agent.

## 5. Non-goals

- Claiming that a browser can make a user literally fingerprint-free.
- Silently launching or operating a VPN/Tor service.
- Rewriting Chromium's TLS stack or claiming JA3/JA4 indistinguishability.
- Uploading browsing history, site-intelligence events, form values, or permission decisions to an Aegis cloud service.
- Persisting a cross-session behavioral tracking profile.
- Reading sensitive form field values for site intelligence.

## 6. Baseline findings that drive v0.9

The supplied browser tests exposed several important gaps in the previous build. AdBlockBench reported strong network blocking but weak cosmetic/API coverage. The separate ad-network test blocked 52 of 79 tested networks. BrowserLeaks showed that WebRTC local-IP leakage was prevented, TLS 1.2/1.3 and mixed-content handling were healthy, while Canvas/WebGL and multiple high-entropy JavaScript APIs remained observable. The public-IP page showed the system route's public IP, which is expected when no privacy proxy/VPN route is configured. Speedometer 3 measured a score around 38.2 on the tested machine.

v0.9 treats these as engineering inputs rather than marketing scores. The goal is to improve real controls while preserving compatibility and performance.

## 7. Functional requirements

### 7.1 Isolated browsing identities

- Every normal tab MUST use a unique non-`persist:` Chromium partition.
- Disk cache MUST remain disabled for private browsing tabs.
- Closing a tab MUST clear its session data/cache/connections.
- New Identity MUST destroy active browsing identities, rotate fingerprint seeds, clear temporary permissions, reset memory-only tracker learning, and open a fresh tab.
- Security Suite MUST behaviorally verify that a cookie written in one disposable session is absent from another.

### 7.2 Network and content filtering

- Known advertising, analytics, attribution, social, telemetry, cryptomining, and fingerprinting hosts MUST be blocked in the main process.
- Strict mode SHOULD block high-confidence first-party analytics resource paths such as Matomo/Piwik scripts and tracking/beacon endpoints.
- Known ad SDK endpoints, including Google IMA, SHOULD be covered by native filtering.
- Custom filter rules MUST support hostname block/allow syntax and a safe subset of ABP cosmetic selectors.
- Cosmetic filtering MUST use user-origin CSS so ordinary page CSS cannot trivially override it.
- `sendBeacon` and anchor `ping` to known tracking destinations SHOULD be suppressed when the beacon guard is enabled.
- Compatibility mode MAY relax content filtering per tab but MUST NOT disable sandboxing, permission enforcement, TLS minimum, session isolation, or the WebRTC route policy.

### 7.3 Anti-fingerprinting

Strict mode MUST:

- normalize page-visible UA/platform/language values;
- reduce high-entropy Client Hints;
- normalize hardware concurrency/device memory to common values;
- set timezone/locale to the profile standard;
- letterbox content dimensions when enabled;
- apply deterministic, site-and-identity-scoped Canvas perturbation;
- normalize WebGL vendor/renderer debug information and perturb readback;
- add small deterministic audio-readback perturbation;
- suppress speech-voice enumeration;
- sanitize media-device identifiers/labels;
- remove battery/network metadata where practical.

The Privacy API Guard MUST be independently controllable and, when enabled, suppress Local Font Access, Web Bluetooth/USB/Serial/HID surfaces, Protected Audience APIs, Private State Token surfaces, and Storage Access API entry points.

Maximum mode MAY additionally disable WebGL contexts, return privacy-preserving Canvas export placeholders, restrict font probing, disable service-worker registration, and block dynamic string `eval`. The UI MUST warn that Maximum may break complex sites.

### 7.4 Permission firewall

- Global persistent `allow` MUST NOT be a valid default.
- Camera, microphone, location, notifications, clipboard read, screen capture, local fonts, window management, idle detection, MIDI, USB, Serial, and HID MUST be governed by explicit policy.
- USB, Serial, and HID MUST remain hard blocked at the device-selection layer.
- Prompt UX MUST explain what data the requested capability can expose and its practical risk.
- Supported responses: Allow once, Allow 10 minutes, Always allow for this site, Block once, Always block for this site.
- Temporary permission grants MUST be memory-only and tab-scoped.

### 7.5 Network routing

- System route is the default.
- Direct, SOCKS5, HTTP, and HTTPS proxy modes MUST be available.
- Fixed proxies MAY fail closed and MUST NOT silently fall back when fail-closed is enabled.
- The Tor preset MUST only configure `127.0.0.1:9050`; Aegis MUST state that a local Tor service must already exist.
- WebRTC MUST use Chromium's `disable_non_proxied_udp` policy.
- Security Suite MUST label system/direct routing as a privacy warning rather than falsely reporting that the user's IP is hidden.

### 7.6 Security Suite

The Security Suite MUST support five result classes:

- **PASS** — a control was observed working.
- **WARNING** — usable but privacy-relevant exposure remains.
- **INFO** — factual evidence or known limitation, not a failure.
- **FAIL** — expected protection was not working.
- **NOT TESTED** — evidence could not be collected.

Checks SHOULD include renderer isolation, permission firewall, fingerprint initialization, cosmetic filtering, HTTPS-first behavior, Privacy API Guard, GPC, screen normalization, WebGL debug exposure, UA product leakage, WebRTC local-IP candidates, startup WebRTC policy, site isolation, third-party cookies, tracker filtering, tracking beacons, session isolation, routing posture, DNS/HTTPS connectivity, observed public IP, and TLS fingerprint limitations.

The public-IP lookup MUST be user initiated, use a disposable routed session, disclose the provider, and never be described as proof of anonymity.

### 7.7 Site Privacy Inspector

For the active page, the inspector SHOULD show:

- privacy/security/exposure scores with transparent local heuristics;
- blocked trackers and permissions;
- third-party hostnames contacted/blocked;
- sensitive API attempts;
- fingerprint surfaces used;
- presence of sensitive form intents without reading entered values;
- protection layers active for the tab;
- one-click Harden This Site action;
- a bounded local activity timeline.

### 7.8 Downloads

- High-risk executable/script extensions SHOULD be blocked by default.
- Downloads MUST never be auto-opened.
- Download metadata may persist locally; browsing history must not.

## 8. UX requirements

- Default text scale: **Large**.
- Browser chrome address text SHOULD be at least ~14.5 px at standard OS scale.
- Settings body copy SHOULD generally be 11.5–13.5 px or larger, with headings 15–24 px depending on hierarchy.
- User-selectable text scales: Standard, Large, Extra Large.
- Browser-owned Settings/permission/command UI MUST remain visually above native website renderers.
- Floating inspectors SHOULD reserve page viewport space instead of hiding their content behind a native view.
- Colors MUST communicate state but MUST NOT be the only differentiator; text labels such as PASS/WARNING/FAIL are required.

## 9. Branding system

### Name
**Aegis Privacy Browser**

### Mark
A geometric shield containing a stylized **A** and central protected core. The shape communicates protection; the split top edge suggests an active gate rather than a closed fortress.

### Palette
- **Aegis Night** `#070A12` — primary app background.
- **Citadel** `#111827` — card/surface.
- **Signal Cyan** `#4ED9FF` — interaction and evidence.
- **Guardian Teal** `#4FE1C1` — protected/pass state.
- **Ultraviolet** `#8A72FF` — secondary intelligence accent.
- **Amber** `#F1C76A` — warning.
- **Sentinel Red** `#FF6F8F` — failure/high-risk state.
- **Ice** `#F4F7FB` — primary text.
- **Steel** `#9AAAC0` — secondary text.

### Typography
Use the native system UI stack (`-apple-system`, `BlinkMacSystemFont`, `SF Pro Text`, `Segoe UI`) to avoid shipping font binaries and to preserve macOS familiarity and performance.

### Voice
Precise, calm, concise, technical when useful. Avoid fear-driven language. Aegis should explain risk and evidence without claiming absolute safety.

## 10. Security architecture requirements

Aegis follows current Electron security guidance for untrusted remote content: no Node integration, context isolation, sandboxed renderers, `webSecurity` enabled, permission handlers, restricted navigation/new-window behavior, and a browser-owned custom protocol for privileged local UI.

All IPC MUST be allowlisted. Browser pages MUST NOT receive broad Electron/Node APIs. External protocols MUST NOT be opened automatically from page navigation.

## 11. Performance requirements

- Security controls SHOULD be O(1) or bounded per request where possible.
- Local lists MUST be bounded.
- Site-intelligence ledgers MUST be bounded in memory.
- Expensive diagnostics MUST be user initiated or disposable-session based.
- Privacy hooks MUST avoid continuous timers and large mutation workloads.
- Speedometer regressions SHOULD be measured release-over-release on the same machine; a single score from a different system must not be treated as directly comparable.

## 12. Acceptance criteria for v0.9

- Automated unit/contract tests pass.
- Source syntax checks pass.
- macOS launcher shell syntax passes.
- Security Suite exposes PASS/WARNING/INFO/FAIL/NOT TESTED.
- Privacy API Guard behavior is independently toggleable.
- GPC is observable as `navigator.globalPrivacyControl === true` when enabled.
- User-Agent contains no `Aegis`/`Electron` product token.
- Cosmetic filtering is active in remote documents when Shields are enabled.
- High-entropy permissions include local fonts/window management/idle detection.
- Documentation includes PRD, brand system, threat model, architecture, and test baseline.
- Public repository does not include raw screenshots containing the user's real public IP.

## 13. Post-v0.9 roadmap

1. Signed/notarized macOS application bundle and reproducible release artifacts.
2. Mature list-update pipeline with signed metadata, cache validation, provenance, rollback, and per-list controls.
3. CNAME uncloaking / DNS-aware tracker classification without leaking queries to third parties.
4. Certificate viewer and transport-security panel with chain details and revocation/status evidence.
5. Download reputation integration designed so hashes/URLs are not silently uploaded.
6. First-party isolation/storage partitioning verification beyond cookies.
7. Formal accessibility audit and screen-reader pass.
8. Independent security review, dependency audit, fuzzing, and penetration test.
9. Windows/Linux builds after macOS architecture stabilizes.
