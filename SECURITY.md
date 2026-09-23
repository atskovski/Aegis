# Aegis Security Model — v0.9.0


## Guardian verification model

v0.9 treats configured policy and observed behavior as different evidence classes. The Security Suite reports PASS, WARNING, INFO, FAIL, or NOT TESTED and includes the evidence scope. Behavioral checks include ephemeral cookie-jar separation, WebRTC host-candidate inspection, renderer privacy-surface inspection, routed DNS/HTTPS reachability, and optional public-IP observation through a disposable session.

Aegis does not claim to rewrite Chromium TLS fingerprints. Direct/system routes are not reported as anonymous: they receive an explicit route warning unless a fixed proxy route is configured and healthy.

## Security objective

Aegis treats arbitrary web content as hostile. Public pages are isolated from the trusted browser UI and from local Node/Electron privileges. Privacy features are defense in depth; they are not allowed to silently disable Chromium's core web security model.

## Process and renderer boundaries

The trusted browser shell is served through the private `aegis://app/` protocol. The browser UI uses a narrow preload bridge with context isolation and no direct Node integration. Public pages render inside `WebContentsView` instances with sandboxing, context isolation, Node disabled, `webSecurity` enabled, mixed insecure content disabled, plugins disabled and DevTools disabled.

Every public tab receives a separate non-persistent Chromium session. A private Aegis protocol handler is registered separately on each session for local start/error pages because Electron protocols are session scoped.

IPC handlers validate that the sender frame originates from `aegis://app/` before accepting browser-control operations.

## Network and website reliability

The default route is **System**, which follows Chromium/macOS platform networking. A fresh System session is not mutated with `setProxy()` while the first page is loading; this avoids a startup race that previously could leave a visible browser shell with an unusable tab.

Direct and fixed proxy modes are explicit. SOCKS5/HTTP/HTTPS fixed routes can be configured to fail closed so Aegis will not silently fall back to the system/direct route when the requested proxy cannot be applied.

Network diagnostics use a separate non-persistent Chromium session with the same configured route. Proxy resolution, DNS resolution and HTTPS connectivity are bounded and run in parallel. Diagnostic cleanup destroys its storage/cache/connections after the result is returned.

HTTPS-first upgrades top-level HTTP navigation. Aegis never silently downgrades a failed HTTPS page; eligible failures can offer an explicit one-tab HTTP recovery action.

## Request privacy

The request layer can block high-confidence advertising, analytics, telemetry, social, attribution, cryptomining and fingerprinting hosts. It also supports local hostname block/allow rules and a memory-only cross-site recurrence learner.

Cross-site cookie headers and `Set-Cookie` can be stripped, tracking query parameters can be removed, selected redirect wrappers can be unwrapped, cross-site referrers can be suppressed, ETag validators can be reduced for tracking contexts, public CDN requests can be isolated from cookies/referrers, and GPC/DNT can be sent.

Compatibility Mode is tab scoped. It relaxes the two protections most likely to break sites—heuristic blocking and third-party-cookie stripping—while retaining explicit tracker rules, renderer isolation, permission handling, HTTPS-first behavior, WebRTC restrictions and download policy.

## Permission model

Powerful capabilities default to Block or Ask. Aegis implements both Electron permission-request and permission-check handlers. Site exceptions are explicit and local. WebUSB, Web Serial and WebHID remain denied through device-selection/device-permission handlers.

Permission prompts time out closed if the trusted UI does not respond.

## Fingerprinting model

Aegis uses normalized values and deterministic, site/identity-scoped perturbation. It does not try to return fresh random values on every API call. Strict and Maximum profiles reduce selected Client Hints and normalize selected navigator/screen/WebGL/canvas/media/timing surfaces; Maximum adds stronger audio/font and service-worker controls.

These defenses reduce common fingerprint inputs but do not make fingerprinting impossible. A small browser population can itself be identifying.

## Automatic cleanup

Browsing tabs are memory-only and use disabled disk cache. Closing a tab clears data/cache/connections. New Identity destroys all public sessions, rotates identity seeds and resets memory-only tracker learning.

Cookie AutoDelete can clear an origin after navigation leaves its registrable site. Fireproof exceptions are explicit. Settings and bookmarks are written locally with owner-only file permissions where supported.

## SponsorBlock privacy

SponsorBlock is optional and disabled by default. When enabled, Aegis computes the SHA-256 hash of the YouTube video ID and sends only the four-character hash prefix used by the SponsorBlock privacy-preserving lookup endpoint. Results are matched locally against the exact video ID/hash before segment data is used.

## Downloads

Aegis can deny downloads based on high-risk executable/script extensions. Allowed files are saved to an Aegis Downloads directory, tracked locally, and never auto-opened. This is not antivirus scanning and cannot determine that an allowed file is safe.

## Engine bootstrap and source preflight

Normal macOS launch does not depend on npm. The launcher downloads the exact Electron 44.4.3 macOS release for the current architecture and verifies a pinned official SHA-256 before extraction. macOS code-signature checks provide additional defense in depth.

The launcher runs syntax checks over the main process, preload, every UI script and every core module, then runs `scripts/self-check.js` using Electron's embedded Node runtime before the browser starts.

## Release limitations

The source package is not an Aegis Developer ID–signed/notarized `.app`. A public production release still needs publisher-controlled signing, notarization, signed updates and native macOS release testing. Aegis does not protect against a compromised operating system, browser/OS zero-day, malicious local administrator or global traffic analysis.


## Sentinel data minimization

Sentinel is local-only and bounded. Third-party observations retain hostnames, coarse categories, resource types, counts, and block/allow state; they do not retain complete third-party URLs. Sensitive-form detection records only the field category (for example, password or payment-card field present) and never reads field values or submitted content. The recent activity ledger is kept only in the tab's in-memory state and is destroyed with that tab or New Identity.

The injected audit script is not a security boundary. Enforcement remains in Electron session permission handlers, webRequest filtering, WebContents sandboxing, navigation controls, and isolated ephemeral sessions.
