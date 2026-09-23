# Aegis Chrome Extension Runtime 6

Aegis now uses one extension model: **Chrome extensions**. Runtime 6 removes the split Chrome/Firefox product surface and concentrates compatibility work on Chromium extension semantics.

## Supported installation sources

- Chrome Web Store listing URLs.
- 32-character Chrome extension IDs.
- Local CRX2 and CRX3 packages.
- Direct HTTPS CRX and ZIP package URLs.
- Unpacked Chrome extension folders for development and testing.

Chrome Web Store installs are resolved through Chromium's update service. Aegis parses CRX2/CRX3 headers, derives the signed Chrome extension ID from package cryptographic material, verifies the developer signature, and fails closed when the downloaded package identity does not match the requested store ID.

## Runtime 6 reference extension: Privacy Badger

Runtime 6 uses the Chrome build of Privacy Badger 2026.9.15 as a compatibility reference because it exercises a demanding combination of Manifest V2 background pages, storage, tabs, cookies, privacy settings, scripting, WebNavigation, WebRequest, WebRequestBlocking, browser actions, alarms and all-frame document-start content scripts.

The previous `js/utils.js:26` failure was consistent with Privacy Badger receiving an incomplete manifest during early background startup: its `hasOwn()` helper was called with an undefined manifest field. Large manifests are no longer transported in Electron command-line arguments. Background pages synchronously request their authenticated bootstrap data from the Aegis browser process before extension page code runs.

Runtime 6 also makes read-only cookie queries safe before the first private tab exists, implements Chrome reserved i18n messages such as `@@ui_locale` and `@@extension_id`, verifies the background page sees a complete manifest, and records renderer stack traces in extension health diagnostics.

## Why Aegis uses its own extension runtime

Normal Aegis browsing tabs use isolated, non-persistent Chromium sessions. Runtime 6 preserves that compartment model while hosting extension background pages, popups, options pages and content scripts in Aegis-controlled sandboxed contexts with no Node.js access.

## Installation and update flow

1. The user selects a CRX/ZIP package, unpacked folder, Chrome Web Store page, Chrome extension ID or direct HTTPS package URL.
2. Aegis enforces compressed-package, expanded-size, file-count and path-safety limits.
3. CRX headers and package identity are parsed before installation; Chrome Web Store CRX signatures must verify.
4. `manifest.json` must be Manifest V2 or V3.
5. Localized manifest labels are resolved and static source inspection detects requested Chrome API namespaces.
6. Aegis computes a SHA-256 package digest and builds a permission, host-access, signature and runtime review.
7. Installation proceeds only after explicit user approval and enterprise extension policy checks.
8. Installed background contexts, content scripts, toolbar actions, options pages and supported APIs become active.
9. Store-installed extensions retain their original source for explicit update checks.

## Implemented Chrome extension surfaces

Runtime 6 implements or safely emulates the major surfaces currently needed by the reference workload:

- runtime: manifest/URL/platform/browser metadata, messaging, long-lived Ports, reload, contexts and options opening.
- storage: local, session, sync compatibility storage and read-only managed storage.
- tabs: query/get/create/update/reload/remove/sendMessage, frame-targeted messaging, executeScript, CSS insertion/removal, zoom and visible-tab capture.
- windows: current-window metadata operations used by extension UI.
- cookies: host-scoped access across Aegis private-tab stores, including safe empty reads before tabs exist.
- permissions: declared-permission inspection.
- i18n: locale lookup plus Chrome reserved messages.
- alarms and commands.
- scripting: registered content scripts, packaged file/code execution, frameIds/allFrames and MAIN/ISOLATED worlds.
- webNavigation observation with subframe metadata.
- webRequest observation plus bounded Manifest V2 blocking listeners for cancel/redirect and privacy-strengthening header changes.
- declarativeNetRequest static/dynamic/session block, allow, redirect, upgradeScheme and constrained privacy-strengthening header removal.
- privacy query/set compatibility governed by Aegis security policy.
- notifications through Aegis browser chrome.
- menus/contextMenus.
- action/browserAction/pageAction popup, click, badge, title and icon state.
- Manifest V2 background pages and scripts, plus Manifest V3 service-worker code through Aegis's sandboxed host.
- packaged extension resources through the private `aegis-extension://` origin.

## Runtime integrity

Large extension manifests and locale data are delivered through authenticated synchronous IPC instead of process command-line arguments. Runtime 6 verifies that a background page can read a complete Chrome manifest before considering the host started.

Extension-page and background unhandled errors are reported back to the browser process with stack context. Health checks retain enough of that stack to identify the failing extension file and line rather than only reporting a generic runtime failure.

## Security boundaries

Chrome extensions cannot replace Aegis routing, disable the privacy firewall, weaken hardened/anonymous compartments, use Node.js/native messaging, manage other extensions, attach the Chrome debugger, or remove Aegis security-critical headers. These are browser security boundaries rather than installation failures.

## Known compatibility boundaries

Runtime 6 does not claim that every Chrome extension API is identical to upstream Chrome. The remaining compatibility report is about runtime behavior, not whether a package was only partially installed. Unsupported privileged surfaces remain explicit instead of being silently faked.
