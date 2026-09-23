# Aegis Extension Runtime 5

Aegis Runtime 5 installs complete Chrome and Firefox WebExtension packages while keeping execution inside an Aegis-owned compatibility runtime. Package installation and browser-API compatibility are deliberately reported as two separate facts.

## Supported installation sources

- Chrome Web Store listing URLs and 32-character Chrome extension IDs.
- Local Chrome CRX2 and CRX3 packages.
- Firefox Add-ons listing URLs.
- Local Firefox XPI packages.
- Direct HTTPS CRX, XPI and ZIP package URLs.
- Unpacked WebExtension folders for development and testing.

Chrome Web Store installs are resolved through Chromium's update service. Aegis parses CRX2/CRX3 headers, derives the signed Chrome extension ID from package cryptographic material, verifies the developer signature, and fails closed if the downloaded package identity does not match the requested store ID.

Firefox Add-ons installs resolve the current package through Mozilla's Add-ons API and verify that the package's Gecko identity matches the add-on GUID returned by Mozilla. Runtime 5 detects Mozilla signature metadata inside XPI files but does not claim independent cryptographic verification of arbitrary XPI signatures.

## Why Aegis does not use Electron's built-in extension loader

Aegis normal browsing tabs intentionally use non-persistent, per-tab Chromium sessions. Electron's native extension loader only loads unpacked extensions into persistent sessions and explicitly supports only a subset of Chrome extension APIs. Switching normal Aegis tabs to persistent shared sessions just to use that loader would weaken the current tab-compartment model.

Runtime 5 therefore extracts and validates the package itself, stores it in owner-only local storage, hosts extension background/popup/options contexts in sandboxed extension windows, and injects supported content scripts into dedicated per-extension isolated worlds. Extension code receives no Node.js access.

## Installation and update flow

1. The user selects a local package, unpacked folder, Chrome Web Store page, Firefox Add-ons page, Chrome extension ID or direct HTTPS package URL.
2. Aegis enforces compressed-package, expanded-size, file-count and path-safety limits.
3. CRX headers and package identity are parsed before installation; Chrome Web Store CRX signatures must verify.
4. manifest.json must be WebExtensions manifest v2 or v3.
5. Localized manifest labels are resolved and static source inspection detects requested browser/chrome API namespaces.
6. Aegis computes a SHA-256 package digest and builds a permission, host-access, signature and compatibility review.
7. The review explicitly shows **100% package installable** separately from the API/runtime compatibility percentage.
8. Installation only proceeds after explicit user approval and enterprise extension policy checks.
9. Installed background contexts, content scripts, toolbar actions, options pages and supported APIs become active.
10. Store-installed extensions keep their original source. **Check update** downloads the current package from that same source, re-runs identity/signature/permission/compatibility review, and requires approval before replacement.
11. Updates preserve the installed extension identity, resource token, install timestamp and enabled/disabled state.

## Implemented WebExtension surfaces

Runtime 5 currently implements or emulates the following major surfaces:

- runtime: manifest/URL/platform/browser metadata, messaging, long-lived Ports, reload, contexts and options opening.
- storage: local, session, local compatibility sync and read-only managed.
- tabs: query/get/create/update/reload/remove/sendMessage, executeScript, CSS insertion/removal, zoom and visible-tab capture.
- windows: basic current-window and window metadata operations used by extension UIs.
- cookies: host-scoped access tied to extension host permissions and visible private tabs.
- permissions: declared-permission inspection.
- i18n: manifest/default-locale message lookup.
- alarms and commands.
- scripting: file/code execution and CSS insertion/removal for the top-level frame.
- webNavigation observation.
- webRequest observation.
- declarativeNetRequest static/dynamic/session rules for block, allow, redirect and upgradeScheme decisions.
- privacy read/query compatibility surfaces controlled by Aegis policy.
- notifications rendered through Aegis browser chrome.
- menus/contextMenus integrated into Aegis context menus.
- action, browserAction and pageAction popup/click/badge/title/icon state.
- MV2 background scripts, MV3 service-worker code through a sandboxed persistent background-host emulation, and custom background pages.
- packaged extension resources through the private aegis-extension:// resource origin.

## Known compatibility boundaries

Runtime 5 does not claim universal Chrome or Firefox API parity.

- Aegis owns synchronous network blocking. Blocking webRequest listener return values are not exposed; extensions should use supported declarativeNetRequest behavior where possible.
- declarativeNetRequest modifyHeaders is intentionally not allowed to weaken Aegis security headers, and matched-rule telemetry is reduced.
- proxy replacement, native messaging, browsing-history database access, extension management, debugger APIs and DevTools extension pages are withheld.
- optional_permissions and optional_host_permissions are detected and reviewed, but runtime permission-request/removal prompts are not yet implemented.
- content_scripts.all_frames and scripting allFrames are not yet implemented; supported script injection targets the top-level frame.
- document_start uses Aegis early-navigation isolated-world injection, but exact Firefox/Chromium pre-page-script ordering is not guaranteed on every navigation.
- MV3 service workers run in a persistent sandboxed host rather than Chromium's suspend/resume lifecycle.
- function-object scripting injection is not transferred across Aegis IPC; packaged files or code strings are supported.
- notifications, context menus and some browser chrome integrations are intentionally reduced compared with upstream browser UI.

These boundaries remain visible in the compatibility review and health diagnostics instead of being silently reported as working.

## Runtime health and repair

Each extension has runtime health evidence for manifest parsing, compatibility bootstrap compilation, referenced package resources, API compatibility, background-host state and recorded runtime errors. The Add-ons manager exposes Health check, Repair runtime, Reload, Enable/Disable, Check update and Remove controls.

Repair can restart an expected background context when it has stopped. It does not pretend an unsupported API is fixed.

## Security boundaries

- no Node.js in extension content scripts, background hosts, popups or options pages;
- isolated per-extension execution worlds;
- extension IPC validates extension identity and the sending renderer;
- private aegis-extension:// resource tokens prevent exposing local filesystem paths;
- host permissions gate extension network and tab access;
- extensions are excluded from hardened and anonymous compartments;
- extensions cannot disable the renderer sandbox, privacy firewall, HTTPS-first policy, routing configuration or Security Kernel;
- package extraction rejects traversal paths and symlinks and enforces file/size limits;
- Chrome Web Store identity/signature mismatches fail closed;
- enterprise allowlist/block-unlisted policy is enforced before installation.

## Engine direction

Aegis can keep expanding Runtime 5 compatibility, but exact arbitrary-Chrome-extension or arbitrary-Firefox-XPI behavior eventually requires a browser engine with upstream extension semantics rather than an Electron compatibility layer. Runtime 5's goal is to install packages completely, execute a broad safe subset faithfully, and make every remaining incompatibility explicit.
