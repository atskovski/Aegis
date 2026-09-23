# Aegis Extension Runtime

Aegis supports installing Firefox-style WebExtension packages (.xpi) through an Aegis-owned compatibility runtime.

## Why Aegis does not use Electron's built-in extension loader

Aegis normal tabs intentionally use non-persistent Chromium sessions. Electron's built-in Chrome-extension support is limited to unpacked extensions on persistent sessions and implements only a subset of extension APIs. Using it as if it were Firefox XPI support would either weaken Aegis's tab-isolation model or create misleading compatibility claims.

The Aegis Extension Runtime therefore treats an XPI as an untrusted WebExtension package, validates it, extracts it into owner-only local storage, analyzes its manifest and permissions, and runs supported content scripts inside a dedicated isolated JavaScript world. Add-on code receives no Node.js access.

## Installation flow

1. The user chooses Settings → Add-ons → Install .xpi.
2. Aegis limits archive size and file count and rejects zip-slip/absolute paths.
3. manifest.json must be WebExtensions manifest v2 or v3.
4. Aegis computes a SHA-256 digest and derives an extension ID when a Gecko ID is absent.
5. A permission review shows high-risk host/API permissions.
6. A compatibility report identifies unsupported APIs before installation.
7. Only after explicit approval is the extension copied into Aegis's local extension directory.
8. Matching content scripts are injected into isolated world 1004 after a remote document loads.
9. The extension may use the supported Aegis browser API bridge.
10. Disabling/removing an extension reloads active tabs so old content scripts do not continue running.

## Currently implemented APIs

- browser.runtime: manifest metadata/URL helpers, platform info, messaging surface
- browser.storage.local
- browser.storage.session
- browser.tabs: query/create/update/remove/sendMessage
- browser.permissions.contains
- basic browser.i18n locale information
- WebExtension match/exclude-match handling for HTTP/HTTPS content scripts
- extension-provided CSS content injection

## Explicit limitations

The current Electron-based Aegis engine does not claim universal Firefox add-on compatibility.

Background pages/service workers are currently reported as unsupported rather than silently ignored. Aegis also withholds or does not yet implement powerful APIs including blocking webRequest, declarativeNetRequest, extension-owned proxy replacement, native messaging, history access, extension management, and broad cookie-store access.

These are security boundaries, not hidden failures. The Add-ons page exposes the compatibility score and unsupported API list for each package.

## Path to full Firefox XPI compatibility

If runs-arbitrary-Firefox-XPIs-exactly-as-Firefox-does becomes a hard product requirement, Aegis must move from an Electron/Chromium shell to a Gecko/Firefox-derived engine or maintain a substantially larger compatibility implementation. That would be an engine migration, not a small extension-loader feature.

Aegis should not describe the Electron compatibility runtime as full Firefox compatibility until that migration occurs.

## Security boundaries

- no Node.js in extension content scripts;
- isolated extension world separate from the page's main JavaScript world;
- main-process IPC validates extension ID and method names;
- privileged unsupported APIs fail rather than being emulated unsafely;
- extensions cannot disable Aegis's renderer sandbox, private-session model, permission firewall, HTTPS-first policy, or routing configuration;
- XPI source is local-only and is not uploaded by Aegis.