# Aegis Extension Runtime 5

Aegis supports installing Firefox-style WebExtension packages (.xpi) through an Aegis-owned compatibility runtime.

## Why Aegis does not use Electron's built-in extension loader

Aegis normal tabs intentionally use non-persistent Chromium sessions. Electron's built-in Chrome-extension support is limited to unpacked extensions on persistent sessions and implements only a subset of extension APIs. Using it as if it were Firefox XPI support would either weaken Aegis's tab-isolation model or create misleading compatibility claims.

The Aegis Extension Runtime therefore treats an XPI as an untrusted WebExtension package, validates it, extracts it into owner-only local storage, analyzes its manifest and permissions, and runs supported content scripts inside a dedicated per-extension isolated JavaScript world. Add-on code receives no Node.js access.

## Installation flow

1. The user chooses Settings → Add-ons → Install .xpi.
2. Aegis limits archive size and file count and rejects zip-slip/absolute paths.
3. manifest.json must be WebExtensions manifest v2 or v3.
4. Aegis computes a SHA-256 digest and derives an extension ID when a Gecko ID is absent.
5. A permission review shows high-risk host/API permissions.
6. A compatibility report identifies unsupported APIs before installation.
7. Only after explicit approval is the extension copied into Aegis's local extension directory.
8. Matching content scripts are injected into a dedicated per-extension isolated world after a remote document loads.
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

Firefox `background.scripts` and MV3 `service_worker` entries are supported through a sandboxed, non-persistent Aegis background host. MV3 service workers are emulated as a persistent hidden host, so Firefox/Chromium service-worker lifecycle semantics are not identical. Custom `background.page` HTML remains unsupported and is reported explicitly. Aegis also withholds or does not yet implement powerful APIs including blocking webRequest, declarativeNetRequest, extension-owned proxy replacement, native messaging, history access, extension management, and broad cookie-store access.

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

Each installed extension is assigned its own isolated-world ID. The renderer preload binds the IPC bridge to that extension identity, so one content-script world cannot request storage or APIs as another extension merely by changing an ID argument. Installing, enabling, disabling, or removing an extension rebuilds active tab renderers so the new privilege map is applied before extension scripts execute.


## Content-script timing

Aegis honors `document_end` at Electron's DOM-ready phase and `document_idle` after the document finishes loading. Electron does not provide this compatibility runtime with Firefox-equivalent pre-page-script `document_start` injection into the same isolated world, so `document_start` currently falls back to DOM-ready and generates a compatibility warning. Aegis does not count that package as fully compatible.

Relative `url(...)` references in extension CSS are rewritten to the private `aegis-extension://` resource origin so packaged images/fonts continue to resolve without exposing local filesystem paths.


## Package installation vs runtime compatibility

Runtime 5 treats installation and execution compatibility as separate facts. A valid CRX, XPI, ZIP, or unpacked WebExtension is installed as a complete package after review. The compatibility percentage reports Aegis API/runtime coverage; it is not an installation-progress percentage.

Chrome CRX identity is taken from the verified CRX signature before any Gecko identity embedded in a cross-browser manifest. Firefox/XPI packages continue to use their Gecko identity. Localized manifest placeholders such as `__MSG_name__` and `__MSG_description__` are resolved from package locale files for review and display.

Aegis does not claim unsupported APIs work. Current engine limitations remain visible in the review so users can distinguish “installed successfully” from “every requested browser API behaves exactly like upstream Chrome or Firefox.”
