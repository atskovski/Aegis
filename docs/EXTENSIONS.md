# Aegis Extensions Architecture

## Goal
Aegis must not claim that a Firefox XPI is supported merely because it can be unzipped. A Firefox add-on depends on WebExtensions APIs implemented by Gecko. The current Electron/Chromium engine does not implement Firefox's full extension runtime.

## Two-runtime model

### Aegis WebExtensions Compatibility Runtime
The Chromium/Electron edition accepts WebExtension packages only after manifest analysis. It can support a bounded capability set such as content scripts, styles, local storage, active-tab operations, limited tab APIs, context menus, notifications and commands. Unsupported permissions are rejected before installation.

The extension manager reports one of:
- **Compatible** — every requested capability has an Aegis backend.
- **Requires Gecko** — valid WebExtension/XPI, but it requests Firefox APIs or background/runtime behavior Aegis Chromium does not implement.
- **Invalid** — malformed or unsafe package.

Aegis does not silently ignore missing APIs.

### Gecko edition
True arbitrary Firefox XPI compatibility is a separate engine target based on Mozilla's Gecko/Firefox WebExtensions implementation. This is the production route for extensions that require Firefox-specific APIs, background execution semantics, contextual identities, proxy APIs, native messaging, or other Gecko-owned capabilities.

## Security model
Extensions are privileged code. Installation must show:
- extension name/version/id;
- requested host access;
- requested browser capabilities;
- whether it can read/change all pages;
- whether it runs in private browsing;
- persistent storage use;
- unsupported capabilities;
- package source and SHA-256.

Extension permissions are independent from normal site permissions. An extension cannot silently weaken Aegis's process sandbox, certificate policy, updater, or internal `aegis://` pages.

## Private tabs
Electron only loads its native extension API into persistent sessions, while Aegis private tabs intentionally use non-persistent sessions. Therefore the compatibility runtime injects only capabilities that Aegis itself implements into ephemeral tabs. A persistent extension host must never be treated as the tab's cookie/storage session.

## Non-goal
“Install succeeded” is not evidence of compatibility. Aegis will reject rather than pretend when the active engine cannot fulfill the manifest.
