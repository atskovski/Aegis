# Security Test Matrix

This matrix maps common browser-security test families to Aegis controls. Passing a third-party score is not treated as proof of anonymity; the purpose is to make failures actionable.

| Test family | What Aegis verifies/controls | Expected Aegis evidence | Boundary |
|---|---|---|---|
| Public IP / IP leak | Routed public IP lookup through Chromium session | Security Suite observed IP + provider + route mode | A normal/system route exposes that route's public IP |
| DNS leak | SOCKS/Tor diagnostics skip local `resolveHost`; HTTPS request exercises proxied route | Diagnostics states local DNS probe was skipped for SOCKS | OS/VPN DNS behavior outside Aegis is not controlled |
| WebRTC leak | Chromium non-proxied UDP disabled globally; WebRTC API removed in Anonymous | Behavioral candidate test or 'surface removed' | Normal WebRTC still exposes the configured route's public IP |
| TLS / SSL | TLS 1.2 minimum, TLS 1.3 allowed, invalid certificates fail closed | Runtime policy + connection result | Chromium TLS/JA3/JA4 characteristics remain observable |
| Tracking ads | main-process domain/category filter + heuristic rules + cosmetic CSS | blocked counts, host ledger, enforcement status | Filter coverage changes as ad-tech changes |
| Invisible trackers | third-party tracker filtering, beacon/ping guard, cookie stripping, referrer reduction | Sentinel network ledger | First-party tracking can require heuristic detection |
| Third-party cookies | request Cookie and response Set-Cookie stripping | Runtime enforcement + blocked-cookie count | Compatibility mode can relax this in ordinary tabs |
| GPC / DNT | Sec-GPC/DNT request headers and JavaScript-visible signals | behavioral + runtime evidence | Sites may ignore preference signals |
| Canvas | cohort perturbation in Strict; placeholder readout in Maximum | fingerprint preload evidence | Rendering differences can still exist outside guarded readback paths |
| WebGL | debug renderer hidden; cohort readback perturbation; WebGL disabled in Maximum | behavioral debug exposure test | Strict keeps WebGL for compatibility |
| Fonts | local-font permission blocked; font-enumeration metric normalization | CSS font test | Layout/font rendering cannot be made universally identical |
| Audio | cohort readout perturbation | fingerprint preload evidence | Hardware/engine timing can expose residual entropy |
| Screen / DPR | standardized values plus browser letterboxing | behavioral screen test | Window geometry and rendering behavior can still vary |
| Client hints / UA | generic Chromium UA, reduced high-entropy client hints, no Aegis token | product identifier test | Chromium major version is still intentionally visible |
| Local-network exposure | anonymous mode blocks localhost, .local, RFC1918, CGNAT, link-local and ULA literals | compartment test + block counter | DNS names resolving to internal resources must remain routed through the anonymity proxy |
| Extensions | per-extension isolated worlds, permissions review, host-permission-limited background HTTP(S) | Add-ons compatibility/risk report | Electron cannot provide universal Firefox XPI semantics |
| Downloads | risky downloads blocked globally; all downloads blocked by default in Anonymous | download policy evidence | User can intentionally use an ordinary tab to download |
| Browser update/version | version shown in About; CI hardening checks source | release pipeline evidence | Automatic signed updater remains a production release gate |
| Port/firewall scans | Not a browser-layer control | N/A | Host/router firewall must be tested separately |

## Release principle

A third-party test that reports a failure becomes a release input. Aegis should either (a) implement a real mitigation and a regression test, or (b) document why the result is an engine/network/OS boundary. It must not turn a failing benchmark into a green UI status by relabeling the test.