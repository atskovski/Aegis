# Aegis Anonymity & Compartment Model

## Goal

Aegis reduces linkability and attack surface with browser-owned security domains. It does not claim perfect anonymity. The anonymous compartment is a fail-closed mode for users who already operate a local Tor SOCKS service; it is not a replacement for Tor Browser or Tails.

## Design influences

### Qubes OS: security by compartmentalization
Aegis treats ordinary private tabs, hardened tabs and anonymous tabs as different security domains. A hardened/anonymous transition changes backend policy, not only UI state. Each tab already uses its own non-persistent Chromium partition; the security-domain layer additionally changes permissions, content APIs, networking, extensions and lifecycle policy.

### Tails: amnesic workflow and LAN isolation
Anonymous tabs use memory-only partitions, block local/private-network destinations, remove persistent site exceptions and block downloads by default. The intent is to reduce accidental crossover between anonymous activity and the host/local network.

### Tor Browser: uniformity over arbitrary randomization
Fingerprint defenses favor standardized/cohort values for Strict/Maximum/anonymous profiles. Per-install random noise can itself become a stable identifier, so Aegis avoids using a user-specific seed for those profiles. Maximum/anonymous also remove or disable additional high-entropy surfaces.

## Security domains

### Private
- unique non-persistent tab partition
- sandbox/context isolation/Node disabled
- normal configured privacy profile
- installed extensions may run subject to Aegis extension boundaries

### Hardened
- Maximum fingerprint profile
- all third-party requests blocked
- extensions excluded from the tab
- service-worker registration disabled
- sensitive permissions blocked
- HTTPS downgrade disabled
- compatibility mode disabled
- existing cookies/storage/cache/service-worker data cleared before reload
- renderer rebuilt so new-document protections actually take effect

### Anonymous
Everything in Hardened, plus:
- SOCKS5 route dedicated to the tab
- route must be verified as Tor by the Tor Project by default
- fail closed when verification fails
- local/private network destinations blocked
- WebRTC APIs removed
- JavaScript disabled by default
- downloads blocked by default
- extensions excluded
- no persistent site-permission exceptions
- no fireproofed origins
- local DNS diagnostic probes skipped so Aegis diagnostics do not create a separate resolver lookup

## Why Aegis does not claim 'zero fingerprint'

A fingerprint test compares a browser against a population. A small browser population can remain distinctive even when many surfaces are normalized. Aegis can reduce stable entropy, hide product identifiers, standardize APIs and block common probes, but it cannot make an Electron/Chromium TLS stack indistinguishable from Tor Browser's Firefox-based population.

## Why the anonymous compartment is not Tor Browser

Tor Browser modifies Firefox and browser behavior as a coherent anonymity system. Routing a different browser through Tor can expose a different browser fingerprint and behavioral surface. Aegis therefore requires route proof and applies stronger local restrictions, but still labels the mode honestly as an Aegis anonymous compartment—not Tor Browser equivalence.

## Fail-closed rules

1. Invalid TLS certificates are rejected; no certificate click-through is provided.
2. Tor verification failure prevents anonymous browsing.
3. Fixed-proxy setup failure does not fall back to direct/system networking.
4. HTTP fallback is unavailable in hardened/anonymous compartments.
5. Anonymous diagnostics skip direct DNS resolution.
6. Local/private-network targets are rejected in anonymous mode.
7. Downloads and JavaScript default to blocked in anonymous mode.

## Remaining 1.0/1.1 release gates

- native macOS end-to-end BrowserLeaks/Cover Your Tracks reruns
- signed/notarized macOS build
- independent security review
- reproducible update/signature pipeline
- broader extension-package compatibility corpus
- external DNS/WebRTC/IP leak validation using real Tor and VPN routes
- TLS/HTTP2/HTTP3 fingerprint review
- accessibility and UI failure-state audit