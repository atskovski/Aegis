# Privacy Control Enforcement Contract

Aegis privacy settings are not considered complete when a checkbox exists. Each advertised control has an enforcement layer and a runtime evidence state.

## States

**ENFORCED** — the user enabled the control and Aegis confirmed the applicable enforcement path is installed for the current tab/session.

**DEGRADED** — the user enabled the control, but Aegis cannot currently confirm the required document/session enforcement path. This is intentionally visible and must never be presented as protected.

**DISABLED** — the setting is off.

The Security Suite additionally uses behavioral PASS / WARNING / INFO / FAIL / NOT TESTED results. Runtime enforcement and behavioral verification are related but different: a handler can be installed correctly while a behavioral probe may still expose an engine limitation.

## Layers

- network-firewall — main-process request cancellation/classification
- network-headers — request/response header rewriting
- document-css — user-origin cosmetic filter CSS
- document-preload — new-document anti-fingerprinting/privacy API guards
- navigation — URL cleaning, redirect unwrapping, HTTPS-first and destination analysis
- download-policy — will-download gate and risky-file controls
- session-lifecycle — ephemeral storage and cleanup
- sentinel — local observation and evidence presentation

## Release rule

A privacy control may ship as user-facing production functionality only when:

1. its settings value is sanitized/persisted;
2. its enforcement path consumes that value;
3. disabling/enabling changes behavior;
4. Diagnostics can report whether the enforcement path is active;
5. a regression test covers the contract;
6. failures are visible rather than silently converted to protected.

This contract exists specifically to prevent a security UI from becoming a collection of decorative toggles.