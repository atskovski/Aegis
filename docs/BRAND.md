# Aegis Brand System

## Brand idea

Aegis is **protective infrastructure made visible**. The visual system combines a shield, an A-shaped gate, and a small protected core. It should feel premium, calm, and technical—not militaristic or cyberpunk.

**Tagline:** Browse with proof.  
**Support line:** Private by default. Verifiable by design.

## Logo use

- `assets/brand/aegis-mark.svg` — standalone shield mark for app icon, toolbar, avatars, favicons.
- `assets/brand/aegis-wordmark.svg` — text-only wordmark.
- `assets/brand/aegis-lockup.svg` — mark + wordmark + descriptor.
- `assets/brand/aegis-mark-mono.svg` — one-color version for monochrome surfaces.

Keep clear space around the mark equal to at least one quarter of the shield width. Do not stretch, skew, add glow-heavy effects, or place the mark on low-contrast imagery.

## Color tokens

Machine-readable CSS tokens are also provided in `assets/brand/tokens.css`.


| Token | Hex | Role |
|---|---|---|
| Aegis Night | `#070A12` | Primary background |
| Citadel | `#111827` | Cards and panels |
| Rampart | `#26334A` | Borders/dividers |
| Signal Cyan | `#4ED9FF` | Primary interaction |
| Guardian Teal | `#4FE1C1` | Protected/pass |
| Ultraviolet | `#8A72FF` | Intelligence/secondary accent |
| Amber | `#F1C76A` | Warning |
| Sentinel Red | `#FF6F8F` | Failure/high risk |
| Ice | `#F4F7FB` | Primary text |
| Steel | `#9AAAC0` | Secondary text |

## UI typography

Use platform UI fonts rather than bundling a custom font:

`-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif`

Default Aegis text scale is **Large**. Small technical labels may be compact, but essential settings, evidence, and permissions must remain readable without zoom.

## Shape language

- 10–20 px panel radii.
- Thin high-contrast borders rather than heavy shadows.
- Cyan/teal reserved for interaction and verified protection.
- Amber and red reserved for warnings/failures.
- Avoid an all-green UI; green/teal should mean something.

## Voice

Good: “System routing is active. Destination sites can observe the route's public IP.”  
Avoid: “You are anonymous.”

Good: “Camera access can expose live video from your device.”  
Avoid: “This site is spying on you.”

Good: “WebGL debug renderer information is unavailable to this page.”  
Avoid: “Fingerprinting defeated.”
