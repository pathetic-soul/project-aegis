# Project Aegis Design System

## Direction

Forensic laboratory light table. The interface treats every document, signature, and ledger block as inspectable evidence. The visual world is calm, institutional, and exact rather than theatrical.

## Modes

- Landing page: Persuade. Prove the mechanism quickly and route evaluators into the demo.
- Login and workspaces: Operate. Make role boundaries and the next permitted action unmistakable.

## Tokens

- Background: ink navy `#050d16`
- Elevated surface: deep slate `#0b1926`
- Paper: cool off-white `#f2f5f8`
- Primary text: `#eef4fb`
- Secondary text: blue gray `#98a9ba`
- Accent: signal blue `#1b67d0`
- Success: `#38c69b`
- Warning: `#f1a15b`
- Failure: `#ed6a78`
- Radius: 14px for surfaces, 10px for controls, pill only for compact status
- Display type: system sans with tight tracking and strong weight
- Data type: system monospace only for identifiers, hashes, and cryptographic measurements

## Composition

- Desktop landing uses an asymmetric split hero with a real forensic-document photograph.
- Product workspaces use a stable top bar and one dominant task surface per role.
- Authentication stays within the same dark visual world, with the form separated by structure rather than a light-theme panel.
- Grouping uses spacing and quiet borders. Cards appear only for distinct interactive tasks.
- The page remains dark across every route.

## Interaction

- One first-visit entry sequence reveals the hero copy and evidence image, followed by a single scan pass.
- Selected landing-page sections reveal once as they enter the viewport. Repeated operational screens remain static.
- Buttons compress slightly on activation.
- Hover motion is limited to fine-pointer devices and clear action feedback.
- At compact widths, primary navigation becomes one keyboard-accessible disclosure menu with Escape-to-close behavior.
- PDF controls confirm the selected filename and local file size before submission.
- Long verification values expose a compact copy action without changing the evidence text.
- Motion uses transform and opacity only. All nonessential motion is disabled under `prefers-reduced-motion`.

## Voice

Use direct operational language: distribute, decrypt, sign, commit, investigate, verify. Avoid exaggerated security claims. Distinguish exact-copy verification from marker-only evidence.
