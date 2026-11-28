# Cross-platform app release standard

This repository is included in the standing cross-platform app rollout.

## Required project-specific install targets
- Android: APK/AAB
- iOS/iPadOS: IPA and App Store / TestFlight
- macOS: signed and notarized app
- Windows: installer/MSIX or executable
- Linux: AppImage/deb/rpm
- Web: installable PWA where a browser UI exists

Repository: `gaussa72-boop/Quantum-Shield`

## Engineering requirements
- Inspect the existing framework, routes, APIs, build commands, authentication and deployments before implementation. Preserve the existing app; do not replace it with a generic wrapper.
- Use Capacitor for suitable web-based mobile apps, Tauri for suitable desktop apps, and a PWA for web installation. Use native OS modules when needed.
- Preserve this project's own branding, AI persona, data, accounts, permissions, payment paths, and integrations. Do not merge independent products or user databases.
- Provide responsive/adaptive UI, safe areas, keyboard and accessibility support, deep links, secure credential storage, error/offline states and update handling as appropriate.
- Add icons, splash screens, privacy disclosures, support links, CI build jobs, and store metadata after reviewing the real app and required credentials.
- Run tests and produce each installer before marking a target complete. Never claim a signed package, successful deployment, or store approval without verifiable evidence.
- Keep secrets out of Git; use environment/secret stores. Check root causes, protect data, and verify deploy health after changes.

## Release evidence
This file defines the rollout requirement only. Append real artifact paths, checksums, build IDs, test results and deployment URLs after verification. No signed packages or store approvals are asserted by this file.

## ULTIMA operations
Register this project in the central ULTIMA project/update inventory while respecting its independent product and account boundaries.
