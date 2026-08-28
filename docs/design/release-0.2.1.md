# Yonder 0.2.1 Release Correction

## Status

`0.2.1` is the first deployable release of the enterprise feature set defined by the `0.2.0` design contract. The published `0.2.0` build is withdrawn and must not be deployed because a controller could start OAuth twice during strict relay-only fallback and persistent audit identity permissions were validated only after enterprise authorization.

GitHub immutable releases permanently reserve a published tag name even after the release and tag are deleted. Consequently, `v0.2.0` cannot be restored or replaced; the corrected release is `v0.2.1`.

## Changes From The Withdrawn Build

- Enterprise resolve is performed at most once per `yon connect` command. A strict relay-only rebuild verifies the same enterprise relay and reuses only the in-process resolved target while creating a fresh endpoint PeerId and repeating end-to-end OPAQUE authentication.
- Controller and host preflight persistent audit storage before relay connection, browser authorization, locator registration, or connection-code display. The audit handshake still performs the authoritative second check for TOCTOU changes.
- Windows and Unix use the same fail-closed product semantics for invalid audit ownership or permissions. Feishu and WeCom share the one-browser-opener regression contract.
- Windows invalid destination file names are classified before the operating-system commit call, making synchronous and asynchronous no-replace commits deterministic.
- The production and fuzz lockfiles use the non-yanked compatible `chacha20 0.10.2`; direct dependencies, enabled features, wire protocols, resource limits, and product scope are unchanged.

## Evidence And Recovery Boundary

Commit `c4bfc88287b6668487dcf3bdc644997e1c5cb850` passed CI run `33153546109` and Release candidate run `33153563784`. The CI evidence includes six native/MSRV targets, five independent coverage targets, Miri, ASan/TSan, supply-chain gates, and four parallel five-minute fuzz targets. The candidate evidence includes release stress, the real network matrix, three-platform performance/resource gates, six-platform static release builds, SBOMs, licenses, checksums, and provenance.

The `0.2.1` recovery may change only first-party package versions, internal exact version constraints, mechanically derived lockfile entries, release recovery automation, and documentation. `.github/scripts/verify-version-only-recovery.py` compares TOML structures across the approved base and rejects source, external dependency, feature, or resolved dependency changes. Only version-bound binaries, archives, SBOMs, checksums, licenses, and provenance are regenerated.

## Deployment

Do not mix `0.2.0` into an enterprise deployment. Upgrade `yon`, host-side `yon`, and `yon-relay` to `0.2.1` in the same change window, then perform the real-tenant provider acceptance tests required by the operations manual. Standard-mode wire compatibility with `0.1.1` remains as specified by the original contract.
