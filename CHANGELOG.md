# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-08-09

### Fixed

- `repository` pointed at `github.com/BinFlip/inno-rs`, which does not exist. Every
  published version so far has carried a dead repository link on crates.io. It now points
  at the real repository, `github.com/ATRAPSLLC/innospect`.

### Changed

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. No functional change.
- Dropped the deprecated `authors` field.
- Raised the `pascalscript` minimum to 0.1.2. `Container` is re-exported publicly, so that
  release's backward-branch resolution fix is part of this crate's effective API surface.
- Refreshed remaining dependencies (`cargo update`); `bitflags` moved to 2.13.1.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.1.2] - 2026-07-06

### Fixed

- Header string-table parsing for Inno Setup 6.4.3+ installers that carry a
  `[Code]` section (or non-empty license/info text) no longer fails with
  `invalid UTF-16LE in CloseApplicationsFilterExcludes`. The `String` fields
  added since 6.3.0 (`CloseApplicationsFilterExcludes`, `SevenZipLibraryName`,
  `UsePrevious*`) are now read ahead of the `AnsiString` tail, matching
  `TSetupHeader`'s all-strings-then-all-ansistrings serialization
  (GitHub [#1](https://github.com/ATRAPSLLC/innospect/issues/1)).

### Added

- Codepage-aware string decoding via `LanguageCodepage::decode`: UTF-16LE for
  modern Unicode builds and Windows ANSI code pages (cp1251 / cp1252 / cp932 / …)
  for legacy installers, with a lossy replacement fallback for unmappable pages.
  `LanguageEntry` name / language-name accessors now decode through it.
- Public `from_raw` inverse constructors on record enums, for reconstructing
  typed values from stored raw discriminants: `FileEntryType`, `SignMode`,
  `Bitness`, `DeleteTargetType`, `CloseOnExit`, `RunWait`, `SetupTypeKind`,
  `RegistryHive`, `RegistryValueType`, and `LanguageCodepage`.

### Changed

- Bumped dependencies: `bitflags` 2.11.1 → 2.13.0, `goblin` 0.10.5 → 0.10.7,
  `chacha20` 0.10.0 → 0.10.1.

### Added (dependencies)

- `encoding_rs` 0.8.35 and `codepage` 0.1.2, for the codepage-aware decoding above.

## [0.1.1] - 2026-06-09

- Initial published release.

[0.1.3]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ATRAPSLLC/innospect/releases/tag/v0.1.1
