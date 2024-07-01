# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

* Moved the `LocalFree()` call of the `DroppablePointer` into `drop()`. This will panic in debug mode on error

### Removed

* Remove `local_free()` from private API

## [0.1.1] - 2024-06-30

### Added

* Update `Cargo.toml` to use a license specifier instead of the `license-file` directive
* Added note that the crate is Windows only to the readme

## [0.1.0] - 2024-06-30

Initial Release

[unreleased]: https://github.com/jschpp/laps-rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jschpp/laps-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jschpp/laps-rs/releases/tag/v0.1.0