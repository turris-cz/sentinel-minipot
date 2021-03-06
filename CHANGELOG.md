# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2021-12-14
### Added
- Gitlab CI
- `libevent_logc` and `libczmq_logc` as dependency

### Changed
- Repository layout
- Minimal version of LogC to 0.2.0
- SMTP minipot: split received username string to username and domain
- integration tests: check timestamp value

### Fixed
- Out of source tree build


## [2.2] - 2021-03-04
### Added
- Pipeline integration tests
- Doc comments
- Throughput integration tests
- Logging

### Removed
- Manual proxy - moved to Proxy repo
- Minipots doc - moved to internal wiki

### Changed
- Update README
- Update integration tests doc
- Update Minipots doc
- Send invalid Sentinel message if missing username
- HTTP minipot - limit announced version
- HTTP minipot - make user agent optional part of Sentinel message

### Fixed
- Debug prints
- HTTP content length parsing
- SMTP SASL mechanism field name


## [2.1.0] - 2020-12-15
### Added
- Server data check
- Unit tests
- Scripts for easy test setup

### Changed
- Integration tests refactored
- Sentinel messages formats


## [2.0.1] - 2020-08-03
### Fixed
- Telnet getting stuck with specific control sequence being received


## [2.0.0] - 2020-07-27
### Added
- Minipot for HTTP protocol
- Minipot for FTP protocol
- Minipot for SMTP submission protocol

### Changed
- Argument parsing
