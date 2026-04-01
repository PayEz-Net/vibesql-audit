# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-02-16

### Added
- Phase 1: C extension with PostgreSQL hook scaffold, UDP event emission, SQL schema, CI pipeline, and deploy tooling
- Phase 2: Rust forwarder sidecar with hash-chain integrity, batch writer, GELF log forwarding, and health endpoint
- Phase 3: WAL-based JSONB change capture with sensitive field detection
- PostgreSQL extension documentation in README

### Fixed
- Review round 8: assorted code quality fixes across extension and forwarder
- Review round 12: JSON escape handling in hooks, removed unused `wal_publication` config, fixed retry queue capacity bypass
