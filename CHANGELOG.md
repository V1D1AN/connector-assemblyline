# Changelog

## [1.1.0] - 2026-02-26

### Added
- **Sequential Mode**: New `ASSEMBLYLINE_SEQUENTIAL_MODE` option (enabled by default) that checks if AssemblyLine has active analyses before submitting a new file, preventing platform overload
- New `_wait_for_al_ready()` method that queries `state:submitted` on AL submission index
- Configurable poll interval (`ASSEMBLYLINE_POLL_INTERVAL`, default: 30s)
- Logs with `[Sequential]` prefix when waiting for AL to be idle

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2024-01-25

### Added

- Initial release of OpenCTI AssemblyLine Connector
- Automatic file submission to AssemblyLine for analysis
- Intelligent caching - reuses existing AssemblyLine analysis results
- Automatic retry mechanism for files still being uploaded
- Malicious IOC extraction (domains, IPs, URLs)
- STIX Indicator creation with proper patterns
- Observable creation with "based-on" relationships to Indicators
- Malware family detection and Malware object creation
- MITRE ATT&CK technique extraction and Attack Pattern creation
- Malware Analysis SDO creation (STIX 2.1)
- Author attribution to "AssemblyLine" identity
- Configurable suspicious IOC inclusion
- File size limit configuration
- Comprehensive note creation with analysis summary
- Docker and Docker Compose support
- Full configuration via environment variables or YAML file

### Configuration Options

- `ASSEMBLYLINE_URL` - AssemblyLine instance URL
- `ASSEMBLYLINE_USER` - AssemblyLine username
- `ASSEMBLYLINE_APIKEY` - AssemblyLine API key
- `ASSEMBLYLINE_VERIFY_SSL` - SSL verification toggle
- `ASSEMBLYLINE_SUBMISSION_PROFILE` - Submission profile selection
- `ASSEMBLYLINE_TIMEOUT` - Analysis timeout configuration
- `ASSEMBLYLINE_FORCE_RESUBMIT` - Force reanalysis option
- `ASSEMBLYLINE_MAX_FILE_SIZE_MB` - File size limit
- `ASSEMBLYLINE_INCLUDE_SUSPICIOUS` - Include suspicious IOCs
- `ASSEMBLYLINE_CREATE_ATTACK_PATTERNS` - MITRE ATT&CK toggle
- `ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS` - Malware Analysis SDO toggle
- `ASSEMBLYLINE_CREATE_OBSERVABLES` - Observable creation toggle

### Supported Observable Types

- Artifact
- StixFile

### Created Object Types

- Indicator (Domain-Name, IPv4-Addr, IPv6-Addr, URL patterns)
- Observable (Domain-Name, IPv4-Addr, IPv6-Addr, URL)
- Malware (family detection)
- Attack Pattern (MITRE ATT&CK)
- Malware Analysis (STIX 2.1 SDO)
- Note (analysis summary)
- Relationship (related-to, based-on, uses, communicates-with)

---

## Version History

- **1.0.0** - Initial release with full feature set
