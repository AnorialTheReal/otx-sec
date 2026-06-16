# Changelog

## 0.1.1-alpha

### Changed
- Removed ClamAV from the core scan flow.
- Removed YARA from the native core.
- Native OTXv2 engine is now the main detection layer.
- OTX, VirusTotal and MalwareBazaar remain reputation checks only.
- Manual backend scans now use internal analysis instead of external scanners.

### Added
- Native entropy scoring.
- Native suspicious marker detection.
- Native ELF/PE checks.
- Executable permission checks.
- Script/shebang detection.
- Allowlist and blocklist support.

### Fixed
- Removed external antivirus dependency from core scan reports.
- Cleaned documentation to match the native engine direction.
