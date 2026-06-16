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

## 0.1.1-alpha

### Antivirus Focus
- Clarified that OTX-Sec is being developed as an open-source Linux antivirus.
- Added README section for current and future antivirus capabilities.

### Scanner
- Improved native Linux malware heuristics.
- Added single-file scan mode.
- Restored daemon mode as default service behavior.
- Added native scan details to reports.

### YARA
- Added Linux-first YARA detection rules.
- Added reverse shell test sample.
- Added rules for Linux persistence, downloader behavior, base64 execution, and LD_PRELOAD hijacking.

### Threat Intelligence
- Kept AlienVault OTX, VirusTotal, MalwareBazaar, and URLHaus as reputation providers.
- Documented that provider errors and missing API keys must not crash the scanner.

### GUI
- Added native engine details to event summaries.

### Cleanup
- Removed ClamAV from the core scan flow.
- Kept author metadata as Anorial.
- Updated README development hours to 68.
