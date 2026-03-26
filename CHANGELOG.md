# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Complete MVP: VCL application generating CycloneDX 1.5 JSON SBOMs from Delphi projects
- Project parser: extracts unit list from `.dpr`, version/platform/search paths from `.dproj`
- RTL scanner: auto-detects Delphi installation from registry, scans `.dcu` files
- Unit classifier: RTL/VCL, third-party (exact + prefix matching), own code, unclassified
- SBOM builder: CycloneDX 1.5 JSON with PURL, licence, supplier metadata
- Automatic library discovery: scans file system for unclassified units, groups by directory,
  extracts vendor from source headers, detects licence from LICENSE files
- One-click "Save Libraries & Regenerate SBOM" to update components.json and re-run
- Background threading for UI responsiveness during scanning
- Auto-creation of default components.json when missing
- Delphi version mapping (MSBuild ProjectVersion → product version)
- Repository documentation: README, CLAUDE.md, SCHEMA.md, CYCLONEDX-NOTES.md

### Changed
- PURL name and version segments now URL-encoded per RFC 3986
- Unresolved IDE environment variable paths logged as warnings instead of silently skipped
- `IsValidUnitName` rejects malformed scoped names (leading/trailing dots, consecutive dots)
- Malformed `components.json` array entries skipped gracefully instead of raising cast errors
- EurekaLog `.eof` config files added to `.gitignore`
- Dead `FFoundDirs` field removed from `uLibraryDiscovery`

### Fixed
- UUID braces stripped from SBOM serialNumber
- Project version fallback to VerInfo_Keys when individual elements absent
- Project directories (containing .dpr/.dproj) excluded from library discovery
- Unit prefix computed from all .pas files in directory, not just unclassified ones
- Copyright symbol (©) and en-dash (–) handled in vendor extraction
- Own-code detection from .dpr `in` file references
- Auto-detection of own code from sibling project directories
- "Mark Unresolved as Own Code" button for remaining unresolved units
- `own_code_units` array in components.json for persistent own-code tracking
- Delphi IDE environment variables resolved for library path discovery
- Horizontal splitter between results and log panels
- Busy cursor during SBOM generation
- Vendor name parenthesis cleanup (e.g. Ethea S.r.l)
- Generic directory names use parent for display (e.g. "EurekaLog 7 - Source")
- Scoped and unscoped .pas filenames searched (finds Vcl.StyledTaskDialog.pas)
- View SBOM File button — inspect generated JSON in a read-only viewer
- Optional SynEdit integration (USE_SYNEDIT) for syntax-highlighted JSON viewing
- Smart library naming from .dpk package files (StyledComponents, EurekaLogCore)
- Nested library directory merging (EurekaLog Source + Extras → single entry)
- Scoped unit names matched against manifest exact/prefix entries
- "by " prefix stripped from vendor names
- Empty version no longer produces trailing @ in PURL
