# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- Form close crash: added `FormCloseQuery` guard to prevent closing during background processing
- `.dproj` metadata parser now reads from Base (unconditioned) PropertyGroup, avoiding
  config-specific version number overrides (Win32 Debug vs Win64 Debug)
- Uses clause parser strips comments before searching for `uses` keyword, preventing
  matches inside line comments or block comments
- Uses clause parser handles semicolons inside string literals (file path references)
- `SaveDiscoveredLibraries` now checks for existing components by name before adding,
  preventing duplicates on repeated Save+Regenerate
- Output directory validated before writing SBOM file, with clear error message on failure
- ManifestPath resolution logic deduplicated in `uSBOMEngine` (was computed twice)
- Stale per-project INI sections cleaned up when MRU list is saved
- Documentation version footers synchronised between Help.md and UsersGuide.md

### Changed
- Removed internal company/project references from all source files and documentation
- `.gitignore` comment corrected: `.eof` files identified as EurekaLog config (not IDE files)
- Sample `components.sample.json`: Indy units moved from `units_prefix` to `units_exact`
  (prefix "Id" is only 2 characters, below the MinPrefixLength=3 threshold)

## [1.0.0] - 2026-03-26

### Documentation
- User's Guide: expanded "Subsequent Runs" section to explain stateless regeneration model,
  covering adding, removing, and updating dependencies, and dormant `components.json` entries
- User's Guide: added note to "Keeping the SBOM Current" reinforcing safe, idempotent regeneration

### Changed
- Engine now logs an `[INFO]` message for each `components.json` entry not referenced by any
  project unit, making dormant entries visible without removing them

### Added
- Project MRU (Most Recently Used) dropdown — recent projects available from a combo box,
  with per-project manifest, output dir, and version override restored automatically
- Settings persisted to `%APPDATA%\DelphiSBOM\DelphiSBOM.ini` (INI format, max 10 entries)
- New unit `uSettings.pas` — `TMRUManager` class for MRU persistence
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
