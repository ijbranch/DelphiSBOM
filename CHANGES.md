# DelphiSBOM — Change Log

All project changes are documented here in reverse chronological order.

## 2026-03-27 - Second Audit Pass: 5 Additional Fixes

**Problem:** Follow-up audit of post-fix codebase found 3 medium and 2 low issues.

**Changes Made:**
1. **uSBOMBuilder.pas** — `supplier.url` array now emitted in metadata when
   `supplier.url` is present in components.json (CycloneDX data was being dropped)
2. **uSBOMBuilder.pas** — `licence_url` now emitted as `license.url` field in
   each component's licence object (CycloneDX data was being dropped)
3. **uMainForm.pas** — `AutoPopulateDefaults` now checks directory exists before
   attempting to create default manifest; wrapped in try/except for robustness
4. **uProjectParser.pas** — Removed dead compiler directive stripping loop from
   `SplitUnitNames` (now handled by `StripComments` upstream)
5. **uMainForm.pas** — Added outer loop `Break` in `DisplayDiscoveredLibraries`
   and `GetUnresolvedUnits` for early exit once a unit is found

**Result:** Clean compile on Win64 Debug. CycloneDX output now includes all
user-provided licence and supplier URLs.

**Files Modified:** uSBOMBuilder.pas, uMainForm.pas, uProjectParser.pas

## 2026-03-27 - Code Audit: 18 Issues Identified and Fixed

**Problem:** Comprehensive code audit of all 10 source units revealed 2 critical,
4 high, 5 medium, and 7 low severity issues. 6 additional reports were verified
as false positives and dismissed.

**Changes Made:**

1. **uMainForm.pas** — Added `FormCloseQuery` handler to prevent form closure
   while background thread is processing (critical: use-after-free AV).
   Wired via `OnCloseQuery := FormCloseQuery` in `FormCreate`.

2. **uProjectParser.pas** — Replaced blind `FindNodeText` DFS with new
   `FindBasePropertyValue` that searches unconditioned `<PropertyGroup>` elements
   first (Base config), falling back to conditioned groups. Prevents reading
   version info from the wrong build configuration.

3. **uProjectParser.pas** — Added `StripComments` helper function that removes
   `//`, `{...}`, and `(*...*)` comments while preserving string literals.
   `ExtractUsesBlock` now: strips comments before searching, checks word
   boundaries for the `uses` keyword, and skips semicolons inside string
   literals when finding the uses clause terminator.

4. **uManifestLoader.pas** — `SaveDiscoveredLibraries` now checks for existing
   components by name before adding, preventing duplicates on repeated
   Save+Regenerate operations.

5. **uSBOMBuilder.pas** — `BuildAndSave` validates output directory exists before
   `TFile.WriteAllText`, with descriptive error messages on failure.

6. **uSBOMEngine.pas** — ManifestPath resolution extracted to single computation
   at the top of `Execute`, removing duplicated logic at lines 89 and 170.

7. **uSettings.pas** — `Save` now enumerates all INI sections and erases
   orphaned `MRU:*` sections before writing current entries. Added
   `System.Classes` to implementation uses for `TStringList`.

8. **All source files** (11 files) — Removed internal company name from copyright
   headers. Internal project names redacted from `PROGRESS.md`. Internal
   references cleaned from plan documents and `Docs/UsersGuide.md`.

9. **Docs/Help.md, Docs/UsersGuide.md** — Version footers synchronised.

10. **Samples/components.sample.json** — Indy entry moved from `units_prefix`
    to `units_exact` (prefix "Id" is 2 chars, below MinPrefixLength=3).

11. **.gitignore** — Corrected comment: `.eof` files are EurekaLog config, not IDE files.

**Result:** Clean compile on Win64 Debug. All code fixes verified by build.
One remaining issue (#6 — .dproj version number inconsistency across configs)
requires manual synchronisation in the Delphi IDE.

**Files Modified:** uMainForm.pas, uProjectParser.pas, uSBOMBuilder.pas,
uSBOMEngine.pas, uManifestLoader.pas, uSettings.pas, uTypes.pas,
uUnitClassifier.pas, uRTLScanner.pas, uLibraryDiscovery.pas, DelphiSBOM.dpr
(copyright only), PROGRESS.md, Help.md, UsersGuide.md,
components.sample.json, .gitignore, DelphiSBOM_Refined_Plan.md,
Delphi_SBOM_PLAN.md

## 2026-03-26 - Dormant Manifest Entry Logging

**Problem:** Users had no visibility into `components.json` entries that were
no longer referenced by any project unit (e.g. after removing a library).

**Changes Made:**
1. `uSBOMEngine.pas` — Engine now logs an `[INFO]` message for each
   `components.json` entry not referenced by any project unit
2. User's Guide expanded "Subsequent Runs" section: stateless regeneration
   model for adding, removing, and updating dependencies
3. User's Guide added "Keeping the SBOM Current" note reinforcing safe,
   idempotent regeneration

**Result:** Dormant entries visible in log without needing to remove them.

**Files Modified:** uSBOMEngine.pas, UsersGuide.md, Help.md, SCHEMA.md

## 2026-03-26 - Project MRU Feature

**Problem:** Users had to re-enter project paths each time they ran DelphiSBOM.

**Changes Made:**
1. New `uSettings.pas` unit with `TMRUManager` class (INI persistence)
2. `FEdtProject` changed from `TEdit` to `TComboBox` (csDropDown)
3. Per-project settings (manifest, output dir, version) restored on selection
4. Settings persisted to `%APPDATA%\DelphiSBOM\DelphiSBOM.ini` (max 10 entries)

**Result:** Recent projects available from dropdown, settings auto-restored.

**Files Modified:** uSettings.pas (new), uMainForm.pas, uMainForm.dfm,
DelphiSBOM.dpr, DelphiSBOM.dproj

## 2026-03-26 - Code Audit (Session 3)

**Problem:** First code quality review after MVP completion.

**Changes Made:**
1. PURL name and version segments now URL-encoded per RFC 3986
2. Dead `FFoundDirs` field removed from `uLibraryDiscovery`
3. `IsValidUnitName` rejects malformed scoped names (leading/trailing dots,
   consecutive dots)
4. Malformed `components.json` array entries skipped gracefully instead of
   raising cast errors
5. Unresolved IDE environment variable paths logged as warnings instead of
   silently skipped
6. EurekaLog `.eof` config files added to `.gitignore`

**Result:** Six fixes applied. No memory leaks, thread safety issues, or
CycloneDX compliance problems found.

**Files Modified:** uSBOMBuilder.pas, uLibraryDiscovery.pas,
uProjectParser.pas, uManifestLoader.pas, .gitignore

## 2026-03-26 - MVP Complete

**Problem:** Delphi developers had no Delphi-native tool for generating
CycloneDX SBOMs to meet EU CRA and other regulatory requirements.

**Changes Made:**
1. Full VCL application: project parser, RTL scanner, unit classifier,
   SBOM builder, manifest loader, library discovery engine
2. CycloneDX 1.5 JSON output with PURL, licence, and supplier metadata
3. Automatic library discovery with vendor/licence extraction from source
4. Background threading for UI responsiveness
5. Optional SynEdit integration for syntax-highlighted JSON viewing
6. UUID braces stripped from SBOM serialNumber
7. Project version fallback to VerInfo_Keys when individual elements absent
8. Own-code detection from `.dpr` `in` file references and sibling directories
9. Smart library naming from `.dpk` package files
10. Nested library directory merging
11. Scoped unit names matched against manifest exact/prefix entries
12. Repository documentation: README, CLAUDE.md, SCHEMA.md, CYCLONEDX-NOTES.md

**Result:** Working application generating valid CycloneDX 1.5 SBOMs from
Delphi projects. Tested against three projects.

**Files Modified:** All source files (initial implementation)
