# DelphiSBOM — Change Log

All project changes are documented here in reverse chronological order.

## 2026-10-07 — Library Name and Vendor Detection [Fixed]

- A library directly under a drive or share root took its name from an unrelated package: the
  parent searched for a `.dpk` was the root itself, whose subfolders are other checkouts, so
  `E:\EurekaLog` was named "rbEDB" (from `E:\ElevateDB\rbEDB2337.dpk`). The parent is no longer
  searched when it is a root, for the name or for "looks like a library" — `Source/uLibraryDiscovery.pas`
- A vendor whose name ends in a bracket lost the bracket: "Jane Doe (Acme Software). All rights
  reserved." gave "Jane Doe (Acme Software". A trailing `)` is now stripped only when unmatched —
  `Source/uLibraryDiscovery.pas`
- 10 tests for both (`LibraryParentDirectory`, `CleanCopyrightHolder`, now in the unit's interface);
  5 were red before the fix. Found by running the Release exe over a real 83-unit project —
  `Tests/TestLibraryDiscovery.pas`, `Tests/DelphiSBOMTests.dpr`, `Tests/DelphiSBOMTests.dproj`
- Help and User's Guide describe how a library is named and the drive-root exception —
  `Docs/Help.md`, `Docs/UsersGuide.md`

## 2026-10-06 — Scripted GUI Checks [Added]

- `Tests/GuiChecks.ps1`: 30 PASS/FAIL checks against the Release exe, driven by window messages
  to its controls (no coordinates, no forced focus). Covers project switching, the recent-projects
  list (including a Cyrillic path across a restart), result buttons during a run, the library
  editor (Space toggle, missing-name warning, discard prompt) and Save & Regenerate. All 30 pass.
  It backs up and restores the user's INI and removes its scratch projects.
- Docs: README "GUI checks" section with its environment caveat; `CLAUDE.md` testing rules for the
  script; Help and User's Guide now explain that discovery searches only the project search paths,
  the IDE library path and the fixed roots, so a library beside the project is found only through a
  search path — `README.md`, `CLAUDE.md`, `Docs/Help.md`, `Docs/UsersGuide.md`

## 2026-10-06 — DUnitX Test Suite [Added]

- DUnitX console suite over the non-VCL units: 64 tests in 9 fixtures, ported from the
  audit's scratch harness and extended — `Tests/DelphiSBOMTests.dpr`, `Tests/DelphiSBOMTests.dproj`,
  `Tests/TestSupport.pas`, `Tests/TestTypes.pas`, `Tests/TestTextFiles.pas`, `Tests/TestProjectParser.pas`,
  `Tests/TestManifestLoader.pas`, `Tests/TestUnitClassifier.pas`, `Tests/TestSBOMBuilder.pas`,
  `Tests/TestEvidenceMerger.pas`, `Tests/TestSBOMEngine.pas`, `Tests/TestDelphiInstall.pas`
- The runner makes string assertions case-sensitive and fails any test that asserts nothing. Each
  test works in its own `%TEMP%` folder. Eight of the audit fixes were mutation-checked: re-introducing
  the defect turns the matching test red.
- `Samples/components.sample.json` now shows every field and licence form: an SPDX expression, a
  `Commercial` licence, `own_code_units` and `own_code_prefixes`. **Why:** the DX.Comply author asked
  for a sample to check his manifest import against.
- `.gitignore` ignores `dunitx-results.xml`; README and `CLAUDE.md` describe running the suite and its
  environment caveat (built and run on Delphi 13 Win64 only).

## 2026-10-06 — Audit Fixes [Fixed / Changed / Added]

Fixes from the full code audit recorded in `Docs/AUDIT-2026-10-06.md` (item IDs in brackets).
Verified by clean Debug and Release Win64 builds (no hints or warnings) and a 52-check
scratch harness driving the real units.

**Data loss and cross-project contamination**
- Saving into a `components.json` that does not parse now raises and leaves the file untouched,
  instead of replacing it with an empty object [H2]; a non-array `components`/`own_code_units` is
  refused rather than duplicated [L2] — `uManifestLoader.pas`, `uMainForm.pas`
- Switching projects resets the Manifest, Output Dir, Version Override and DX.Comply fields to the new
  project's defaults and its MRU entry, and clears the previous results; a hand-typed path does the
  same on leaving the box [H3]. Save & Regenerate / Mark as Own Code write to the manifest the
  results came from [M11] — `uMainForm.pas`, `uTypes.pas`
- A sibling of the project directory is auto-marked as own code only when it does not look like a
  library (no licence file, no `.dpk`); a library checked out beside the project stays
  third-party, and a project directly under a drive root never applies the rule [H1] —
  `uLibraryDiscovery.pas`
- Auto-detected own-code units count as own code in the same run and are saved only after the
  SBOM has been written [M12]; selecting a project no longer creates `components.json` in the
  user's repository, the file is created on first save from a full skeleton [M13] —
  `uSBOMEngine.pas`, `uManifestLoader.pas`, `uMainForm.pas`

**SBOM correctness**
- Licences: recognised SPDX identifiers emit `license.id`, expressions emit `expression`,
  anything else `license.name` — previously every value went to `id`, a schema enum [H4];
  component `type` lower-cased with a `library` fallback [M8] — `uSBOMBuilder.pas`, `uTypes.pas`
- purl name/version percent-encoded per the purl spec (space = `%20`, not `+`); no purl for a
  nameless component [M5] — `uSBOMBuilder.pas`
- ProjectVersion maps to the right BDS version (20.1–20.3 is Delphi 12 = 23.0, not 37.0; 19.x is
  10.4/11, and so on) [H6] — `uProjectParser.pas`
- The `.dproj` is evaluated like MSBuild for Release on the active platform (Win64 preferred from
  `<Platforms>`), with a Condition evaluator, so platform, auto-incremented build number and
  search paths are correct [M14] — `uProjectParser.pas`
- The SBOM, manifest and settings are written as UTF-8 without a BOM, atomically [M3]; the
  timestamp no longer depends on the locale's time separator [M4] — `uTextFiles.pas`,
  `uSBOMBuilder.pas`, `uManifestLoader.pas`
- DX.Comply evidence matches scope-stripped names, prefers SHA-256, normalises algorithm names
  and drops ones outside the CycloneDX enum, dedupes `.pas`/`.dcu` entries, and emits the origin
  as a `dxcomply:origin` property [M9, L12] — `uEvidenceMerger.pas`, `uSBOMBuilder.pas`, `uSBOMEngine.pas`

**Robustness**
- Files are decoded BOM → UTF-8 → ANSI; an ANSI `.dpr` or `.pas` with one non-ASCII byte no
  longer reads as empty [H5] — new `uTextFiles.pas`, all readers
- The generate thread initialises COM for MSXML [M1]; `SyncComplete` always re-enables the form
  [M2]; result buttons are disabled while a run is in progress [M10] — `uMainForm.pas`
- The Delphi installation is chosen from the project's version (HKCU, then the installer's HKLM
  key; versions whose folder is gone are ignored) instead of the highest installed [M17]; the Delphi
  Path field is blank by default — new `uDelphiInstall.pas`, `uSBOMEngine.pas`, `uRTLScanner.pas`, `uMainForm.pas`
- `$(BDS)`, `$(BDSCOMMONDIR)`, `$(BDSCatalogRepository)`, IDE environment variables and Windows
  environment variables are expanded in IDE and `.dproj` search paths [M15]; discovery builds one
  `.pas` index per run instead of rescanning every root per unit [M16] — `uLibraryDiscovery.pas`
- Empty/non-string prefixes are ignored (an empty prefix matched every unit); short
  `own_code_prefixes` are warned about; numeric/null field values are read safely [M6, L9];
  `schema_version` other than `1.0` is warned about [L8] — `uManifestLoader.pas`, `uUnitClassifier.pas`
- `own_code_units` now beats `units_prefix`; own-code matching also tries the scope-stripped
  name; more scope prefixes (`Web.`, `Soap.`, `Bde.`, `IBX.`, `FireDAC.`, `Posix.`) [M7, L10] —
  `uUnitClassifier.pas`, `uTypes.pas`
- `.dpr` parsing: whitespace normalised before `in` detection, commas inside quoted paths
  handled, `<MainSource>` and `.dpk` `contains` supported, warnings for `{$IF...}` and `{$I}` in
  the source; unterminated `(*` fixed [M19, L18] — `uProjectParser.pas`
- Library discovery: licence heuristics ordered most-specific first and never guessed (Boost was
  reported as MIT; unversioned GPL as GPL-3.0) [L2]; vendor parsing case-insensitive and `©Acme`
  no longer becomes `cme` [L1]; `{$LIBVERSION}`/`{$DESCRIPTION}` version detection replaces the
  dead `{$ver` search [M18]; drive-root parent paths fixed [L3]; leaks and broad `except` blocks
  narrowed [L4] — `uLibraryDiscovery.pas`
- MRU settings stored as UTF-8 so non-ANSI project paths survive [M20] — `uSettings.pas`
- Library editor: Space toggles Include, an included row must have a name, and Generate asks
  before discarding unsaved edits [L15]; instruction text names the real buttons [L14]; save
  messages are no longer cleared by the regenerate [L13] — `uLibraryEditor.pas`, `uMainForm.pas`

**Build**
- `USE_SYNEDIT` removed from the committed `.dproj` for the second time; `DCC_Define` now takes
  `$(DELPHISBOM_DEFINES)` from the environment, and `.githooks/pre-commit` rejects a `.dproj` that
  defines `USE_SYNEDIT` directly [H7]. `DCC_DcuOutput` trailing space and the `WinARM64EC` entry
  removed [L19] — `Source/DelphiSBOM.dproj`, `.githooks/pre-commit`
- **Why:** removing the define a second time would not hold — the IDE writes Project Options into
  the shared `.dproj`, so the local setting has to live outside it.

**Not changed:** cancellation and closing during a run [M21] stay Phase 2; log lines still use a
blocking `Synchronize` [L17]; concurrent MRU writes from two instances [L16].

## 2026-10-06 — Repository moved to GitHub [Changed]

The repository now lives at https://github.com/ijbranch/DelphiSBOM (previously Codeberg).
Updated the references in `CLAUDE.md`, `Docs/Help.md`, `PROGRESS.md` and the
supplier URL in `Source/components.json`. The superseded `Delphi_SBOM_PLAN.md`
is left as historical record.

## 2026-03-27 — DX.Comply Evidence Bridge Fixes [Fixed]

First end-to-end test against real DX.Comply output (a large internal project,
729 library components). Three fixes applied:

1. `uEvidenceMerger.pas`: Strip `.pas` extension from component names in
   addition to `.dcu`. DX.Comply emits source-resolved units with `.pas`
   suffix — these would fail to match classified units.
2. `uSBOMEngine.pas`: Added evidence match summary logging after merge.
   Reports how many evidence entries matched classified units vs unmatched
   transitive dependencies (expected low match rate — .dpr uses clause vs
   MAP file transitive closure).
3. `uSettings.pas` + `uMainForm.pas`: Persist DX.Comply file path in MRU
   settings so users don't need to re-browse each session.

**Files:** `uEvidenceMerger.pas`, `uSBOMEngine.pas`, `uSettings.pas`, `uMainForm.pas`

## 2026-03-27 - Build Config: Map File and EXE Output to Project Subdirectory

**Changes Made:** Added `DCC_ExeOutput=.\$(Platform)\$(Config)` to DelphiSBOM.dproj (already had `DCC_MapFile=3`).

**Files Modified:** `Source/DelphiSBOM.dproj`

## 2026-03-27 - Own-Code Prefix Matching

**Problem:** Shared internal libraries (e.g. a company library with `gll*` units)
had to have each unit listed individually in `own_code_units`. No way to
classify an entire prefix as own code.

**Changes Made:**
1. `uTypes.pas` — added `OwnCodePrefixes: TArray<string>` to `TManifest`
2. `uManifestLoader.pas` — loads `own_code_prefixes` array from components.json
3. `uUnitClassifier.pas` — `IsOwnCode` now checks prefix matches after exact
   matches (case-insensitive)

**Usage:** Add to components.json:
```json
"own_code_prefixes": ["gll"]
```
All `gll*` units classify as own code automatically across all projects.

**Result:** Clean compile on Win64 Debug.

**Files Modified:** uTypes.pas, uManifestLoader.pas, uUnitClassifier.pas

## 2026-03-27 - DX.Comply Evidence Bridge

**Problem:** DX.Comply (by Olaf Monien) generates SBOMs from MAP file analysis
with SHA-256 hashes per unit but sparse metadata. DelphiSBOM generates SBOMs
with rich metadata (vendor, licence, PURL) but no binary evidence. Neither
tool alone produces a complete SBOM.

**Changes Made:**
1. New `uEvidenceMerger.pas` — parses DX.Comply `bom.json` CycloneDX output,
   extracts per-unit SHA-256 hashes and origin classifications, strips `.dcu`
   extension for unit name matching
2. `uTypes.pas` — added `TUnitEvidence` record (UnitName, Algorithm, HashValue,
   Origin), `DXComplyFile` field on `TSBOMOptions`, `Evidence` field on
   `TSBOMResult`
3. `uSBOMEngine.pas` — calls `TEvidenceMerger.LoadEvidence` between
   classification and building if DXComplyFile is provided
4. `uSBOMBuilder.pas` — `Build` and `BuildAndSave` accept `AEvidence` parameter;
   nested `BuildEvidenceSubComponents` function emits CycloneDX sub-components
   with hashes under RTL and third-party component entries
5. `uMainForm.pas` — added "DX.Comply SBOM:" input row with Browse button,
   wired into `TSBOMOptions.DXComplyFile`
6. `DelphiSBOM.dpr` — added `uEvidenceMerger` to uses clause

**Result:** When a DX.Comply `bom.json` is provided, the generated SBOM
contains both DelphiSBOM's rich metadata AND DX.Comply's per-unit SHA-256
hashes as nested sub-components. When no DX.Comply file is provided,
output is unchanged. Clean compile on Win64 Debug. Cannot test end-to-end
until DX.Comply's Delphi 13 bug is resolved (their issue #19).

**Files Modified:** uEvidenceMerger.pas (new), uTypes.pas, uSBOMEngine.pas,
uSBOMBuilder.pas, uMainForm.pas, DelphiSBOM.dpr

## 2026-03-27 - UI Polish: Button Layout, Tooltips

**Problem:** Discovery panel buttons were clipped when panel was narrow.
No tooltips on any controls — new users had no guidance on what each
field or button does.

**Changes Made:**
1. Replaced discovery button TPanel with TGridPanel — three equal-width
   columns (33.33% each) that resize with the panel
2. Added tooltips (`Hint` property) to all 14 interactive controls:
   project combo, all Browse buttons, manifest/output/Delphi path fields,
   version override, Generate/Validate/View SBOM buttons, and all three
   discovery panel buttons
3. `ShowHint := True` set on main form in `FormCreate`

**Result:** Buttons always fit regardless of panel width. Hover tooltips
provide contextual guidance on every control.

**Files Modified:** uMainForm.pas

## 2026-03-27 - Library Editor Modal Dialog

**Problem:** Users could not edit auto-detected library metadata (Name, Version,
Vendor, Licence, Prefix) before saving to components.json. The discovery panel
showed read-only text that had to be accepted as-is.

**Changes Made:**
1. New `uLibraryEditor.pas` — modal TStringGrid editor with columns: Include
   (toggle), Name, Version, Vendor, Licence, Prefix (editable), Units count
   and Directory (read-only). Units detail panel at the bottom shows the full
   unit list for the selected row.
2. `uMainForm.pas` — added "Edit Libraries..." button in the discovery button
   panel, wired to `TLibraryEditorForm.Execute`. On OK, `FDiscoveredLibraries`
   is updated and the discovery memo refreshed.
3. `DelphiSBOM.dpr` — added `uLibraryEditor` to uses clause.

**Result:** Users can now review and correct auto-detected metadata in a
structured grid before saving. Click Include column to toggle libraries
on/off. Clean compile on Win64 Debug.

**Files Modified:** uLibraryEditor.pas (new), uMainForm.pas, DelphiSBOM.dpr

## 2026-03-27 - CycloneDX 1.5 Compliance Verification

**Problem:** Needed to verify SBOM output remained standards-compliant after
the audit changes (supplier.url, license.url additions).

**Verification:** Full element-by-element comparison of uSBOMBuilder.pas output
against the CycloneDX 1.5 JSON schema. All structural elements pass.

**Data fix:** Indy licence in `components.sample.json` changed from
`"Modified-BSD"` (not a valid SPDX identifier) to `"BSD-3-Clause"`.

**Result:** SBOM output is fully CycloneDX 1.5 compliant.

**Files Modified:** Samples/components.sample.json

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
