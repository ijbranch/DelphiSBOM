# DelphiSBOM — Refined Implementation Plan

**A CycloneDX SBOM Generator for Delphi Applications**
Version 0.6 — Final Draft (VCL Application)
Prepared by: Claude (Anthropic) in collaboration with Ian

---

## Context

DelphiSBOM is a free, open-source **VCL desktop application** that generates CycloneDX 1.5 SBOM files from Delphi projects, helping developers meet EU Cyber Resilience Act requirements (Dec 2027). This plan refines the original `Delphi_SBOM_PLAN.md` based on design decisions made during review, including a change from console application to VCL GUI.

---

## Design Decisions

### Decision 1 — Manifest Location

| Option | Description |
|--------|-------------|
| Per-project | Each project has its own `components.json` beside the `.dpr`. More portable, better for open-source, and each project only lists what it actually uses |
| Shared on D:\ | One master `components.json` on D:\ used by all projects. Easier to maintain centrally but less portable and includes irrelevant entries per project |
| Both — fallback chain | Look for per-project first, fall back to a shared default. Most flexible but adds complexity |

**Decision: Per-project** — `components.json` alongside each `.dpr`

---

### Decision 2 — RTL/VCL Unit List Source

| Option | Description |
|--------|-------------|
| Hand-curated text file | Ship a static `rtl-units.txt` with known RTL/VCL/FMX unit names. Simple, predictable, easy to update manually |
| Auto-extract from Delphi install | Scan the Delphi installation directory for `.dcu` files to build the list dynamically. More accurate but adds complexity and requires a Delphi install on the build machine |
| Embedded in code | Hard-code the RTL unit list as a const array in `uRTLUnitRegistry.pas`. No external file dependency, but harder to update |

**Decision: Auto-extract from Delphi install** — scan `.dcu` files at runtime

---

### Decision 3 — Product Version String Source

| Option | Description |
|--------|-------------|
| Auto-read from `.dproj`, user override | Read `VerInfo_MajorVer/MinorVer/Release/Build` from the `.dproj` XML by default, but allow user to override via form field |
| CLI flag only | Require the version to be passed via `--version` flag. Simplest but less convenient |
| `.dproj` only | Always read from `.dproj` VerInfo. No CLI override. Simplest code path but inflexible |

**Decision: Auto-read from `.dproj`** with user override via Version Override field

---

### Decision 4 — Scope Prefix Handling

| Option | Description |
|--------|-------------|
| Strip prefixes | Strip known scope prefixes before matching against RTL list and `components.json`. `System.SysUtils` becomes `SysUtils` for matching |
| Match both forms | Try matching with the full qualified name first, then stripped. More robust but slightly more complex |
| No stripping | Require RTL list and `components.json` to use fully qualified names. Simpler code but harder to maintain the lists |

**Decision: Strip prefixes** (`Vcl.`, `System.`, `Winapi.`, etc.) before classification

---

### Decision 5 — SBOM Output Location

| Option | Description |
|--------|-------------|
| Same directory as project | Write `<ProjectName>.cdx.json` alongside the `.dpr`/`.dproj`. Overridable with `--output` flag |
| Dedicated output subdirectory | Create an `sbom` subdirectory under the project and write there. Keeps project root cleaner |
| Current working directory | Write to wherever `DelphiSBOM.exe` was invoked from. Standard CLI convention but less predictable |

**Decision: Same directory as project**, overridable via Output Dir field

---

### Decision 6 — Multi-Project Support

| Option | Description |
|--------|-------------|
| Single `.dpr` only | Accept one `.dpr` or `.dproj` at a time. Simplest, safest for v1.0. Multi-project can come in Phase 3 |
| Accept a list of `.dpr` files | Allow multiple `.dpr` paths on the command line, generate one SBOM per project. Moderate complexity |
| Support `.groupproj` | Parse Delphi group project files to process all projects at once. Most complex but most convenient for large solutions |

**Decision: Single `.dpr` only** for v1.0

---

### Decision 7 — Delphi Installation Location

| Option | Description |
|--------|-------------|
| Registry + user override | Read the Delphi install path from the Windows registry (`HKCU\Software\Embarcadero\BDS\...\RootDir`). Allow user to override via Delphi Path field. Fully automatic for most users |
| Manual path only | Require the user to specify the Delphi path every time. Explicit but less convenient |
| Environment variable | Check `DELPHI_ROOT` or `BDS` env var first, fall back to registry. Good for CI environments |

**Decision: Registry lookup** with user override via Delphi Path field

---

### Decision 8 — RTL Representation in SBOM

| Option | Description |
|--------|-------------|
| Single 'Delphi RTL' component | List Embarcadero RTL/VCL/FMX as one aggregate component with the Delphi version. Cleaner, more practical for compliance |
| Omit RTL entirely | Only list third-party and own-code components. RTL is implicit — everyone knows Delphi apps use the RTL |
| List individual RTL units | Each RTL unit used becomes its own component entry. Most granular but creates massive SBOMs with limited value |

**Decision: Single aggregate "Embarcadero Delphi RTL" component** with Delphi version

---

### Decision 9 — Own-Code Units in SBOM

| Option | Description |
|--------|-------------|
| Not listed — own code is the application | Own-code units are part of the main application component (`metadata.component`), not separate entries. Standard SBOM practice |
| List as internal components | List own-code units individually with type `file`. Provides a complete inventory but bloats the SBOM |
| Optional via `--include-own` flag | Off by default, but `--include-own` lists them. Flexibility for teams that want full traceability |

**Decision: Not listed** — own code is the application itself (`metadata.component`)

---

### Decision 10 — Unit Matching in `components.json`

| Option | Description |
|--------|-------------|
| Both prefix and exact | Add an optional `units_exact` array alongside `units_prefix`. Exact names matched first, then prefixes. Handles libraries with non-prefixed unit names (e.g. `SuperObject`) |
| Prefix only | Keep it simple — prefix matching covers most cases. Libraries with odd unit names can list their units as prefixes of length = full name |
| Regex patterns | Allow regex in the matching field. Most powerful but hardest to maintain and error-prone |

**Decision: Both prefix and exact** — `units_exact` array + `units_prefix` array

---

### Decision 11 — Dependency Relationships

| Option | Description |
|--------|-------------|
| No dependencies in v1.0 | Just list components flat. Dependency graphs between Delphi libraries are hard to derive accurately and CycloneDX doesn't require them |
| Basic top-level dependencies | Show that all third-party components depend on the main application. Simple parent-child relationship only |
| Full dependency mapping | Attempt to map inter-component dependencies from uses clauses. Most accurate but significantly more complex |

**Decision: No dependency relationships** in v1.0 (flat component list)

---

### Decision 12 — Component Type Field

| Option | Description |
|--------|-------------|
| Map to CycloneDX types | Use valid CycloneDX component types: `library`, `framework`, `application`. The `type` field in `components.json` maps directly to the SBOM output |
| Freeform tag, default to `library` | Keep `type` as a descriptive tag in `components.json`. Always output `library` in the SBOM since that's what Delphi packages are |
| Both fields | Keep descriptive `category` in `components.json` for human use, add separate `cdx_type` for CycloneDX mapping |

**Decision: Map to CycloneDX types** (`library`, `framework`) directly

---

### Decision 13 — Delphi Version for RTL Component

| Option | Description |
|--------|-------------|
| From `.dproj` ProjectVersion | Read the Delphi/compiler version from the `.dproj` XML. This is the version that actually compiled the project |
| From registry/install | Use the installed Delphi version from the registry. Reflects the current environment, not necessarily what built the project |
| Both, prefer `.dproj` | Try `.dproj` first, fall back to installed version if not found in the project file |

**Decision: From `.dproj` `ProjectVersion`** for the RTL component version

---

### Decision 14 — Application Type

| Option | Description |
|--------|-------------|
| Console application | Single `.exe`, CLI-driven, suitable for scripting and CI/CD. No visual feedback during processing |
| VCL desktop application | GUI with file dialogs, option controls, and interactive results display. More approachable for Delphi developers. CI/CLI mode can be added later |

**Decision: VCL desktop application** — more natural for the Delphi community. A `--cli` mode or lightweight console wrapper can be added in Phase 2 if CI/CD integration is needed.

---

## Decisions Summary

| # | Decision | Resolution |
|---|----------|------------|
| 1 | Manifest location | **Per-project** — `components.json` alongside each `.dpr` |
| 2 | RTL unit list source | **Auto-extract at runtime** from Delphi install (scan `.dcu` files) |
| 3 | Version string source | **Auto-read from `.dproj`** with user override via form field |
| 4 | Scope prefix handling | **Strip prefixes** (`Vcl.`, `System.`, etc.) before classification |
| 5 | SBOM output location | **Same directory as project**, overridable via Output Dir field |
| 6 | Multi-project support | **Single `.dpr` only** for v1.0 |
| 7 | Delphi install location | **Registry lookup** with user override via form field |
| 8 | RTL in SBOM | **Single aggregate "Delphi RTL" component** with Delphi version |
| 9 | Own-code units | **Not listed** — own code is the application itself |
| 10 | Unit matching | **Both prefix and exact** — `units_exact` + `units_prefix` |
| 11 | Dependencies | **No dependency relationships** in v1.0 |
| 12 | Component type field | **Map to CycloneDX types** directly |
| 13 | Delphi version source | **From `.dproj` `ProjectVersion`** |
| 14 | Application type | **VCL desktop application** — CLI mode deferred to Phase 2 |

---

## Architecture

### Processing Pipeline

```
  User selects .dpr / .dproj via file dialog
         │
         ▼
  ┌─────────────────┐
  │  Project Parser  │  Extracts: project name, Delphi version, target platform,
  │  uProjectParser  │  unit list, search paths, version info from VerInfo_*
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  RTL Scanner     │  Scans Delphi install dir (from registry or user-specified
  │  uRTLScanner     │  path) to build list of known RTL/VCL/FMX .dcu unit names
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │ Manifest Loader  │  Reads per-project components.json
  │ uManifestLoader  │  Validates schema, loads component entries
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  Unit Classifier │  Classifies each unit using priority:
  │  uUnitClassifier │  1. RTL/VCL (from scanner)  2. Third-party (from manifest,
  │                  │     exact match then prefix)  3. Own code  4. Unclassified
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  SBOM Builder    │  Assembles CycloneDX 1.5 JSON using System.JSON
  │  uSBOMBuilder    │  Outputs <ProjectName>.cdx.json
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  Results Display │  Shows classification results, warnings, and unclassified
  │  (MainForm)      │  units interactively before/after SBOM generation
  └─────────────────┘
```

### Unit Structure

| Unit | Purpose |
|------|---------|
| `DelphiSBOM.dpr` | VCL application entry point |
| `uMainForm.pas` / `.dfm` | Main form — file selection, options, generate button, results display |
| `uTypes.pas` | Shared record types (`TComponentEntry`, `TProjectInfo`, `TClassifiedUnit`, etc.) |
| `uProjectParser.pas` | Parse `.dpr` uses clause + `.dproj` XML metadata |
| `uRTLScanner.pas` | Scan Delphi install for `.dcu` files to build RTL unit list |
| `uManifestLoader.pas` | Load and validate `components.json` |
| `uUnitClassifier.pas` | Classify units (RTL → third-party → own → unclassified) |
| `uSBOMBuilder.pas` | Assemble and emit CycloneDX 1.5 JSON |
| `uSBOMEngine.pas` | Pipeline orchestrator — called by the form, coordinates all processing steps |
| `uReportWriter.pas` | Human-readable `.txt` summary report *(Phase 2)* |

### Main Form Layout (`uMainForm`)

```
┌─────────────────────────────────────────────────────────────────────┐
│  DelphiSBOM — CycloneDX SBOM Generator                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Project File:  [________________________] [Browse...]              │
│  Manifest:      [________________________] [Browse...]  (optional)  │
│  Output Dir:    [________________________] [Browse...]  (optional)  │
│  Delphi Path:   [________________________] [Browse...]  (auto)      │
│  Version Override: [__________]  (blank = read from .dproj)         │
│                                                                     │
│  [Generate SBOM]    [Validate Manifest]                             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Results                                                            │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Classification Summary          │  Unclassified Units         │ │
│  │  ─────────────────────────       │  ───────────────────        │ │
│  │  RTL/VCL units:        142       │  SomeUnknownUnit            │ │
│  │  Third-party units:     28       │  AnotherMysteryUnit         │ │
│  │  Own-code units:        65       │                             │ │
│  │  Unclassified:           3       │                             │ │
│  │                                  │                             │ │
│  │  Third-Party Components          │                             │ │
│  │  ──────────────────────          │                             │ │
│  │  OmniThreadLibrary 3.7.8        │                             │ │
│  │  ElevateDB 2.x                  │                             │ │
│  │  TMS VCL UI Pack 12.x           │                             │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Log                                                                │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  [INFO] Loaded project: MyApp.dpr                              │ │
│  │  [INFO] Delphi 13 detected (37.0) — scanning RTL units...     │ │
│  │  [INFO] Found 1,847 RTL units                                  │ │
│  │  [INFO] Loaded components.json — 5 components defined          │ │
│  │  [WARNING] 3 units could not be classified                     │ │
│  │  [INFO] SBOM written to C:\Projects\MyApp\MyApp.cdx.json      │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Status: Ready                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Form behaviour:**
- **Project File**: `TOpenDialog` filtering for `*.dpr;*.dproj`. When selected, auto-populates Manifest and Output Dir defaults (same directory)
- **Manifest**: `TOpenDialog` filtering for `*.json`. Defaults to `components.json` in the project directory
- **Output Dir**: `Vcl.FileCtrl.SelectDirectory` (folder browser, not `TOpenDialog`). Defaults to project directory
- **Delphi Path**: Auto-populated from registry on form load. User can override via `Vcl.FileCtrl.SelectDirectory` (folder browser)
- **Version Override**: Blank by default = read from `.dproj`. If populated, overrides the SBOM metadata version
- **Generate SBOM**: Runs the full pipeline on a background `TTask` and displays results. Enabled only when a valid project file is selected. Disabled during processing
- **Validate Manifest**: Runs schema validation on `components.json` only, on a background `TTask`, without generating SBOM
- **Results panel**: Split view using `TPanel` + `TSplitter` + `TPanel` (not `TPageControl`) — classification summary (left) and unclassified units list (right) are visible simultaneously
- **Log panel**: Scrolling `TMemo` showing `[INFO]`, `[WARNING]`, `[ERROR]` messages, updated via `TThread.Queue` during processing

### Background Processing (Section 8.11)

The RTL scanner iterates 1,800+ `.dcu` files from disk, and the full pipeline involves file I/O, XML parsing, and JSON generation. Running this on the UI thread will freeze the form.

**Required approach:** All processing in `uSBOMEngine` must run on a background task using `TTask.Run` from `System.Threading` (Delphi RTL — no third-party dependency). This applies to both **Generate SBOM** and **Validate Manifest** operations.

**Threading rules:**
- `uSBOMEngine.Execute` runs entirely inside `TTask.Run`
- Log panel updates must be marshalled to the UI thread via `TThread.Queue`
- The **Generate SBOM** and **Validate Manifest** buttons must be **disabled** while processing is in progress and **re-enabled** on completion (or error)
- All input fields (Project File, Manifest, Output Dir, Delphi Path, Version Override) must also be disabled during processing to prevent the user changing parameters mid-run
- On completion, results are passed back to the form via `TThread.Queue` and displayed in the results panel
- `uSBOMEngine` itself has no UI dependencies — it accepts a logging callback (`TProc<string>`) that the form wraps in `TThread.Queue`

**Exception handling inside `TTask.Run`:** The entire pipeline call inside the `TTask.Run` lambda must be wrapped in `try/except`. If an unhandled exception occurs, catch it within the task body, log it via the `TThread.Queue` callback as `[ERROR]`, and signal completion so the form re-enables its controls. Do not let exceptions propagate out of the `TTask.Run` lambda — they will be silently swallowed (raised as `EAggregateException` only if the task is awaited, which this code does not do). This is a known Delphi `TTask` gotcha.

**Cancellation:** A Cancel button during processing is a **Phase 2 enhancement** via `ICancellationToken` passed to `TTask.Run`. For v1.0, processing runs to completion once started.

### Key Design Notes

- **No third-party dependencies** — uses only Delphi RTL: `System.JSON`, `Xml.XMLDoc`, `Xml.XMLIntf`, `System.Win.Registry`, `System.Threading`
- **Registry lookup**: Enumerate all subkeys under `HKCU\Software\Embarcadero\BDS\` and select the highest numeric version key found, then read its `RootDir` value. Known keys for reference: Delphi 12 = `23.0`, Delphi 13 = `37.0` — but the code must not hardcode these; it must discover them dynamically to support future Delphi versions. Scan `<RootDir>\lib\<platform>\release\` for `.dcu` files, where `<platform>` is read from the `.dproj` target platform (e.g. `win32`, `win64`) — never hardcoded. Strip `.dcu` extension to get unit names
- **Scope prefix stripping**: Before classification, strip known prefixes (`System.`, `Vcl.`, `Winapi.`, `Data.`, `Xml.`, `Datasnap.`, `FMX.`, `REST.`, `Net.`) from unit names
- **Classification priority**: RTL match → exact manifest match → prefix manifest match → own code (on project search path) → unclassified

### RTL Scanner Graceful Degradation (Section 8.10)

If the Delphi install path cannot be determined (registry key absent, user-specified path invalid, or no `.dcu` files found at the expected location), `uRTLScanner` must:

1. Log a `[WARNING]` to the log panel (e.g. "Delphi installation not found — RTL unit classification unavailable. Specify the Delphi path manually.")
2. **Continue processing** — this is not a fatal error
3. The **RTL component is still emitted** in the SBOM using the Delphi version from `.dproj`
4. Classification of RTL units will **degrade to "unclassified"**, which is acceptable
5. These units will appear in the unclassified units list with a note that RTL scanning was unavailable
6. The **Delphi Path** field on the form should show a visual indicator (e.g. red border or warning icon) when auto-detection fails, prompting the user to browse to their Delphi install manually

---

## Refined `components.json` Schema

```json
{
  "schema_version": "1.0",
  "last_updated": "2026-03-26",
  "supplier": {
    "name": "Your Company",
    "url": "https://example.com"
  },
  "components": [
    {
      "name": "OmniThreadLibrary",
      "version": "3.7.8",
      "vendor": "Primož Gabrijelčič",
      "vendor_url": "https://github.com/gabr42/OmniThreadLibrary",
      "licence": "BSD-3-Clause",
      "licence_url": "https://opensource.org/licenses/BSD-3-Clause",
      "type": "library",
      "units_prefix": ["Otl"],
      "units_exact": ["GpLists", "GpStuff", "HVStringBuilder"],
      "notes": "High-level threading library"
    }
  ]
}
```

### Schema Changes from Original Plan

- **Added `units_exact`** (optional array): Exact unit name matches, checked before prefix matches. Handles libraries with non-prefixed unit names (e.g. `SuperObject`, `GpLists`)
- **`type` field**: Must be a valid CycloneDX component type: `library`, `framework`, or `application`. Maps directly to SBOM output
- **`units_prefix`**: Simplified — use short prefixes (e.g. `"Otl"` not individual unit names). Prefix match is case-insensitive

### Prefix Length Safety Rule

**Minimum prefix length: 3 characters.** The implementation must reject any `units_prefix` entry shorter than 3 characters during `components.json` validation, and report it as a `[WARNING]`. Short prefixes like `"In"` (Indy) or `"DB"` (DBISAM) would accidentally match unrelated units (e.g. `IntToStr`, `DBGrid`). Use `units_exact` for libraries whose unit names are too short or ambiguous for prefix matching.

This rule must be documented in `SCHEMA.md` as a `components.json` authoring guideline:

> **Authoring guideline:** Prefixes must be at least 3 characters long. If a library's units share only a 1–2 character prefix, list the individual unit names in `units_exact` instead. For example, Indy units should use `units_prefix: ["IdHTTP", "IdSMTP", "IdTCP", "IdSSL"]` (longer, unambiguous prefixes) or `units_exact` for specific unit names — never `units_prefix: ["Id"]`.

---

## CycloneDX 1.5 Output Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:<generated>",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-26T10:00:00Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "DelphiSBOM",
          "version": "1.0.0",
          "supplier": { "name": "DelphiSBOM Contributors" }
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "<ProjectName>",
      "version": "<from .dproj VerInfo or Version Override field>",
      "supplier": { "name": "<from components.json supplier>" }
    }
  },
  "components": [
    {
      "type": "framework",
      "name": "Embarcadero Delphi RTL",
      "version": "<from .dproj ProjectVersion>",
      "supplier": { "name": "Embarcadero Technologies" },
      "purl": "pkg:delphi/embarcadero-rtl@<version>"
    },
    {
      "type": "library",
      "name": "OmniThreadLibrary",
      "version": "3.7.8",
      "supplier": { "name": "Primož Gabrijelčič" },
      "licenses": [{ "license": { "id": "BSD-3-Clause" } }],
      "externalReferences": [
        { "type": "website", "url": "https://github.com/gabr42/OmniThreadLibrary" }
      ],
      "purl": "pkg:delphi/OmniThreadLibrary@3.7.8"
    }
  ]
}
```

### Key Differences from Original Plan

- **`tools` field**: Uses CycloneDX 1.5 format (`tools.components` array, not `tools` array of objects)
- **RTL as single component**: Embarcadero Delphi RTL listed once with type `framework`
- **No own-code units**: Own code is the `metadata.component`, not in the `components` array
- **No dependency relationships**: Flat component list, no `dependencies` section
- **Commercial licences**: Use `{ "license": { "name": "Commercial" } }` (no `id` field)

---

## User Interface Controls

All former CLI options are now form controls:

| CLI Option (retired) | VCL Control | Behaviour |
|----------------------|-------------|-----------|
| `<project.dpr>` | Project File + Browse button | `TOpenDialog` for `*.dpr;*.dproj` |
| `--manifest` | Manifest + Browse button | Defaults to same dir as project; user can override |
| `--output` | Output Dir + Browse button | Defaults to same dir as project; user can override |
| `--version` | Version Override edit | Blank = read from `.dproj` |
| `--delphi-path` | Delphi Path + Browse button | Auto-populated from registry; user can override |
| `--validate` | Validate Manifest button | Runs validation only, results shown in log panel |
| `--list-unclassified` | Unclassified units list | Always visible in results panel after generation |
| `--report` | Checkbox on form (Phase 2) | Also write `.txt` summary alongside SBOM |
| `--help` | About dialog / Help menu | Standard VCL About box |
| `--app-version` | About dialog | Shown in title bar and About box |

### Future: CLI Mode (Phase 2)

A `--cli` command-line mode or lightweight console wrapper can be added in Phase 2 for CI/CD integration. The core engine (`uSBOMEngine`) is UI-independent, so this is straightforward to add later.

---

## Repository Files

### `CLAUDE.md` Content

The repository needs its own standalone `CLAUDE.md` — the master `E:\_Standards\claude.md` is private and must not be referenced or copied. The repo `CLAUDE.md` should contain:

- **Project overview** — what DelphiSBOM is, single-paragraph summary
- **Build requirements** — Delphi 12+, Win64, VCL application, no third-party dependencies
- **Coding standards** (public-facing subset):
  - 162-character line limit
  - British English spelling
  - Inline `var` declarations preferred
  - Spaces inside parentheses and square brackets
  - Blank line after main method `begin` and before main method `end`
  - `System.JSON` for all JSON work, `Xml.XMLDoc`/`Xml.XMLIntf` for XML
  - `TTask.Run` from `System.Threading` for background processing
- **Architecture summary** — pipeline stages, unit responsibilities, `uSBOMEngine` is UI-independent
- **No internal references** — this is a public repository (Section 8.2 rule)
- **Commit conventions** — `feat:`, `fix:`, `docs:`, `test:`, `refactor:` prefixes

Ian to review the draft `CLAUDE.md` before it is committed.

### `.gitignore` Content

Based on the standard Delphi `.gitignore` template, tailored for this project:

```
# Delphi compiled output
*.dcu
*.dcp
*.bpl
*.exe
*.dll
*.bpi
*.drc
*.map
*.dres
*.rsm
*.tds
*.lib

# IDE files
*.identcache
*.local
*.stat
*.skincfg
__history/
__recovery/
*.~*

# Build output directories
Win32/
Win64/

# OS files
Thumbs.db
.DS_Store
```

### `CHANGELOG.md` Format

Use **CHANGELOG.md** (not CHANGES.md) following the [Keep a Changelog](https://keepachangelog.com) convention:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Initial project setup
```

### `Docs/` Directory

| File | Purpose |
|------|---------|
| `Docs/SCHEMA.md` | `components.json` schema reference — field descriptions, authoring guidelines (including prefix length rule), worked examples |
| `Docs/CYCLONEDX-NOTES.md` | Notes on CycloneDX 1.5 compliance and Delphi-specific decisions (PURL convention, RTL as single component, commercial licence handling). Must include a **Known Limitations** section noting: if multiple Delphi versions are installed, the auto-detected RTL scan uses the highest version — which may not match the project's actual compiler version. The Delphi Path field is the mitigation. Misclassification risk is low as RTL unit names are largely stable between versions |

### `Samples/` Directory

The repository must include a `Samples/` directory with:

| File | Purpose |
|------|---------|
| `components.sample.json` | Fully commented example manifest using publicly recognisable Delphi libraries (OTL, Indy, Spring4D, etc.) |
| `example-output.cdx.json` | Example SBOM output for reference — shows what a generated SBOM looks like |

These are essential for onboarding — newcomers need a worked example to understand `components.json` authoring.

---

## Implementation Order (Phase 1 — MVP)

1. **Repository setup** — `.dpr`, `.dproj`, `CLAUDE.md` (Ian to review draft), `README.md`, `LICENCE`, `CHANGELOG.md`, `.gitignore`, `Samples/`
2. **`uTypes.pas`** — Shared record types
3. **`uProjectParser.pas`** — Parse `.dpr` uses clause + `.dproj` XML
4. **`uRTLScanner.pas`** — Registry lookup + `.dcu` directory scan
5. **`uManifestLoader.pas`** — Load/validate `components.json`
6. **`uUnitClassifier.pas`** — Classification engine
7. **`uSBOMBuilder.pas`** — CycloneDX JSON assembly
8. **`uSBOMEngine.pas`** — Pipeline orchestrator (UI-independent, coordinates steps 3–7)
9. **`uMainForm.pas` / `.dfm`** — VCL form with file selection, options, results display, and log panel
10. **Manual testing** — Ian provides a real `.dpr`/`.dproj` for validation

---

## Verification

- Launch the application; confirm Delphi Path auto-populates from registry
- Browse to a real `.dpr`/`.dproj` file; confirm defaults populate correctly
- Click **Generate SBOM**; verify classification results appear in the results panel
- Open the generated `.cdx.json` and verify it is valid CycloneDX 1.5 JSON
- Check unclassified units list shows units not covered by RTL scan or manifest
- Click **Validate Manifest** with a malformed `components.json`; confirm errors appear in the log
- Clear the Delphi Path field; regenerate; confirm `[WARNING]` appears and processing continues
- Verify version info is correctly extracted from `.dproj` (and overridden when Version Override is populated)

---

*End of Refined Plan v0.6*
*Review and update before Phase 1 begins.*
