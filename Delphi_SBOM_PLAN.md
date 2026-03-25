# DelphiSBOM — Project Plan
**A CycloneDX SBOM Generator for Delphi Applications**
Version 0.1 — Draft
Prepared by: Claude (Anthropic) in collaboration with Ian (GITLAK Software)

---

## 1. Project Overview

### Purpose
DelphiSBOM is a free, open-source utility that generates a standards-compliant
**CycloneDX 1.5 Software Bill of Materials (SBOM)** from a Delphi project. It is
designed to help Delphi developers meet emerging regulatory requirements (principally
the EU Cyber Resilience Act, effective December 2027) without relying on generic
SBOM tools that have no awareness of the Delphi ecosystem.

### Audience
- Delphi developers who need to produce or maintain an SBOM for their applications
- Development teams subject to software supply chain audit requirements
- Any Delphi shop wanting a documented, repeatable inventory of their dependencies

### Repository
- **Host:** Codeberg (public repository)
- **Suggested name:** `DelphiSBOM`
- **Licence:** MIT
- **Language:** Delphi (Win64, Delphi 12+)

---

## 2. Goals and Non-Goals

### Goals
- Parse Delphi `.dpr` and `.dproj` files to extract project metadata and unit lists
- Classify each unit as: **RTL/VCL** (Embarcadero), **third-party** (from a curated
  manifest), or **own code** (developer-authored)
- Read a maintainable `components.json` manifest describing known third-party
  libraries with version, vendor, licence, and URL metadata
- Generate a valid **CycloneDX 1.5 JSON** SBOM file
- Produce a human-readable **summary report** alongside the SBOM
- Operate as a **console application** suitable for scripting and CI/CD integration
- Be genuinely useful to the broader Delphi community — not GITLAK-specific

### Non-Goals (v1.0)
- Binary / DCU deep inspection (post-v1.0 consideration)
- Cryptographic signing of the SBOM output
- Integration with vulnerability databases (CVE lookup)
- GUI front-end (console-first; GUI wrapper is a post-v1.0 option)
- Support for Delphi versions prior to Delphi 12 (may work, but not tested/targeted)

---

## 3. Architecture

### 3.1 Application Type
Console application (`DelphiSBOM.exe`). Single executable, no installer required.
Designed to be dropped into a project folder or placed on the system PATH.

### 3.2 High-Level Processing Pipeline

```
  .dpr / .dproj files
         │
         ▼
  ┌─────────────────┐
  │  Project Parser  │  Extracts: project name, Delphi version, target platform,
  │                  │  unit list, search paths, output path
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  Unit Classifier │  Classifies each unit as RTL/VCL, third-party, or own code
  │                  │  using: built-in RTL/VCL unit registry + components.json
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │ Manifest Loader  │  Reads components.json — the curated list of known
  │                  │  third-party libraries with full metadata
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  SBOM Builder    │  Assembles CycloneDX 1.5 JSON document
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────┐
  │  Report Writer   │  Writes .json SBOM + optional .txt summary report
  └─────────────────┘
```

### 3.3 Key Data Files

| File | Role | Maintained by |
|---|---|---|
| `components.json` | Third-party library manifest (per-project or shared) | Developer |
| `rtl-units.txt` | Built-in list of known Embarcadero RTL/VCL/FMX units | Shipped with tool |
| `<ProjectName>.cdx.json` | Generated CycloneDX SBOM output | Tool |
| `<ProjectName>.sbom-report.txt` | Human-readable summary | Tool |

### 3.4 `components.json` Schema (Draft)

This is the heart of the semi-automated approach. The developer maintains this file
once; it changes only when dependencies are added, updated, or removed.

```json
{
  "schema_version": "1.0",
  "last_updated": "2026-03-26",
  "supplier": {
    "name": "GITLAK Software",
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
      "units_prefix": ["OtlCommon", "OtlCollections", "OtlTask",
                       "OtlTaskControl", "OtlSync", "OtlParallel",
                       "OtlEventMonitor", "OtlThreadPool"],
      "notes": "Mandated threading library per GITLAK coding standards"
    },
    {
      "name": "ElevateDB",
      "version": "2.x",
      "vendor": "Elevate Software",
      "vendor_url": "https://www.elevatesoft.com",
      "licence": "Commercial",
      "licence_url": "https://www.elevatesoft.com/products?category=edb",
      "type": "database",
      "units_prefix": ["EDB"]
    },
    {
      "name": "EurekaLog",
      "version": "7.x",
      "vendor": "FastMM Solutions",
      "vendor_url": "https://www.eurekalog.com",
      "licence": "Commercial",
      "licence_url": "https://www.eurekalog.com",
      "type": "library",
      "units_prefix": ["EurekaLog", "EL"]
    },
    {
      "name": "TMS VCL UI Pack",
      "version": "12.x",
      "vendor": "TMS Software",
      "vendor_url": "https://www.tmssoftware.com",
      "licence": "Commercial",
      "licence_url": "https://www.tmssoftware.com/site/tmspolicies.asp",
      "type": "ui-library",
      "units_prefix": ["TMS", "AdvGrid", "AdvEdit", "AdvPanel", "AdvTree",
                       "AdvMemo", "AdvPlanner"]
    },
    {
      "name": "Indy",
      "version": "10.x",
      "vendor": "Indy Project / Embarcadero",
      "vendor_url": "https://www.indyproject.org",
      "licence": "Modified-LGPL",
      "licence_url": "https://www.indyproject.org/license.aspx",
      "type": "library",
      "units_prefix": ["IdHTTP", "IdSMTP", "IdMessage", "IdSSLOpenSSL",
                       "IdTCPClient", "IdComponent"]
    }
  ]
}
```

**Design notes on `units_prefix`:**
The classifier matches each unit found in the project's `uses` clauses against these
prefix lists. Matching is case-insensitive and prefix-based (e.g., `"EDB"` matches
`EDBEngine`, `EDBSession`, `EDBDatabase`, etc.). This approach is robust without
requiring exhaustive unit enumeration.

---

## 4. CycloneDX 1.5 Output Structure

The generated SBOM will conform to CycloneDX specification 1.5. Key sections:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:<generated-uuid>",
  "version": 1,
  "metadata": {
    "timestamp": "<ISO-8601>",
    "tools": [ { "vendor": "GITLAK / Ian", "name": "DelphiSBOM", "version": "1.0.0" } ],
    "component": {
      "type": "application",
      "name": "<ProjectName>",
      "version": "<supplied or from .dproj>",
      "description": "<optional>",
      "supplier": { "name": "<from components.json supplier>" }
    }
  },
  "components": [
    {
      "type": "library",
      "name": "OmniThreadLibrary",
      "version": "3.7.8",
      "supplier": { "name": "Primož Gabrijelčič" },
      "licenses": [ { "license": { "id": "BSD-3-Clause" } } ],
      "externalReferences": [
        { "type": "website", "url": "https://github.com/gabr42/OmniThreadLibrary" }
      ],
      "purl": "pkg:delphi/OmniThreadLibrary@3.7.8"
    }
  ]
}
```

**Note on `purl`:** The Package URL (`purl`) scheme for Delphi is not formally
registered in the PURL spec. We will use `pkg:delphi/<name>@<version>` as a
pragmatic convention, and document this clearly in the README. This is consistent
with how other niche ecosystems handle the gap.

---

## 5. Command-Line Interface

```
DelphiSBOM [options] <project.dpr | project.dproj>

Options:
  -m, --manifest <path>    Path to components.json (default: same dir as project)
  -o, --output <path>      Output directory (default: same dir as project)
  -v, --version <ver>      Override product version string in SBOM metadata
  -r, --report             Also generate human-readable .txt summary report
  -q, --quiet              Suppress console output (for CI use)
  --validate               Validate components.json schema without generating SBOM
  --list-unclassified      List any units not matched to RTL/VCL or a manifest entry
      --help               Show this help
      --version            Show tool version
```

The `--list-unclassified` flag is particularly useful during initial setup — it shows
you exactly which units in your project aren't yet covered by your `components.json`,
helping you fill gaps in the manifest.

---

## 6. Project Structure (Repository Layout)

```
DelphiSBOM/
│
├── Source/
│   ├── DelphiSBOM.dpr               Main project file
│   ├── DelphiSBOM.dproj
│   ├── uMain.pas                    Console entry point, CLI parsing
│   ├── uProjectParser.pas           .dpr / .dproj parser
│   ├── uUnitClassifier.pas          Unit → library classification engine
│   ├── uManifestLoader.pas          components.json reader/validator
│   ├── uSBOMBuilder.pas             CycloneDX JSON assembly
│   ├── uReportWriter.pas            Human-readable report output
│   ├── uRTLUnitRegistry.pas         Embarcadero RTL/VCL unit list (auto-generated)
│   └── uTypes.pas                   Shared record/enum types
│
├── Data/
│   └── rtl-units.txt                Canonical RTL/VCL unit list (Delphi 12+)
│
├── Samples/
│   ├── components.sample.json       Fully commented sample manifest
│   └── example-output.cdx.json     Example SBOM output for reference
│
├── Tests/
│   └── (DUnit/DUnitX test project — Phase 2)
│
├── Docs/
│   ├── PLAN.md                      This document
│   ├── SCHEMA.md                    components.json schema reference
│   └── CYCLONEDX-NOTES.md          Notes on CycloneDX 1.5 + Delphi-specific decisions
│
├── README.md
├── LICENCE                          MIT
├── CHANGELOG.md
└── CLAUDE.md                        Instructions for Claude Code (see Section 8)
```

---

## 7. Implementation Phases

### Phase 1 — Core Pipeline (MVP)
*Target: working tool that produces a valid SBOM from a real project*

- [ ] Repository initialised on Codeberg with MIT licence, README skeleton, CLAUDE.md
- [ ] `components.json` schema finalised and documented
- [ ] `rtl-units.txt` compiled — complete list of RTL/VCL/FMX units for Delphi 12+
- [ ] `uTypes.pas` — shared record types (`TComponentEntry`, `TProjectInfo`,
      `TClassifiedUnit`, etc.)
- [ ] `uManifestLoader.pas` — load and validate `components.json`
- [ ] `uProjectParser.pas` — parse `.dpr` (uses clause) and `.dproj` (XML metadata,
      search paths, version info)
- [ ] `uUnitClassifier.pas` — classify all units against RTL registry + manifest
- [ ] `uSBOMBuilder.pas` — assemble and emit CycloneDX 1.5 JSON
- [ ] `uMain.pas` — CLI argument parsing and pipeline orchestration
- [ ] Manual testing against a real DBiWorkflow project file (Ian)
- [ ] README — installation, quick-start, components.json authoring guide

### Phase 2 — Polish and Reliability
- [ ] `uReportWriter.pas` — human-readable summary report
- [ ] `--list-unclassified` output
- [ ] `--validate` mode for `components.json`
- [ ] DUnitX test project covering parser and classifier logic
- [ ] `components.sample.json` with all common Delphi third-party libraries documented
- [ ] CHANGELOG.md
- [ ] First tagged release on Codeberg (v1.0.0)

### Phase 3 — Community and Ecosystem (Post-v1.0)
- [ ] Shared community `components.json` contributions via pull requests
- [ ] Support for scanning multiple projects in one pass (solution-level SBOM)
- [ ] Optional binary hash of output `.exe` added to SBOM metadata
- [ ] Investigate formal PURL `pkg:delphi` registration
- [ ] Optional GUI wrapper (simple VCL form)

---

## 8. Instructions for Claude Code (CC)

> **CC should read this section carefully before beginning any implementation work.**

### 8.1 General Standards
- Follow all GITLAK coding standards as defined in the master `CLAUDE.md` at
  `E:\_Standards\claude.md`. This project uses those standards even though it is a
  public repository — they represent good Delphi practice generally.
- Target: **Delphi 12+, Win64, console application**.
- No third-party library dependencies beyond the Delphi RTL and standard library.
  This project must compile with a clean Delphi 12 installation and nothing else.
  `System.JSON` (built-in) is to be used for all JSON work. No external JSON
  libraries.
- Use `inline var` declarations throughout.
- XML parsing of `.dproj` files: use `Xml.XMLDoc` and `Xml.XMLIntf` (built-in).

### 8.2 No GITLAK-Internal References
This is a **public repository**. Do not reference GITLAK Software, DBiWorkflow,
GITLAKLib, or any internal system names in code, comments, or documentation. The
`components.sample.json` should use generic, publicly recognisable Delphi libraries
as examples. The only GITLAK reference is in the tool's `supplier` metadata field,
which is supplied at runtime via `components.json` — not hardcoded.

### 8.3 JSON Handling
Use `System.JSON` exclusively:
- `TJSONObject`, `TJSONArray`, `TJSONString`, `TJSONNumber`, `TJSONBool`
- Always use `TJSONObject.ParseJSONValue` for reading; build output using
  `TJSONObject` / `TJSONArray` constructors
- All JSON output must be pretty-printed (use `TJSONAncestor.Format`)

### 8.4 File Parsing Notes

**.dpr parsing:**
The `uses` clause in a `.dpr` file is plain text. Parse it with a simple state-machine
text reader — do not attempt to use a full Pascal parser. Extract unit names from
the `uses ... ;` block, stripping `in '...'` file references. Ignore `{$...}`
compiler directives.

**.dproj parsing:**
`.dproj` files are MSBuild XML. Key elements to extract:
- `<ProductVersion>` or `<VersionInfoKeys>` → product version string
- `<DCC_Namespace>` → unit scope names (important for RTL classification)
- `<Platform>` → target platform (Win32/Win64)
- `<DCC_UnitSearchPath>` → search paths (semicolon-delimited)
- `<VerInfo_ProductVersion>` → version info

### 8.5 Unit Classification Logic
Classification priority order (first match wins):

1. If the unit name (after stripping scope prefix, e.g. `Vcl.` or `System.`) matches
   an entry in `rtl-units.txt` → classify as **RTL/VCL** (supplier: Embarcadero)
2. If the bare unit name matches a `units_prefix` entry in `components.json`
   (case-insensitive, prefix match) → classify as **Third-Party**, linked to that
   component entry
3. If the unit file is found on a search path that resolves to within the project's
   own source tree → classify as **Own Code**
4. Otherwise → classify as **Unclassified** (reported via `--list-unclassified`)

### 8.6 CycloneDX Conformance
- Use spec version `"1.5"` throughout
- `serialNumber` must be a valid UUID in `urn:uuid:` format — generate with
  `TGuid.NewGuid`
- `timestamp` must be ISO 8601 format — use `TTimeZone.Local.ToUniversalTime` then
  format as `yyyy-mm-ddThh:nn:ssZ`
- Every component must have at minimum: `type`, `name`, `version`
- `licenses` array uses the SPDX licence identifier format where possible
  (e.g. `"MIT"`, `"BSD-3-Clause"`, `"Apache-2.0"`). For commercial licences use
  `{ "license": { "name": "Commercial" } }` (no `id` field)
- Do not invent fields not present in CycloneDX 1.5 spec. When uncertain, refer to:
  https://cyclonedx.org/docs/1.5/json/

### 8.7 Error Handling
- Use exceptions for unrecoverable errors (file not found, malformed JSON, etc.)
- Report errors to `StdErr` with a clear prefix: `[ERROR]`, `[WARNING]`, `[INFO]`
- Exit codes: `0` = success, `1` = usage error, `2` = file/parse error,
  `3` = validation error
- Never silently swallow exceptions

### 8.8 Testing Inputs
Ian will provide real `.dpr` / `.dproj` samples for testing. Do not fabricate test
data — ask Ian when real project file samples are needed. The `--list-unclassified`
output is the primary diagnostic tool during development.

### 8.9 Commit Discipline
- Commit frequently with descriptive messages following conventional commits style:
  `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Each unit should be implemented and committed individually — do not batch multiple
  units into a single large commit
- Do not commit generated SBOM output files or `.local` / `.identcache` IDE files

---

## 9. Decisions Still to Be Made (Before Phase 1 Start)

These require Ian's input:

| # | Decision | Options | Notes |
|---|---|---|---|
| 1 | Shared vs per-project `components.json` | Single shared file on D:\ vs one per project | Shared is more maintainable; per-project is more portable for public use |
| 2 | RTL unit list source | Hand-curated vs auto-extracted from Delphi install | Auto-extraction is more accurate but adds complexity |
| 3 | Version string source | CLI flag only vs auto-read from `.dproj` VerInfo | `.dproj` is preferred but not always populated |
| 4 | SBOM output location | Alongside project vs dedicated output dir | Should default to project dir, overridable |
| 5 | Scope prefix handling | Strip scope prefixes (`Vcl.`, `System.`) before classifying | Almost certainly yes — confirm |
| 6 | Multi-project support in v1.0 | Single `.dpr` only vs accept a list or a `.groupproj` | Single `.dpr` for v1.0 is safer |

---

## 10. Reference Links

- CycloneDX 1.5 JSON Schema: https://cyclonedx.org/docs/1.5/json/
- CycloneDX specification on GitHub: https://github.com/CycloneDX/specification
- SPDX Licence List: https://spdx.org/licenses/
- Package URL specification: https://github.com/package-url/purl-spec
- EU Cyber Resilience Act (official): https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- Codeberg: https://codeberg.org

---

*End of Plan v0.1*
*Review and update before Phase 1 begins.*
