# DelphiSBOM — User's Guide

## Introduction

DelphiSBOM generates a Software Bill of Materials (SBOM) for your Delphi
applications. An SBOM is a formal inventory of every component, library, and
framework your application depends on — required by regulations such as the
EU Cyber Resilience Act (effective December 2027).

DelphiSBOM produces SBOMs in the **CycloneDX 1.5 JSON** format, a widely
adopted open standard maintained by OWASP.

Unlike generic SBOM tools, DelphiSBOM understands the Delphi ecosystem. It
knows which units belong to the Embarcadero RTL, can discover third-party
libraries on your disk, and lets you build an accurate SBOM without manually
cataloguing every dependency.

## Installation

DelphiSBOM is a standalone Windows application. No installer is required.

1. Download `DelphiSBOM.exe` (or build from source)
2. Place it anywhere on your system
3. Run it — no configuration needed

### Building from Source

1. Open `Source/DelphiSBOM.dproj` in Delphi 12 or later
2. Select your target platform (Win32 or Win64)
3. Build (Ctrl+F9) or Run (F9)

No third-party libraries are required.

## First Run

When you launch DelphiSBOM for the first time:

1. The **Delphi Path** field auto-populates from the Windows registry. If you
   have multiple Delphi versions installed, the highest version is selected.
   You can change this by clicking Browse.

2. All other fields start empty, waiting for you to select a project.

## Generating Your First SBOM

### Step 1: Select Your Project

Click **Browse** next to the Project File field and select your application's
`.dpr` or `.dproj` file.

When you select a project:
- The **Output Dir** automatically sets to the project's directory
- If a `components.json` file exists in that directory, the **Manifest** field
  populates. If not, a minimal empty one is created automatically
- The **Version Override** field remains blank (the version will be read from
  the `.dproj`)

### Step 2: Generate

Click **Generate SBOM**. The app runs the following pipeline in the background
(your UI stays responsive):

1. **Parses** the `.dpr` file to extract all unit names from the `uses` clause
2. **Reads** the `.dproj` file for project metadata: name, version, target
   platform, search paths
3. **Scans** your Delphi installation's `lib` directory to build a list of
   known RTL/VCL/FMX units
4. **Loads** your `components.json` manifest (if any libraries are defined)
5. **Classifies** every unit using a priority system:
   - First: is it an RTL/VCL unit? (matched against the Delphi installation scan)
   - Second: does it match a library in `components.json`? (exact name match,
     then prefix match)
   - Otherwise: unclassified
6. **Discovers** libraries for unclassified units by searching the file system:
   - Searches your project's search paths (from the `.dproj`)
   - Searches common library locations (`D:\`, `C:\Program Files`)
   - Groups found `.pas` files by directory (one directory = one library)
   - Extracts metadata: library name from directory name, vendor from source
     file headers, licence from LICENSE files
7. **Generates** the CycloneDX 1.5 JSON SBOM and writes it to the output
   directory

### Step 3: Review Results

After generation completes, two panels show the results:

**Left panel — Classification Summary:**
```
Classification Summary
══════════════════════
RTL/VCL units:        142
Third-party units:     28
Own-code units:         0
Unclassified:           3

Third-Party Components
──────────────────────
  OmniThreadLibrary 3.7.8
  ElevateDB 2.x
```

**Right panel — Discovered Libraries:**

If unclassified units were found and their `.pas` files located on disk, the
app groups them by library and shows:

```
DISCOVERED LIBRARIES
════════════════════
── GITLAKLib ──
  Directory: D:\GITLAKLib
  Vendor:    Ian Branch (GITLAK Software)
  Prefix:    gll
  Units (3):
    gllFunctions
    gllDateTimeHelpers
    gllStringUtils
```

Any units whose `.pas` files could not be found appear under
**UNRESOLVED UNITS** at the bottom of the panel.

### Step 4: Save and Regenerate

If the discovery panel shows libraries you want to include in your SBOM:

1. Review the discovered libraries — the name, vendor, and licence are
   pre-populated where possible
2. Click **Save Libraries & Regenerate SBOM**

This does two things:
- Saves the discovered libraries to your `components.json` file
- Immediately re-runs the SBOM generation pipeline

On the second run, the previously unclassified units now match their libraries
in `components.json` and appear as third-party components in the SBOM.

### Step 5: Done

Your SBOM is saved as `<ProjectName>.cdx.json` in the output directory. This
file is ready for compliance submission, auditing, or integration into your
build pipeline.

## Subsequent Runs

Once your `components.json` is populated (either from discovery or manual
editing), subsequent runs against the same project classify everything
immediately — no discovery step needed. Just click Generate SBOM and the
output is ready.

If you add new third-party libraries to your project, new unclassified units
will appear and the discovery process will find them automatically.

## Understanding the Output

### The SBOM File

The generated `.cdx.json` contains:

- **Metadata**: your application name, version, supplier, and the tool that
  generated the SBOM
- **Components**: a flat list of all third-party dependencies, each with:
  - Name and version
  - Supplier/vendor
  - Licence (SPDX identifier)
  - Package URL (`pkg:delphi/<name>@<version>`)
  - External references (vendor website)
- **Embarcadero Delphi RTL**: listed as a single framework component with
  the Delphi version number

### What is NOT in the SBOM

- **Your own code** — own-code units are the application itself, not dependencies
- **Individual RTL units** — the entire RTL is listed as one component
- **Dependency relationships** — the component list is flat (no dependency graph)

## The `components.json` Manifest

### Automatic Management

DelphiSBOM creates and updates `components.json` automatically:

- **Created** when you first select a project (empty template)
- **Updated** when you click Save Libraries & Regenerate SBOM (discovered
  libraries are appended)

### Manual Editing

You can also edit `components.json` directly to:

- Correct auto-detected library names, versions, or licences
- Add libraries that weren't discovered automatically
- Set the supplier information for your organisation
- Remove incorrectly identified libraries

See `Docs/SCHEMA.md` for the complete field reference and authoring guidelines.

### Key Fields

Each component in the manifest has:

| Field | Purpose | Example |
|-------|---------|---------|
| `name` | Library display name | `"OmniThreadLibrary"` |
| `version` | Version string | `"3.7.8"` |
| `vendor` | Author or company | `"Primož Gabrijelčič"` |
| `licence` | SPDX licence ID | `"BSD-3-Clause"` |
| `type` | CycloneDX type | `"library"` or `"framework"` |
| `units_prefix` | Unit name prefixes to match | `["Otl"]` |
| `units_exact` | Exact unit names to match | `["GpLists", "GpStuff"]` |

### Matching Rules

- **Prefix matching** is case-insensitive: prefix `"Otl"` matches `OtlParallel`,
  `OtlTask`, `OtlCommon`, etc.
- **Exact matching** is case-insensitive: `"GpLists"` matches only `GpLists`
- Prefixes must be at least 3 characters long to avoid false matches
- For libraries with short or ambiguous unit names, use `units_exact` instead
  of `units_prefix`

## Tips

### Running Against Multiple Projects

DelphiSBOM processes one project at a time. Each project gets its own
`components.json` in its directory. However, many libraries are shared — once
you've run discovery on one project, you can copy its `components.json` to
another project as a starting point.

### Overriding the Version

If your `.dproj` doesn't contain version information (or you want to use a
different version for the SBOM), type the version in the **Version Override**
field before generating. This overrides whatever the `.dproj` contains.

### CI/CD Integration

The current version is a GUI application. A command-line mode for CI/CD
integration is planned for a future release. In the meantime, generate your
SBOM once and commit the `components.json` and `.cdx.json` files to version
control.

### Keeping the SBOM Current

Regenerate your SBOM whenever you:

- Add or remove third-party libraries
- Update a library version
- Change your project's version number
- Prepare a release

The process takes seconds — just click Generate SBOM.

## Glossary

| Term | Definition |
|------|------------|
| **SBOM** | Software Bill of Materials — a formal inventory of software components |
| **CycloneDX** | An OWASP open standard for SBOM format (JSON/XML) |
| **SPDX** | Software Package Data Exchange — a licence identifier standard |
| **PURL** | Package URL — a standardised way to identify software packages |
| **RTL** | Run-Time Library — Delphi's built-in standard library |
| **VCL** | Visual Component Library — Delphi's Windows UI framework |
| **FMX** | FireMonkey — Delphi's cross-platform UI framework |
| **EU CRA** | EU Cyber Resilience Act — regulation requiring SBOMs for digital products |

---
*Version: 1.0 – 26 March 2026 08:30*
