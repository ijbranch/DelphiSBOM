# DelphiSBOM

A CycloneDX 1.5 SBOM (Software Bill of Materials) generator for Delphi applications.

## What is an SBOM?

A **Software Bill of Materials (SBOM)** is a formal, machine-readable inventory
of all components, libraries, and dependencies that make up a software
application — essentially a "ingredients list" for software. SBOMs are
becoming a regulatory requirement in many jurisdictions:

- **EU Cyber Resilience Act** (effective December 2027) requires manufacturers
  of products with digital elements to provide an SBOM
- **US Executive Order 14028** recommends SBOMs for software sold to the
  federal government
- **FDA** requires SBOMs for medical device software

## What is CycloneDX?

**CycloneDX** is an open standard for SBOMs maintained by OWASP (the Open
Worldwide Application Security Project). It defines a structured format
(JSON or XML) for describing software components, their versions, suppliers,
licences, and relationships. DelphiSBOM generates CycloneDX 1.5 JSON — the
current stable version of the specification.

CycloneDX is one of two widely adopted SBOM formats (the other being SPDX).
It was designed specifically for security and software supply chain use cases,
making it the natural choice for compliance with regulations like the EU CRA.

More information: https://cyclonedx.org

## Purpose

DelphiSBOM helps Delphi developers produce standards-compliant SBOMs to meet
these emerging regulatory requirements without relying on generic SBOM tools
that have no awareness of the Delphi ecosystem.

## How It Works

1. **Parse** your Delphi `.dpr` and `.dproj` files to extract project metadata
   and the full unit list
2. **Scan** the Delphi installation to identify RTL/VCL/FMX units automatically
3. **Classify** each unit as RTL/VCL (Embarcadero), third-party (from the
   `components.json` manifest), or your own code
4. **Discover** — for any unclassified units, scan the file system to find their
   `.pas` source files, group them by library directory, and extract metadata
   (vendor from source headers, licence from LICENSE files)
5. **Review & Save** — confirm discovered libraries in the app, then save to
   `components.json` with one click
6. **Generate** a valid CycloneDX 1.5 JSON SBOM file

## Quick Start

1. Run DelphiSBOM and browse to your `.dpr`, `.dpk` or `.dproj` file (or select a
   recent project from the dropdown)
2. Click **Generate SBOM**
3. Review the results — discovered third-party libraries are shown with
   auto-detected names, vendors, and licences (click **Edit...** to correct them)
4. Click **Save & Regenerate** to confirm and save
5. Find your `<ProjectName>.cdx.json` in the project directory

No manual JSON editing required. DelphiSBOM creates and maintains
`components.json` for you based on what it discovers on disk.

## The `components.json` Manifest

DelphiSBOM uses a `components.json` file to track your project's third-party
libraries. It is created the first time you save discovered libraries or
own-code units — selecting a project never writes into your repository — and
updated each time you confirm more. If an existing `components.json` is not
valid JSON, DelphiSBOM refuses to save rather than overwrite it.

You can also edit it manually for fine-tuning. See
`Samples/components.sample.json` for a fully commented example, and
`Docs/SCHEMA.md` for the complete schema reference.

## Files Read and Written

DelphiSBOM is a read-only tool with respect to your project source — it never
modifies your `.dpr`, `.dproj`, or `.pas` files. The files it does read and
write are:

### Files Read

| What | Where | Purpose |
|------|-------|---------|
| `.dpr` / `.dpk` / `.dproj` | Your project directory | Parses unit list, version info, search paths, target platform (the `.dproj` is evaluated for Release on the target platform) |
| `.dcu` files | `<Delphi Install>\lib\<Platform>\release\` | Enumerates RTL/VCL unit names for classification |
| `components.json` | Your project directory | Reads third-party library definitions and own-code unit lists |
| Windows Registry | `HKCU\Software\Embarcadero\BDS\*`, `HKLM\SOFTWARE\WOW6432Node\Embarcadero\BDS\*` | **Read-only.** Detects installed Delphi versions and their installation paths — the version matching the project's `ProjectVersion` is preferred. Also reads IDE environment variables and the IDE library path |

### Files Written

| What | Where | Purpose |
|------|-------|---------|
| `<Project>.cdx.json` | Output directory (defaults to project dir) | The generated CycloneDX 1.5 SBOM — this is the deliverable. UTF-8 without a BOM, written atomically |
| `components.json` | Your project directory | Written when you click "Save & Regenerate" or "Mark as Own Code", and after a successful run that auto-detected own-code units |
| `DelphiSBOM.ini` | `%APPDATA%\DelphiSBOM\` | Application settings (UTF-8): MRU project list (up to 10) with per-project manifest path, output directory, version override and DX.Comply file. Created on first successful SBOM generation |

DelphiSBOM does **not** write to the Windows Registry.

## Requirements

- Windows (Win32 or Win64)
- A Delphi installation (for RTL unit auto-detection)
- No mandatory runtime dependencies — single standalone `.exe`
- Optional: [SynEdit](https://github.com/SynEdit/SynEdit) for syntax-highlighted SBOM viewing

## Building from Source

Open `Source/DelphiSBOM.dproj` in Delphi and compile. The project compiles
with only the Delphi RTL — no third-party libraries are required for the
core functionality.

**Development and test environment:** DelphiSBOM is developed, built and
tested **only on Delphi 13 Florence, Win64, VCL**. Delphi 10.3 Rio is the
language floor (inline variable declarations), not a tested configuration:
earlier compilers are untested and may need small changes. Win32 builds are
declared in the project but not routinely tested. Reports from other versions
are welcome.

**Optional:** Add [SynEdit](https://github.com/SynEdit/SynEdit) to your
library path for syntax-highlighted JSON viewing in the SBOM viewer, then
enable it **locally** — do not add `USE_SYNEDIT` to the committed `.dproj`:

```
setx DELPHISBOM_DEFINES USE_SYNEDIT
```

(or add `DELPHISBOM_DEFINES=USE_SYNEDIT` under Tools > Options > Environment
Variables in the IDE), then restart the IDE. The `.dproj` passes
`$(DELPHISBOM_DEFINES)` to the compiler, so a machine without the variable
builds the plain `TMemo` viewer. A pre-commit hook in `.githooks/` rejects a
`.dproj` that defines `USE_SYNEDIT` directly; enable it once per clone with
`git config core.hooksPath .githooks`.

## Running the Tests

`Tests/DelphiSBOMTests.dproj` is a [DUnitX](https://github.com/VSoftTechnologies/DUnitX)
console suite covering the pipeline units (everything except the VCL forms):
encoding detection, `.dproj` evaluation, unit-list parsing, manifest safety,
classification precedence, CycloneDX output (licences, purls, timestamp,
evidence) and an end-to-end engine run. DUnitX must be on your library path.

```
Tests\Win64\Debug\DelphiSBOMTests.exe --exitbehavior:Continue
```

The exit code is non-zero when any test fails. String assertions are
case-sensitive (`Assert.IgnoreCaseDefault := False`), and a test that asserts
nothing fails.

**Environment caveat (tests):** the suite is built and run only on Delphi 13
Florence, Win64. Two fixtures read the machine: `TestDelphiInstall` checks
registry-detection invariants that hold with or without Delphi installed, and
`TestSBOMEngine` runs library discovery, which also scans `D:\` and the Program
Files folders (its unit names are unique, so nothing found there can match).
Each test writes only to its own `%TEMP%\DelphiSBOMTests-<guid>` folder and
deletes it afterwards.

### GUI checks

`Tests/GuiChecks.ps1` drives the built application (`Source\Win64\Release\DelphiSBOM.exe`)
through window messages to its controls — no screen coordinates, no stealing
focus — and reports PASS/FAIL for 30 checks: switching projects resets the
per-project fields, the recent-projects list restores them (including a path
with Cyrillic characters, across a restart), result buttons are disabled while
a run is in progress, the library editor's Space toggle, missing-name warning
and discard prompt, and Save & Regenerate writing the manifest.

```
pwsh -File Tests\GuiChecks.ps1
```

It needs PowerShell 7. Your `%APPDATA%\DelphiSBOM\DelphiSBOM.ini` is backed up
first and restored afterwards; the exit code is non-zero when a check fails.
**Environment caveat:** run only on Windows 11 with Delphi 13; it assumes the
application's default layout (the app is DPI-unaware).

## Licence

MIT — see [LICENCE](LICENCE).
