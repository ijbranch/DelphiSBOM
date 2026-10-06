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

1. Open `Source/DelphiSBOM.dproj` in Delphi
2. Select the Win64 target platform
3. Build (Ctrl+F9) or Run (F9)

No mandatory third-party libraries are required for core functionality.

**Development and test environment:** DelphiSBOM is developed, built and
tested only on **Delphi 13 Florence, Win64, VCL**. Delphi 10.3 Rio is the
language floor (inline variables), not a tested configuration — earlier
compilers and Win32 builds are untested.

**Optional dependency:** For syntax-highlighted JSON viewing, add
[SynEdit](https://github.com/SynEdit/SynEdit) (MPL-1.1 licence) to your
Delphi library path and set the environment variable
`DELPHISBOM_DEFINES=USE_SYNEDIT` (Windows: `setx DELPHISBOM_DEFINES USE_SYNEDIT`,
or Tools > Options > Environment Variables in the IDE), then restart the IDE.
Do **not** add `USE_SYNEDIT` to the project's conditional defines: that would
be saved into the shared `.dproj` and break builds without SynEdit. Without
SynEdit, the SBOM viewer uses a plain text display.

## First Run

When you launch DelphiSBOM for the first time:

1. The **Delphi Path** field is blank. Blank means "use the installed Delphi
   version that matches the project": each run maps the project's
   `ProjectVersion` to its Delphi version and looks it up in the registry
   (`HKCU\Software\Embarcadero\BDS`, then the installer's `HKLM` key). If that
   version is not installed, the newest installed version is used and the log
   says so. Browse to a path only to force a specific installation. This is a
   **read-only** registry access — DelphiSBOM never writes to the registry.

2. All other fields start empty, waiting for you to select a project.

On subsequent launches, the **Project File** dropdown shows your recently used
projects (up to 10). Select one to restore all settings (manifest path, output
directory, version override, DX.Comply file) from your last session. These settings are stored
in `%APPDATA%\DelphiSBOM\DelphiSBOM.ini`.

## Generating Your First SBOM

### Step 1: Select Your Project

Click **Browse** next to the Project File field and select your application's
`.dpr`, `.dpk` or `.dproj` file. Or, if you have used DelphiSBOM before, choose a
recent project from the dropdown list.

When you select a project, every per-project field is reset so nothing carries
over from the previous project:
- The **Output Dir** is set to the project's directory
- The **Manifest** is set to `components.json` in the project's directory. The
  file is not created yet — DelphiSBOM writes it only when you first save
  libraries or own-code units
- The **Version Override** and **DX.Comply SBOM** fields are cleared (the
  version will be read from the `.dproj`)
- If you have used the project before, its remembered settings are then restored

### Step 2: Generate

Click **Generate SBOM**. The app runs the following pipeline in the background
(your UI stays responsive):

1. **Reads** the `.dproj` file for project metadata — name, version, target
   platform, search paths — evaluating it the way MSBuild does for a Release
   build of the target platform (Win64 when active)
2. **Parses** the `.dpr` (or the `.dproj`'s `MainSource`; for a package, the
   `.dpk` `contains` clause) to extract all unit names — or, when a **MAP File**
   is given, takes the units the linker used from it (see
   [MAP Files](#map-files-optional))
3. **Scans** the `lib` directory of the Delphi installation matching the
   project's version to build a list of known RTL/VCL/FMX units
4. **Loads** your `components.json` manifest (if any libraries are defined)
5. **Classifies** every unit using a priority system:
   - First: is it an RTL/VCL unit? (matched against the Delphi installation scan)
   - Second: is it listed by exact name in `components.json` (`units_exact`)?
   - Third: is it listed in `own_code_units`?
   - Fourth: does it match a library prefix (`units_prefix`)?
   - Fifth: is it your own code (an `in 'file.pas'` reference, or `own_code_prefixes`)?
   - Otherwise: unclassified
6. **Discovers** libraries for unclassified units by searching the file system:
   - Searches the project directory, your project's search paths (from the
     `.dproj`, with `$(BDS)`-style macros expanded) and the IDE library path
   - For a unit with no `.pas` there, looks for its `.dcu` in the search paths
     and the IDE library path — many libraries are installed as compiled units
     only — and treats the folder above the build-output folders
     (`Lib\Win64\Release`, `37.0\Win64\Release`, ...) as the library, using
     the unit's source if it is anywhere under that folder
   - Searches common library locations (`D:\`, `C:\Program Files`) as a fallback:
     a `.pas` found only there gives way to the unit's `.dcu` on the search or
     library path, so a stray copy in an old folder is not taken for the library
   - Nothing else: a library folder is found only if one of these points at it,
     so a library checked out beside your project needs to be on the project's
     search path or the IDE library path
   - Groups found `.pas` files by directory (one directory = one library)
   - Extracts metadata: library name from its runtime package or directory name,
     vendor from the copyright holder most of its source file headers name,
     licence from LICENSE files
7. **Generates** the CycloneDX 1.5 JSON SBOM and writes it to the output
   directory
8. **Checks** the written file against the schema rules its output could break,
   and writes the HTML and Markdown reports if you ticked **Write HTML and
   Markdown reports**

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
── MyComponentLib ──
  Directory: D:\MyComponentLib
  Vendor:    Example Author
  Prefix:    mcl
  Units (3):
    mclFunctions
    mclDateTimeHelpers
    mclStringUtils
```

Units found in the project directory or its subfolders, and in sibling
directories (sharing the same parent as your project, such as a shared code
folder), that do not look
like a library, are automatically marked as own code. A directory "looks like a
library" when it, or its parent, has a `LICENSE`/`LICENCE`/`COPYING` file, or a
`.dpk` package sits in it, its parent (unless the parent is a drive root such as
`E:\`) or a subdirectory — so a third-party
library checked out beside your project is not mistaken for your own code.
Auto-detected own-code units count as own code in the same run, and are saved to
`components.json` once the SBOM has been written. You don't need to do anything
for these.

A library found only as `.dcu` files is shown with **Found as: DCUs only**.
Its name, licence and version come from the library folder; there is no source
to read a vendor from, so check the vendor in **Edit...**.

Any remaining units with neither a `.pas` nor a `.dcu` file found appear under
**UNRESOLVED UNITS** at the bottom of the panel.

### Step 4: Save and Regenerate

If the discovery panel shows libraries you want to include in your SBOM:

1. Review the discovered libraries — the name, vendor, and licence are
   pre-populated where possible
2. *(Optional)* Click **Edit...** to open the library editor and correct any
   auto-detected metadata (Name, Version, Vendor, Licence, Prefix) before
   saving. Click the Include column (or press Space on it) to exclude
   individual libraries. Edits are held until you save — clicking **Generate
   SBOM** instead asks before discarding them.
3. Click **Save & Regenerate**

This does two things:
- Saves the discovered libraries to your `components.json` file
- Immediately re-runs the SBOM generation pipeline

On the second run, the previously unclassified units now match their libraries
in `components.json` and appear as third-party components in the SBOM.

### Step 4a: Mark Remaining Unresolved Units (if any)

If any units remain in the **UNRESOLVED UNITS** list after saving libraries,
these are typically your own shared project files. Click
**Mark as Own Code** to save them to the `own_code_units` array
in `components.json`. The SBOM will regenerate automatically.

Both buttons write to the manifest the results came from, even if you have
changed the Manifest field since. If that `components.json` is not valid JSON,
nothing is written and the error is shown — fix the file (Validate Manifest
helps) and try again.

### Step 5: View the SBOM

Click **View SBOM File** to inspect the generated JSON in a read-only viewer.
If the project was compiled with SynEdit support (`USE_SYNEDIT` conditional
define), the viewer shows syntax-highlighted JSON with line numbers.

### Step 6: Done

Your SBOM is saved as `<ProjectName>.cdx.json` in the output directory. This
file is ready for compliance submission, auditing, or integration into your
build pipeline.

## Subsequent Runs

### Stateless Regeneration

DelphiSBOM builds every SBOM from scratch. Each run re-reads the `.dpr` uses
clause, re-scans the Delphi RTL, re-loads `components.json`, and re-classifies
every unit. There is no incremental update and no memory of previous runs —
the generated SBOM always reflects the current state of the project at the
moment you click Generate.

This means regeneration is always safe: you cannot end up with stale data
carried forward from an earlier run.

### Adding a Dependency

When you add a new third-party library to your project, its units appear in
the uses clause. On the next run they will be unclassified (unless already
in `components.json`), and the discovery process will find them automatically.
Click **Save & Regenerate** to persist and include them.

### Removing a Dependency

When you remove a library from your project (i.e. delete its units from the
`.dpr` uses clause), the next SBOM generation simply will not include it.
The removed units are no longer in the uses clause, so they are never parsed,
never classified, and never appear in the output. The component disappears
from the SBOM entirely.

**Note on `components.json`:** Removing a library from your project does
*not* automatically remove its entry from `components.json`. The entry
remains but becomes dormant — no unit in the project references it, so it
has no effect on the generated SBOM. You can tidy up dormant entries manually
if you wish, but leaving them is harmless.

DelphiSBOM logs an informational message for each dormant entry so you can
see what is no longer referenced:

```
[INFO] components.json: 'OmniThreadLibrary' not referenced by any project unit
```

### Updating a Dependency Version

To update a library's version in your SBOM:

1. Edit the `version` field in `components.json`
2. Click **Generate SBOM**

The new version flows into the SBOM immediately. No other steps are needed.

## DX.Comply Evidence Bridge (Optional)

[DX.Comply](https://github.com/omonien/dx.comply) by Olaf Monien generates
SBOMs from Delphi MAP file analysis. It produces per-unit SHA-256 hashes with
strong binary evidence, but sparse metadata (no vendor, licence, or PURL).

DelphiSBOM produces the opposite: rich metadata but no binary evidence.
Together, they produce a complete SBOM.

### How It Works

1. Build your project with MAP file generation enabled (Project > Options >
   Linking > Map File = Detailed)
2. Run DX.Comply against your project to generate a `bom.json`
3. In DelphiSBOM, set the **DX.Comply SBOM** field to the path of that
   `bom.json` file
4. Click **Generate SBOM**

DelphiSBOM merges the hashes from DX.Comply into its own output — the SHA-256
hash when DX.Comply lists one, otherwise the first algorithm CycloneDX 1.5
defines (names such as `SHA256` are normalised to `SHA-256`; algorithms outside
the CycloneDX enum are skipped). Each RTL and third-party component gains a
nested `components` array listing the individual units with their binary
hashes and a `dxcomply:origin` property. Units match by name as written or
scope-stripped (`SysUtils` matches `System.SysUtils.dcu`), and a unit DX.Comply
lists twice (`.pas` and `.dcu`) appears once. This provides cryptographic
evidence that specific compiled units are present in your binary.

### Match Rate

DelphiSBOM classifies units from the `.dpr` uses clause (explicit
dependencies). DX.Comply analyses the MAP file and finds all transitively
linked units. DX.Comply typically reports many more units than appear in the
`.dpr` file — this is expected. The log shows how many evidence entries
matched, e.g.:

```
[INFO] DX.Comply evidence: 33 of 729 entries matched classified units
       (696 unmatched - transitive dependencies not in .dpr uses clause)
```

The unmatched entries are transitive dependencies that your project uses
indirectly. They are not lost — they remain in DX.Comply's own `bom.json`.

### Without DX.Comply

The DX.Comply field is entirely optional. If left blank, DelphiSBOM produces
a standard SBOM with no binary hashes — fully valid and compliant.

## MAP Files (Optional)

Without a MAP file, the unit list is the project's uses clause read as text. That
misses units the project uses only indirectly (a unit used by one of your units),
includes units in every `{$IFDEF}` branch whether or not the build compiles them,
and cannot read `{$I}` include files.

A detailed MAP file, written by the linker, lists exactly the units in the built
program. To use one:

1. In Project Options > Building > Delphi Compiler > Linking, set **Map file** to
   **Detailed** (for MSBuild: `/p:DCC_MapFile=3`), and build the configuration you
   ship.
2. Give the `.map` file (normally beside the `.exe`, e.g. `Win64\Release\MyApp.map`)
   in **MAP File**, and Generate.

The log reports how the two lists differ, for example
`MAP file MyApp.map lists 166 linked units: 151 not named in the uses clause,
3 uses-clause units not linked`, and warns when the map is older than the `.dpr`
(rebuild so it matches the current code). Expect many more units: the RTL and
every library's internal units appear. RTL units still collapse into the single
RTL component, and a library's units into its one component, so the SBOM grows
by libraries, not by units.

The MAP file is remembered per project. It also raises the DX.Comply match rate,
since DX.Comply's evidence comes from the same kind of file.

## Online Check (Optional)

Your `components.json` records each library's licence and version by hand, and
they drift: a library is updated, a licence changes, a project is abandoned.
**Check Online** compares each component whose `vendor_url` is a GitHub
repository (`https://github.com/owner/repo`) with what GitHub reports:

- **Licence** — GitHub's detection of the repository's licence file. A missing
  licence in the manifest gets a suggestion; a different one is flagged. When
  GitHub finds no licence file (some libraries state the licence only in their
  source headers, as FastMM5 does), it says so rather than guessing.
- **Version** — the latest release (or the newest tag). A matching version is
  reported as current; an older one is flagged, without a suggestion, because
  the manifest must keep the version you actually use; a missing one gets a
  suggestion.
- **Archived** — an archived repository is no longer maintained.
- **purl** — the `pkg:github/owner/repo@tag` package URL, for information.

The findings open in a list. Nothing is ticked: tick only the suggestions that
apply to the version you use (GitHub describes its default branch and latest
release, not your copy), then **Apply Ticked** writes them to `components.json`.
Generate again to use them. Components without a GitHub `vendor_url` are listed
as not checked — commercial vendors have no machine-readable data to compare.

Without a token GitHub allows 60 requests an hour (about two per component);
set the `GITHUB_TOKEN` environment variable for more. After a refusal the check
stops asking and says so. From the command line, `--check-online` prints the
same findings after the run; it is advice and never changes the exit code.

## Reports (Optional)

Tick **Write HTML and Markdown reports** to write, beside the SBOM,
`<Project>.sbom-report.html` and `<Project>.sbom-report.md`. They are for people
rather than tools: the run details (Delphi version, where the unit list came from,
the SBOM check result), the classification counts, each component with its version,
supplier, licence and number of units, the units of each library, your own code,
and — most useful while you are still completing `components.json` — the units not
yet in the SBOM with the libraries found on disk for them.

## Understanding the Output

### The SBOM File

The generated `.cdx.json` contains:

- **Metadata**: your application name, version, supplier, and the tool that
  generated the SBOM
- **Components**: a flat list of all third-party dependencies, each with:
  - Name and version
  - Supplier/vendor
  - Licence — an SPDX `id` when the value is a recognised SPDX identifier, an
    SPDX `expression` when it contains `OR`/`AND`/`WITH`, otherwise a licence
    `name` (e.g. `Commercial`)
  - Package URL (`pkg:delphi/<name>@<version>`, percent-encoded, so a space is `%20`)
  - External references (vendor website)
- **Embarcadero Delphi RTL**: listed as a single framework component with
  the Delphi version number
- **Binary evidence** (when DX.Comply is used): nested sub-components under
  RTL and third-party entries, each with SHA-256 hashes from MAP file analysis
- **Dependencies**: every component has a `bom-ref`, and the `dependencies`
  section records that your application uses the RTL and each library

### What is NOT in the SBOM

- **Your own code** — own-code units are the application itself, not dependencies
- **Individual RTL units** — the entire RTL is listed as one component
- **Library-to-library dependencies** — the graph says your application uses
  each library, not which libraries use which; a library's own dependencies are
  left unstated rather than claimed to be none

## The `components.json` Manifest

### Automatic Management

DelphiSBOM creates and updates `components.json` automatically:

- **Created** the first time something is saved to it — Save & Regenerate,
  Mark as Own Code, or a successful run that auto-detected own-code units.
  Selecting a project does not create it
- **Updated** when you click Save & Regenerate (discovered libraries are
  appended) or Mark as Own Code (`own_code_units` are appended)
- **Never overwritten** when it does not parse — fix the JSON first
- Written as UTF-8 without a BOM, via a temporary file, so a failed save cannot
  truncate it

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

`DelphiSBOMCLI.exe` runs the same pipeline from a build script, with exit codes
(0 success, 1 usage, 2 file or parse error, 3 validation error) and an optional
`.delphisbom.json` beside the project for its settings. Build with a detailed MAP
file and pass `--map` and `--fail-on-unclassified`, so a library added without a
`components.json` entry fails the build rather than slipping out of the SBOM:

```
DelphiSBOMCLI MyApp.dproj --map=Win64\Release\MyApp.map --report=both --fail-on-unclassified
```

Complete `components.json` in the app first: the command line does not add
libraries to it. See [CI-INTEGRATION.md](CI-INTEGRATION.md) for GitHub Actions and
GitLab examples, and `DelphiSBOMCLI --help` for every option.

### Keeping the SBOM Current

Regenerate your SBOM whenever you:

- Add or remove third-party libraries
- Update a library version
- Change your project's version number
- Prepare a release

The process takes seconds — just click Generate SBOM. Because each run is a
fresh, stateless scan (see [Subsequent Runs](#subsequent-runs)), you never
need to worry about stale data from a previous generation. Running it again
always produces an accurate, up-to-date SBOM.

## What To Do With Your SBOM

Generating the `.cdx.json` file is the first step. Here's how SBOMs are
typically used in practice.

### Ship With Your Product

The SBOM should accompany your software when you deliver it. For the EU Cyber
Resilience Act, it must be provided as part of the product's technical
documentation. For FDA-regulated medical devices, it is submitted with regulatory
filings (510(k) or PMA).

Include the `.cdx.json` file in your release package, or make it available via
a download link alongside the software.

### Commit to Version Control

Commit both `components.json` and the generated `.cdx.json` alongside each
release tag. This creates a permanent, auditable record of exactly what
components were in each version of your software.

```
git add components.json MyApp.cdx.json
git commit -m "docs: update SBOM for release 4.1.0"
git tag v4.1.0
```

### Vulnerability Monitoring

The most valuable ongoing use of an SBOM is **continuous vulnerability
monitoring**. Tools like [OWASP Dependency-Track](https://dependencytrack.org/)
ingest your CycloneDX SBOM and automatically check every component against
vulnerability databases (NVD/CVE).

If a security vulnerability is published for any library in your SBOM — for
example, a CVE affecting the version of OpenSSL that Indy uses — you are
alerted immediately, even months after the SBOM was generated.

**How to set up Dependency-Track:**

1. Install Dependency-Track (available as Docker container or WAR file)
2. Create a project in the Dependency-Track UI
3. Upload your `.cdx.json` file (via the UI or REST API)
4. Dependency-Track will analyse the components and report any known
   vulnerabilities

This turns a static compliance document into an active security monitoring
tool.

### Licence Compliance

Legal and compliance teams use SBOMs to verify that all third-party licences
are compatible with your product's distribution model. Common concerns include:

- **GPL libraries** in proprietary/commercial products (may require source
  disclosure)
- **LGPL libraries** (generally safe for dynamic linking, restrictions on
  static linking)
- **Commercial licences** that require per-developer or per-deployment fees

The `licenses` field in the SBOM uses SPDX identifiers, making automated
licence compliance checking straightforward with tools like
[FOSSology](https://www.fossology.org/) or
[FOSSA](https://fossa.com/).

### Supply Chain Auditing

Customers, procurement teams, and enterprise buyers increasingly request SBOMs
before purchasing or deploying software. Having a ready-to-deliver SBOM
demonstrates:

- You know what's in your software
- You track your dependencies actively
- You can respond quickly to vulnerability disclosures
- You meet regulatory requirements proactively

### Regulatory Submission

| Regulation | Requirement |
|------------|-------------|
| **EU Cyber Resilience Act** | SBOM required as part of technical documentation for products with digital elements. Effective December 2027 |
| **US Executive Order 14028** | Recommends SBOMs for software sold to the US federal government |
| **FDA Cybersecurity Guidance** | SBOMs required for medical device software submissions |
| **NIS2 Directive** | EU directive requiring supply chain security measures, where SBOMs support compliance |

### What DelphiSBOM Does Not Do (Yet)

The following capabilities are planned for future versions:

- **Vulnerability checking** — CVE lookup against component versions
- **Licence compatibility analysis** — automated conflict detection
- **SBOM signing** — cryptographic attestation of SBOM authenticity
- **Registry upload** — direct integration with Dependency-Track or other platforms
- **SBOM diffing** — compare two SBOMs to see what changed between versions

## Files and Privacy

DelphiSBOM is a local-only tool. It sends no telemetry, and makes no network
connections — except when you ask for the [online check](#online-check-optional)
(the **Check Online** button, or `--check-online`). That sends
`api.github.com` the GitHub repository names from your `components.json`
(`vendor_url`) and nothing else; set `GITHUB_TOKEN` to have the requests
authenticated.

| File | Location | Purpose |
|------|----------|---------|
| `<Project>.cdx.json` | Output directory | The generated CycloneDX 1.5 SBOM |
| `<Project>.sbom-report.html` / `.md` | Beside the SBOM | Optional reports |
| `components.json` | Project directory | Third-party library manifest (created on first save, updated on each save) |
| `.delphisbom.json` | Project directory | Optional command-line settings; read only, never written |
| `DelphiSBOM.ini` | `%APPDATA%\DelphiSBOM\` | MRU project list and per-project settings (UTF-8). Safe to delete |

**Registry access** is read-only: `HKCU\Software\Embarcadero\BDS` (and the
installer's `HKLM\SOFTWARE\WOW6432Node\Embarcadero\BDS`) is read to detect
Delphi installations, IDE environment variables and the IDE library path.
DelphiSBOM never writes to the Windows Registry.

**Your source files** (`.dpr`, `.dproj`, `.pas`, `.dfm`) are read but never
modified.

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
| **NVD** | National Vulnerability Database — US government repository of vulnerability data |
| **CVE** | Common Vulnerabilities and Exposures — standardised vulnerability identifiers |
| **Dependency-Track** | OWASP tool for continuous SBOM analysis and vulnerability monitoring |
| **NIS2** | EU directive on network and information security, includes supply chain requirements |

---
*Version: 1.1 – 26 March 2026 09:45*
*Version: 1.2 – 26 March 2026 11:00*
*Version: 1.3 – 26 March 2026 12:00*
*Version: 1.4 – 27 March 2026 — DX.Comply evidence bridge documentation*
*Version: 1.4 – 26 March 2026 — MRU feature*
*Version: 1.5 – 26 March 2026 — Stateless regeneration documentation*
*Version: 1.6 – 27 March 2026 — Code audit fixes*
*Version: 1.7 – 27 March 2026 — Library editor, tooltips*
