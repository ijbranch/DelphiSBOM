# DelphiSBOM — Help

## Quick Reference

### Main Window

| Control | Purpose |
|---------|---------|
| **Project File** | Path to your Delphi `.dpr`, `.dpk` or `.dproj` file. Click Browse to select, or choose a recent project from the dropdown. Changing the project resets the fields below to that project's defaults and remembered settings |
| **Manifest** | Path to `components.json`. Defaults to the project directory when a project is selected; the file itself is only created when you first save to it |
| **Output Dir** | Directory where the SBOM `.cdx.json` file will be written. Defaults to the project directory |
| **Delphi Path** | Path to your Delphi installation. Leave blank (the default) to use the installed Delphi version that matches the project's `ProjectVersion`, or the newest installed version if that one is missing |
| **Version Override** | Optional. If set, overrides the project version read from the `.dproj` file |
| **DX.Comply SBOM** | Optional. Path to a DX.Comply `bom.json` file. If provided, SHA-256 hashes from DX.Comply's MAP file analysis are merged into the SBOM output as nested sub-components |
| **Generate SBOM** | Runs the full pipeline: parse, classify, discover, generate |
| **Validate Manifest** | Checks `components.json` for schema errors without generating an SBOM |
| **Save & Regenerate** | Saves discovered libraries to `components.json` and re-runs the pipeline |
| **Edit...** | Opens a modal grid editor to review and modify discovered library metadata (Name, Version, Vendor, Licence, Prefix) before saving |
| **Mark as Own Code** | Saves remaining unresolved units to `own_code_units` in `components.json` and re-runs |
| **View SBOM File** | Opens the generated `.cdx.json` in a read-only viewer. If SynEdit is available (compile with `USE_SYNEDIT`), shows syntax-highlighted JSON with line numbers |

> **Tip:** Hover over any control for a tooltip describing its purpose.

### Results Panel (Left)

Shows a classification summary after generation:

- **RTL/VCL units** — units from the Delphi RTL, VCL, or FMX frameworks
- **Third-party units** — units matched to a library in `components.json`
- **Own-code units** — your project's own source files
- **Unclassified** — units that could not be matched to any category

Also lists all recognised third-party components with their versions.

### Discovery Panel (Right)

Shows libraries discovered automatically by scanning the file system:

- **Library name** — the name of a `.dpk` package in the library directory, one of its
  subdirectories, its parent or a `Packages` folder beside it; otherwise the nearest
  non-generic directory name. The parent is not searched when it is a drive or share root
  (`E:\`), whose other folders are unrelated libraries
- **Directory** — where the `.pas` files were found
- **Vendor** — extracted from copyright headers in source files
- **Licence** — detected from LICENSE/LICENCE/COPYING files
- **Prefix** — computed common prefix for unit matching
- **Units** — list of units belonging to this library

Click **Edit...** to open the library editor — a grid where you can review and
correct auto-detected metadata (Name, Version, Vendor, Licence, Prefix) before
saving. Click the Include column (or press Space on it) to toggle individual
libraries on or off. An included library must have a name. The bottom of the
editor shows the full unit list for the selected library. Editor changes are
kept only until you click **Save & Regenerate**; clicking **Generate SBOM**
first asks before discarding them.

Units found in the project directory, and in sibling directories (same parent
as the project) that do **not** look like a library — no `LICENSE`/`LICENCE`/
`COPYING` file and no `.dpk` package — are marked as own code in the same run,
and saved to `own_code_units` in `components.json` once the SBOM has been
written. A library checked out beside your project (e.g. `C:\Dev\Indy` next to
`C:\Dev\MyApp`) has a licence file or package, so it stays third-party.

Any remaining unresolved units are listed at the bottom. These can be
manually marked as own code using the **Mark as Own Code** button.

### Log Panel

Shows timestamped messages during processing:

- `[INFO]` — normal progress messages
- `[WARNING]` — non-fatal issues (e.g. missing manifest, RTL scan unavailable)
- `[ERROR]` — fatal errors that prevented completion

After classification, an `[INFO]` message is logged for each `components.json`
entry that is not referenced by any unit in the project. These are dormant
entries — they have no effect on the SBOM but indicate a library that was
once used and may no longer be needed in the manifest.

## Troubleshooting

### "Delphi installation not found"

The app could not find a Delphi installation in the Windows registry. For each
run, DelphiSBOM reads `HKEY_CURRENT_USER\Software\Embarcadero\BDS` and the
installer's `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Embarcadero\BDS` to find
installed Delphi versions whose installation folder still exists, and uses the
one matching the project's `ProjectVersion` (logging a warning and using the
newest when that version is not installed). This is a **read-only** registry
access — DelphiSBOM never writes to the registry. If no installation is found,
RTL units cannot be classified and will appear as unclassified.

**Fix:** Click Browse next to the Delphi Path field and navigate to your Delphi installation directory (e.g. `C:\Program Files (x86)\Embarcadero\Studio\37.0` for Delphi 13). DelphiSBOM requires Delphi 10.3 Rio or later to build, but can scan RTL units from any Delphi installation.

### All units show as unclassified

This typically means:

1. **RTL scan failed** — check the log for the Delphi installation used, or set the Delphi Path field
2. **No `components.json`** — it contains no library definitions until you run discovery and save

**Fix:** Click Generate SBOM. If libraries are discovered, click Save & Regenerate.

### "... is not valid JSON — fix it ... before saving"

Your `components.json` has a syntax error (often a trailing comma after a hand
edit). DelphiSBOM will not save into a file it cannot read, because rewriting it
would discard every entry. The file is left exactly as it was.

**Fix:** Click **Validate Manifest** to see the error, correct the file, then save again.

### Warnings about conditional directives or include files

The unit list is read from the `.dpr` uses clause (or the `.dpk` contains clause)
as text. Units inside every `{$IFDEF}` branch are included, and units listed in
`{$I}` include files are not read. Review the SBOM if your uses clause depends
on conditional compilation.

### A library next to my project is not discovered

Discovery looks for `.pas` files only in the project's unit search paths (from
the `.dproj`), the IDE library path for the project's Delphi version, the
top-level folders of `D:\`, and the Program Files folders — each with its parent
and one level of subfolders. A library checked out beside your project (e.g.
`C:\Dev\MyLib` next to `C:\Dev\MyApp`) is found only when one of those points at
it. A plain `.dpr` with no `.dproj` has no search paths.

**Fix:** add the library folder to the project's search path (Project > Options >
Building > Delphi Compiler > Search path) or to the IDE library path, then
Generate again.

### A project directory is incorrectly identified as a library

The discovery scanner excludes directories containing `.dpr` or `.dproj` files. If a directory is still being misidentified:

**Fix:** Click **Edit...** and set Include to No for that library, or do not click Save & Regenerate. The incorrectly identified library will not be saved. On the next run with an updated `components.json`, those units will be classified correctly or remain unclassified.

### "Could not create output file"

The output `.exe` or `.cdx.json` file is locked by another process.

**Fix:** Close any application that might have the file open, then retry.

### Version shows as "0.0.0.0"

The `.dproj` file does not contain version information, or the version fields could not be parsed. The version is read the way MSBuild evaluates the `.dproj` for a **Release** build of the target platform (Win64 when it is active), so an auto-incremented build number in the Release configuration is picked up.

**Fix:** Set the version in the Version Override field, or configure version info in your Delphi project options (Project > Options > Version Info).

### Licence not detected

The licence detection scans for `LICENSE`, `LICENCE`, or `COPYING` files in the library directory and its parent. It recognises common licence texts (MIT, Apache-2.0, BSD-2/3/4-Clause, BSL-1.0, ISC, Zlib, Unlicense, GPL, LGPL, MPL). When a GPL/LGPL/MPL text does not state its version, the licence is left empty rather than guessed.

If your library uses a non-standard licence file name or format, the licence field will be empty. Enter it in the **Edit...** grid or in `components.json`.

### Licence written as a "name" instead of an SPDX id

CycloneDX 1.5 only accepts recognised SPDX identifiers in `license.id`. A value
DelphiSBOM does not recognise (e.g. `"MPL 1.1"` with a space) is written as
`license.name` so the SBOM stays valid, and Validate Manifest warns about it.
Values containing `OR`, `AND` or `WITH` (e.g. `"MPL-1.1 OR LGPL-2.1-or-later"`)
are written as an SPDX `expression`.

## Files Read and Written

DelphiSBOM never modifies your project source files (`.dpr`, `.dproj`, `.pas`).

### Output: `<ProjectName>.cdx.json`

The generated CycloneDX 1.5 SBOM. This is the file you submit for compliance
purposes. Written to the output directory (defaults to the project directory).
Conforms to the specification at https://cyclonedx.org/docs/1.5/json/.

### Input/Output: `components.json`

A JSON manifest in your project directory describing third-party libraries and
own-code units. Created the first time you click "Save & Regenerate" or "Mark
as Own Code" (or when a successful run auto-detects own-code units); updated on
each later save. Written as UTF-8 without a BOM. See `Docs/SCHEMA.md` for the
complete field reference.

### Application Settings: `DelphiSBOM.ini`

Stored at `%APPDATA%\DelphiSBOM\DelphiSBOM.ini`. Contains:

- **MRU list** — up to 10 recently used project file paths
- **Per-project settings** — the manifest path, output directory, version
  override, and DX.Comply file path last used for each project

Created on first successful SBOM generation. You can safely delete this file
to reset the MRU list. DelphiSBOM recreates it as needed.

### Windows Registry (Read-Only)

DelphiSBOM reads the following registry keys to auto-detect your Delphi
installation. It **never writes** to the registry.

| Key | Purpose |
|-----|---------|
| `HKCU\Software\Embarcadero\BDS\*` | Enumerates installed Delphi/RAD Studio versions |
| `HKLM\SOFTWARE\WOW6432Node\Embarcadero\BDS\*` | Installer-written versions, used when the IDE has never been run by this user |
| `...\BDS\<ver>\RootDir` | Gets the installation path for each version (versions whose folder no longer exists are ignored) |
| `HKCU\Software\Embarcadero\BDS\<ver>\Environment Variables` | Reads IDE environment variables for library path resolution |
| `HKCU\Software\Embarcadero\BDS\<ver>\Library\<Platform>` | Reads the IDE library search path (macros such as `$(BDS)`, `$(BDSCOMMONDIR)` and `$(BDSCatalogRepository)` are expanded) |

### RTL Unit Detection

RTL units are detected by scanning `.dcu` files in:
```
<Delphi Install>\lib\<Platform>\release\
```

Where `<Platform>` is read from the `.dproj` target platform (e.g. `Win32`, `Win64`).

## Recent Projects (MRU)

The Project File field is a dropdown that remembers your most recent projects
(up to 10). Select a project from the dropdown to load it along with its
associated manifest path, output directory, and version override from your
last session.

Projects that no longer exist on disk are automatically removed from the list.
The MRU list updates each time you successfully generate an SBOM.

## Keyboard Shortcuts

There are no keyboard shortcuts in the main window. In the library editor, press **Space** on the Include column to toggle a library.

## Support

Report issues at the project repository on GitHub: https://github.com/ijbranch/DelphiSBOM/issues

---
*Version: 1.0 – 26 March 2026 08:30*
*Version: 1.1 – 26 March 2026 11:00*
*Version: 1.2 – 26 March 2026 12:00*
*Version: 1.3 – 26 March 2026 — MRU feature*
*Version: 1.4 – 26 March 2026 — Stateless regeneration documentation*
*Version: 1.5 – 27 March 2026 — Code audit fixes*
*Version: 1.6 – 27 March 2026 — Library editor, tooltips*
*Version: 1.7 – 27 March 2026 — DX.Comply evidence bridge documentation*
*Version: 1.8 – 6 October 2026 — Audit fixes: project-matched Delphi version, manifest safety, licence emission*
