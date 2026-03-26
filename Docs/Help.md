# DelphiSBOM — Help

## Quick Reference

### Main Window

| Control | Purpose |
|---------|---------|
| **Project File** | Path to your Delphi `.dpr` or `.dproj` file. Click Browse to select, or choose a recent project from the dropdown |
| **Manifest** | Path to `components.json`. Auto-populated when a project is selected |
| **Output Dir** | Directory where the SBOM `.cdx.json` file will be written. Defaults to the project directory |
| **Delphi Path** | Path to your Delphi installation. Auto-detected from the Windows registry (`HKCU\Software\Embarcadero\BDS`) on startup |
| **Version Override** | Optional. If set, overrides the project version read from the `.dproj` file |
| **Generate SBOM** | Runs the full pipeline: parse, classify, discover, generate |
| **Validate Manifest** | Checks `components.json` for schema errors without generating an SBOM |
| **Save Libraries & Regenerate SBOM** | Saves discovered libraries to `components.json` and re-runs the pipeline |
| **Mark Unresolved as Own Code** | Saves remaining unresolved units to `own_code_units` in `components.json` and re-runs |
| **View SBOM File** | Opens the generated `.cdx.json` in a read-only viewer. If SynEdit is available (compile with `USE_SYNEDIT`), shows syntax-highlighted JSON with line numbers |

### Results Panel (Left)

Shows a classification summary after generation:

- **RTL/VCL units** — units from the Delphi RTL, VCL, or FMX frameworks
- **Third-party units** — units matched to a library in `components.json`
- **Own-code units** — your project's own source files
- **Unclassified** — units that could not be matched to any category

Also lists all recognised third-party components with their versions.

### Discovery Panel (Right)

Shows libraries discovered automatically by scanning the file system:

- **Library name** — derived from the directory name
- **Directory** — where the `.pas` files were found
- **Vendor** — extracted from copyright headers in source files
- **Licence** — detected from LICENSE/LICENCE/COPYING files
- **Prefix** — computed common prefix for unit matching
- **Units** — list of units belonging to this library

Units found in sibling project directories (same parent as the project) are
automatically marked as own code and saved to `components.json`.

Any remaining unresolved units are listed at the bottom. These can be
manually marked as own code using the **Mark Unresolved as Own Code** button.

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

The app could not find a Delphi installation in the Windows registry. On
startup, DelphiSBOM reads `HKEY_CURRENT_USER\Software\Embarcadero\BDS` to
find installed Delphi versions and selects the highest. This is a **read-only**
registry access — DelphiSBOM never writes to the registry. If no BDS keys
exist, RTL units cannot be classified and will appear as unclassified.

**Fix:** Click Browse next to the Delphi Path field and navigate to your Delphi installation directory (e.g. `C:\Program Files (x86)\Embarcadero\Studio\37.0` for Delphi 13). DelphiSBOM requires Delphi 10.3 Rio or later to build, but can scan RTL units from any Delphi installation.

### All units show as unclassified

This typically means:

1. **RTL scan failed** — check the Delphi Path field is correct
2. **No `components.json`** — the app creates an empty one automatically, but it contains no library definitions until you run discovery and save

**Fix:** Click Generate SBOM. If libraries are discovered, click Save Libraries & Regenerate SBOM.

### A project directory is incorrectly identified as a library

The discovery scanner excludes directories containing `.dpr` or `.dproj` files. If a directory is still being misidentified:

**Fix:** Do not click Save Libraries & Regenerate SBOM. The incorrectly identified library will not be saved. On the next run with an updated `components.json`, those units will be classified correctly or remain unclassified.

### "Could not create output file"

The output `.exe` or `.cdx.json` file is locked by another process.

**Fix:** Close any application that might have the file open, then retry.

### Version shows as "0.0.0.0"

The `.dproj` file does not contain version information, or the version fields could not be parsed.

**Fix:** Set the version in the Version Override field, or configure version info in your Delphi project options (Project > Options > Version Info).

### Licence not detected

The licence detection scans for `LICENSE`, `LICENCE`, or `COPYING` files in the library directory and its parent. It recognises common licence texts (MIT, Apache-2.0, BSD-3-Clause, GPL, LGPL, MPL).

If your library uses a non-standard licence file name or format, the licence field will be empty. You can edit `components.json` manually to add the licence.

## Files Read and Written

DelphiSBOM never modifies your project source files (`.dpr`, `.dproj`, `.pas`).

### Output: `<ProjectName>.cdx.json`

The generated CycloneDX 1.5 SBOM. This is the file you submit for compliance
purposes. Written to the output directory (defaults to the project directory).
Conforms to the specification at https://cyclonedx.org/docs/1.5/json/.

### Input/Output: `components.json`

A JSON manifest in your project directory describing third-party libraries and
own-code units. Created automatically on first run; updated when you click
"Save Libraries & Regenerate SBOM" or "Mark Unresolved as Own Code". See
`Docs/SCHEMA.md` for the complete field reference.

### Application Settings: `DelphiSBOM.ini`

Stored at `%APPDATA%\DelphiSBOM\DelphiSBOM.ini`. Contains:

- **MRU list** — up to 10 recently used project file paths
- **Per-project settings** — the manifest path, output directory, and version
  override last used for each project

Created on first successful SBOM generation. You can safely delete this file
to reset the MRU list. DelphiSBOM recreates it as needed.

### Windows Registry (Read-Only)

DelphiSBOM reads the following registry keys to auto-detect your Delphi
installation. It **never writes** to the registry.

| Key | Purpose |
|-----|---------|
| `HKCU\Software\Embarcadero\BDS\*` | Enumerates installed Delphi/RAD Studio versions |
| `HKCU\Software\Embarcadero\BDS\<ver>\RootDir` | Gets the installation path for each version |
| `HKCU\Software\Embarcadero\BDS\<ver>\Environment Variables` | Reads IDE environment variables (e.g. `BDSLIB`) for library path resolution |

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

There are no keyboard shortcuts in the current version. All actions are performed via buttons.

## Support

Report issues at the project repository on Codeberg.

---
*Version: 1.0 – 26 March 2026 08:30*
*Version: 1.1 – 26 March 2026 11:00*
*Version: 1.2 – 26 March 2026 12:00*
*Version: 1.3 – 26 March 2026 — MRU feature*
