# DelphiSBOM — Help

## Quick Reference

### Main Window

| Control | Purpose |
|---------|---------|
| **Project File** | Path to your Delphi `.dpr` or `.dproj` file. Click Browse to select |
| **Manifest** | Path to `components.json`. Auto-populated when a project is selected |
| **Output Dir** | Directory where the SBOM `.cdx.json` file will be written. Defaults to the project directory |
| **Delphi Path** | Path to your Delphi installation. Auto-detected from the Windows registry on startup |
| **Version Override** | Optional. If set, overrides the project version read from the `.dproj` file |
| **Generate SBOM** | Runs the full pipeline: parse, classify, discover, generate |
| **Validate Manifest** | Checks `components.json` for schema errors without generating an SBOM |
| **Save Libraries & Regenerate SBOM** | Saves discovered libraries to `components.json` and re-runs the pipeline |

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

Unresolved units (no `.pas` file found on disk) are listed at the bottom.

### Log Panel

Shows timestamped messages during processing:

- `[INFO]` — normal progress messages
- `[WARNING]` — non-fatal issues (e.g. missing manifest, RTL scan unavailable)
- `[ERROR]` — fatal errors that prevented completion

## Troubleshooting

### "Delphi installation not found"

The app could not find a Delphi installation in the Windows registry. This means RTL units cannot be classified and will appear as unclassified.

**Fix:** Click Browse next to the Delphi Path field and navigate to your Delphi installation directory (e.g. `C:\Program Files (x86)\Embarcadero\Studio\37.0`).

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

## File Formats

### Output: `<ProjectName>.cdx.json`

A CycloneDX 1.5 JSON file conforming to the specification at https://cyclonedx.org/docs/1.5/json/. This is the SBOM you submit for compliance purposes.

### Input/Output: `components.json`

A JSON manifest describing your third-party libraries. See `Docs/SCHEMA.md` for the complete field reference.

### RTL Unit Detection

RTL units are detected by scanning `.dcu` files in:
```
<Delphi Install>\lib\<Platform>\release\
```

Where `<Platform>` is read from the `.dproj` target platform (e.g. `Win32`, `Win64`).

## Keyboard Shortcuts

There are no keyboard shortcuts in the current version. All actions are performed via buttons.

## Support

Report issues at the project repository on Codeberg.

---
*Version: 1.0 – 26 March 2026 08:30*
