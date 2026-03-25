# DelphiSBOM

A CycloneDX 1.5 SBOM (Software Bill of Materials) generator for Delphi applications.

## Purpose

DelphiSBOM helps Delphi developers produce standards-compliant SBOMs to meet
emerging regulatory requirements — principally the EU Cyber Resilience Act
(effective December 2027) — without relying on generic SBOM tools that have
no awareness of the Delphi ecosystem.

## How It Works

1. **Parse** your Delphi `.dpr` and `.dproj` files to extract project metadata
   and the full unit list
2. **Classify** each unit as RTL/VCL (Embarcadero), third-party (from your
   `components.json` manifest), or your own code
3. **Generate** a valid CycloneDX 1.5 JSON SBOM file

## Quick Start

1. Place a `components.json` file in your Delphi project directory describing
   your third-party dependencies (see `Samples/components.sample.json` for an
   example)
2. Run DelphiSBOM and browse to your `.dpr` or `.dproj` file
3. Click **Generate SBOM**
4. Find your `<ProjectName>.cdx.json` in the project directory

## The `components.json` Manifest

This is the heart of DelphiSBOM. You maintain a simple JSON file listing your
third-party libraries with version, vendor, licence, and unit-matching rules.
DelphiSBOM uses this to classify units it finds in your project.

See `Samples/components.sample.json` for a fully commented example, and
`Docs/SCHEMA.md` for the complete schema reference.

## Requirements

- Windows (Win64)
- A Delphi 12+ installation (for RTL unit auto-detection)
- No runtime dependencies — single standalone `.exe`

## Building from Source

Open `Source/DelphiSBOM.dproj` in Delphi 12 or later and compile. No
third-party libraries are required — the project uses only the Delphi RTL.

## Licence

MIT — see [LICENCE](LICENCE).
