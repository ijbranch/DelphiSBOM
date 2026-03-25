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

- Windows (Win32 or Win64)
- A Delphi 12+ installation (for RTL unit auto-detection)
- No runtime dependencies — single standalone `.exe`

## Building from Source

Open `Source/DelphiSBOM.dproj` in Delphi 12 or later and compile. No
third-party libraries are required — the project uses only the Delphi RTL.

## Licence

MIT — see [LICENCE](LICENCE).
