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

1. Run DelphiSBOM and browse to your `.dpr` or `.dproj` file
2. Click **Generate SBOM**
3. Review the results — discovered third-party libraries are shown with
   auto-detected names, vendors, and licences
4. Click **Save Libraries & Regenerate SBOM** to confirm and save
5. Find your `<ProjectName>.cdx.json` in the project directory

No manual JSON editing required. DelphiSBOM creates and maintains
`components.json` for you based on what it discovers on disk.

## The `components.json` Manifest

DelphiSBOM uses a `components.json` file to track your project's third-party
libraries. This file is created automatically when you first scan a project,
and updated when you confirm discovered libraries.

You can also edit it manually for fine-tuning. See
`Samples/components.sample.json` for a fully commented example, and
`Docs/SCHEMA.md` for the complete schema reference.

## Requirements

- Windows (Win32 or Win64)
- A Delphi installation (for RTL unit auto-detection)
- No runtime dependencies — single standalone `.exe`

## Building from Source

Open `Source/DelphiSBOM.dproj` in Delphi and compile. No third-party
libraries are required — the project uses only the Delphi RTL.

**Minimum compiler version:** Delphi 10.3 Rio (uses inline variable
declarations and other 10.3+ language features). Tested and developed
on Delphi 13 Florence.

**Optional:** Add [SynEdit](https://github.com/SynEdit/SynEdit) and define
`USE_SYNEDIT` for syntax-highlighted JSON viewing in the SBOM viewer.

## Licence

MIT — see [LICENCE](LICENCE).
