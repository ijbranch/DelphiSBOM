# CycloneDX 1.5 — Delphi-Specific Notes

## Overview

DelphiSBOM generates SBOMs conforming to the CycloneDX 1.5 specification
(JSON format). This document records Delphi-specific decisions and known
limitations.

**Specification reference:** https://cyclonedx.org/docs/1.5/json/

## Delphi-Specific Decisions

### Package URL (PURL) Convention

The PURL scheme for Delphi is not formally registered in the
[PURL specification](https://github.com/package-url/purl-spec). DelphiSBOM
uses the convention:

```
pkg:delphi/<component-name>@<version>
```

Examples:
- `pkg:delphi/OmniThreadLibrary@3.7.8`
- `pkg:delphi/TMS%20VCL%20UI%20Pack@13.0`
- `pkg:delphi/embarcadero-rtl@37.0`

Name and version are percent-encoded as the purl specification requires:
unreserved characters (`A-Z a-z 0-9 . - _ ~`) are kept and everything else
becomes `%XX` of its UTF-8 bytes — a space is `%20`, never the form-encoding `+`.
A component with no name gets no purl; one with no version gets no `@`.

A `purl` in a `components.json` entry replaces the generated one, as the purl and
as the `bom-ref` — useful for a library with a registered package type, such as
`pkg:github/owner/repo@tag` (the online check shows that purl for GitHub-hosted
libraries).

The RTL version is the BDS version of the Delphi release that wrote the
`.dproj` (`ProjectVersion` 20.4 and later = 37.0, Delphi 13; 20.1–20.3 = 23.0,
Delphi 12; 19.3–19.5 = 22.0, Delphi 11; and so on), or `unknown`.

This is consistent with how other niche ecosystems handle the gap pending
formal registration.

### RTL as a Single Component

The Embarcadero Delphi RTL/VCL/FMX is represented as a **single aggregate
component** rather than listing individual RTL units:

```json
{
  "type": "framework",
  "name": "Embarcadero Delphi RTL",
  "version": "37.0",
  "supplier": { "name": "Embarcadero Technologies" },
  "purl": "pkg:delphi/embarcadero-rtl@37.0"
}
```

**Rationale:** Listing 1,800+ individual RTL units would produce a massive SBOM
with no practical compliance value. The RTL is a single distributable unit from
a supply-chain perspective.

### Licence Handling

In the CycloneDX 1.5 schema `license.id` is an enum of SPDX identifiers, so a
value that is not a valid identifier makes the whole SBOM fail validation.
DelphiSBOM therefore classifies each `licence` value from `components.json`:

| Value | Emitted as |
|-------|------------|
| A recognised SPDX identifier (case-insensitive; emitted in canonical case) | `{ "license": { "id": "MIT" } }` |
| Contains ` OR `, ` AND ` or ` WITH ` | `{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }` |
| Anything else, e.g. `Commercial` | `{ "license": { "name": "Commercial" } }` |

The recognised list is a practical subset of the SPDX licence list covering the
Delphi ecosystem (MIT, Apache, BSD, MPL, GPL/LGPL/AGPL in all their forms, BSL,
ISC, Zlib, Unlicense, EPL, CDDL and others). An identifier outside that subset is
emitted as a `name` — still valid, just less machine-readable — and Validate
Manifest warns about it. `licence_url` is added to `id`/`name` entries; CycloneDX
does not allow a URL on an expression.

### Own-Code Units

Units classified as "own code" (the developer's own source files) are not
listed as separate components. They are part of the main application, which
appears in `metadata.component`. This follows standard SBOM practice — the
SBOM describes what the application *depends on*, not the application itself.

### Tools Metadata

The `metadata.tools` field uses the CycloneDX 1.5 format:

```json
"tools": {
  "components": [
    {
      "type": "application",
      "name": "DelphiSBOM",
      "version": "1.0.0",
      "supplier": { "name": "DelphiSBOM Contributors" }
    }
  ]
}
```

Note: CycloneDX 1.5 changed `tools` from an array of objects to an object with
a `components` array. Earlier formats are not used.

### Binary Evidence via DX.Comply

When a DX.Comply `bom.json` is provided, DelphiSBOM merges per-unit
hashes into the SBOM as **nested sub-components**. The CycloneDX 1.5
specification allows `components` arrays within components:

```json
{
  "type": "framework",
  "name": "Embarcadero Delphi RTL",
  "version": "37.0",
  "components": [
    {
      "type": "library",
      "name": "System.SysUtils",
      "hashes": [{ "alg": "SHA-256", "content": "88de45b3a6f2..." }],
      "properties": [{ "name": "dxcomply:origin", "value": "Embarcadero RTL" }]
    }
  ]
}
```

This nesting provides unit-level binary evidence while preserving the
aggregate component model. Third-party library components receive the same
treatment — each gains a nested `components` array listing its constituent
units with hashes.

DX.Comply classifies units by origin (Embarcadero RTL, Embarcadero VCL,
Third party, Local project); that origin is carried into the
`dxcomply:origin` property. DelphiSBOM matches evidence to its own
classified units by unit name (case-insensitive), as written or with the scope
prefix stripped on both sides. Only RTL and third-party units receive evidence
in the output — own-code units are excluded by design.

Every hash DX.Comply lists for a unit is kept, in its order — e.g. SHA-256 and
the SHA-512 that BSI TR-03183-2 asks for — with an algorithm that is listed
twice written once. Algorithm names are normalised (`SHA256` becomes `SHA-256`),
and hashes with an algorithm outside the CycloneDX 1.5 `hash-alg` enum are
dropped with a warning, because they would make the SBOM invalid. A unit listed
twice by DX.Comply (`.pas` and `.dcu`) is emitted once.

Only units named in the project's own uses clause are classified, so DX.Comply
entries for units the project uses transitively are not matched; the log
reports how many entries matched.

### bom-ref and the Dependency Graph

The application (`metadata.component`), the RTL and every library carry a
`bom-ref`: the component's purl, `application:<name>@<version>` for the
application, and `component:<index>` for a manifest row with no name. A
repeated value (two manifest rows with the same name and version) gets a
`#2`, `#3`, ... suffix, since CycloneDX requires every `bom-ref` to be unique.

The `dependencies` section has two levels:

```json
"dependencies": [
  { "ref": "application:MyApp@2.4.0.0",
    "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/OmniThreadLibrary@3.7.8" ] },
  { "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] }
]
```

The application depends on the RTL and on each library; the RTL depends on
nothing third-party. A library has no entry: CycloneDX 1.5 reads an empty
`dependsOn` as "has no dependencies", which DelphiSBOM cannot know.

Library units stay nested under their library when DX.Comply evidence is
merged (see below); the graph does not replace that nesting.

The graph is declared incomplete, in the same shape DX.Comply writes:

```json
"compositions": [ { "aggregate": "incomplete", "dependencies": [ "application:MyApp@2.4.0.0" ] } ]
```

Libraries' own dependencies are not resolved (see Known Limitations), and units
that could not be classified are not listed, so "complete" would overstate it.

### Vendor Contact

A manifest `vendor_email` is written as the library's supplier contact:
`"supplier": { "name": "Vendor", "contact": [ { "email": "sales@vendor.example.com" } ] }`.
CycloneDX defines `email` as `idn-email`, so a value that is not an email
address is left out (Validate Manifest warns about it).

### Post-Write Check

Every SBOM is read back after writing and checked against the schema rules
DelphiSBOM's output could break: `bomFormat` and `specVersion`, the
`serialNumber` pattern, an integer `version` of at least 1, the timestamp
format, component types (the 1.5 enum, case-sensitive) and names, `license`
holding exactly one of `id`/`name` with `id` an SPDX identifier in its exact
spelling, `licenses` items holding exactly one of `license`/`expression`, hash
algorithms from the 1.5 enum with a digest of the right length, purls starting
`pkg:<type>/`, external reference types, a supplier's `url` and `contact` being
arrays, unique `bom-ref`s, dependency `ref`/`dependsOn` values that name a
component, and composition `aggregate` values (the 1.5 enum) with
`assemblies`/`dependencies` that name a component. Problems are reported with
their JSON path; the file is kept. This is not a full schema validation.

## Known Limitations

### Multi-Version Delphi Installations

With the Delphi Path field left blank, each run uses the installation that
matches the project's `ProjectVersion` — Delphi 12 for a Delphi 12 project on a
machine with Delphi 12 and 13 — for both the RTL unit scan and the IDE library
path. If that version is not installed, the newest installed version is used
and the log warns about it. The **Delphi Path** field forces a specific
installation.

### Unit List Is Read as Text

The unit list comes from the `.dpr` uses clause (or the `.dpk` contains clause)
read as text: units in every `{$IFDEF}` branch are included, and units listed in
`{$I}` include files are not read. The log warns when either is present. A
detailed MAP file given as input replaces this list with the units the linker
used, which has none of these gaps (it describes one build configuration).

### Library-to-Library Dependencies Are Not Recorded

The dependency graph has two levels (see above). Which library uses which
cannot be read from the project alone, so libraries have no entries of their
own: their dependencies are unknown, not empty.

### Scope Prefix Stripping

Unit names are matched both as written and with a known Delphi scope prefix
stripped (`System.`, `Vcl.`, `Winapi.`, `Data.`, `Xml.`, `Datasnap.`, `FMX.`,
`REST.`, `Net.`, `Web.`, `Soap.`, `Bde.`, `IBX.`, `FireDAC.`, `Posix.`), so
`components.json` entries may use either form. A unit like
`System.Generics.Collections` becomes `Generics.Collections` for matching
purposes — only the first scope segment is stripped.

### Output Encoding

The SBOM is written as UTF-8 **without** a byte-order mark (RFC 8259 forbids a
BOM in JSON, and common parsers reject one), via a temporary file, so a failed
write leaves the previous SBOM intact. The `metadata.timestamp` is ISO 8601 UTC
(`2026-10-06T08:53:54Z`) regardless of the Windows locale.
