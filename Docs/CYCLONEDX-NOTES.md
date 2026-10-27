# CycloneDX 1.6 — Delphi-Specific Notes

## Overview

DelphiSBOM generates SBOMs conforming to the CycloneDX 1.6 specification
(JSON format), with the data fields of BSI TR-03183-2 v2.1.0, which requires
CycloneDX 1.6 or later.  This document records Delphi-specific decisions and
known limitations.

**Specification reference:** https://cyclonedx.org/docs/1.6/json/

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
  "manufacturer": { "name": "Embarcadero Technologies", "url": [ "https://www.embarcadero.com" ] },
  "licenses": [ { "expression": "LicenseRef-DelphiSBOM-Embarcadero-RAD-Studio-EULA",
                  "acknowledgement": "concluded" } ],
  "purl": "pkg:delphi/embarcadero-rtl@37.0"
}
```

The RTL is distributed under the RAD Studio licence agreement, which has no SPDX
or ScanCode LicenseDB identifier, so DelphiSBOM names it with a `LicenseRef-`
identifier of its own, as BSI TR-03183-2 section 6.1 (rule 3) asks.

**Rationale:** Listing 1,800+ individual RTL units would produce a massive SBOM
with no practical compliance value. The RTL is a single distributable unit from
a supply-chain perspective.

### Licence Handling

In the CycloneDX 1.6 schema `license.id` is an enum of SPDX identifiers, so a
value that is not a valid identifier makes the whole SBOM fail validation.
DelphiSBOM therefore classifies each `licence` value from `components.json`:

| Value | Emitted as |
|-------|------------|
| A recognised SPDX identifier (case-insensitive; emitted in canonical case) | `{ "license": { "id": "MIT" } }` |
| Contains ` OR `, ` AND ` or ` WITH ` | `{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }` |
| A `LicenseRef-` identifier (letters, digits, `.` and `-` after the prefix) | `{ "expression": "LicenseRef-scancode-commercial-license" }` |
| Anything else, e.g. `Commercial` | `{ "license": { "name": "Commercial" } }` |

The recognised list is a practical subset of the SPDX licence list covering the
Delphi ecosystem (MIT, Apache, BSD, MPL, GPL/LGPL/AGPL in all their forms, BSL,
ISC, Zlib, Unlicense, EPL, CDDL and others). An identifier outside that subset is
emitted as a `name` — still valid, just less machine-readable — and Validate
Manifest warns about it. `licence_url` is added to `id`/`name` entries; CycloneDX
does not allow a URL on an expression.

Every licence entry carries `"acknowledgement": "concluded"` (new in CycloneDX
1.6): it is the licence the component is distributed under, which BSI TR-03183-2
calls the distribution licence.  The application's own licence comes from the
manifest's top-level `application_licence`.  A `name` is valid CycloneDX but not
an identifier, so the BSI TR-03183-2 check reports it as `TR-6.1-LICENCE`: use
the SPDX identifier, a `LicenseRef-scancode-` key from ScanCode LicenseDB, or a
`LicenseRef-` of your own.

### Own-Code Units

Units classified as "own code" (the developer's own source files) are not
listed as separate components. They are part of the main application, which
appears in `metadata.component`. This follows standard SBOM practice — the
SBOM describes what the application *depends on*, not the application itself.

### The Application Component and Its Binary

`metadata.component` also describes the deployable file.  The `.dproj` is
evaluated for Release on the target platform and the binary located from
`DCC_ExeOutput` (`.exe`, or `.dll` for `AppType` `Library`), or for a package
from `DCC_BplOutput` (`.bpl`).  A package or library takes `DllPrefix` and
`DllSuffix` ({$LIBPREFIX} / {$LIBSUFFIX}) around its name, and a `{$E}` directive
in the main source replaces the extension (`{$E cpl}`).  A package left on the
IDE default `$(BDSCOMMONDIR)\Bpl`, or an output folder or affix naming a macro
that cannot be resolved outside the IDE (`$(Auto)`, an IDE-only environment
variable), is treated as having no binary rather than given a guessed path.  The
command line's `--binary` names the file instead.

A binary that exists but is empty (a failed link) or cannot be opened (a linker
or scanner holding it) is warned about and left out; the run does not fail.  When
the file's version resource differs from the version the SBOM gives the
application, the log warns that it may be a stale build.

When the file exists, the application gets its SHA-512 in `hashes`, in a
`distribution` external reference, and the four file properties of BSI
TR-03183-2:

```json
"externalReferences": [ { "type": "distribution", "url": "MyApp.exe",
                          "hashes": [ { "alg": "SHA-512", "content": "9b71d2..." } ] } ],
"properties": [
  { "name": "bsi:component:filename",   "value": "MyApp.exe" },
  { "name": "bsi:component:executable", "value": "executable" },
  { "name": "bsi:component:archive",    "value": "no archive" },
  { "name": "bsi:component:structured", "value": "unstructured" }
]
```

The reference's `url` is the file name, since the file has no download location
of its own, with the characters an IRI-reference may not hold (a space, `#`,
`%` ...) percent-encoded; `bsi:component:filename` keeps the name as it is.  A Delphi binary with statically linked libraries is one
unstructured executable file; the libraries in it are "logical components"
(TR 3.2.1, 3.2.2) and get no file name or hash.  With no binary the log warns,
and the hash, the reference and the properties are left out, never guessed.

### Tools Metadata

The `metadata.tools` field uses the format CycloneDX 1.5 introduced and 1.6 keeps:

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
hashes into the SBOM as **nested sub-components**. The CycloneDX 1.6
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
and hashes with an algorithm outside the CycloneDX 1.6 `hash-alg` enum are
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

The `dependencies` section:

```json
"dependencies": [
  { "ref": "application:MyApp@2.4.0.0",
    "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/OmniThreadLibrary@3.7.8",
                   "pkg:delphi/Spring4D@2.0" ] },
  { "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] },
  { "ref": "pkg:delphi/OmniThreadLibrary@3.7.8", "dependsOn": [] },
  { "ref": "pkg:delphi/Spring4D@2.0", "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0" ] }
]
```

The application depends on the RTL and on each library; the RTL depends on
nothing third-party. A library's own entry comes from its source: for each of
the library's units in the project, the `.pas` file is looked up on the paths
the compiler searches (the project folder, the project search path and the IDE
library path, each with its parent and subfolders — no drive scan); for a unit
compiled from a DCU folder there, under the library's root (the folder above
`Lib\Win64\Release` and similar build-output folders). Its `uses` clauses are read. A unit used there that belongs to another library in
the SBOM, or to the RTL, is an edge. Units of the same library, own code,
unclassified units and libraries not in the SBOM are not. The log says how many
sources were read.

Every component has an entry, as BSI TR-03183-2 requires: a library none of
whose units' source was found, or whose source uses no other library and not
the RTL, has an empty `dependsOn`.  That is not a claim that it uses nothing:
the composition below names it, so its dependencies are declared incomplete.  A
library shipped as DCUs only is a leaf. Library-to-library edges follow
DX.Comply's rule (edges only where source was read, only between components
already in the SBOM).

Library units stay nested under their library when DX.Comply evidence is
merged (see below); the graph does not replace that nesting.

The graph is declared incomplete, in the shape DX.Comply writes, naming the
application, the RTL and every library so that each component's completeness
is stated:

```json
"compositions": [ { "aggregate": "incomplete",
                    "dependencies": [ "application:MyApp@2.4.0.0", "pkg:delphi/embarcadero-rtl@37.0",
                                      "pkg:delphi/OmniThreadLibrary@3.7.8", "pkg:delphi/Spring4D@2.0" ] } ]
```

A library whose source was not read has no edges (see Known Limitations), and
units that could not be classified are not listed, so "complete" would overstate it.

### Vendor Contact

A manifest `vendor_email` is written as the library's supplier contact:
`"supplier": { "name": "Vendor", "contact": [ { "email": "sales@vendor.example.com" } ] }`.
CycloneDX defines `email` as `idn-email`, so a value that is not an email
address is left out (Validate Manifest warns about it).

### Manufacturer (the Creator)

BSI TR-03183-2 asks for the email of the SBOM's creator and of each component's
creator, or a URL when there is no email.  DelphiSBOM writes both as CycloneDX
1.6 `manufacturer`, with the email when there is one and the URL only without:

| Where | From `components.json` |
|-------|------------------------|
| `metadata.manufacturer` (the SBOM's creator) | `supplier`: `name`, with `email`, else `url` |
| `metadata.component.manufacturer` (the application) | the same |
| a library's `manufacturer` | `creator_email` / `creator_url`; without either, `vendor` with `vendor_email` / `vendor_url` (the vendor taken as creator) |
| the RTL's `manufacturer` | Embarcadero Technologies, `https://www.embarcadero.com` |

For example `"manufacturer": { "name": "Example Ltd", "contact": [ { "email": "sbom@example.com" } ] }`.
With neither an email nor a URL no `manufacturer` is written, and the BSI
TR-03183-2 check reports it.

### Post-Write Check

Every SBOM is read back after writing and checked against the schema rules
DelphiSBOM's output could break: `bomFormat` and `specVersion`, the
`serialNumber` pattern, an integer `version` of at least 1, the timestamp
format, component types (the 1.6 enum of 13, case-sensitive, including
`cryptographic-asset`) and names, `license` holding exactly one of `id`/`name`
with `id` an SPDX identifier in its exact spelling, `licenses` items holding
exactly one of `license`/`expression`, an `expression` being the only item of
its `licenses`, a licence `acknowledgement` being `declared` or `concluded`, hash
algorithms from the 1.6 enum with a digest of the right length, purls starting
`pkg:<type>/`, external reference types (the 1.6 enum of 43, including
`source-distribution`, `rfc-9116`, `electronic-signature` and
`digital-signature`), a supplier's or manufacturer's `url` and `contact` being
arrays, unique `bom-ref`s, dependency `ref`/`dependsOn` values that name a
component with no `dependsOn` value listed twice, and composition `aggregate` values (the 1.6 enum) with
`assemblies`/`dependencies` that name a component. Problems are reported with
their JSON path; the file is kept. This is not a full schema validation.

### BSI TR-03183-2 Check

After the SBOM check, the written file is checked against the required data
fields of BSI TR-03183-2 v2.1.0 (sections 4, 5.2.1 and 5.2.2, the licence rules
of 6.1, and no vulnerabilities by 3.1).  Each finding is logged as a `[WARNING]`
led by its rule ID and naming the component.  It is advice: a GUI run never
fails on it, and only the command line's `--fail-on-tr` turns findings into exit
code 3.

| Rule ID | Requires |
|---------|----------|
| `TR-4-FORMAT` | CycloneDX, `specVersion` 1.6 or later |
| `TR-3.1-VULNERABILITIES` | no vulnerability information in the SBOM |
| `TR-5.2.1-CREATOR` | an email or URL in `metadata.manufacturer` |
| `TR-5.2.1-TIMESTAMP` | `metadata.timestamp` |
| `TR-5.2.2-NAME` / `-VERSION` | a name and a version for every component |
| `TR-5.2.2-CREATOR` | an email or URL in each component's `manufacturer` |
| `TR-5.2.2-DEPENDENCIES` | an entry in `dependencies`, and a place in a composition's `dependencies` (not `assemblies`, which describes parts), for each component |
| `TR-5.2.2-LICENCE` | a licence acknowledged `concluded` for each component |
| `TR-5.2.2-FILENAME` / `-HASH` / `-EXECUTABLE` / `-ARCHIVE` / `-STRUCTURED` | the file fields (see [The Application Component and Its Binary](#the-application-component-and-its-binary)) |
| `TR-6.1-LICENCE` | a licence named by an SPDX identifier or expression, not a `name`; an expression must have SPDX syntax (identifiers joined by upper-case `AND` / `OR` / `WITH`), so free text such as "Apache License 2.0 or later" is reported.  The SPDX list itself is not consulted |

The application and every top-level component are checked; nested DX.Comply
evidence components are parts of their parent and are not.  The file fields
apply to the application (the deployable binary) and to any component that
names a file: a statically linked library is a logical component without a file
name or hash.

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

### Library-to-Library Dependencies Are Partial

A library's edges come only from the source of its units that the project uses
and that are found on the compiler's paths or under the library root of their
DCU folder (see above). A library shipped as DCUs only, or whose source lies
elsewhere, has an empty entry, and the incomplete composition says its
dependencies are unknown, not empty. Source found
under a DCU folder's library root is assumed to match the DCUs. The uses clauses are read as text, so units in every `{$IFDEF}`
branch count; an edge is still recorded only to a library that is in the SBOM.
In uses-clause mode the project's unit list is the `.dpr` only, so a library
used only by another library is not in the SBOM and gets no edge — give a MAP
file to list every linked unit.

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
