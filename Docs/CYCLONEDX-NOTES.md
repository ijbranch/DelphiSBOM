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
- `pkg:delphi/embarcadero-rtl@37.0`

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

### Commercial Licence Handling

CycloneDX licence entries use SPDX identifiers where available. For commercial
(non-SPDX) licences, the `name` field is used instead of `id`:

```json
"licenses": [{ "license": { "name": "Commercial" } }]
```

This is valid CycloneDX — the spec allows either `id` (SPDX) or `name`
(freeform), but not both.

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

When a DX.Comply `bom.json` is provided, DelphiSBOM merges per-unit SHA-256
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
      "hashes": [{ "alg": "SHA-256", "content": "88de45b3a6f2..." }]
    }
  ]
}
```

This nesting provides unit-level binary evidence while preserving the
aggregate component model. Third-party library components receive the same
treatment — each gains a nested `components` array listing its constituent
units with hashes.

DX.Comply classifies units by origin (Embarcadero RTL, Embarcadero VCL,
Third party, Local project). DelphiSBOM matches evidence to its own
classified units by unit name (case-insensitive). Only RTL and third-party
units receive evidence in the output — own-code units are excluded by design.

## Known Limitations

### Multi-Version Delphi Installations

When multiple Delphi versions are installed, the RTL auto-detection scans the
highest version found in the registry. If a user opens a project built with an
older Delphi version (e.g. Delphi 12 on a machine with Delphi 13), the RTL
unit list will come from the newer version.

In practice, RTL unit names are largely stable between versions, so
misclassification is unlikely. The **Delphi Path** field on the form allows
the user to manually point to the correct Delphi installation if needed.

### No Dependency Graph

v1.0 produces a flat component list with no inter-component dependency
relationships. CycloneDX supports a `dependencies` section, but accurately
deriving dependency graphs between Delphi libraries from `uses` clauses is
complex and deferred to a future version.

### Scope Prefix Stripping

Unit names are stripped of known Delphi scope prefixes (`System.`, `Vcl.`,
`Winapi.`, etc.) before classification. This means `components.json` entries
should use bare unit names, not fully qualified ones. A unit like
`System.Generics.Collections` becomes `Generics.Collections` for matching
purposes — only the first scope segment is stripped.
