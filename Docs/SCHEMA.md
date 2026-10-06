# components.json Schema Reference

## Overview

The `components.json` file is a developer-maintained manifest describing the
third-party libraries used by a Delphi project. DelphiSBOM reads this file to
classify units and populate the SBOM with accurate vendor, version, and licence
metadata.

Place `components.json` in the same directory as your `.dpr` / `.dproj` file.

## Schema

```json
{
  "schema_version": "1.0",
  "last_updated": "YYYY-MM-DD",
  "supplier": {
    "name": "Your Company or Name",
    "url": "https://example.com"
  },
  "components": [
    {
      "name": "Library Name",
      "version": "1.0.0",
      "vendor": "Vendor Name",
      "vendor_url": "https://vendor.example.com",
      "licence": "MIT",
      "licence_url": "https://opensource.org/licenses/MIT",
      "type": "library",
      "units_prefix": ["LibPrefix"],
      "units_exact": ["SpecificUnitName"],
      "notes": "Optional notes"
    }
  ],
  "own_code_units": ["MySharedUnit", "AnotherProjectUnit"],
  "own_code_prefixes": ["gll", "mylib"]
}
```

## Field Reference

### Root Fields

| Field | Required | Description |
|-------|----------|-------------|
| `schema_version` | Yes | Must be `"1.0"` (any other value is warned about and read as 1.0) |
| `last_updated` | Yes | ISO date (`YYYY-MM-DD`) of last manifest update |
| `supplier` | Yes | Object with `name` (required) and `url` (optional) identifying the application's publisher |
| `own_code_units` | No | Array of unit names that are your own project code (not third-party). These are classified as own code and excluded from the SBOM components list. An exact name listed here beats any `units_prefix` rule. Auto-populated by the app for units in the project directory and in sibling directories that do not look like a library, and via the "Mark as Own Code" button |
| `own_code_prefixes` | No | Array of unit name prefixes that classify as own code (case-insensitive). Any unit whose name starts with a listed prefix is treated as own code. Useful for internal shared libraries (e.g. `"gll"` matches `gllFunctions`, `gllDateTimeHelpers`, etc.). Applied after `units_prefix`; prefixes shorter than 3 characters are warned about |

Missing required fields are reported as warnings, not errors, so an incomplete
manifest still produces an SBOM. Empty strings and non-string entries in any
array are ignored with a warning (an empty prefix would otherwise match every
unit). Numeric values such as `"version": 3.7` are read as text; `null` is
treated as missing.

### Component Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Library display name (e.g. `"OmniThreadLibrary"`) |
| `version` | Yes | Version string (e.g. `"3.7.8"`, `"2.x"`) |
| `vendor` | Yes | Library author or vendor name |
| `vendor_url` | No | URL to the library's home page or repository |
| `licence` | Yes | SPDX licence identifier (e.g. `"MIT"`, `"BSD-3-Clause"`), an SPDX expression (e.g. `"MPL-1.1 OR LGPL-2.1-or-later"`), or a plain name such as `"Commercial"`. Recognised identifiers are emitted as `license.id`, expressions as `expression`, anything else as `license.name` (Validate Manifest warns about unrecognised values other than `Commercial`) |
| `licence_url` | No | URL to licence text (not emitted for an expression, which CycloneDX does not allow a URL on) |
| `type` | Yes | CycloneDX component type: `"library"`, `"framework"`, or `"application"`. Case-insensitive; emitted lower-case, and an unrecognised value is emitted as `"library"` |
| `units_prefix` | No | Array of unit name prefixes for matching (case-insensitive) |
| `units_exact` | No | Array of exact unit names for matching (case-insensitive) |
| `notes` | No | Freeform notes for documentation purposes |

At least one of `units_prefix` or `units_exact` must be present for the
component to participate in unit classification.

### Dormant Entries

If a component entry in `components.json` is not matched by any unit in the
project, it is considered dormant. Dormant entries are harmless — they are
ignored during SBOM generation and do not appear in the output. DelphiSBOM
logs an `[INFO]` message for each dormant entry so you can identify them.

This commonly occurs when a library is removed from a project but its entry
remains in `components.json`. You can remove dormant entries manually if you
wish, but there is no requirement to do so.

## Unit Matching

DelphiSBOM matches each unit found in a project's `uses` clause against the
manifest entries, trying both the name as written and the name with its Delphi
scope prefix stripped (`System.`, `Vcl.`, `Winapi.`, `Data.`, `Xml.`,
`Datasnap.`, `FMX.`, `REST.`, `Net.`, `Web.`, `Soap.`, `Bde.`, `IBX.`,
`FireDAC.`, `Posix.`).

**Priority order** (first match wins), after RTL/VCL units:
1. `units_exact` — exact case-insensitive name match
2. `own_code_units` — exact case-insensitive name match (own code)
3. `units_prefix` — case-insensitive prefix match (unit name starts with prefix)
4. Own code by `in 'file.pas'` reference in the `.dpr`, or by `own_code_prefixes`

A vendored library compiled from source through an `in` reference still
classifies as third-party when a `units_exact` or `units_prefix` rule matches it.

If a unit matches multiple components, the first match in the `components`
array wins.

## Authoring Guidelines

### Prefix Length Rule

**Prefixes must be at least 3 characters long.** Short prefixes risk false
matches — for example, `"Id"` would match `IdHTTP` (Indy) but also `IdleTimer`
or any other unit starting with `Id`. DelphiSBOM will warn on prefixes shorter
than 3 characters.

If a library's units share only a 1-2 character common prefix, use `units_exact`
instead:

```json
{
  "name": "Indy",
  "version": "10.x",
  "units_prefix": ["IdHTTP", "IdSMTP", "IdTCP", "IdSSL", "IdMessage"],
  "units_exact": ["IdComponent", "IdGlobal"]
}
```

### Commercial Licences

For commercially licenced libraries, use `"Commercial"` as the licence value:

```json
{
  "licence": "Commercial",
  "licence_url": "https://vendor.example.com/licence"
}
```

### Type Selection

| Value | Use for |
|-------|---------|
| `"library"` | Most third-party Delphi packages and component libraries |
| `"framework"` | Large frameworks that provide application structure (e.g. a full ORM or application framework) |
| `"application"` | Standalone tools or applications included as dependencies |

When in doubt, use `"library"`.
