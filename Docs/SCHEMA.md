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
  "own_code_units": ["MySharedUnit", "AnotherProjectUnit"]
}
```

## Field Reference

### Root Fields

| Field | Required | Description |
|-------|----------|-------------|
| `schema_version` | Yes | Must be `"1.0"` |
| `last_updated` | Yes | ISO date (`YYYY-MM-DD`) of last manifest update |
| `supplier` | Yes | Object with `name` (required) and `url` (optional) identifying the application's publisher |
| `own_code_units` | No | Array of unit names that are your own project code (not third-party). These are classified as own code and excluded from the SBOM components list. Auto-populated by the app for units in sibling project directories, and via the "Mark Unresolved as Own Code" button |

### Component Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Library display name (e.g. `"OmniThreadLibrary"`) |
| `version` | Yes | Version string (e.g. `"3.7.8"`, `"2.x"`) |
| `vendor` | Yes | Library author or vendor name |
| `vendor_url` | No | URL to the library's home page or repository |
| `licence` | Yes | SPDX licence identifier (e.g. `"MIT"`, `"BSD-3-Clause"`) or `"Commercial"` |
| `licence_url` | No | URL to licence text |
| `type` | Yes | CycloneDX component type: `"library"`, `"framework"`, or `"application"` |
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

DelphiSBOM matches each unit found in a project's `uses` clauses against the
manifest entries. Matching is performed after stripping Delphi scope prefixes
(`System.`, `Vcl.`, `Winapi.`, etc.).

**Priority order** (first match wins):
1. `units_exact` — exact case-insensitive name match
2. `units_prefix` — case-insensitive prefix match (unit name starts with prefix)

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
