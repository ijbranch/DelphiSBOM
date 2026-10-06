# Third-Party Notices

DelphiSBOM ships no third-party code. This file credits the work its design draws
on, and lists the optional and test-only dependencies with their licences.

## DX.Comply — design credit

[DX.Comply](https://github.com/omonien/DX.Comply), copyright 2026 Olaf Monien,
MIT licence.

The following DelphiSBOM features follow approaches DX.Comply takes. They were
written for DelphiSBOM; no DX.Comply source code is included.

| DelphiSBOM | Approach taken from DX.Comply |
|------------|-------------------------------|
| `Source/uMapFile.pas` | Reading linked units from a detailed MAP file's `M=` segment entries and "Line numbers for" headers |
| `Source/uCommandLine.pas`, `CLI/DelphiSBOMCLI.dpr` | A per-project JSON config whose settings yield to options given explicitly on the command line |
| `Source/uSBOMBuilder.pas` (dependency graph) | A two-level `dependencies` section: the application depends on its components |
| `Source/uSBOMValidator.pas` | A structural check of the written SBOM (serial number, hashes, dependency references) |
| `Source/uReportWriter.pas` | Human-readable HTML and Markdown companion reports |
| `Docs/CI-INTEGRATION.md` | Build-server examples for GitHub Actions and GitLab |

DX.Comply's licence, for reference:

```
MIT License

Copyright (c) 2026 Olaf Monien

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

DelphiSBOM also reads the `bom.json` that DX.Comply writes (`Source/uEvidenceMerger.pas`)
to merge its unit hashes.

## Optional dependency

| Library | Licence | Use |
|---------|---------|-----|
| [SynEdit](https://github.com/SynEdit/SynEdit) | MPL-1.1 | Syntax-highlighted SBOM viewer, compiled in only when `USE_SYNEDIT` is defined. Not distributed with DelphiSBOM |

## Test-only dependency

| Library | Licence | Use |
|---------|---------|-----|
| [DUnitX](https://github.com/VSoftTechnologies/DUnitX) | Apache-2.0 | The `Tests/` suite. Not part of the application |

## Standards

- [CycloneDX](https://cyclonedx.org/) 1.5 — the output format.
- [SPDX License List](https://spdx.org/licenses/) — licence identifiers.
- [Package URL](https://github.com/package-url/purl-spec) — component identifiers.
