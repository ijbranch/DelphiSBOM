# DelphiSBOM — Claude Code Instructions

## Project Overview

DelphiSBOM is a free, open-source VCL desktop application that generates
CycloneDX 1.5 Software Bill of Materials (SBOM) files from Delphi projects.
It parses `.dpr`/`.dproj` files, classifies units (RTL, third-party, own code),
and outputs a standards-compliant JSON SBOM.

**Repository:** Codeberg (public)
**Licence:** MIT

## Session Protocol

**First action every session:** Read `PROGRESS.md` in the project root. Check
Current State, Next Action, and Blockers before doing anything else.

**Last action every session:** Update `PROGRESS.md` — mark completed items DONE,
update Current State, write a specific Next Action, add a session log entry.
Never mark a task DONE if it is only partially complete — leave it IN PROGRESS
and describe the partial state in the Next Action line.

## Build Requirements

- **Delphi 10.3 Rio or later** (minimum), Win32/Win64, VCL application. Developed and tested on Delphi 13 Florence
- **No mandatory third-party dependencies** — the project must compile with
  a clean Delphi installation and nothing else
- **Optional dependency:** [SynEdit](https://github.com/SynEdit/SynEdit)
  (MPL-1.1 licence) for syntax-highlighted SBOM viewer. Guarded by
  `USE_SYNEDIT` conditional define. All SynEdit-dependent code must be inside
  `{$IFDEF USE_SYNEDIT}` blocks with a `TMemo` fallback. The project must
  always compile cleanly without SynEdit installed. `USE_SYNEDIT` is NOT
  enabled in the committed `.dproj` — developers add it locally if they
  have SynEdit on their library path
- Allowed RTL units: `System.JSON`, `Xml.XMLDoc`, `Xml.XMLIntf`,
  `System.Win.Registry`, `System.Threading`, and standard RTL/VCL units
- After any code edit to `.pas`, `.dfm`, or `.dproj` files, prompt the user
  to build and report the result. Do not attempt to compile automatically.

## Architecture

```
  uMainForm  →  uSBOMEngine  →  uProjectParser
                              →  uRTLScanner
                              →  uManifestLoader
                              →  uUnitClassifier
                              →  uSBOMBuilder
```

- **`uSBOMEngine`** is the UI-independent pipeline orchestrator. It has zero
  VCL/form dependencies and accepts a `TProc<string>` logging callback.
- **`uMainForm`** handles all UI concerns. It calls `uSBOMEngine` via
  `TTask.Run` and marshals results back via `TThread.Queue`.
- All other units are pure logic — no UI coupling.

## Threading Model

- All processing runs inside `TTask.Run` (`System.Threading`)
- Log updates marshalled to UI thread via `TThread.Queue`
- The entire pipeline inside `TTask.Run` must be wrapped in `try/except` —
  exceptions inside `TTask.Run` are silently swallowed if not caught
- On error: log via callback as `[ERROR]`, signal completion, re-enable controls
- Form controls (inputs + buttons) disabled during processing, re-enabled on
  completion or error
- Cancellation via `ICancellationToken` is a Phase 2 enhancement

## Coding Standards

- **Line length:** 162 characters maximum
- **Spelling:** British English throughout (initialise, colour, optimise)
- **Variables:** Inline `var` declarations preferred
- **Spacing:** Spaces inside parentheses `( content )` and square brackets `[ content ]`
- **Blank lines:** After main method `begin`, before main method `end`.
  Single blank lines only — never two consecutive blank lines.
  Do not add blank lines for nested `begin/end` blocks.
- **Single-statement blocks:** No `begin/end` for single-statement `if/while/for`
- **JSON:** `System.JSON` exclusively — `TJSONObject`, `TJSONArray`,
  `TJSONObject.ParseJSONValue` for reading, constructor-based building for output.
  All JSON output must be pretty-printed.
- **XML:** `Xml.XMLDoc` and `Xml.XMLIntf` for `.dproj` parsing
- **Error output:** `[ERROR]`, `[WARNING]`, `[INFO]` prefixed log messages
- **Exit codes (future CLI mode):** 0 = success, 1 = usage error,
  2 = file/parse error, 3 = validation error

## Public Repository Rules

This repository will become public. The following rules apply now:

- Do **not** reference GITLAK Software, DBiWorkflow, GITLAKLib, or any
  internal system names in code, comments, documentation, or sample files
- Sample files (`components.sample.json`) must use only publicly recognisable
  Delphi libraries as examples (OmniThreadLibrary, Indy, Spring4D, etc.)
- The only supplier reference is in `components.json` at runtime — not hardcoded

## Commit Conventions

- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- Commit each unit individually — do not batch multiple units into one commit
- Do not commit generated SBOM output, `.local`, `.identcache`, or IDE files
- Do not commit or push automatically — prompt the user first

## Key Files

| File | Purpose |
|------|---------|
| `PROGRESS.md` | Implementation progress tracker — read first, update last |
| `DelphiSBOM_Refined_Plan.md` | Full implementation specification (v0.6) |
| `CHANGELOG.md` | Change log (Keep a Changelog format) |
| `Docs/SCHEMA.md` | `components.json` schema reference |
| `Docs/CYCLONEDX-NOTES.md` | CycloneDX 1.5 compliance notes and known limitations |
| `Samples/components.sample.json` | Example manifest for onboarding |
