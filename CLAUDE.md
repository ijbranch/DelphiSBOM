# DelphiSBOM — Claude Code Instructions

## Project Overview

DelphiSBOM is a free, open-source VCL desktop application that generates
CycloneDX 1.5 Software Bill of Materials (SBOM) files from Delphi projects.
It parses `.dpr`/`.dproj` files, classifies units (RTL, third-party, own code),
and outputs a standards-compliant JSON SBOM.

**Repository:** GitHub (public) — https://github.com/ijbranch/DelphiSBOM
**Licence:** MIT

## Session Protocol

**First action every session:** Read `PROGRESS.md` in the project root. Check
Current State, Next Action, and Blockers before doing anything else.

**Last action every session:** Update `PROGRESS.md` — mark completed items DONE,
update Current State, write a specific Next Action, add a session log entry.
Never mark a task DONE if it is only partially complete — leave it IN PROGRESS
and describe the partial state in the Next Action line.

## Build Requirements

- **Delphi 10.3 Rio or later** (language floor: inline variables), Win32/Win64, VCL application
- **Environment caveat:** developed, built and tested ONLY on Delphi 13 Florence, Win64.
  Rio and Win32 are not tested — say so whenever compatibility is claimed, and avoid
  APIs newer than Rio where an older equivalent exists (e.g. `TFormatSettings.Create( 'en-US' )`
  rather than `TFormatSettings.Invariant`; `TFile.ReadAllText` without an encoding is NOT
  equivalent across versions — use `uTextFiles.ReadTextFile`)
- **No mandatory third-party dependencies** — the project must compile with
  a clean Delphi installation and nothing else
- **Optional dependency:** [SynEdit](https://github.com/SynEdit/SynEdit)
  (MPL-1.1 licence) for syntax-highlighted SBOM viewer. Guarded by
  `USE_SYNEDIT` conditional define. All SynEdit-dependent code must be inside
  `{$IFDEF USE_SYNEDIT}` blocks with a `TMemo` fallback. The project must
  always compile cleanly without SynEdit installed.
  - The committed `.dproj` passes `$(DELPHISBOM_DEFINES)` to `DCC_Define`; developers
    with SynEdit set the environment variable `DELPHISBOM_DEFINES=USE_SYNEDIT`.
  - NEVER add `USE_SYNEDIT` to Project Options: the IDE saves it into the shared
    `.dproj` (this happened twice). `.githooks/pre-commit` rejects such a `.dproj`
    (enable once per clone: `git config core.hooksPath .githooks`)
- Allowed RTL units: `System.JSON`, `Xml.XMLDoc`, `Xml.XMLIntf`,
  `System.Win.Registry`, `System.Threading`, and standard RTL/VCL units
- After any code edit to `.pas`, `.dfm`, or `.dproj` files, prompt the user
  to build and report the result. Do not attempt to compile automatically.

## Architecture

```
  GUI  (Source/DelphiSBOM.dpr):   uMainForm, uSettings, uLibraryEditor  ─┐
  CLI  (CLI/DelphiSBOMCLI.dpr):   uCommandLine                          ─┤
                                                                         ▼
  uSBOMEngine  →  uProjectParser / uMapFile   unit list (uses clause, or the linker's MAP file)
               →  uDelphiInstall              Delphi installation for the project's version
               →  uRTLScanner                 RTL unit names
               →  uManifestLoader             components.json
               →  uUnitClassifier             RTL / third-party / own code
               →  uLibraryDiscovery           .pas, then .dcu on the search and library path
               →  uEvidenceMerger             DX.Comply hashes
               →  uSBOMBuilder                components, bom-refs, dependency graph
               →  uSBOMValidator              post-write check
               →  uReportWriter               HTML / Markdown reports
  shared: uTypes (records, SPDX/hash helpers), uTextFiles (encoding-safe read, atomic UTF-8 write)
```

- **`uSBOMEngine`** is the UI-independent pipeline orchestrator. It has zero
  VCL/form dependencies and accepts a `TProc<TLogLevel, string>` logging callback.
  It resolves the Delphi installation from the project's `ProjectVersion`
  (`uDelphiInstall`) and passes it to the RTL scanner and library discovery.
- **`uSettings`** manages MRU persistence to `%APPDATA%\DelphiSBOM\DelphiSBOM.ini` (UTF-8).
  No VCL dependencies.
- **`uMainForm`** handles all UI concerns. It runs `uSBOMEngine` on a `TThread`
  descendant and marshals log lines and results back via `Synchronize`.
- **`uCommandLine`** is the whole command-line mode (argument parsing, the
  `.delphisbom.json` project config, exit codes) behind `RunCommandLine`, which
  takes output callbacks so the suite tests it without a console. `CLI/DelphiSBOMCLI.dpr`
  only forwards `ParamStr` and sets the console to UTF-8. Config values never override
  options given on the command line (`TCLIOptions.Explicit`).
- All other units are pure logic — no UI coupling.
- All file reads go through `uTextFiles.ReadTextFile`/`ReadTextFileHead` (BOM, then
  UTF-8, then ANSI); all JSON writes through `WriteTextFileAtomic` (UTF-8, no BOM).

## Threading Model

- Processing runs on `TSBOMGenerateThread` / `TSBOMValidateThread` (`TThread`
  descendants, `FreeOnTerminate`). `TTask.Run` with nested anonymous methods failed on
  Win64, so it is not used.
- The generate thread calls `CoInitializeEx` / `CoUninitialize`: the `.dproj` is read
  with `TXMLDocument` (MSXML, COM).
- Log updates marshalled to the UI thread via `Synchronize`; the main thread never
  waits on a worker, so there is no `Synchronize` deadlock path.
- The engine call inside `Execute` is wrapped in `try/except`; on error log `[ERROR]`,
  then always `Synchronize( SyncComplete )`. `SyncComplete` re-enables the form in a
  `finally`, so an exception while displaying results cannot strand it.
- Form controls (inputs, action and result buttons) disabled during processing,
  re-enabled on completion or error. Close is refused while a run is in progress.
- Cancellation is a Phase 2 enhancement.

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
- **Exit codes (CLI, `uCommandLine` constants):** 0 = success, 1 = usage error,
  2 = file/parse error, 3 = validation error (SBOM check, invalid manifest, `--fail-on-unclassified`)

## Public Repository Rules

This repository will become public. The following rules apply now:

- Do **not** reference GITLAK Software, DBiWorkflow, GITLAKLib, or any
  internal system names in code, comments, documentation, or sample files
- Sample files (`components.sample.json`) must use only publicly recognisable
  Delphi libraries as examples (OmniThreadLibrary, Indy, Spring4D, etc.)
- The only supplier reference is in `components.json` at runtime — not hardcoded
- **Attribution:** a feature modelled on another project's design is credited in its unit
  header and in `THIRD-PARTY-NOTICES.md` (with that project's licence text); copied code
  additionally keeps its original copyright notice. README "Acknowledgements" links the file

## Testing

- `Tests/DelphiSBOMTests.dproj` — DUnitX console suite over the non-VCL units (`..\Source`).
  Build it (Win64 Debug) and run `Tests\Win64\Debug\DelphiSBOMTests.exe --exitbehavior:Continue`
  after any change to those units; exit code is non-zero on failure.
- The runner sets `Assert.IgnoreCaseDefault := False` and `FailsOnNoAsserts := True`: pass the
  third argument only when a comparison is genuinely case-insensitive, and never add a test
  without an assertion that a real defect would fail.
- Fixtures are discovered by `[TestFixture]` + RTTI only; do not also call `RegisterTestFixture`
  (stock DUnitX runs a doubly registered fixture twice).
- Each test writes only to its own `TScratchDir` (`TestSupport.pas`), and fixtures that read a
  `.dproj` call `CoInitializeEx` in setup (MSXML).
- New behaviour gets a test whose `<summary>` says what it proves; mutation-check it (reintroduce
  the defect, see the test fail) before relying on it.
- `Tests/GuiChecks.ps1` (pwsh 7) drives the Release exe by window messages — `WM_SETTEXT`,
  `BM_CLICK`, `WM_CHAR`, `CB_SETCURSEL` + `CBN_SELCHANGE` — never screen coordinates or forced
  focus. Run it after UI changes in `uMainForm`/`uLibraryEditor`; extend it when a UI behaviour is
  added. It backs up and restores the user's INI. Dialogs are found by class (`TMessageForm`,
  `#32770`) only: other windows in the process (e.g. a monitor utility's helper) must be ignored.
  Detect run completion from the log text, not from the Generate button (a fast run can start and
  finish between two polls).
- After a change to `uCommandLine` or the engine, also build `CLI/DelphiSBOMCLI.dproj`
  (Win64 Release) and run `DelphiSBOMCLI --help`.
- **Environment caveat:** the suite runs only on Delphi 13 Win64. `TestSBOMEngine` also scans
  the machine's library roots and `TestDelphiInstall` reads the registry — both are written to
  hold on any machine, but have only been run on one.

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
| `CHANGES.md` | Project change log (reverse chronological) |
| `Docs/SCHEMA.md` | `components.json` schema reference |
| `Docs/CYCLONEDX-NOTES.md` | CycloneDX 1.5 compliance notes and known limitations |
| `Samples/components.sample.json` | Example manifest for onboarding (every field and licence form) |
| `CLI/DelphiSBOMCLI.dproj` | Command-line exe (build Win64 Release) |
| `Docs/CI-INTEGRATION.md` | Build-server use of the CLI (untested examples) |
| `Samples/delphisbom.sample.json` | Example `.delphisbom.json` project config |
| `THIRD-PARTY-NOTICES.md` | Design credits (DX.Comply) and optional/test dependencies |
| `Tests/DelphiSBOMTests.dproj` | DUnitX suite |
| `Tests/GuiChecks.ps1` | Scripted GUI checks against the Release exe |
| `Docs/AUDIT-2026-10-06.md` | Audit findings and their status |
