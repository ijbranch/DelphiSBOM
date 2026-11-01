# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> The change record of the `DelphiSBOMTests` test suite (`Tests`).  Product changes, including those that change a product unit
> together with its tests, stay in the repository's `CHANGELOG.md`.

## [Unreleased]

### Changed

- (2026-11-01) **Converted to DUnitX #533's attribute names** — `TestCommandLine.pas`, `TestLibraryDiscovery.pas`, `TestOnlineCheck.pas`, `TestProjectParser.pas`, `TestSBOMValidator.pas`, `TestTypes.pas`.  124 `[TestCase(...)]` became `[NamedTestCase(...)]` (every test keeps its name).  No `[AutoNameTestCase]` to rename.  Test count unchanged: 268 before and after (0 ignored), every test name and result identical.  **Why:** our DUnitX fork took upstream #533, under which an unconverted `[TestCase('Name', 'values')]` compiles with a different meaning.
