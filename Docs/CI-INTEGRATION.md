# Generating the SBOM in a Build

`DelphiSBOMCLI.exe` (built from `CLI/DelphiSBOMCLI.dproj`) runs the same pipeline as
the app without a window, so a build can produce the SBOM next to the binaries it
describes. It needs a Windows machine with the Delphi version the project uses, because
RTL units are recognised from that installation, and the libraries the project uses.
In practice that means a self-hosted build agent.

> **Untested examples.** The pipeline files below show the shape of a job; they have not
> been run on GitHub or GitLab. Adapt paths, runner labels and the Delphi version.

## The recommended sequence

1. **Build** the project with a detailed map file (`DCC_MapFile=3`), so DelphiSBOM reads
   the units the linker actually used — including units used only indirectly, and without
   units excluded by `{$IFDEF}`s.
2. **Generate** with `--map`, and `--fail-on-unclassified` so a new, unrecorded library
   fails the build instead of silently missing from the SBOM.
3. **Keep** `<Project>.cdx.json` (and the reports) as build artefacts of the release.

```
DelphiSBOMCLI MyApp.dproj --map=Win64\Release\MyApp.map --report=both --fail-on-unclassified
```

`components.json` must be in the repository: the command line never adds libraries to it
(review discovered libraries in the app). It does save auto-detected own-code units, so a
build agent's checkout may show `components.json` modified; commit those additions from a
developer machine instead.

Exit codes: `0` success, `1` usage error, `2` file or parse error, `3` validation error
(the SBOM failed its check, or `--fail-on-unclassified` found units missing from it).

## A project config instead of long command lines

Put the settings in `.delphisbom.json` beside the project; the job then only names the
project. Relative paths are resolved from the file's folder, and any option given on the
command line overrides the file.

```json
{
    "map": "Win64\\Release\\MyApp.map",
    "output": "sbom",
    "report": "both",
    "failOnUnclassified": true
}
```

## GitHub Actions (self-hosted Windows runner)

```yaml
name: SBOM
on:
  push:
    tags: [ 'v*' ]

jobs:
  sbom:
    runs-on: [ self-hosted, windows, delphi13 ]
    steps:
      - uses: actions/checkout@v4

      - name: Build with a detailed map file
        shell: cmd
        run: |
          call "C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
          msbuild MyApp.dproj /t:Build /p:Config=Release /p:Platform=Win64 /p:DCC_MapFile=3

      - name: Generate the SBOM
        shell: cmd
        run: C:\Tools\DelphiSBOM\DelphiSBOMCLI.exe MyApp.dproj --map=Win64\Release\MyApp.map --report=both --fail-on-unclassified

      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            *.cdx.json
            *.sbom-report.*
```

## GitLab CI (Windows runner with the shell executor)

```yaml
sbom:
  stage: build
  tags: [ windows, delphi13 ]
  script:
    - cmd /c '"C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat" && msbuild MyApp.dproj /t:Build /p:Config=Release /p:Platform=Win64 /p:DCC_MapFile=3'
    - C:\Tools\DelphiSBOM\DelphiSBOMCLI.exe MyApp.dproj --map=Win64\Release\MyApp.map --report=both --fail-on-unclassified
  artifacts:
    paths:
      - "*.cdx.json"
      - "*.sbom-report.*"
    expire_in: never
```

`expire_in: never` keeps the SBOM for as long as the release it describes; set it to your
retention requirement instead if that is shorter.

## Without a MAP file

Leave out `--map` and the unit list comes from the project's uses clause, as in the app.
That needs no build first, but lists units from every `{$IFDEF}` branch and misses units
the project uses only indirectly; the log warns when the uses clause holds conditional
directives.

The structure of this guide follows DX.Comply's CI guide (Olaf Monien, MIT) — see
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).
