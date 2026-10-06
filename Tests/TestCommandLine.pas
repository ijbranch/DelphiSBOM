(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestCommandLine.pas — Tests for command-line parsing, the project config file and exit codes
*)
unit TestCommandLine;

interface

uses
  DUnitX.TestFramework,
  uTypes, TestSupport;

type
  /// <summary>
  ///   Parsing arguments and applying the project config file.
  /// </summary>
  [TestFixture]
  TCommandLineTests = class
  private
    FScratch: TScratchDir;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves every option reaches its pipeline setting, relative paths are made absolute against
    ///   the current folder, and each is recorded as given explicitly.
    /// </summary>
    [Test]
    procedure OptionsReachTheirSettings;

    /// <summary>
    ///   Proves a wrong command line is refused with a reason rather than run with a guess: an
    ///   unknown option, a missing value, a bad --report value, a value on a flag, two projects.
    /// </summary>
    /// <param name="AArgs">The arguments, separated by spaces.</param>
    /// <param name="AExpected">Text the error must contain.</param>
    [Test]
    [TestCase( 'unknown option', 'App.dproj --colour=red|Unknown option --colour', '|' )]
    [TestCase( 'missing value', 'App.dproj --manifest|--manifest needs a value', '|' )]
    [TestCase( 'bad report', 'App.dproj --report=pdf|--report must be', '|' )]
    [TestCase( 'value on flag', 'App.dproj --quiet=yes|--quiet takes no value', '|' )]
    [TestCase( 'two projects', 'App.dproj Other.dproj|More than one project file', '|' )]
    procedure BadCommandLineIsRefused( const AArgs, AExpected: string );

    /// <summary>
    ///   Proves the config file fills the settings the command line left out, resolving its relative
    ///   paths from its own folder, not the current one.
    /// </summary>
    [Test]
    procedure ConfigFillsUnsetSettingsFromItsFolder;

    /// <summary>
    ///   Proves a setting given on the command line beats the config file's value: --report=none
    ///   keeps reports off although the file says "both", and an explicit --manifest wins.
    /// </summary>
    [Test]
    procedure CommandLineBeatsConfig;

    /// <summary>
    ///   Proves an unknown config key is warned about and ignored, and a value of the wrong type is an
    ///   error naming the key, so a typo is not silently ignored.
    /// </summary>
    [Test]
    procedure ConfigTyposAreReported;
  end;

  /// <summary>
  ///   RunCommandLine end to end, checking the exit code each outcome maps to.
  /// </summary>
  [TestFixture]
  TCommandLineRunTests = class
  private
    FScratch: TScratchDir;
    FTag: string;
    FOut: string;
    FErr: string;

    function Run( const AArgs: TArray<string> ): Integer;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves no arguments, or a bad option, exits 1 with usage advice.
    /// </summary>
    [Test]
    procedure UsageErrorExitsOne;

    /// <summary>
    ///   Proves a missing project file, or a broken config file, exits 2.
    /// </summary>
    [Test]
    procedure FileErrorExitsTwo;

    /// <summary>
    ///   Proves a normal run exits 0, writes the SBOM where the project config says, and prints a
    ///   summary line.
    /// </summary>
    [Test]
    procedure SuccessfulRunExitsZero;

    /// <summary>
    ///   Proves --fail-on-unclassified exits 3 and names the units missing from the SBOM, while the
    ///   same run without it exits 0.
    /// </summary>
    [Test]
    procedure UnclassifiedUnitsFailOnlyWhenAsked;

    /// <summary>
    ///   Proves --validate-manifest exits 3 for an invalid manifest and 0 for a valid one.
    /// </summary>
    [Test]
    procedure ValidateManifestExitCodes;

    /// <summary>
    ///   Proves --check-online prints a finding for a component with a GitHub vendor_url, including the
    ///   suggestion, and leaves the exit code alone (the check is advice); and that without the flag no
    ///   request is made at all.
    /// </summary>
    [Test]
    procedure CheckOnlineReportsAndOnlyWhenAsked;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
  uCommandLine, uOnlineCheck;

{ TCommandLineTests }

procedure TCommandLineTests.Setup;
begin

  FScratch := TScratchDir.Create;

end;

procedure TCommandLineTests.TearDown;
begin

  FScratch.Free;

end;

procedure TCommandLineTests.OptionsReachTheirSettings;
begin

  var CLI: TCLIOptions;
  var Error: string;
  var Here := GetCurrentDir;

  Assert.IsTrue( ParseCommandLine( [ 'App.dproj', '--manifest=m.json', '--output=out', '--map=App.map', '--dxcomply=bom.json',
    '--delphi=C:\Delphi', '--product-version=2.0.1', '--report=both', '--fail-on-unclassified', '--quiet' ], CLI, Error ), Error );

  Assert.AreEqual( TPath.Combine( Here, 'App.dproj' ), CLI.Options.ProjectFile );
  Assert.AreEqual( TPath.Combine( Here, 'm.json' ), CLI.Options.ManifestFile );
  Assert.AreEqual( TPath.Combine( Here, 'out' ), CLI.Options.OutputDir );
  Assert.AreEqual( TPath.Combine( Here, 'App.map' ), CLI.Options.MapFile );
  Assert.AreEqual( TPath.Combine( Here, 'bom.json' ), CLI.Options.DXComplyFile );
  Assert.AreEqual( 'C:\Delphi', CLI.Options.DelphiPath );
  Assert.AreEqual( '2.0.1', CLI.Options.VersionOverride );
  Assert.IsTrue( CLI.Options.ReportFormats = [ rfMarkdown, rfHtml ], 'Reports' );
  Assert.IsTrue( CLI.FailOnUnclassified, 'Fail on unclassified' );
  Assert.IsTrue( CLI.Quiet, 'Quiet' );
  Assert.IsTrue( CLI.Explicit = [ csManifest, csOutput, csDelphi, csProductVersion, csDXComply, csMap, csReports,
    csFailOnUnclassified ], 'Explicit settings' );

end;

procedure TCommandLineTests.BadCommandLineIsRefused( const AArgs, AExpected: string );
begin

  var CLI: TCLIOptions;
  var Error: string;

  Assert.IsFalse( ParseCommandLine( AArgs.Split( [ ' ' ] ), CLI, Error ), 'Accepted: ' + AArgs );
  Assert.Contains( Error, AExpected );

end;

procedure TCommandLineTests.ConfigFillsUnsetSettingsFromItsFolder;
begin

  var ConfigFile := FScratch.PathOf( 'Proj\' + ConfigFileName );
  WriteUtf8File( ConfigFile, '{ "manifest": "meta\\components.json", "output": "sbom", "map": "Win64\\Release\\App.map", ' +
    '"productVersion": "3.1", "report": "html", "failOnUnclassified": true }' );

  var CLI: TCLIOptions;
  var Error: string;
  Assert.IsTrue( ParseCommandLine( [ FScratch.PathOf( 'Proj\App.dproj' ) ], CLI, Error ), Error );

  ApplyConfigFile( ConfigFile, CLI, nil );

  Assert.AreEqual( FScratch.PathOf( 'Proj\meta\components.json' ), CLI.Options.ManifestFile );
  Assert.AreEqual( FScratch.PathOf( 'Proj\sbom' ), CLI.Options.OutputDir );
  Assert.AreEqual( FScratch.PathOf( 'Proj\Win64\Release\App.map' ), CLI.Options.MapFile );
  Assert.AreEqual( '3.1', CLI.Options.VersionOverride );
  Assert.IsTrue( CLI.Options.ReportFormats = [ rfHtml ], 'Reports from config' );
  Assert.IsTrue( CLI.FailOnUnclassified, 'failOnUnclassified from config' );

end;

procedure TCommandLineTests.CommandLineBeatsConfig;
begin

  var ConfigFile := FScratch.PathOf( 'Proj\' + ConfigFileName );
  WriteUtf8File( ConfigFile, '{ "manifest": "from-config.json", "report": "both", "failOnUnclassified": true }' );

  var CLI: TCLIOptions;
  var Error: string;
  Assert.IsTrue( ParseCommandLine( [ FScratch.PathOf( 'Proj\App.dproj' ), '--report=none',
    '--manifest=' + FScratch.PathOf( 'explicit.json' ) ], CLI, Error ), Error );

  ApplyConfigFile( ConfigFile, CLI, nil );

  Assert.IsTrue( CLI.Options.ReportFormats = [ ], 'Config turned reports back on' );
  Assert.AreEqual( FScratch.PathOf( 'explicit.json' ), CLI.Options.ManifestFile );
  Assert.IsTrue( CLI.FailOnUnclassified, 'An unset setting still comes from the config' );

end;

procedure TCommandLineTests.ConfigTyposAreReported;
begin

  var ConfigFile := FScratch.PathOf( 'Proj\' + ConfigFileName );
  WriteUtf8File( ConfigFile, '{ "manifset": "x.json" }' );

  var CLI := Default( TCLIOptions );
  var Warnings := '';

  ApplyConfigFile( ConfigFile, CLI,
    procedure( AMessage: string )
    begin
      Warnings := Warnings + AMessage;
    end );

  Assert.Contains( Warnings, 'manifset' );
  Assert.AreEqual( '', CLI.Options.ManifestFile );

  WriteUtf8File( ConfigFile, '{ "failOnUnclassified": "yes" }' );

  Assert.WillRaiseWithMessageRegex(
    procedure
    begin
      ApplyConfigFile( ConfigFile, CLI, nil );
    end, ECommandLineConfig, 'failOnUnclassified' );

end;

{ TCommandLineRunTests }

procedure TCommandLineRunTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FTag := 'Dsbl' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  // Ok: every unit in the project folder. Gap: one unit found nowhere
  WriteUtf8File( FScratch.PathOf( 'Ok\Ok.dpr' ),
    'program Ok;' + sLineBreak + 'uses' + sLineBreak + Format( '  %0:sMain in ''%0:sMain.pas'';', [ FTag ] ) + sLineBreak + 'begin end.' );
  WriteUtf8File( FScratch.PathOf( 'Ok\' + FTag + 'Main.pas' ), 'unit ' + FTag + 'Main; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'Ok\' + ConfigFileName ), '{ "output": "sbom" }' );
  TDirectory.CreateDirectory( FScratch.PathOf( 'Ok\sbom' ) );

  WriteUtf8File( FScratch.PathOf( 'Gap\Gap.dpr' ),
    'program Gap;' + sLineBreak + 'uses' + sLineBreak + Format( '  %sNowhere;', [ FTag ] ) + sLineBreak + 'begin end.' );

  WriteUtf8File( FScratch.PathOf( 'Broken\Broken.dpr' ), 'program Broken;' + sLineBreak + 'begin end.' );
  WriteUtf8File( FScratch.PathOf( 'Broken\' + ConfigFileName ), '{ "report": "pdf" }' );

end;

procedure TCommandLineRunTests.TearDownFixture;
begin

  FScratch.Free;

end;

function TCommandLineRunTests.Run( const AArgs: TArray<string> ): Integer;
begin

  FOut := '';
  FErr := '';

  Result := RunCommandLine( AArgs,
    procedure( ALine: string )
    begin
      FOut := FOut + ALine + sLineBreak;
    end,
    procedure( ALine: string )
    begin
      FErr := FErr + ALine + sLineBreak;
    end );

end;

procedure TCommandLineRunTests.UsageErrorExitsOne;
begin

  Assert.AreEqual( ExitUsageError, Run( [ ] ) );
  Assert.Contains( FErr, '--help' );
  Assert.AreEqual( ExitUsageError, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--nonsense' ] ) );

end;

procedure TCommandLineRunTests.FileErrorExitsTwo;
begin

  Assert.AreEqual( ExitFileError, Run( [ FScratch.PathOf( 'Missing\Missing.dpr' ) ] ) );
  Assert.Contains( FErr, 'not found' );

  Assert.AreEqual( ExitFileError, Run( [ FScratch.PathOf( 'Broken\Broken.dpr' ) ] ) );
  Assert.Contains( FErr, 'report' );

end;

procedure TCommandLineRunTests.SuccessfulRunExitsZero;
begin

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ) ] ), FErr );
  Assert.IsTrue( FileExists( FScratch.PathOf( 'Ok\sbom\Ok.cdx.json' ) ), 'SBOM not written to the config''s output folder' );
  Assert.Contains( FOut, 'SBOM: ' );
  Assert.Contains( FOut, 'own code 1' );

end;

procedure TCommandLineRunTests.UnclassifiedUnitsFailOnlyWhenAsked;
begin

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Gap\Gap.dpr' ), '--quiet' ] ), FErr );

  Assert.AreEqual( ExitValidationError, Run( [ FScratch.PathOf( 'Gap\Gap.dpr' ), '--fail-on-unclassified', '--quiet' ] ) );
  Assert.Contains( FErr, FTag + 'Nowhere' );

end;

procedure TCommandLineRunTests.ValidateManifestExitCodes;
begin

  var Manifest := FScratch.PathOf( 'Gap\components.json' );

  WriteUtf8File( Manifest, '{ "components": [ { "name": "Acme", ' );
  Assert.AreEqual( ExitValidationError, Run( [ FScratch.PathOf( 'Gap\Gap.dpr' ), '--validate-manifest', '--manifest=' + Manifest ] ) );

  WriteUtf8File( Manifest, '{ "schema_version": "1.0", "components": [ { "name": "Acme", "version": "1", "vendor": "Acme", ' +
    '"licence": "MIT", "units_exact": [ "AcmeUnit" ] } ] }' );
  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Gap\Gap.dpr' ), '--validate-manifest', '--manifest=' + Manifest ] ), FErr );

end;

procedure TCommandLineRunTests.CheckOnlineReportsAndOnlyWhenAsked;
begin

  var Manifest := FScratch.PathOf( 'Online\components.json' );
  WriteUtf8File( FScratch.PathOf( 'Online\Online.dpr' ), 'program Online;' + sLineBreak + 'begin end.' );
  WriteUtf8File( Manifest, '{ "schema_version": "1.0", "components": [ { "name": "Acme", "version": "1.0", "vendor": "Acme", ' +
    '"vendor_url": "https://github.com/acme/widgets", "licence": "", "units_exact": [ "AcmeUnit" ] } ] }' );

  var Requests := 0;
  OnlineHttpOverride :=
    function( const AUrl: string; out AStatus: Integer ): string
    begin
      Inc( Requests );
      AStatus := 200;

      if AUrl.EndsWith( '/releases/latest' ) then
        Result := '{ "tag_name": "v1.0" }'
      else
        Result := '{ "license": { "spdx_id": "MIT" }, "archived": false }';
    end;
  try
    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Online\Online.dpr' ), '--quiet' ] ), FErr );
    Assert.AreEqual( 0, Requests, 'Requests made without --check-online' );

    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Online\Online.dpr' ), '--check-online' ] ), FErr );
    Assert.IsTrue( Requests > 0, 'No request made with --check-online' );
    Assert.Contains( FOut, 'online: Acme' );
    Assert.Contains( FOut, 'suggested licence: MIT' );
  finally
    OnlineHttpOverride := nil;
  end;

end;

end.
