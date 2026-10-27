(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
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
    ///   Proves --fail-on-tr exits 3 when the SBOM lacks a BSI TR-03183-2 field (this project has no manifest
    ///   supplier, no licence and no binary), naming the TR, while the same run without it exits 0: the TR check
    ///   is advice unless asked for.
    /// </summary>
    [Test]
    procedure TRFindingsFailOnlyWhenAsked;

    /// <summary>
    ///   Proves --binary names the file described: the SBOM carries its file name and its SHA-512, checked against
    ///   the FIPS 180-2 test vector for "abc" rather than against the hash function the code itself calls.
    /// </summary>
    [Test]
    procedure BinaryIsHashedIntoTheSBOM;

    /// <summary>
    ///   Proves a binary that cannot be described is a warning, never a failed run or a wrong hash: an empty file (a
    ///   failed link) and a file another process holds exclusively both leave the file data out and exit 0.
    /// </summary>
    [Test]
    procedure UndescribableBinaryIsAWarning;

    /// <summary>
    ///   Proves a binary whose file version differs from the version the SBOM states is warned about as a possibly
    ///   stale build, with both versions named; Windows' notepad.exe serves as a file with a version resource.
    /// </summary>
    [Test]
    procedure BinaryOfAnotherVersionIsWarnedAbout;

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

    /// <summary>
    ///   Proves --version-from-git-tag asks for the newest tag of the project folder and writes its version
    ///   (v4.5.6 gives 4.5.6) as the application version; that --product-version beats it; that no tag gives
    ///   a warning and the version the run has without the option; and that without the option git is not run.
    /// </summary>
    [Test]
    procedure VersionFromGitTagSetsTheProductVersion;
  end;

  /// <summary>
  ///   uGit against the real git: the only tests that run a process. They need git on the PATH.
  /// </summary>
  [TestFixture]
  TGitTests = class
  public
    /// <summary>
    ///   Proves LatestGitTag runs git in the folder it is given and returns the tag reachable from HEAD, and
    ///   '' for a work tree with no tag. Built with plumbing commands (write-tree, commit-tree, update-ref) so
    ///   the user's commit and tag signing settings play no part.
    /// </summary>
    [Test]
    procedure LatestGitTagReadsTheWorkTree;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils, System.JSON,
  uCommandLine, uOnlineCheck, uGit, uTextFiles;

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
    '--delphi=C:\Delphi', '--product-version=2.0.1', '--report=both', '--fail-on-unclassified', '--quiet', '--binary=App.exe',
    '--fail-on-tr' ], CLI, Error ), Error );

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
  Assert.AreEqual( TPath.Combine( Here, 'App.exe' ), CLI.Options.BinaryFile );
  Assert.IsTrue( CLI.FailOnTR, 'Fail on TR' );
  Assert.IsTrue( CLI.Explicit = [ csManifest, csOutput, csDelphi, csProductVersion, csDXComply, csMap, csReports,
    csFailOnUnclassified, csBinary, csFailOnTR ], 'Explicit settings' );

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
    '"productVersion": "3.1", "report": "html", "failOnUnclassified": true, "versionFromGitTag": true, ' +
    '"binary": "Win64\\Release\\App.exe", "failOnTr": true }' );

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
  Assert.IsTrue( CLI.VersionFromGitTag, 'versionFromGitTag from config' );
  Assert.AreEqual( FScratch.PathOf( 'Proj\Win64\Release\App.exe' ), CLI.Options.BinaryFile );
  Assert.IsTrue( CLI.FailOnTR, 'failOnTr from config' );

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

procedure TCommandLineRunTests.TRFindingsFailOnlyWhenAsked;
begin

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--quiet' ] ), FErr );
  Assert.Contains( FOut + FErr, 'TR-5.2.1-CREATOR' );

  Assert.AreEqual( ExitValidationError, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--fail-on-tr', '--quiet' ] ) );
  Assert.Contains( FErr, 'does not meet BSI TR-03183-2' );

end;

procedure TCommandLineRunTests.BinaryIsHashedIntoTheSBOM;
begin

  // SHA-512( "abc" ), FIPS 180-2 appendix C.1
  const AbcSHA512 = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
    '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';

  var Binary := FScratch.PathOf( 'Ok\Built\Ok.exe' );
  TDirectory.CreateDirectory( ExtractFilePath( Binary ) );
  TFile.WriteAllBytes( Binary, TEncoding.ANSI.GetBytes( 'abc' ) );

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--binary=' + Binary, '--quiet' ] ), FErr );

  var Root := TJSONObject.ParseJSONValue( ReadTextFile( FScratch.PathOf( 'Ok\sbom\Ok.cdx.json' ) ) ) as TJSONObject;
  try
    var App := Root.GetValue<TJSONObject>( 'metadata.component' );
    Assert.AreEqual( 'Ok.exe', App.GetValue<string>( 'externalReferences[0].url' ) );
    Assert.AreEqual( AbcSHA512, App.GetValue<string>( 'externalReferences[0].hashes[0].content' ) );
    Assert.AreEqual( AbcSHA512, App.GetValue<string>( 'hashes[0].content' ) );
  finally
    Root.Free;
  end;

end;

procedure TCommandLineRunTests.UndescribableBinaryIsAWarning;
begin

  // Whether the written SBOM describes a file at all
  var HasFileData :=
    function: Boolean
    begin
      var Root := TJSONObject.ParseJSONValue( ReadTextFile( FScratch.PathOf( 'Ok\sbom\Ok.cdx.json' ) ) ) as TJSONObject;
      try
        Result := Assigned( Root.GetValue<TJSONObject>( 'metadata.component' ).GetValue( 'hashes' ) );
      finally
        Root.Free;
      end;
    end;

  var Empty := FScratch.PathOf( 'Ok\Built\Empty.exe' );
  TDirectory.CreateDirectory( ExtractFilePath( Empty ) );
  TFile.WriteAllBytes( Empty, [ ] );

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--binary=' + Empty ] ), FErr );
  Assert.Contains( FOut + FErr, 'is empty' );
  Assert.IsFalse( HasFileData(), 'An empty file was hashed' );

  var Locked := FScratch.PathOf( 'Ok\Built\Locked.exe' );
  TFile.WriteAllBytes( Locked, TEncoding.ANSI.GetBytes( 'abc' ) );

  var Holder := TFileStream.Create( Locked, fmOpenRead or fmShareExclusive );
  try
    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--binary=' + Locked ] ), FErr );
  finally
    Holder.Free;
  end;

  Assert.Contains( FOut + FErr, 'could not be' );
  Assert.IsFalse( HasFileData(), 'A locked file was given file data' );

end;

procedure TCommandLineRunTests.BinaryOfAnotherVersionIsWarnedAbout;
begin

  var Notepad := TPath.Combine( GetEnvironmentVariable( 'SystemRoot' ), 'System32\notepad.exe' );
  Assert.IsTrue( FileExists( Notepad ), 'Test data: ' + Notepad + ' not found' );

  var Versioned := FScratch.PathOf( 'Ok\Built\Versioned.exe' );
  TDirectory.CreateDirectory( ExtractFilePath( Versioned ) );
  TFile.Copy( Notepad, Versioned, True );

  Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--binary=' + Versioned, '--product-version=0.0.0.1' ] ), FErr );
  Assert.Contains( FOut + FErr, 'Versioned.exe has file version' );
  Assert.Contains( FOut + FErr, 'gives the application version 0.0.0.1' );

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

/// <summary>The application version written to an SBOM file.</summary>
function SBOMProductVersion( const AFile: string ): string;
begin

  var Root := TJSONObject.ParseJSONValue( ReadTextFile( AFile ) ) as TJSONObject;
  try
    Result := Root.GetValue<string>( 'metadata.component.version' );
  finally
    Root.Free;
  end;

end;

procedure TCommandLineRunTests.VersionFromGitTagSetsTheProductVersion;
begin

  var SBOMFile := FScratch.PathOf( 'Ok\sbom\Ok.cdx.json' );
  var Calls := 0;
  var AskedDir := '';
  var Tag := 'v4.5.6';

  GitTagSource :=
    function( ADir: string ): string
    begin
      Inc( Calls );
      AskedDir := ADir;
      Result := Tag;
    end;
  try
    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ) ] ), FErr );
    Assert.AreEqual( 0, Calls, 'git asked for a tag without --version-from-git-tag' );
    var Untagged := SBOMProductVersion( SBOMFile );

    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--version-from-git-tag' ] ), FErr );
    Assert.AreEqual( FScratch.PathOf( 'Ok' ), AskedDir );
    Assert.AreEqual( '4.5.6', SBOMProductVersion( SBOMFile ) );
    Assert.Contains( FOut, 'from git tag v4.5.6' );

    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--version-from-git-tag', '--product-version=9.9' ] ), FErr );
    Assert.AreEqual( '9.9', SBOMProductVersion( SBOMFile ) );

    Tag := '';
    Assert.AreEqual( ExitOK, Run( [ FScratch.PathOf( 'Ok\Ok.dpr' ), '--version-from-git-tag' ] ), FErr );
    Assert.Contains( FOut, '[WARNING] No git tag' );
    Assert.AreEqual( Untagged, SBOMProductVersion( SBOMFile ) );
  finally
    GitTagSource := nil;
  end;

end;

{ TGitTests }

procedure TGitTests.LatestGitTagReadsTheWorkTree;
begin

  var Scratch := TScratchDir.Create;
  try
    var Repo := Scratch.PathOf( 'Repo' );
    TDirectory.CreateDirectory( Repo );

    var Output: string;
    Assert.IsTrue( RunGit( 'init -q', Repo, '', Output ), 'git init failed (is git on the PATH?): ' + Output );
    Assert.IsTrue( RunGit( 'write-tree', Repo, '', Output ), Output );
    var Tree := Trim( Output );
    Assert.IsTrue( RunGit( '-c user.name=DelphiSBOM -c user.email=tests@example.com commit-tree ' + Tree + ' -m Tests', Repo, '', Output ),
      Output );
    var Commit := Trim( Output );
    Assert.IsTrue( RunGit( 'update-ref HEAD ' + Commit, Repo, '', Output ), Output );

    Assert.AreEqual( '', LatestGitTag( Repo ), 'A work tree with no tag' );

    Assert.IsTrue( RunGit( 'update-ref refs/tags/v1.2.3 ' + Commit, Repo, '', Output ), Output );
    Assert.AreEqual( 'v1.2.3', LatestGitTag( Repo ) );
  finally
    // git writes its objects read-only, which a recursive delete cannot remove
    if TDirectory.Exists( Scratch.PathOf( 'Repo' ) ) then
      for var F in TDirectory.GetFiles( Scratch.PathOf( 'Repo' ), '*', TSearchOption.soAllDirectories ) do
        SetFileAttributes( PChar( F ), FILE_ATTRIBUTE_NORMAL );

    Scratch.Free;
  end;

end;

end.
