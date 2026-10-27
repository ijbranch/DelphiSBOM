(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uCommandLine.pas — Command-line mode: arguments, the .delphisbom.json project config, exit codes
  The config precedence (defaults, then the file, then the flags actually given) follows DX.Comply
  (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uCommandLine;

interface

uses
  System.SysUtils,
  uTypes;

const
  /// <summary>Exit code: the SBOM was written and passed the check.</summary>
  ExitOK            = 0;

  /// <summary>Exit code: the command line is wrong (unknown option, missing value, no project).</summary>
  ExitUsageError    = 1;

  /// <summary>Exit code: a file is missing or unreadable, or the run failed (project, manifest, config, MAP file).</summary>
  ExitFileError     = 2;

  /// <summary>Exit code: the SBOM failed the post-write check, the manifest is invalid, or
  ///   --fail-on-unclassified found units missing from the SBOM.</summary>
  ExitValidationError = 3;

  /// <summary>The project config file looked for beside the project file.</summary>
  ConfigFileName    = '.delphisbom.json';

type
  /// <summary>
  ///   Raised for a project config file that cannot be used: invalid JSON, or a value of the wrong type.
  /// </summary>
  ECommandLineConfig = class( Exception );

  /// <summary>
  ///   A setting that can come from either the command line or the config file.
  /// </summary>
  TCLISetting = ( csManifest, csOutput, csDelphi, csProductVersion, csDXComply, csMap, csReports, csFailOnUnclassified,
    csCheckOnline, csVersionFromGitTag, csBinary, csFailOnTR );

  /// <summary>
  ///   The settings given explicitly on the command line; the config file never overrides these.
  /// </summary>
  TCLISettings = set of TCLISetting;

  /// <summary>
  ///   Everything the command line asked for.
  /// </summary>
  TCLIOptions = record
    /// <summary>The pipeline inputs; paths are absolute</summary>
    Options: TSBOMOptions;
    /// <summary>--config=<file> (empty = look for .delphisbom.json beside the project)</summary>
    ConfigFile: string;
    /// <summary>--no-config: ignore any project config file</summary>
    NoConfig: Boolean;
    /// <summary>Settings given on the command line</summary>
    Explicit: TCLISettings;
    /// <summary>Exit 3 when units are missing from the SBOM</summary>
    FailOnUnclassified: Boolean;
    /// <summary>--fail-on-tr: exit 3 when the SBOM does not meet BSI TR-03183-2</summary>
    FailOnTR: Boolean;
    /// <summary>--validate-manifest: check components.json and stop</summary>
    ValidateManifestOnly: Boolean;
    /// <summary>--check-online: compare components.json with the libraries' GitHub repositories</summary>
    CheckOnline: Boolean;
    /// <summary>--version-from-git-tag: the product version from the newest git tag</summary>
    VersionFromGitTag: Boolean;
    /// <summary>Show warnings and errors only</summary>
    Quiet: Boolean;
    /// <summary>--help: print the usage text and stop</summary>
    ShowHelp: Boolean;
    /// <summary>--version: print the DelphiSBOM version and stop</summary>
    ShowVersion: Boolean;
  end;

/// <summary>
///   Parses the command line. The one positional argument is the project file; options are
///   --name=value or --flag. Relative paths are made absolute against the current directory.
/// </summary>
/// <param name="AArgs">The arguments, without the program name.</param>
/// <param name="AOptions">The parsed options.</param>
/// <param name="AError">Why parsing failed, when it returns False.</param>
/// <returns>True when the command line is valid.</returns>
function ParseCommandLine( const AArgs: TArray<string>; out AOptions: TCLIOptions; out AError: string ): Boolean;

/// <summary>
///   Applies a project config file to every setting the command line did not give. Relative paths in
///   the file are resolved against the file's own folder.
/// </summary>
/// <param name="AConfigFile">Full path of the config file.</param>
/// <param name="AOptions">The options to complete.</param>
/// <param name="AWarn">Receives a message for each key the file has that DelphiSBOM does not know.</param>
/// <exception cref="ECommandLineConfig">The file is not a JSON object, or a value has the wrong type.</exception>
/// <exception cref="EFOpenError">The file cannot be opened.</exception>
procedure ApplyConfigFile( const AConfigFile: string; var AOptions: TCLIOptions; const AWarn: TProc<string> );

/// <summary>
///   The --help text.
/// </summary>
/// <returns>Usage, options, config file keys and exit codes.</returns>
function UsageText: string;

/// <summary>
///   Runs DelphiSBOM from the command line: parses the arguments, applies the project config, runs
///   the pipeline and maps the outcome to an exit code. The calling thread must not have initialised
///   COM in a multithreaded apartment (the .dproj is read with MSXML).
/// </summary>
/// <param name="AArgs">The arguments, without the program name.</param>
/// <param name="AOut">Receives each line of normal output.</param>
/// <param name="AErr">Receives each error line.</param>
/// <returns>ExitOK, ExitUsageError, ExitFileError or ExitValidationError.</returns>
function RunCommandLine( const AArgs: TArray<string>; const AOut, AErr: TProc<string> ): Integer;

var
  /// <summary>
  ///   Where --version-from-git-tag gets the newest tag of a folder: uGit.LatestGitTag when nil. Test seam:
  ///   tests assign it so no real git is run. Leave nil in production.
  /// </summary>
  GitTagSource: TFunc<string, string>;

implementation

uses
  System.Classes, System.IOUtils, System.JSON, Winapi.ActiveX,
  uSBOMEngine, uTextFiles, uManifestLoader, uOnlineCheck, uGit;

/// <summary>Parses a report setting: md, html, both or none.</summary>
function TryParseReports( const AValue: string; out AFormats: TReportFormats ): Boolean;
begin

  Result            := True;
  var V             := LowerCase( Trim( AValue ) );

  if V = 'md' then
    AFormats        := [ rfMarkdown ]
  else if V = 'html' then
    AFormats        := [ rfHtml ]
  else if V = 'both' then
    AFormats        := [ rfMarkdown, rfHtml ]
  else if V = 'none' then
    AFormats        := [ ]
  else
    Result          := False;

end;

/// <summary>An absolute path: AValue as given when rooted, else resolved against ABaseDir.</summary>
function ResolvePath( const AValue, ABaseDir: string ): string;
begin

  if AValue = '' then Exit( '' );

  if TPath.IsPathRooted( AValue ) then
    Result          := TPath.GetFullPath( AValue )
  else
    Result          := TPath.GetFullPath( TPath.Combine( ABaseDir, AValue ) );

end;

function ParseCommandLine( const AArgs: TArray<string>; out AOptions: TCLIOptions; out AError: string ): Boolean;
begin

  AOptions          := Default( TCLIOptions );
  AError            := '';
  var CurrentDir    := GetCurrentDir;

  for var Arg in AArgs do
  begin
    if ( Arg = '-h' ) or ( Arg = '-?' ) or ( Arg = '/?' ) or SameText( Arg, '--help' ) then
    begin
      AOptions.ShowHelp := True;
      Continue;
    end;

    if ( not Arg.StartsWith( '--' ) ) then
    begin
      if AOptions.Options.ProjectFile <> '' then
      begin
        AError      := Format( 'More than one project file given: %s and %s', [ AOptions.Options.ProjectFile, Arg ] );
        Exit( False );
      end;

      AOptions.Options.ProjectFile := ResolvePath( Arg, CurrentDir );
      Continue;
    end;

    var Name        := LowerCase( Copy( Arg, 3, MaxInt ) );
    var Value       := '';
    var HasValue    := Pos( '=', Name ) > 0;

    if HasValue then
    begin
      Value         := Copy( Arg, Pos( '=', Arg ) + 1, MaxInt );
      Name          := Copy( Name, 1, Pos( '=', Name ) - 1 );
    end;

    // Flags take no value
    if ( Name = 'version' ) or ( Name = 'quiet' ) or ( Name = 'no-config' ) or ( Name = 'fail-on-unclassified' ) or
      ( Name = 'validate-manifest' ) or ( Name = 'check-online' ) or ( Name = 'version-from-git-tag' ) or ( Name = 'fail-on-tr' ) then
    begin
      if HasValue then
      begin
        AError      := Format( '--%s takes no value', [ Name ] );
        Exit( False );
      end;

      if Name = 'version' then
        AOptions.ShowVersion := True
      else if Name = 'quiet' then
        AOptions.Quiet := True
      else if Name = 'no-config' then
        AOptions.NoConfig := True
      else if Name = 'validate-manifest' then
        AOptions.ValidateManifestOnly := True
      else if Name = 'check-online' then
      begin
        AOptions.CheckOnline := True;
        Include( AOptions.Explicit, csCheckOnline );
      end
      else if Name = 'version-from-git-tag' then
      begin
        AOptions.VersionFromGitTag := True;
        Include( AOptions.Explicit, csVersionFromGitTag );
      end
      else if Name = 'fail-on-tr' then
      begin
        AOptions.FailOnTR := True;
        Include( AOptions.Explicit, csFailOnTR );
      end
      else
      begin
        AOptions.FailOnUnclassified := True;
        Include( AOptions.Explicit, csFailOnUnclassified );
      end;

      Continue;
    end;

    if ( not HasValue ) or ( Trim( Value ) = '' ) then
    begin
      if ( Name = 'manifest' ) or ( Name = 'output' ) or ( Name = 'delphi' ) or ( Name = 'product-version' ) or
        ( Name = 'dxcomply' ) or ( Name = 'map' ) or ( Name = 'report' ) or ( Name = 'config' ) or ( Name = 'binary' ) then
        AError      := Format( '--%s needs a value: --%0:s=<value>', [ Name ] )
      else
        AError      := Format( 'Unknown option --%s', [ Name ] );

      Exit( False );
    end;

    if Name = 'manifest' then
    begin
      AOptions.Options.ManifestFile := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csManifest );
    end
    else if Name = 'output' then
    begin
      AOptions.Options.OutputDir := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csOutput );
    end
    else if Name = 'delphi' then
    begin
      AOptions.Options.DelphiPath := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csDelphi );
    end
    else if Name = 'product-version' then
    begin
      AOptions.Options.VersionOverride := Trim( Value );
      Include( AOptions.Explicit, csProductVersion );
    end
    else if Name = 'dxcomply' then
    begin
      AOptions.Options.DXComplyFile := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csDXComply );
    end
    else if Name = 'map' then
    begin
      AOptions.Options.MapFile := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csMap );
    end
    else if Name = 'binary' then
    begin
      AOptions.Options.BinaryFile := ResolvePath( Value, CurrentDir );
      Include( AOptions.Explicit, csBinary );
    end
    else if Name = 'report' then
    begin
      if ( not TryParseReports( Value, AOptions.Options.ReportFormats ) ) then
      begin
        AError      := Format( '--report must be md, html, both or none, not "%s"', [ Value ] );
        Exit( False );
      end;

      Include( AOptions.Explicit, csReports );
    end
    else if Name = 'config' then
      AOptions.ConfigFile := ResolvePath( Value, CurrentDir )
    else
    begin
      AError        := Format( 'Unknown option --%s', [ Name ] );
      Exit( False );
    end;
  end;

  Result            := True;

end;

procedure ApplyConfigFile( const AConfigFile: string; var AOptions: TCLIOptions; const AWarn: TProc<string> );
begin

  var Parsed        := TJSONObject.ParseJSONValue( ReadTextFile( AConfigFile ) );
  try
    if ( not ( Parsed is TJSONObject ) ) then
      raise ECommandLineConfig.CreateFmt( '%s is not a JSON object', [ AConfigFile ] );

    var BaseDir     := ExtractFilePath( AConfigFile );

    // A string value, or an error naming the key
    var StringOf :=
      function( APair: TJSONPair ): string
      begin
        if ( not ( APair.JsonValue is TJSONString ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "%s" must be a string', [ AConfigFile, APair.JsonString.Value ] );

        Result      := TJSONString( APair.JsonValue ).Value;
      end;

    for var Pair in TJSONObject( Parsed ) do
    begin
      var Key       := Pair.JsonString.Value;

      if Key = 'manifest' then
      begin
        if ( not ( csManifest in AOptions.Explicit ) ) then
          AOptions.Options.ManifestFile := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'output' then
      begin
        if ( not ( csOutput in AOptions.Explicit ) ) then
          AOptions.Options.OutputDir := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'delphi' then
      begin
        if ( not ( csDelphi in AOptions.Explicit ) ) then
          AOptions.Options.DelphiPath := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'productVersion' then
      begin
        if ( not ( csProductVersion in AOptions.Explicit ) ) then
          AOptions.Options.VersionOverride := Trim( StringOf( Pair ) );
      end
      else if Key = 'dxcomply' then
      begin
        if ( not ( csDXComply in AOptions.Explicit ) ) then
          AOptions.Options.DXComplyFile := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'map' then
      begin
        if ( not ( csMap in AOptions.Explicit ) ) then
          AOptions.Options.MapFile := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'binary' then
      begin
        if ( not ( csBinary in AOptions.Explicit ) ) then
          AOptions.Options.BinaryFile := ResolvePath( StringOf( Pair ), BaseDir );
      end
      else if Key = 'report' then
      begin
        var Formats: TReportFormats;

        if ( not TryParseReports( StringOf( Pair ), Formats ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "report" must be md, html, both or none', [ AConfigFile ] );

        if ( not ( csReports in AOptions.Explicit ) ) then
          AOptions.Options.ReportFormats := Formats;
      end
      else if Key = 'failOnUnclassified' then
      begin
        if ( not ( Pair.JsonValue is TJSONBool ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "failOnUnclassified" must be true or false', [ AConfigFile ] );

        if ( not ( csFailOnUnclassified in AOptions.Explicit ) ) then
          AOptions.FailOnUnclassified := TJSONBool( Pair.JsonValue ).AsBoolean;
      end
      else if Key = 'failOnTr' then
      begin
        if ( not ( Pair.JsonValue is TJSONBool ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "failOnTr" must be true or false', [ AConfigFile ] );

        if ( not ( csFailOnTR in AOptions.Explicit ) ) then
          AOptions.FailOnTR := TJSONBool( Pair.JsonValue ).AsBoolean;
      end
      else if Key = 'checkOnline' then
      begin
        if ( not ( Pair.JsonValue is TJSONBool ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "checkOnline" must be true or false', [ AConfigFile ] );

        if ( not ( csCheckOnline in AOptions.Explicit ) ) then
          AOptions.CheckOnline := TJSONBool( Pair.JsonValue ).AsBoolean;
      end
      else if Key = 'versionFromGitTag' then
      begin
        if ( not ( Pair.JsonValue is TJSONBool ) ) then
          raise ECommandLineConfig.CreateFmt( '%s: "versionFromGitTag" must be true or false', [ AConfigFile ] );

        if ( not ( csVersionFromGitTag in AOptions.Explicit ) ) then
          AOptions.VersionFromGitTag := TJSONBool( Pair.JsonValue ).AsBoolean;
      end
      else if Assigned( AWarn ) then
        AWarn( Format( '%s: unknown key "%s" ignored', [ ExtractFileName( AConfigFile ), Key ] ) );
    end;
  finally
    Parsed.Free;
  end;

end;

function UsageText: string;
begin

  Result            := string.Join( sLineBreak, [
    AppName + ' ' + AppVersion + ' — CycloneDX 1.6 SBOM generator for Delphi projects (BSI TR-03183-2 v2.1.0)',
    '',
    'Usage: DelphiSBOMCLI <project.dproj | project.dpr | package.dpk> [options]',
    '',
    'Options:',
    '  --manifest=<file>         components.json to use (default: beside the project)',
    '  --output=<dir>            Folder for <Project>.cdx.json (default: the project folder)',
    '  --map=<file>              Detailed .map file: list the units the linker used, not the uses clause',
    '  --binary=<file>           Built binary to describe: file name and SHA-512 (default: the .dproj''s',
    '                            Release output)',
    '  --dxcomply=<file>         DX.Comply bom.json whose unit hashes are merged into the SBOM',
    '  --delphi=<dir>            Delphi installation to use (default: the project''s version)',
    '  --product-version=<ver>   Version for the application (default: from the .dproj)',
    '  --version-from-git-tag    Version from the newest git tag reachable in the project folder',
    '                            (v1.2.3 gives 1.2.3); --product-version wins when both are given',
    '  --report=md|html|both|none  Write <Project>.sbom-report.md / .html beside the SBOM',
    '  --fail-on-unclassified    Exit 3 when any unit is missing from the SBOM',
    '  --fail-on-tr              Exit 3 when the SBOM lacks a data field BSI TR-03183-2 v2.1.0 requires',
    '  --validate-manifest       Check components.json only, then stop',
    '  --check-online            Also compare components.json with each GitHub vendor_url (licence,',
    '                            latest release, archived). Advice only: the exit code is unchanged',
    '  --config=<file>           Project config to use (default: ' + ConfigFileName + ' beside the project)',
    '  --no-config               Ignore any project config file',
    '  --quiet                   Show warnings and errors only',
    '  --version                 Show the DelphiSBOM version',
    '  --help                    Show this text',
    '',
    'Project config (' + ConfigFileName + '), every key optional; command-line options win:',
    '  { "manifest": "components.json", "output": "sbom", "map": "Win64\\Release\\App.map",',
    '    "dxcomply": "bom.json", "delphi": "C:\\...\\Studio\\37.0", "productVersion": "1.2.3",',
    '    "report": "both", "failOnUnclassified": true, "checkOnline": false, "versionFromGitTag": true,',
    '    "binary": "Win64\\Release\\App.exe", "failOnTr": true }',
    '  Relative paths are resolved from the config file''s folder.',
    '',
    'Exit codes:',
    '  0  SBOM written and passed the check',
    '  1  Usage error',
    '  2  File or parse error (project, manifest, config or MAP file)',
    '  3  Validation error (SBOM check, invalid manifest, --fail-on-unclassified or --fail-on-tr)'
    ] );

end;

/// <summary>Runs the online check on a manifest and prints one line per finding.</summary>
procedure ReportOnlineCheck( const AManifest: TManifest; const ALog: TProc<TLogLevel, string>; const AOut: TProc<string>; AQuiet: Boolean );
begin

  var Checker       := TOnlineChecker.Create( ALog );
  try
    for var F in Checker.Check( AManifest ) do
    begin
      if AQuiet and ( F.Kind = ofkInfo ) then Continue;

      var Line      := Format( 'online: %s: %s', [ F.Component, F.Message ] );

      if F.Field <> '' then
        Line        := Line + Format( ' (suggested %s: %s)', [ F.Field, F.Suggested ] );

      if F.Kind = ofkWarning then
        AOut( FormatLogMessage( llWarning, Line ) )
      else
        AOut( FormatLogMessage( llInfo, Line ) );
    end;
  finally
    Checker.Free;
  end;

end;

function RunCommandLine( const AArgs: TArray<string>; const AOut, AErr: TProc<string> ): Integer;
begin

  var CLI: TCLIOptions;
  var Error         := '';

  if ( not ParseCommandLine( AArgs, CLI, Error ) ) then
  begin
    AErr( '[ERROR] ' + Error );
    AErr( 'Run with --help for usage.' );
    Exit( ExitUsageError );
  end;

  if CLI.ShowHelp then
  begin
    AOut( UsageText );
    Exit( ExitOK );
  end;

  if CLI.ShowVersion then
  begin
    AOut( AppName + ' ' + AppVersion );
    Exit( ExitOK );
  end;

  if CLI.Options.ProjectFile = '' then
  begin
    AErr( '[ERROR] No project file given' );
    AErr( 'Run with --help for usage.' );
    Exit( ExitUsageError );
  end;

  if ( not FileExists( CLI.Options.ProjectFile ) ) then
  begin
    AErr( '[ERROR] Project file not found: ' + CLI.Options.ProjectFile );
    Exit( ExitFileError );
  end;

  // The project config: --config, else the one beside the project
  if ( not CLI.NoConfig ) then
  begin
    var ConfigFile  := CLI.ConfigFile;

    if ( ConfigFile <> '' ) and ( not FileExists( ConfigFile ) ) then
    begin
      AErr( '[ERROR] Config file not found: ' + ConfigFile );
      Exit( ExitFileError );
    end;

    if ConfigFile = '' then
    begin
      ConfigFile    := TPath.Combine( ExtractFilePath( CLI.Options.ProjectFile ), ConfigFileName );

      if ( not FileExists( ConfigFile ) ) then
        ConfigFile  := '';
    end;

    if ConfigFile <> '' then
    try
      ApplyConfigFile( ConfigFile, CLI,
        procedure( AMessage: string )
        begin
          AOut( '[WARNING] ' + AMessage );
        end );

      if ( not CLI.Quiet ) then
        AOut( '[INFO] Using project config ' + ConfigFile );
    except
      on E: ECommandLineConfig do
      begin
        AErr( '[ERROR] ' + E.Message );
        Exit( ExitFileError );
      end;
      on E: EFOpenError do
      begin
        AErr( '[ERROR] Cannot read ' + ConfigFile + ': ' + E.Message );
        Exit( ExitFileError );
      end;
    end;
  end;

  var Quiet         := CLI.Quiet;
  var LogProc: TProc<TLogLevel, string> :=
    procedure( ALevel: TLogLevel; AMessage: string )
    begin
      if ALevel = llError then
        AErr( FormatLogMessage( ALevel, AMessage ) )
      else if ( ALevel = llWarning ) or ( not Quiet ) then
        AOut( FormatLogMessage( ALevel, AMessage ) );
    end;

  // The newest git tag beats a productVersion from the config file, but never --product-version
  if CLI.VersionFromGitTag and ( not CLI.ValidateManifestOnly ) then
  begin
    if csProductVersion in CLI.Explicit then
      LogProc( llInfo, '--product-version is given, so the git tag is not used' )
    else
    begin
      var ProjectDir := ExtractFileDir( CLI.Options.ProjectFile );
      var Tag: string;

      if Assigned( GitTagSource ) then
        Tag         := GitTagSource( ProjectDir )
      else
        Tag         := LatestGitTag( ProjectDir );

      var TagVersion := TagToVersion( Tag );

      if TagVersion = '' then
        LogProc( llWarning, Format( 'No git tag with a version is reachable in %s (git missing, not a work tree, or no tag) — ' +
            'the version comes from the config file or the .dproj', [ ProjectDir ] ) )
      else
      begin
        CLI.Options.VersionOverride := TagVersion;
        LogProc( llInfo, Format( 'Product version %s from git tag %s', [ TagVersion, Tag ] ) );
      end;
    end;
  end;

  // MSXML reads the .dproj; S_FALSE (already initialised on this thread) still needs the matching call
  var ComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );
  try
    var Engine      := TSBOMEngine.Create( LogProc );
    try
      if CLI.ValidateManifestOnly then
      begin
        var ManifestFile := CLI.Options.ManifestFile;

        if ManifestFile = '' then
          ManifestFile := TPath.Combine( ExtractFilePath( CLI.Options.ProjectFile ), 'components.json' );

        if ( not FileExists( ManifestFile ) ) then
        begin
          AErr( '[ERROR] Manifest not found: ' + ManifestFile );
          Exit( ExitFileError );
        end;

        if ( not Engine.ValidateManifest( ManifestFile ) ) then
          Exit( ExitValidationError );

        if CLI.CheckOnline then
        begin
          var Loader := TManifestLoader.Create( LogProc );
          try
            ReportOnlineCheck( Loader.Load( ManifestFile ), LogProc, AOut, Quiet );
          finally
            Loader.Free;
          end;
        end;

        Exit( ExitOK );
      end;

      var SBOM: TSBOMResult;

      try
        SBOM        := Engine.Execute( CLI.Options );
      except
        on E: Exception do
        begin
          AErr( '[ERROR] ' + E.Message );
          Exit( ExitFileError );
        end;
      end;

      AOut( Format( 'SBOM: %s (RTL %d, third-party %d, own code %d, unclassified %d units)', [ SBOM.OutputFile,
        SBOM.Summary.RTLCount, SBOM.Summary.ThirdPartyCount, SBOM.Summary.OwnCodeCount, SBOM.Summary.UnclassifiedCount ] ) );

      // Advice only: it never changes the exit code
      if CLI.CheckOnline then
        ReportOnlineCheck( SBOM.Manifest, LogProc, AOut, Quiet );

      if Length( SBOM.ValidationErrors ) > 0 then
        Exit( ExitValidationError );

      if CLI.FailOnUnclassified and ( SBOM.Summary.UnclassifiedCount > 0 ) then
      begin
        var Names   := '';

        for var CU in SBOM.ClassifiedUnits do
          if CU.Classification = ucUnclassified then
            Names   := Names + ' ' + CU.OriginalName;

        AErr( Format( '[ERROR] %d units are not in the SBOM:%s', [ SBOM.Summary.UnclassifiedCount, Names ] ) );
        Exit( ExitValidationError );
      end;

      // The findings were logged as warnings by the engine
      if CLI.FailOnTR and ( Length( SBOM.TRFindings ) > 0 ) then
      begin
        AErr( Format( '[ERROR] the SBOM does not meet BSI TR-03183-2 v2.1.0 (%d findings)', [ Length( SBOM.TRFindings ) ] ) );
        Exit( ExitValidationError );
      end;

      Result        := ExitOK;
    finally
      Engine.Free;
    end;
  finally
    if ComInitialised then
      CoUninitialize;
  end;

end;

end.
