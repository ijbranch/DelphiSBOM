(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
  MIT Licence — see LICENCE file

  uSBOMEngine.pas — UI-independent pipeline orchestrator
  Coordinates: ProjectParser → RTLScanner → ManifestLoader → UnitClassifier → SBOMBuilder
*)
unit uSBOMEngine;

interface

uses
  System.SysUtils,
  uTypes;

type
  /// <summary>
  ///   Orchestrates the full SBOM generation pipeline.
  ///   This class has zero UI dependencies — it accepts a logging callback
  ///   and returns results via TSBOMResult.
  /// </summary>
  TSBOMEngine = class
  private
    FLog: TProc<TLogLevel, string>;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Executes the full SBOM generation pipeline.
    ///   This method is designed to run inside TTask.Run on a background thread.
    /// </summary>
    function Execute( const AOptions: TSBOMOptions ): TSBOMResult;

    /// <summary>
    ///   Validates a components.json manifest without generating an SBOM.
    ///   Returns True if valid.
    /// </summary>
    function ValidateManifest( const AManifestFile: string ): Boolean;
  end;

implementation

uses
  System.IOUtils,
  uProjectParser, uRTLScanner, uManifestLoader, uUnitClassifier, uSBOMBuilder;

{ TSBOMEngine }

constructor TSBOMEngine.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;

end;

procedure TSBOMEngine.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TSBOMEngine.Execute( const AOptions: TSBOMOptions ): TSBOMResult;
begin

  Result := Default( TSBOMResult );

  // Step 1: Parse the project file
  Log( llInfo, 'Starting SBOM generation...' );

  var Parser := TProjectParser.Create( FLog );
  try
    Result.ProjectInfo := Parser.Parse( AOptions.ProjectFile );
  finally
    Parser.Free;
  end;

  // Step 2: Scan RTL units
  var Scanner := TRTLScanner.Create( FLog );
  try
    Result.RTLScanAvailable := Scanner.Scan( AOptions.DelphiPath, Result.ProjectInfo.TargetPlatform );

    // Step 3: Load manifest
    var ManifestPath := AOptions.ManifestFile;

    if ManifestPath = '' then
      ManifestPath := TPath.Combine( Result.ProjectInfo.ProjectDir, 'components.json' );

    if FileExists( ManifestPath ) then
    begin
      var Loader := TManifestLoader.Create( FLog );
      try
        Result.Manifest := Loader.Load( ManifestPath );
      finally
        Loader.Free;
      end;
    end
    else
      Log( llWarning, Format( 'Manifest not found at %s — no third-party classification available', [ ManifestPath ] ) );

    // Step 4: Classify units
    var Classifier := TUnitClassifier.Create( FLog, Scanner, Result.Manifest, Result.RTLScanAvailable );
    try
      Result.ClassifiedUnits := Classifier.Classify( Result.ProjectInfo.Units );
      Result.Summary         := TUnitClassifier.Summarise( Result.ClassifiedUnits );
    finally
      Classifier.Free;
    end;

  finally
    Scanner.Free;
  end;

  // Step 5: Build and save SBOM
  var Builder := TSBOMBuilder.Create( FLog );
  try
    Result.OutputFile := Builder.BuildAndSave(
      Result.ProjectInfo,
      Result.ClassifiedUnits,
      Result.Manifest,
      Result.RTLScanAvailable,
      AOptions.VersionOverride,
      AOptions.OutputDir
    );
  finally
    Builder.Free;
  end;

  Result.Success := True;
  Log( llInfo, 'SBOM generation complete.' );

end;

function TSBOMEngine.ValidateManifest( const AManifestFile: string ): Boolean;
begin

  Log( llInfo, Format( 'Validating manifest: %s', [ ExtractFileName( AManifestFile ) ] ) );

  var Loader := TManifestLoader.Create( FLog );
  try
    Result := Loader.Validate( AManifestFile );
  finally
    Loader.Free;
  end;

  if Result then
    Log( llInfo, 'Manifest validation passed' )
  else
    Log( llError, 'Manifest validation failed' );

end;

end.
