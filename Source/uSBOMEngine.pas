(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMEngine.pas — UI-independent pipeline orchestrator
  Coordinates: ProjectParser → RTLScanner → ManifestLoader → UnitClassifier → LibraryDiscovery → SBOMBuilder
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
    ///   Executes the full SBOM generation pipeline. Designed to run on a worker thread
    ///   (TSBOMGenerateThread); the logging callback is responsible for marshalling to the UI.
    ///   The caller's thread must have initialised COM (the .dproj is read with MSXML).
    /// </summary>
    /// <param name="AOptions">Input files and overrides.</param>
    /// <returns>The run's results; Success is True only when the SBOM file was written.</returns>
    /// <exception cref="Exception">Any pipeline failure (missing project, invalid manifest, unwritable output).</exception>
    function Execute( const AOptions: TSBOMOptions ): TSBOMResult;

    /// <summary>
    ///   Validates a components.json manifest without generating an SBOM.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <returns>True if valid.</returns>
    function ValidateManifest( const AManifestFile: string ): Boolean;
  end;

implementation

uses
  System.IOUtils, System.Generics.Collections,
  uProjectParser, uRTLScanner, uManifestLoader, uUnitClassifier, uSBOMBuilder, uLibraryDiscovery, uEvidenceMerger,
  uDelphiInstall;

{ TSBOMEngine }

constructor TSBOMEngine.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;

end;

procedure TSBOMEngine.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TSBOMEngine.Execute( const AOptions: TSBOMOptions ): TSBOMResult;
begin

  Result            := Default( TSBOMResult );

  // Step 1: Parse the project file
  Log( llInfo, 'Starting SBOM generation...' );

  var Parser        := TProjectParser.Create( FLog );
  try
    Result.ProjectInfo := Parser.Parse( AOptions.ProjectFile );
  finally
    Parser.Free;
  end;

  // Resolve manifest path once for the entire pipeline
  Result.ManifestFile := AOptions.ManifestFile;

  if Result.ManifestFile = '' then
    Result.ManifestFile := TPath.Combine( Result.ProjectInfo.ProjectDir, 'components.json' );

  // Step 1a: Resolve the Delphi installation — the project's own version when it is installed
  var DelphiPath    := AOptions.DelphiPath;
  var BDSVersion    := Result.ProjectInfo.DelphiVersion;
  var Install: TDelphiInstall;
  var ExactMatch    := False;

  if FindDelphiInstall( Result.ProjectInfo.DelphiVersion, Install, ExactMatch ) then
  begin
    if DelphiPath = '' then
    begin
      DelphiPath    := Install.RootDir;
      BDSVersion    := Install.BDSVersion;

      if ( Result.ProjectInfo.DelphiVersion <> '' ) and ( not ExactMatch ) then
        Log( llWarning, Format( 'The project targets BDS %s, which is not installed — using BDS %s (%s) for RTL and library paths',
            [ Result.ProjectInfo.DelphiVersion, Install.BDSVersion, Install.RootDir ] ) )
      else
        Log( llInfo, Format( 'Using Delphi installation BDS %s: %s', [ Install.BDSVersion, Install.RootDir ] ) );
    end
    else if BDSVersion = '' then
      BDSVersion    := Install.BDSVersion;
  end
  else if DelphiPath = '' then
    Log( llWarning, 'No Delphi installation found in the registry' );

  // Step 2: Scan RTL units
  var Scanner       := TRTLScanner.Create( FLog );
  try
    Result.RTLScanAvailable := Scanner.Scan( DelphiPath, Result.ProjectInfo.TargetPlatform );

    // Step 3: Load manifest
    if FileExists( Result.ManifestFile ) then
    begin
      var Loader    := TManifestLoader.Create( FLog );
      try
        Result.Manifest := Loader.Load( Result.ManifestFile );
      finally
        Loader.Free;
      end;
    end
    else
      Log( llWarning, Format( 'Manifest not found at %s — no third-party classification available', [ Result.ManifestFile ] ) );

    // Step 4: Classify units
    var Classifier  := TUnitClassifier.Create( FLog, Scanner, Result.Manifest, Result.RTLScanAvailable, Result.ProjectInfo.OwnCodeUnits );
    try
      Result.ClassifiedUnits := Classifier.Classify( Result.ProjectInfo.Units );
    finally
      Classifier.Free;
    end;
  finally
    Scanner.Free;
  end;

  Result.Summary    := TUnitClassifier.Summarise( Result.ClassifiedUnits );

  // Step 4a: Report dormant manifest entries (components not referenced by any project unit)
  if Length( Result.Manifest.Components ) > 0 then
  begin
    var ReferencedIndices := TDictionary<Integer, Boolean>.Create;
    try
      for var CU in Result.ClassifiedUnits do
        if ( CU.Classification = ucThirdParty ) and ( CU.ComponentIndex >= 0 ) then
          ReferencedIndices.TryAdd( CU.ComponentIndex, True );

      for var I := 0 to High( Result.Manifest.Components ) do
        if not ReferencedIndices.ContainsKey( I ) then
          Log( llInfo, Format( 'components.json: ''%s'' not referenced by any project unit', [ Result.Manifest.Components[ I ].Name ] ) );
    finally
      ReferencedIndices.Free;
    end;
  end;

  // Step 4b: Discover libraries for unclassified units
  if Result.Summary.UnclassifiedCount > 0 then
  begin
    var Discovery   := TLibraryDiscovery.Create( FLog );
    try
      // Collect unclassified unit names
      var UnclassifiedNames := TList<string>.Create;
      try
        for var CU in Result.ClassifiedUnits do
          if CU.Classification = ucUnclassified then
            UnclassifiedNames.Add( CU.OriginalName );

        var AutoOwn: TArray<string>;

        Result.DiscoveredLibraries := Discovery.Discover(
          UnclassifiedNames.ToArray,
          Result.ProjectInfo.SearchPaths,
          Result.ProjectInfo.ProjectDir,
          DelphiPath,
          BDSVersion,
          Result.ProjectInfo.TargetPlatform,
          AutoOwn
          );

        Result.AutoOwnCodeUnits := AutoOwn;
      finally
        UnclassifiedNames.Free;
      end;

      if Length( Result.DiscoveredLibraries ) > 0 then
        Log( llInfo, Format( 'Discovered %d libraries for unclassified units', [ Length( Result.DiscoveredLibraries ) ] ) );
    finally
      Discovery.Free;
    end;

    // Auto-detected own-code units count as own code in THIS run, not only the next one
    if Length( Result.AutoOwnCodeUnits ) > 0 then
    begin
      for var I := 0 to High( Result.ClassifiedUnits ) do
        if Result.ClassifiedUnits[ I ].Classification = ucUnclassified then
          for var OwnUnit in Result.AutoOwnCodeUnits do
            if SameText( Result.ClassifiedUnits[ I ].OriginalName, OwnUnit ) then
            begin
              Result.ClassifiedUnits[ I ].Classification := ucOwnCode;
              Break;
            end;

      Result.Summary := TUnitClassifier.Summarise( Result.ClassifiedUnits );
    end;
  end;

  // Step 4c: Load binary evidence from DX.Comply if provided
  if AOptions.DXComplyFile <> '' then
  begin
    var Merger      := TEvidenceMerger.Create( FLog );
    try
      Result.Evidence := Merger.LoadEvidence( AOptions.DXComplyFile );
    finally
      Merger.Free;
    end;
  end;

  // Step 4d: Log evidence match summary (the same name matching the SBOM builder uses)
  if Length( Result.Evidence ) > 0 then
  begin
    var MatchCount  := 0;

    for var Ev in Result.Evidence do
      for var CU in Result.ClassifiedUnits do
        if SameText( Ev.UnitName, CU.OriginalName ) or SameText( StripScopePrefix( Ev.UnitName ), CU.UnitName ) then
        begin
          Inc( MatchCount );
          Break;
        end;

    Log( llInfo, Format( 'DX.Comply evidence: %d of %d entries matched classified units (%d unmatched - transitive dependencies not in the uses clause)',
        [ MatchCount, Length( Result.Evidence ), Length( Result.Evidence ) - MatchCount ] ) );
  end;

  // Step 5: Build and save SBOM
  var Builder       := TSBOMBuilder.Create( FLog );
  try
    Result.OutputFile := Builder.BuildAndSave(
      Result.ProjectInfo,
      Result.ClassifiedUnits,
      Result.Manifest,
      AOptions.VersionOverride,
      AOptions.OutputDir,
      Result.Evidence
      );
  finally
    Builder.Free;
  end;

  // Step 6: Persist auto-detected own-code units — only once the run has succeeded
  if Length( Result.AutoOwnCodeUnits ) > 0 then
  begin
    var Saver       := TManifestLoader.Create( FLog );
    try
      Saver.SaveOwnCodeUnits( Result.ManifestFile, Result.AutoOwnCodeUnits );
    finally
      Saver.Free;
    end;
  end;

  Result.Success    := True;
  Log( llInfo, 'SBOM generation complete.' );

end;

function TSBOMEngine.ValidateManifest( const AManifestFile: string ): Boolean;
begin

  Log( llInfo, Format( 'Validating manifest: %s', [ ExtractFileName( AManifestFile ) ] ) );

  var Loader        := TManifestLoader.Create( FLog );
  try
    Result          := Loader.Validate( AManifestFile );
  finally
    Loader.Free;
  end;

  if Result then
    Log( llInfo, 'Manifest validation passed' )
  else
    Log( llError, 'Manifest validation failed' );

end;

end.

