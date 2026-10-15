(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMEngine.pas — UI-independent pipeline orchestrator
  Coordinates: ProjectParser (or MapFile) → RTLScanner → ManifestLoader → UnitClassifier → LibraryDiscovery →
  SBOMBuilder → SBOMValidator → ReportWriter
  Library uses edges read from source follow DX.Comply (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uSBOMEngine;

interface

uses
  System.SysUtils,
  uTypes, uRTLScanner, uLibraryDiscovery;

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
    procedure ApplyMapFile( const AMapFile: string; var AResult: TSBOMResult );
    /// <summary>
    ///   What each manifest library in the run uses: the uses clauses of its units' source, found by
    ///   ADiscovery.FindCompilerSources, classified by the run's rules. Edges go to the RTL and to other manifest
    ///   components, never to the library itself; a library with no edge gets no record. A source that cannot be
    ///   opened is logged and skipped.
    /// </summary>
    /// <param name="AResult">The run so far: project, manifest and classified units.</param>
    /// <param name="AScanner">The run's RTL scanner.</param>
    /// <param name="ADiscovery">The run's library discovery, whose search paths are reused.</param>
    /// <param name="ADelphiPath">Resolved Delphi root directory (may be empty).</param>
    /// <param name="ABDSVersion">BDS version of that installation (may be empty).</param>
    /// <returns>One record per library that uses something, in the order of the project's units.</returns>
    function ResolveLibraryDependencies( const AResult: TSBOMResult; AScanner: TRTLScanner; ADiscovery: TLibraryDiscovery;
      const ADelphiPath, ABDSVersion: string ): TArray<TLibraryDependency>;
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Executes the full SBOM generation pipeline. Designed to run on a worker thread
    ///   (TSBOMGenerateThread); the logging callback is responsible for marshalling to the UI.
    ///   The caller's thread must have initialised COM (the .dproj is read with MSXML).
    /// </summary>
    /// <param name="AOptions">Input files and overrides.</param>
    /// <returns>The run's results; Success is True only when the SBOM file was written. Problems the
    ///   post-write check found are in ValidationErrors and do not clear Success.</returns>
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
  System.Classes, System.IOUtils, System.Generics.Collections, System.Generics.Defaults,
  uMapFile, uSBOMValidator, uReportWriter, uTextFiles, uProjectParser, uManifestLoader, uUnitClassifier, uSBOMBuilder, uEvidenceMerger,
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

procedure TSBOMEngine.ApplyMapFile( const AMapFile: string; var AResult: TSBOMResult );
begin

  var Linked        := ReadMapUnitNames( AMapFile );

  // A map older than the main source may describe a build from before its uses clause last changed. Not the
  // .dproj: build-number auto-increment rewrites it on every build
  var MapAge: TDateTime;
  var SourceAge: TDateTime;

  for var Ext in [ '.dpr', '.dpk' ] do
  begin
    var MainSource  := ChangeFileExt( AResult.ProjectInfo.ProjectFile, Ext );

    if FileAge( MainSource, SourceAge ) then
    begin
      if FileAge( AMapFile, MapAge ) and ( MapAge < SourceAge ) then
        Log( llWarning, Format( 'MAP file %s is older than %s — rebuild the project so it lists the current units',
            [ ExtractFileName( AMapFile ), ExtractFileName( MainSource ) ] ) );

      Break;
    end;
  end;

  var InUses        := TDictionary<string, Boolean>.Create( TIStringComparer.Ordinal );
  var InMap         := TDictionary<string, Boolean>.Create( TIStringComparer.Ordinal );
  var Units         := TList<string>.Create;
  try
    for var U in AResult.ProjectInfo.Units do
      InUses.AddOrSetValue( U, True );

    // The program (or library / package) itself is linked as a unit of the project's name
    for var U in Linked do
      if ( not SameText( U, AResult.ProjectInfo.ProjectName ) ) then
      begin
        InMap.AddOrSetValue( U, True );
        Units.Add( U );
      end;

    var Indirect    := 0;

    for var U in Units do
      if ( not InUses.ContainsKey( U ) ) then
        Inc( Indirect );

    var NotLinked   := 0;

    for var U in AResult.ProjectInfo.Units do
      if ( not InMap.ContainsKey( U ) ) then
        Inc( NotLinked );

    AResult.ProjectInfo.Units := Units.ToArray;
    AResult.UnitSource := 'MAP file ' + ExtractFileName( AMapFile );

    Log( llInfo, Format( 'MAP file %s lists %d linked units: %d not named in the uses clause, %d uses-clause units not linked',
        [ ExtractFileName( AMapFile ), Units.Count, Indirect, NotLinked ] ) );
  finally
    Units.Free;
    InMap.Free;
    InUses.Free;
  end;

end;

function TSBOMEngine.ResolveLibraryDependencies( const AResult: TSBOMResult; AScanner: TRTLScanner; ADiscovery: TLibraryDiscovery;
  const ADelphiPath, ABDSVersion: string ): TArray<TLibraryDependency>;
begin

  Result            := nil;

  // The units of manifest components: these are the libraries whose uses are wanted
  var LibraryUnits  := TList<TClassifiedUnit>.Create;
  var Names         := TList<string>.Create;
  var Order         := TList<Integer>.Create; // Component indexes in the order first seen
  var Targets       := TObjectDictionary<Integer, TList<Integer>>.Create( [ doOwnsValues ] );
  try
    for var CU in AResult.ClassifiedUnits do
      if ( CU.Classification = ucThirdParty ) and ( CU.ComponentIndex >= 0 ) and ( CU.ComponentIndex <= High( AResult.Manifest.Components ) ) then
      begin
        LibraryUnits.Add( CU );
        Names.Add( CU.OriginalName );
      end;

    if LibraryUnits.Count = 0 then Exit;

    var Sources     := ADiscovery.FindCompilerSources( Names.ToArray, AResult.ProjectInfo.SearchPaths, AResult.ProjectInfo.ProjectDir,
      ADelphiPath, ABDSVersion, AResult.ProjectInfo.TargetPlatform );

    // The units a library uses are classified by the same rules as the project's own; no log, so the run's
    // classification summary is not repeated for each file
    var Classifier  := TUnitClassifier.Create( nil, AScanner, AResult.Manifest, AResult.RTLScanAvailable, AResult.ProjectInfo.OwnCodeUnits );
    try
      var ReadCount := 0;

      for var I := 0 to LibraryUnits.Count - 1 do
      begin
        if Sources[ I ] = '' then Continue;

        var Content: string;

        try
          Content   := ReadTextFile( Sources[ I ] );
        except
          on E: EFOpenError do
          begin
            Log( llWarning, Format( 'Could not read %s for its uses clause: %s', [ Sources[ I ], E.Message ] ) );
            Continue;
          end;
        end;

        Inc( ReadCount );
        var Owner   := LibraryUnits[ I ].ComponentIndex;
        var OwnerTargets: TList<Integer>;

        if ( not Targets.TryGetValue( Owner, OwnerTargets ) ) then
        begin
          OwnerTargets := TList<Integer>.Create;
          Targets.Add( Owner, OwnerTargets );
          Order.Add( Owner );
        end;

        for var Used in Classifier.Classify( ExtractUsedUnits( Content ) ) do
        begin
          var Target: Integer;

          // Own code, unclassified units and the library's own units are not edges
          if Used.Classification = ucRTL then
            Target  := RTLComponentIndex
          else if ( Used.Classification = ucThirdParty ) and ( Used.ComponentIndex >= 0 ) and ( Used.ComponentIndex <> Owner ) then
            Target  := Used.ComponentIndex
          else
            Continue;

          if ( not OwnerTargets.Contains( Target ) ) then
            OwnerTargets.Add( Target );
        end;
      end;

      var EdgeCount := 0;

      for var Owner in Order do
        if Targets[ Owner ].Count > 0 then
        begin
          var Dependency: TLibraryDependency;
          Dependency.ComponentIndex := Owner;
          Dependency.DependsOn := Targets[ Owner ].ToArray;
          Result    := Result + [ Dependency ];
          Inc( EdgeCount, Length( Dependency.DependsOn ) );
        end;

      Log( llInfo, Format( 'Library uses: read the source of %d of %d third-party units; %d libraries use %d other libraries or the RTL',
          [ ReadCount, LibraryUnits.Count, Length( Result ), EdgeCount ] ) );
    finally
      Classifier.Free;
    end;
  finally
    Targets.Free;
    Order.Free;
    Names.Free;
    LibraryUnits.Free;
  end;

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

  // Step 1b: the units the linker used, when a MAP file is given. It replaces the uses-clause list:
  // it adds units used only indirectly and drops those left out by {$IFDEF}s
  Result.UnitSource := 'project uses clause';

  if AOptions.MapFile <> '' then
    ApplyMapFile( AOptions.MapFile, Result );

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

  // One discovery object for the run: library uses (step 4) and discovery (step 4b) share its search paths
  var Discovery     := TLibraryDiscovery.Create( FLog );
  try
    // Step 2: Scan RTL units
    var Scanner     := TRTLScanner.Create( FLog );
    try
      Result.RTLScanAvailable := Scanner.Scan( DelphiPath, Result.ProjectInfo.TargetPlatform );

      // Step 3: Load manifest
      if FileExists( Result.ManifestFile ) then
      begin
        var Loader  := TManifestLoader.Create( FLog );
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

      // Step 4 (continued): what each library uses, from the uses clauses of its source on the compiler's paths
      Result.LibraryDependencies := ResolveLibraryDependencies( Result, Scanner, Discovery, DelphiPath, BDSVersion );
    finally
      Scanner.Free;
    end;

    Result.Summary  := TUnitClassifier.Summarise( Result.ClassifiedUnits );

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
  finally
    Discovery.Free;
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
      Result.Evidence,
      Result.LibraryDependencies
      );
  finally
    Builder.Free;
  end;

  Result.ProductVersion := EffectiveProductVersion( AOptions.VersionOverride, Result.ProjectInfo.ProjectVersion );

  // Step 5a: check the file as written. A problem is reported, not fatal: the SBOM is kept so it can be inspected
  Result.ValidationErrors := CheckSBOM( ReadTextFile( Result.OutputFile ) );

  if Length( Result.ValidationErrors ) = 0 then
    Log( llInfo, 'SBOM check passed (structure, identifiers, licences, hashes and dependency references)' )
  else
  begin
    for var E in Result.ValidationErrors do
      Log( llError, 'SBOM check: ' + E );

    Log( llError, Format( 'SBOM check found %d problems in %s', [ Length( Result.ValidationErrors ), ExtractFileName( Result.OutputFile ) ] ) );
  end;

  // Step 5b: companion reports
  if AOptions.ReportFormats <> [ ] then
  begin
    Result.ReportFiles := WriteReports( Result, AOptions.ReportFormats );

    for var F in Result.ReportFiles do
      Log( llInfo, Format( 'Report written to %s', [ F ] ) );
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

