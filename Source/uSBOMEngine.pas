(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
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
    /// <summary>
    ///   The deployable binary: ABinaryFile when given, else where the .dproj puts a Release build.  A file that
    ///   exists is hashed with SHA-512.  One that does not exist, is empty or cannot be opened (a linker or scanner
    ///   holding it) is logged, and the SBOM then goes without file data rather than the run failing.  The file's
    ///   version resource is read; when it differs from a version given explicitly, the file may be a stale build and
    ///   that is warned about.
    /// </summary>
    /// <param name="ABinaryFile">The binary named by the caller ('' = the project's Release output).</param>
    /// <param name="AProjectInfo">The parsed project, whose BinaryFile is the default.</param>
    /// <param name="AExplicitVersion">The application version given explicitly ('' = none given).</param>
    /// <returns>The file's name, SHA-512 and file version; FileName is '' when there is no binary to describe.</returns>
    function DescribeBinary( const ABinaryFile: string; const AProjectInfo: TProjectInfo;
      const AExplicitVersion: string ): TBinaryInfo;
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
  Winapi.Windows, System.Classes, System.IOUtils, System.Generics.Collections, System.Generics.Defaults, System.Hash,
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

/// <summary>The file version in a binary's version resource as Major.Minor.Release.Build, or '' when it has none.</summary>
function FileVersionOf( const AFileName: string ): string;
begin

  Result            := '';
  var Handle: DWORD;
  var Size          := GetFileVersionInfoSize( PChar( AFileName ), Handle );

  if Size = 0 then Exit;

  var Buffer: TBytes;
  SetLength( Buffer, Size );

  if ( not GetFileVersionInfo( PChar( AFileName ), 0, Size, @Buffer[ 0 ] ) ) then Exit;

  var Info: PVSFixedFileInfo;
  var InfoSize: UINT;

  if VerQueryValue( @Buffer[ 0 ], '\', Pointer( Info ), InfoSize ) and ( InfoSize >= SizeOf( TVSFixedFileInfo ) ) then
    Result          := Format( '%d.%d.%d.%d', [ HiWord( Info.dwFileVersionMS ), LoWord( Info.dwFileVersionMS ),
      HiWord( Info.dwFileVersionLS ), LoWord( Info.dwFileVersionLS ) ] );

end;

/// <summary>
///   Whether a binary's file version contradicts the version the SBOM states: each numeric part the SBOM gives is
///   compared with the file's ('2.4' is matched by 2.4.x.y).  A version that is not dotted numbers, or a file
///   without a version resource, is no contradiction.
/// </summary>
function VersionsDiffer( const AFileVersion, AVersion: string ): Boolean;
begin

  Result            := False;

  if AFileVersion = '' then Exit;

  var Stated        := AVersion.Split( [ '.' ] );
  var Actual        := AFileVersion.Split( [ '.' ] );

  for var I := 0 to High( Stated ) do
  begin
    var StatedPart: Integer;

    if ( I > High( Actual ) ) or ( not TryStrToInt( Stated[ I ], StatedPart ) ) then Exit( False );

    if StatedPart <> StrToIntDef( Actual[ I ], -1 ) then
      Result        := True;
  end;

end;

function TSBOMEngine.DescribeBinary( const ABinaryFile: string; const AProjectInfo: TProjectInfo;
  const AExplicitVersion: string ): TBinaryInfo;
begin

  Result            := Default( TBinaryInfo );

  var BinaryFile    := ABinaryFile;

  if BinaryFile = '' then
    BinaryFile      := AProjectInfo.BinaryFile;

  if BinaryFile = '' then
  begin
    Log( llWarning, 'No built binary to describe: its file name and SHA-512 are left out (name it to include them)' );
    Exit;
  end;

  if ( not FileExists( BinaryFile ) ) then
  begin
    Log( llWarning, Format( 'Built binary %s not found: its file name and SHA-512 are left out (build Release first)', [ BinaryFile ] ) );
    Exit;
  end;

  // A failed link can leave an empty file, whose hash would describe nothing
  var Size: Int64;

  try
    Size            := TFile.GetSize( BinaryFile );
  except
    on E: EInOutError do
    begin
      Log( llWarning, Format( 'Built binary %s could not be read (%s): its file name and SHA-512 are left out', [ BinaryFile, E.Message ] ) );
      Exit;
    end;
  end;

  if Size = 0 then
  begin
    Log( llWarning, Format( 'Built binary %s is empty: its file name and SHA-512 are left out (rebuild Release)', [ BinaryFile ] ) );
    Exit;
  end;

  try
    Result.SHA512   := LowerCase( THashSHA2.GetHashStringFromFile( BinaryFile, THashSHA2.TSHA2Version.SHA512 ) );
  except
    on E: EFOpenError do
    begin
      Log( llWarning, Format( 'Built binary %s could not be opened (%s): its file name and SHA-512 are left out', [ BinaryFile, E.Message ] ) );
      Exit;
    end;
    on E: EReadError do
    begin
      Log( llWarning, Format( 'Built binary %s could not be read (%s): its file name and SHA-512 are left out', [ BinaryFile, E.Message ] ) );
      Exit;
    end;
  end;

  Result.FileName   := ExtractFileName( BinaryFile );

  // A resource of all zeros names no version
  var FileVersion   := FileVersionOf( BinaryFile );

  if FileVersion = '0.0.0.0' then
    FileVersion     := '';

  Result.FileVersion := FileVersion;

  // A version given explicitly is written as given, so a binary of another version may be a stale build.  Without one
  // the binary's version is written: the .dproj's build number has usually moved on since the build
  if AExplicitVersion <> '' then
  begin
    if VersionsDiffer( FileVersion, AExplicitVersion ) then
      Log( llWarning, Format( 'Built binary %s has file version %s, but the SBOM gives the application version %s — a stale build, ' +
        'or a version set elsewhere: check that the hash describes the release', [ ExtractFileName( BinaryFile ), FileVersion,
        AExplicitVersion ] ) );
  end
  else if FileVersion <> '' then
  begin
    if AProjectInfo.ProjectVersion = '' then
      Log( llInfo, Format( 'Application version %s taken from the binary (the .dproj gives none)', [ FileVersion ] ) )
    else if VersionsDiffer( FileVersion, AProjectInfo.ProjectVersion ) then
    begin
      // The Release output is normally a build behind the .dproj; a binary the caller named may be any file
      if ABinaryFile <> '' then
        Log( llWarning, Format( 'Application version %s taken from %s, but the .dproj says %s — check that it is the release''s binary',
          [ FileVersion, ExtractFileName( BinaryFile ), AProjectInfo.ProjectVersion ] ) )
      else
        Log( llInfo, Format( 'Application version %s taken from the binary; the .dproj says %s (build auto-increment moves it on after ' +
          'each build)', [ FileVersion, AProjectInfo.ProjectVersion ] ) );
    end;
  end;

  var Age: TDateTime;

  if FileAge( BinaryFile, Age ) then
    Log( llInfo, Format( 'Binary: %s, built %s', [ BinaryFile, FormatDateTime( 'yyyy"-"mm"-"dd hh":"nn', Age ) ] ) )
  else
    Log( llInfo, Format( 'Binary: %s', [ BinaryFile ] ) );

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

  // Step 4c: the deployable binary the application component describes (BSI TR-03183-2: filename and SHA-512)
  Result.Binary     := DescribeBinary( AOptions.BinaryFile, Result.ProjectInfo, AOptions.VersionOverride );

  // The application version: one given explicitly (--product-version, a git tag, the form's field), else the binary's
  // own, which BSI TR-03183-2 asks to be kept as its creator set it, else the .dproj's
  var Version       := AOptions.VersionOverride;

  if Version = '' then
    Version         := Result.Binary.FileVersion;

  // Step 5: Build and save SBOM
  var Builder       := TSBOMBuilder.Create( FLog );
  try
    Builder.Binary  := Result.Binary;
    Result.OutputFile := Builder.BuildAndSave(
      Result.ProjectInfo,
      Result.ClassifiedUnits,
      Result.Manifest,
      Version,
      AOptions.OutputDir,
      Result.Evidence,
      Result.LibraryDependencies
      );
  finally
    Builder.Free;
  end;

  Result.ProductVersion := EffectiveProductVersion( Version, Result.ProjectInfo.ProjectVersion );

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

  // Step 5a': conformance to BSI TR-03183-2 v2.1.0.  Mostly a matter of the manifest's data, so it is advice: the
  // command line's --fail-on-tr turns it into a failure
  Result.TRFindings := CheckTR03183( ReadTextFile( Result.OutputFile ) );

  if Length( Result.TRFindings ) = 0 then
    Log( llInfo, 'BSI TR-03183-2 v2.1.0: every required data field is present' )
  else
  begin
    for var F in Result.TRFindings do
      Log( llWarning, 'BSI TR-03183-2: ' + F );

    // No conditional expression: the language floor is Delphi 10.3
    var Noun        := 'requirements';

    if Length( Result.TRFindings ) = 1 then
      Noun          := 'requirement';

    Log( llWarning, Format( 'BSI TR-03183-2 v2.1.0: %d %s not met (rule IDs above)', [ Length( Result.TRFindings ), Noun ] ) );
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

