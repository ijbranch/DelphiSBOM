(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uLibraryDiscovery.pas — Scans the file system to discover third-party libraries
  for unclassified units, extracting metadata from source headers and licence files.
*)
unit uLibraryDiscovery;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  uTypes;

type
  /// <summary>
  ///   Discovers third-party libraries by scanning the file system for
  ///   unclassified units' .pas files, grouping by directory, and extracting metadata.
  /// </summary>
  TLibraryDiscovery = class
  private
    type
      /// <summary>Where a .pas file was found, and the search order it was found in.</summary>
      TIndexEntry = record
        Path: string;
        Order: Integer;
      end;

    var
      FLog          : TProc<TLogLevel, string>;
      FMacros       : TDictionary<string, string>;

    procedure BuildMacroTable( const ADelphiPath, ABDSVersion, APlatform: string );
    function ExpandMacros( const AValue: string ): string;
    function BuildUnitFileIndex( const ASearchPaths: TArray<string> ): TDictionary<string, TIndexEntry>;
    function FindUnitFile( const AUnitName: string; AIndex: TDictionary<string, TIndexEntry> ): string;
    function GetCommonRootDirs: TArray<string>;
    function GetDelphiLibraryPaths( const ABDSVersion: string; const APlatform: string ): TArray<string>;
    function IsProjectDirectory( const ADirectory: string ): Boolean;
    function LooksLikeLibrary( const ADirectory: string ): Boolean;
    function IsGenericDirectoryName( const AName: string ): Boolean;
    function GetAllPasUnitNames( const ADirectory: string ): TArray<string>;
    function DetectLicence( const ADirectory: string; out ALicenceFile: string ): string;
    function DetectVendor( const ADirectory: string ): string;
    function DetectLibraryName( const ADirectory: string ): string;
    function DetectVersion( const ADirectory: string ): string;
    function ComputePrefix( const AUnitNames: TArray<string> ): string;
    function MapLicenceText( const AText: string ): string;
    function ExtractVendorFromFile( const APasFile: string ): string;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );
    destructor Destroy; override;

    /// <summary>
    ///   Discovers libraries for unclassified units.
    ///   Searches project search paths, the IDE library path, and common root directories.
    /// </summary>
    /// <param name="AUnclassifiedUnits">Unit names that no manifest rule classified.</param>
    /// <param name="ASearchPaths">The project's evaluated DCC_UnitSearchPath entries.</param>
    /// <param name="AProjectDir">The project directory.</param>
    /// <param name="ADelphiPath">Resolved Delphi root directory (may be empty).</param>
    /// <param name="ABDSVersion">BDS version of that installation, e.g. '37.0' (may be empty).</param>
    /// <param name="APlatform">Target platform, e.g. 'Win64'.</param>
    /// <param name="AAutoOwnCodeUnits">Units found in the project directory or in sibling own-code directories.</param>
    /// <returns>The libraries found, with nested directories merged.</returns>
    function Discover( const AUnclassifiedUnits: TArray<string>;
      const ASearchPaths: TArray<string>;
      const AProjectDir: string;
      const ADelphiPath: string;
      const ABDSVersion: string;
      const APlatform: string;
      out AAutoOwnCodeUnits: TArray<string> ): TArray<TDiscoveredLibrary>;
  end;

/// <summary>
///   Returns the parent of a library directory when it may be searched for the library's package
///   (.dpk) files, or '' when there is none or it is a drive or share root: a root holds unrelated
///   checkouts, whose packages would otherwise name the library (E:\EurekaLog taking its name from
///   E:\ElevateDB\rbEDB2337.dpk).
/// </summary>
/// <param name="ADirectory">The library directory.</param>
/// <returns>The parent directory, or '' when it must not be searched.</returns>
function LibraryParentDirectory( const ADirectory: string ): string;

/// <summary>
///   Cleans the text that follows a copyright marker down to the holder's name:
///   strips (c) / copyright signs, years and year ranges, "by", comment closers,
///   "All rights reserved" and surrounding punctuation.
/// </summary>
/// <param name="AText">The text after "Copyright" or the copyright sign.</param>
/// <returns>The holder's name, or '' when what remains is not a name.</returns>
function CleanCopyrightHolder( const AText: string ): string;

implementation

uses
  System.IOUtils, System.StrUtils, System.Math, System.RegularExpressions, System.Generics.Defaults,
  System.Win.Registry, Winapi.Windows,
  uTextFiles;

const
  /// <summary>Licence file names looked for in a library directory.</summary>
  LicenceFileNames  : array[ 0..7 ] of string = (
    'LICENSE', 'LICENSE.txt', 'LICENSE.md',
    'LICENCE', 'LICENCE.txt', 'LICENCE.md',
    'COPYING', 'COPYING.txt'
    );

/// <summary>
///   Returns the parent of a directory, or '' for a drive root. Unlike ExtractFilePath on
///   'D:\X', this returns 'D:\' rather than the drive-relative 'D:'.
/// </summary>
function ParentDirectory( const ADirectory: string ): string;
begin

  var Trimmed       := ExcludeTrailingPathDelimiter( ADirectory );
  Result            := TPath.GetDirectoryName( Trimmed );

  if SameText( IncludeTrailingPathDelimiter( Result ), IncludeTrailingPathDelimiter( Trimmed ) ) then
    Result          := '';

end;

function LibraryParentDirectory( const ADirectory: string ): string;
begin

  Result            := ParentDirectory( ADirectory );

  if ( Result <> '' ) and SameText( IncludeTrailingPathDelimiter( TPath.GetPathRoot( Result ) ), IncludeTrailingPathDelimiter( Result ) ) then
    Result          := '';

end;

/// <summary>
///   Strips Delphi-version and numeric suffixes from a package name
///   (StyledComponentsD13 → StyledComponents, EurekaLogCore50 → EurekaLogCore).
/// </summary>
function CleanPackageName( const ADpkName: string ): string;
begin

  Result            := ADpkName;

  // Strip trailing Delphi version suffix like D13, D12, D10_4
  var DPos          := 0;

  for var C := Result.Length downto 1 do
    if CharInSet( Result[ C ], [ 'D', 'd' ] ) then
    begin
      var Suffix    := Copy( Result, C + 1, Length( Result ) );
      var IsVersionSuffix := ( Suffix.Length > 0 );

      for var SC in Suffix do
        if ( not CharInSet( SC, [ '0'..'9', '_' ] ) ) then
        begin
          IsVersionSuffix := False;
          Break;
        end;

      if IsVersionSuffix then
      begin
        DPos        := C;
        Break;
      end;
    end;

  if DPos > 1 then
    Result          := Copy( Result, 1, DPos - 1 );

  // Strip trailing version numbers and a trailing underscore
  while ( Result.Length > 0 ) and CharInSet( Result[ Result.Length ], [ '0'..'9' ] ) do
    Delete( Result, Result.Length, 1 );

  if Result.EndsWith( '_' ) then
    Delete( Result, Result.Length, 1 );

end;

{ TLibraryDiscovery }

constructor TLibraryDiscovery.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;
  FMacros           := TDictionary<string, string>.Create( TIStringComparer.Ordinal );

end;

destructor TLibraryDiscovery.Destroy;
begin

  FMacros.Free;
  inherited;

end;

procedure TLibraryDiscovery.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TLibraryDiscovery.Discover( const AUnclassifiedUnits: TArray<string>;
  const ASearchPaths: TArray<string>;
  const AProjectDir: string;
  const ADelphiPath: string;
  const ABDSVersion: string;
  const APlatform: string;
  out AAutoOwnCodeUnits: TArray<string> ): TArray<TDiscoveredLibrary>;
begin

  AAutoOwnCodeUnits := nil;
  Result            := nil;

  BuildMacroTable( ADelphiPath, ABDSVersion, APlatform );

  var OwnCodeList   := TList<string>.Create;
  var AllPaths      := TList<string>.Create;
  try
    // Project search paths, resolved against the project directory
    for var P in ASearchPaths do
    begin
      try
        var Expanded := ExpandMacros( P );

        if Expanded.Contains( '$(' ) then
        begin
          Log( llWarning, Format( 'Skipping search path with unresolved macro: %s', [ P ] ) );
          Continue;
        end;

        if ( not TPath.IsPathRooted( Expanded ) ) and ( AProjectDir <> '' ) then
          Expanded  := TPath.GetFullPath( TPath.Combine( AProjectDir, Expanded ) );

        if TDirectory.Exists( Expanded ) then
          AllPaths.Add( Expanded )
        else
          Log( llInfo, Format( 'Search path not found, skipped: %s', [ Expanded ] ) );
      except
        on E: EArgumentException do
          Log( llWarning, Format( 'Skipping invalid search path "%s": %s', [ P, E.Message ] ) );
      end;
    end;

    // Delphi IDE library paths from the registry
    for var IP in GetDelphiLibraryPaths( ABDSVersion, APlatform ) do
      if ( not AllPaths.Contains( IP ) ) and TDirectory.Exists( IP ) then
        AllPaths.Add( IP );

    // Common root directories
    for var RD in GetCommonRootDirs do
      if ( not AllPaths.Contains( RD ) ) then
        AllPaths.Add( RD );

    Log( llInfo, Format( 'Searching %d directories for unclassified units...', [ AllPaths.Count ] ) );

    // Phase 1: Find .pas files for each unclassified unit, from a single index of the search tree
    var UnitToDir   := TDictionary<string, string>.Create; // unit name → directory (lower case)
    var UnitToFile  := TDictionary<string, string>.Create; // unit name → full .pas path
    var FileIndex   := BuildUnitFileIndex( AllPaths.ToArray );
    try
      for var UnitName in AUnclassifiedUnits do
      begin
        var FoundFile := FindUnitFile( UnitName, FileIndex );

        if FoundFile <> '' then
        begin
          var Dir   := LowerCase( ExcludeTrailingPathDelimiter( ExtractFilePath( FoundFile ) ) );
          UnitToDir.AddOrSetValue( UnitName, Dir );
          UnitToFile.AddOrSetValue( UnitName, FoundFile );
        end;
      end;

      Log( llInfo, Format( 'Found .pas files for %d of %d unclassified units',
          [ UnitToDir.Count, Length( AUnclassifiedUnits ) ] ) );

      // Phase 2: Group units by directory
      var DirToUnits := TDictionary<string, TList<string>>.Create;
      try
        for var Pair in UnitToDir do
        begin
          if ( not DirToUnits.ContainsKey( Pair.Value ) ) then
            DirToUnits.Add( Pair.Value, TList<string>.Create );

          DirToUnits[ Pair.Value ].Add( Pair.Key );
        end;

        // The sibling rule only applies when the project's parent is a real folder, not a drive root
        var ProjectParent := ParentDirectory( AProjectDir );
        var ParentIsRoot := ( ProjectParent = '' ) or ( ParentDirectory( ProjectParent ) = '' );

        // Phase 3: Build discovered library records
        var Libraries := TList<TDiscoveredLibrary>.Create;
        try
          for var DirPair in DirToUnits do
          begin
            var Lib: TDiscoveredLibrary;
            var ActualDir := DirPair.Key;

            // Use the original case from the first file found
            var FirstUnit := DirPair.Value[ 0 ];

            if UnitToFile.ContainsKey( FirstUnit ) then
              ActualDir := ExcludeTrailingPathDelimiter( ExtractFilePath( UnitToFile[ FirstUnit ] ) );

            // The project's own directory — its units are own code
            if SameText( ExcludeTrailingPathDelimiter( ActualDir ),
              ExcludeTrailingPathDelimiter( AProjectDir ) ) then
            begin
              Log( llInfo, Format( 'Units in the project directory are own code: %s', [ ActualDir ] ) );
              OwnCodeList.AddRange( DirPair.Value );
              Continue;
            end;

            // A sibling of the project directory is treated as related own code only when it does not
            // look like a library (no licence file, no .dpk). Libraries checked out beside the project
            // (C:\Dev\MyApp + C:\Dev\Indy) stay third-party.
            if ( not ParentIsRoot ) and SameText( ProjectParent, ParentDirectory( ActualDir ) ) and
              ( not LooksLikeLibrary( ActualDir ) ) then
            begin
              Log( llInfo, Format( 'Auto-marking %d units from sibling directory as own code (no licence file or package found): %s',
                  [ DirPair.Value.Count, ActualDir ] ) );
              OwnCodeList.AddRange( DirPair.Value );
              Continue;
            end;

            // Skip directories that contain .dpr or .dproj files (other projects, not libraries)
            if IsProjectDirectory( ActualDir ) then
            begin
              Log( llInfo, Format( 'Skipping project directory (contains .dpr): %s', [ ActualDir ] ) );
              Continue;
            end;

            Lib     := Default( TDiscoveredLibrary );
            Lib.Directory := ActualDir;
            Lib.Name := DetectLibraryName( ActualDir );
            Lib.Units := DirPair.Value.ToArray;
            Lib.Confirmed := False;

            // Compute prefix from ALL .pas files in the directory, not just unclassified ones
            var AllUnitNames := GetAllPasUnitNames( ActualDir );

            if Length( AllUnitNames ) > 0 then
              Lib.SuggestedPrefix := ComputePrefix( AllUnitNames )
            else
              Lib.SuggestedPrefix := ComputePrefix( Lib.Units );

            // Detect metadata
            var LicFile := '';
            Lib.Licence := DetectLicence( ActualDir, LicFile );
            Lib.LicenceFile := LicFile;
            Lib.Version := DetectVersion( ActualDir );
            Lib.Vendor := DetectVendor( ActualDir );

            Log( llInfo, Format( 'Discovered library: %s (%d units, dir: %s)',
                [ Lib.Name, Length( Lib.Units ), Lib.Directory ] ) );

            Libraries.Add( Lib );
          end;

          // Post-process: merge libraries whose directories are nested
          var Merged := TList<TDiscoveredLibrary>.Create;
          try
            var MergedFlags := TList<Boolean>.Create;
            try
              for var X := 0 to Libraries.Count - 1 do
                MergedFlags.Add( False );

              for var X := 0 to Libraries.Count - 1 do
              begin
                if MergedFlags[ X ] then Continue;

                var Current := Libraries[ X ];

                // Check if any other library is a subdirectory of this one or vice versa
                for var Y := X + 1 to Libraries.Count - 1 do
                begin
                  if MergedFlags[ Y ] then Continue;

                  var Other := Libraries[ Y ];
                  var CurrentDir := LowerCase( IncludeTrailingPathDelimiter( Current.Directory ) );
                  var OtherDir := LowerCase( IncludeTrailingPathDelimiter( Other.Directory ) );

                  if OtherDir.StartsWith( CurrentDir ) or CurrentDir.StartsWith( OtherDir ) then
                  begin
                    // Merge Other into Current
                    Current.Units := Current.Units + Other.Units;

                    // Use the parent (outer) directory
                    if CurrentDir.StartsWith( OtherDir ) then
                    begin
                      Current.Directory := Other.Directory;
                      Current.Name := DetectLibraryName( Other.Directory );
                    end
                    else
                      Current.Name := DetectLibraryName( Current.Directory );

                    // Keep the richer metadata
                    if ( Current.Vendor = '' ) and ( Other.Vendor <> '' ) then
                      Current.Vendor := Other.Vendor;

                    if ( Current.Licence = '' ) and ( Other.Licence <> '' ) then
                    begin
                      Current.Licence := Other.Licence;
                      Current.LicenceFile := Other.LicenceFile;
                    end;

                    if ( Current.Version = '' ) and ( Other.Version <> '' ) then
                      Current.Version := Other.Version;

                    // Recompute prefix
                    Current.SuggestedPrefix := ComputePrefix( Current.Units );

                    MergedFlags[ Y ] := True;

                    Log( llInfo, Format( 'Merged library "%s" into "%s"', [ Other.Name, Current.Name ] ) );
                  end;
                end;

                Merged.Add( Current );
              end;
            finally
              MergedFlags.Free;
            end;

            Result  := Merged.ToArray;
          finally
            Merged.Free;
          end;
        finally
          Libraries.Free;
        end;
      finally
        for var UnitList in DirToUnits.Values do
          UnitList.Free;

        DirToUnits.Free;
      end;
    finally
      FileIndex.Free;
      UnitToDir.Free;
      UnitToFile.Free;
    end;

    AAutoOwnCodeUnits := OwnCodeList.ToArray;

    if OwnCodeList.Count > 0 then
      Log( llInfo, Format( 'Auto-detected %d own-code units', [ OwnCodeList.Count ] ) );
  finally
    AllPaths.Free;
    OwnCodeList.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  Macro expansion — $(BDS), $(BDSCOMMONDIR), IDE environment variables, etc.
// ---------------------------------------------------------------------------

procedure TLibraryDiscovery.BuildMacroTable( const ADelphiPath, ABDSVersion, APlatform: string );
begin

  FMacros.Clear;

  var Platform      := APlatform;

  if Platform = '' then
    Platform        := 'Win64';

  FMacros.AddOrSetValue( 'Platform', Platform );
  FMacros.AddOrSetValue( 'Config', 'Release' );

  if ADelphiPath <> '' then
  begin
    FMacros.AddOrSetValue( 'BDS', ADelphiPath );
    FMacros.AddOrSetValue( 'BDSLIB', TPath.Combine( ADelphiPath, 'lib' ) );
    FMacros.AddOrSetValue( 'BDSBIN', TPath.Combine( ADelphiPath, 'bin' ) );
    FMacros.AddOrSetValue( 'BDSINCLUDE', TPath.Combine( ADelphiPath, 'include' ) );
  end;

  if ABDSVersion <> '' then
  begin
    var PublicStudio := TPath.Combine( GetEnvironmentVariable( 'PUBLIC' ), 'Documents\Embarcadero\Studio\' + ABDSVersion );
    var UserStudio  := TPath.Combine( TPath.GetDocumentsPath, 'Embarcadero\Studio\' + ABDSVersion );

    FMacros.AddOrSetValue( 'BDSCOMMONDIR', PublicStudio );
    FMacros.AddOrSetValue( 'BDSUSERDIR', UserStudio );
    FMacros.AddOrSetValue( 'BDSCatalogRepository', TPath.Combine( UserStudio, 'CatalogRepository' ) );
    FMacros.AddOrSetValue( 'BDSCatalogRepositoryAllUsers', TPath.Combine( PublicStudio, 'CatalogRepository' ) );

    // IDE-level environment variable overrides (Tools > Options > Environment Variables)
    var Reg         := TRegistry.Create( KEY_READ );
    try
      Reg.RootKey   := HKEY_CURRENT_USER;

      if Reg.OpenKeyReadOnly( Format( 'Software\Embarcadero\BDS\%s\Environment Variables', [ ABDSVersion ] ) ) then
      begin
        var ValueNames := TStringList.Create;
        try
          Reg.GetValueNames( ValueNames );

          for var VN in ValueNames do
            FMacros.AddOrSetValue( VN, Reg.ReadString( VN ) );

          Log( llInfo, Format( 'Loaded %d IDE environment variables', [ ValueNames.Count ] ) );
        finally
          ValueNames.Free;
        end;

        Reg.CloseKey;
      end;
    finally
      Reg.Free;
    end;
  end;

end;

function TLibraryDiscovery.ExpandMacros( const AValue: string ): string;
begin

  Result            := AValue;

  // Repeat so a macro whose value contains another macro ($(InterBase) = $(BDS)\...) resolves fully
  for var Pass := 1 to 4 do
  begin
    if ( not Result.Contains( '$(' ) ) then Break;

    Result          := ExpandMacroReferences( Result,
      function( AName: string ): string
      begin
        if FMacros.TryGetValue( AName, Result ) then Exit;

        Result      := GetEnvironmentVariable( AName );

        if Result = '' then
          Result    := '$(' + AName + ')';
      end );
  end;

end;

// ---------------------------------------------------------------------------
//  Delphi IDE library paths from registry
// ---------------------------------------------------------------------------

function TLibraryDiscovery.GetDelphiLibraryPaths( const ABDSVersion: string; const APlatform: string ): TArray<string>;
begin

  Result            := nil;

  if ABDSVersion = '' then Exit;

  var Platform      := APlatform;

  if Platform = '' then
    Platform        := 'Win64';

  var Reg           := TRegistry.Create( KEY_READ );
  try
    Reg.RootKey     := HKEY_CURRENT_USER;

    if ( not Reg.OpenKeyReadOnly( Format( 'Software\Embarcadero\BDS\%s\Library\%s', [ ABDSVersion, Platform ] ) ) ) then Exit;

    try
      if ( not Reg.ValueExists( 'Search Path' ) ) then Exit;

      var Paths     := TList<string>.Create;
      try
        for var P in Reg.ReadString( 'Search Path' ).Split( [ ';' ] ) do
        begin
          var Trimmed := Trim( ExpandMacros( Trim( P ) ) );

          if Trimmed = '' then Continue;

          if Trimmed.Contains( '$(' ) then
            Log( llWarning, Format( 'Skipping unresolved library path: %s', [ Trimmed ] ) )
          else
            Paths.Add( Trimmed );
        end;

        Result      := Paths.ToArray;
        Log( llInfo, Format( 'Found %d Delphi IDE library paths (BDS %s, %s)', [ Length( Result ), ABDSVersion, Platform ] ) );
      finally
        Paths.Free;
      end;
    finally
      Reg.CloseKey;
    end;
  finally
    Reg.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  Directory classification helpers
// ---------------------------------------------------------------------------

function TLibraryDiscovery.IsProjectDirectory( const ADirectory: string ): Boolean;
begin

  Result            := False;

  try
    // If the directory contains .dpk files, it's a library (packages = library distribution)
    // even if it also has .dpr files (demos, tests, examples)
    var DpkFiles    := TDirectory.GetFiles( ADirectory, '*.dpk', TSearchOption.soTopDirectoryOnly );

    if Length( DpkFiles ) > 0 then
      Exit( False );

    // Check for .dpr files — indicates a standalone project, not a library
    var DprFiles    := TDirectory.GetFiles( ADirectory, '*.dpr', TSearchOption.soTopDirectoryOnly );

    if Length( DprFiles ) > 0 then
    begin
      // Additional check: if there are many .pas files (10+) alongside the .dpr,
      // it's likely a library with a demo/test project, not a standalone app
      var PasFiles  := TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly );

      if Length( PasFiles ) >= 10 then
        Exit( False );

      Exit( True );
    end;
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
  end;

end;

function TLibraryDiscovery.LooksLikeLibrary( const ADirectory: string ): Boolean;
begin

  // A licence file, or a package (.dpk) in the directory, its parent (unless a root), or a subdirectory
  var LicFile       := '';
  DetectLicence( ADirectory, LicFile );

  if LicFile <> '' then Exit( True );

  try
    var Candidates: TArray<string> := [ ADirectory ];
    var Parent      := LibraryParentDirectory( ADirectory );

    if Parent <> '' then
      Candidates    := Candidates + [ Parent ];

    Candidates      := Candidates + TDirectory.GetDirectories( ADirectory );

    for var Dir in Candidates do
      if Length( TDirectory.GetFiles( Dir, '*.dpk', TSearchOption.soTopDirectoryOnly ) ) > 0 then
        Exit( True );
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
  end;

  Result            := False;

end;

function TLibraryDiscovery.IsGenericDirectoryName( const AName: string ): Boolean;
begin

  var GenericNames: TArray<string> := [
    'source', 'src', 'lib', 'code', 'extras', 'delphi', 'pascal',
    'common', 'shared', 'include', 'units', 'packages', 'components',
    'dev', 'bin', 'release', 'debug', 'pas'
    ];

  for var GN in GenericNames do
    if SameText( AName, GN ) then
      Exit( True );

  Result            := False;

end;

function TLibraryDiscovery.GetAllPasUnitNames( const ADirectory: string ): TArray<string>;
begin

  Result            := nil;

  try
    var PasFiles    := TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly );
    SetLength( Result, Length( PasFiles ) );

    for var I := 0 to High( PasFiles ) do
      Result[ I ]   := TPath.GetFileNameWithoutExtension( PasFiles[ I ] );
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
  end;

end;

// ---------------------------------------------------------------------------
//  File search — one index over the search tree, built once per run
// ---------------------------------------------------------------------------

function TLibraryDiscovery.BuildUnitFileIndex( const ASearchPaths: TArray<string> ): TDictionary<string, TIndexEntry>;
begin

  var Index         := TDictionary<string, TIndexEntry>.Create;
  var Order         := 0;
  var Visited       := TDictionary<string, Boolean>.Create;
  try
    // Each search directory, then its parent, then one level of subdirectories — the same
    // order the per-unit search used, so the first location found still wins
    var AddDirectory :=
      procedure( const ADir: string )
      begin
        var Key     := LowerCase( ExcludeTrailingPathDelimiter( ADir ) );

        if ( ADir = '' ) or Visited.ContainsKey( Key ) then Exit;

        Visited.Add( Key, True );

        try
          for var PasFile in TDirectory.GetFiles( ADir, '*.pas', TSearchOption.soTopDirectoryOnly ) do
          begin
            var FileKey := LowerCase( ExtractFileName( PasFile ) );

            if ( not Index.ContainsKey( FileKey ) ) then
            begin
              var Entry: TIndexEntry;
              Entry.Path := PasFile;
              Entry.Order := Order;
              Index.Add( FileKey, Entry );
            end;
          end;
        except
          on EInOutError do
            ; // Access denied or vanished directory — nothing to index
          on EArgumentException do
            ; // Invalid characters in a configured path — nothing to index
        end;

        Inc( Order );
      end;

    for var SearchDir in ASearchPaths do
    begin
      AddDirectory( SearchDir );
      AddDirectory( ParentDirectory( SearchDir ) );

      try
        for var SubDir in TDirectory.GetDirectories( SearchDir ) do
          AddDirectory( SubDir );
      except
        on EInOutError do
          ; // Access denied — skip this directory's children
        on EArgumentException do
          ; // Invalid characters in a configured path
      end;
    end;
  finally
    Visited.Free;
  end;

  Result            := Index;
  Log( llInfo, Format( 'Indexed %d .pas files', [ Result.Count ] ) );

end;

function TLibraryDiscovery.FindUnitFile( const AUnitName: string; AIndex: TDictionary<string, TIndexEntry> ): string;
begin

  Result            := '';

  // Try both the original name (Vcl.StyledTaskDialog.pas) and the scope-stripped name (StyledTaskDialog.pas);
  // when both exist, the one found earlier in the search order wins
  var BestOrder     := MaxInt;
  var Candidates: TArray<string> := [ AUnitName ];
  var StrippedName  := StripScopePrefix( AUnitName );

  if StrippedName <> AUnitName then
    Candidates      := Candidates + [ StrippedName ];

  for var Candidate in Candidates do
  begin
    var Entry: TIndexEntry;

    if AIndex.TryGetValue( LowerCase( Candidate + '.pas' ), Entry ) and ( Entry.Order < BestOrder ) then
    begin
      BestOrder     := Entry.Order;
      Result        := Entry.Path;
    end;
  end;

end;

function TLibraryDiscovery.GetCommonRootDirs: TArray<string>;
begin

  var Dirs          := TList<string>.Create;
  try
    // D:\ top-level directories (a common location for Delphi libraries) and the Program Files folders
    var RootDirs: TArray<string> := [
      'D:\',
      'C:\Program Files',
      'C:\Program Files (x86)'
      ];

    for var RD in RootDirs do
    begin
      if ( not TDirectory.Exists( RD ) ) then Continue;

      try
        Dirs.AddRange( TDirectory.GetDirectories( RD ) );
      except
        on E: EInOutError do
          Log( llWarning, Format( 'Could not read directory %s: %s', [ RD, E.Message ] ) );
      end;
    end;

    Result          := Dirs.ToArray;
  finally
    Dirs.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  Library name detection from .dpk files
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectLibraryName( const ADirectory: string ): string;
begin

  // Strategy 1: Find a .dpk file in this directory or nearby and use its name
  var SearchDirs: TArray<string> := [ ADirectory ];

  // Also check the parent and a sibling Packages directory (common pattern), unless the parent is a root
  var ParentDir     := LibraryParentDirectory( ADirectory );

  if ParentDir <> '' then
  begin
    SearchDirs      := SearchDirs + [ ParentDir ];

    var PackagesDir := TPath.Combine( ParentDir, 'Packages' );

    if TDirectory.Exists( PackagesDir ) then
      SearchDirs    := SearchDirs + [ PackagesDir ];
  end;

  for var SearchDir in SearchDirs do
  begin
    try
      // This directory first, then one level of subdirectories
      var Dirs: TArray<string> := [ SearchDir ];
      Dirs          := Dirs + TDirectory.GetDirectories( SearchDir );

      for var Dir in Dirs do
        for var DpkFile in TDirectory.GetFiles( Dir, '*.dpk', TSearchOption.soTopDirectoryOnly ) do
        begin
          var DpkName := TPath.GetFileNameWithoutExtension( DpkFile );

          // Skip design-time packages (dcl prefix)
          if DpkName.StartsWith( 'dcl', True ) then Continue;

          var CleanName := CleanPackageName( DpkName );

          if CleanName.Length >= 3 then
            Exit( CleanName );
        end;
    except
      on E: EInOutError do
        Log( llWarning, Format( 'Could not read directory %s: %s', [ SearchDir, E.Message ] ) );
    end;
  end;

  // Strategy 2: Use the nearest non-generic ancestor directory name
  var DirName       := ExtractFileName( ExcludeTrailingPathDelimiter( ADirectory ) );

  if ( not IsGenericDirectoryName( DirName ) ) then
    Exit( DirName );

  var Current       := ParentDirectory( ADirectory );

  while Current <> '' do
  begin
    var Name        := ExtractFileName( Current );

    if ( Name <> '' ) and ( not IsGenericDirectoryName( Name ) ) then
      Exit( Name );

    Current         := ParentDirectory( Current );
  end;

  // Fallback
  Result            := DirName;

end;

// ---------------------------------------------------------------------------
//  Licence detection
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectLicence( const ADirectory: string; out ALicenceFile: string ): string;
begin

  Result            := '';
  ALicenceFile      := '';

  // This directory first, then the parent (some libraries nest source in a subdirectory)
  var Dirs: TArray<string> := [ ADirectory ];
  var ParentDir     := ParentDirectory( ADirectory );

  if ParentDir <> '' then
    Dirs            := Dirs + [ ParentDir ];

  for var Dir in Dirs do
    for var LName in LicenceFileNames do
    begin
      var FullPath := TPath.Combine( Dir, LName );

      if ( not FileExists( FullPath ) ) then Continue;

      ALicenceFile  := FullPath;

      try
        // The first 50 lines carry the identifying text
        var Lines   := ReadTextFileHead( FullPath, 16384 ).Split( [ #10 ] );
        var Preview := '';

        for var I := 0 to Min( 49, High( Lines ) ) do
          Preview   := Preview + Trim( Lines[ I ] ) + ' ';

        Result      := MapLicenceText( Preview );
      except
        on E: EInOutError do
          Log( llWarning, Format( 'Could not read licence file %s: %s', [ FullPath, E.Message ] ) );
        on E: EStreamError do
          Log( llWarning, Format( 'Could not read licence file %s: %s', [ FullPath, E.Message ] ) );
      end;

      Exit;
    end;

end;

function TLibraryDiscovery.MapLicenceText( const AText: string ): string;
begin

  Result            := '';

  var Upper         := UpperCase( TRegEx.Replace( AText, '\s+', ' ' ) );

  // Most specific texts first: the Boost and MPL texts quote phrases other licences use
  if Pos( 'BOOST SOFTWARE LICENSE', Upper ) > 0 then
    Exit( 'BSL-1.0' );

  if Pos( 'MOZILLA PUBLIC LICENSE', Upper ) > 0 then
  begin
    if Pos( 'VERSION 2.0', Upper ) > 0 then
      Exit( 'MPL-2.0' )
    else if Pos( 'VERSION 1.1', Upper ) > 0 then
      Exit( 'MPL-1.1' )
    else if Pos( 'VERSION 1.0', Upper ) > 0 then
      Exit( 'MPL-1.0' );

    Exit;
  end;

  if ( Pos( 'APACHE LICENSE', Upper ) > 0 ) and ( Pos( 'VERSION 2.0', Upper ) > 0 ) then
    Exit( 'Apache-2.0' );

  if Pos( 'GNU LESSER GENERAL PUBLIC LICENSE', Upper ) > 0 then
  begin
    if Pos( 'VERSION 3', Upper ) > 0 then
      Exit( 'LGPL-3.0' )
    else if Pos( 'VERSION 2.1', Upper ) > 0 then
      Exit( 'LGPL-2.1' );

    Exit;
  end;

  if Pos( 'GNU GENERAL PUBLIC LICENSE', Upper ) > 0 then
  begin
    if Pos( 'VERSION 3', Upper ) > 0 then
      Exit( 'GPL-3.0' )
    else if Pos( 'VERSION 2', Upper ) > 0 then
      Exit( 'GPL-2.0' );

    Exit;
  end;

  if Pos( 'THIS IS FREE AND UNENCUMBERED SOFTWARE', Upper ) > 0 then
    Exit( 'Unlicense' );

  if ( Pos( 'MIT LICENSE', Upper ) > 0 ) or ( Pos( 'PERMISSION IS HEREBY GRANTED, FREE OF CHARGE, TO ANY PERSON OBTAINING A COPY', Upper ) > 0 ) then
    Exit( 'MIT' );

  if Pos( 'PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE', Upper ) > 0 then
    Exit( 'ISC' );

  if ( Pos( 'ALTERED SOURCE VERSIONS MUST BE PLAINLY MARKED', Upper ) > 0 ) then
    Exit( 'Zlib' );

  if Pos( 'REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS', Upper ) > 0 then
  begin
    if Pos( 'ADVERTISING MATERIALS', Upper ) > 0 then
      Exit( 'BSD-4-Clause' )
    else if Pos( 'NEITHER THE NAME', Upper ) > 0 then
      Exit( 'BSD-3-Clause' )
    else
      Exit( 'BSD-2-Clause' );
  end;

end;

// ---------------------------------------------------------------------------
//  Vendor/author detection from .pas header
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectVendor( const ADirectory: string ): string;
begin

  Result            := '';

  // Try multiple .pas files in the directory until we find vendor info
  try
    for var PasFile in TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly ) do
    begin
      Result        := ExtractVendorFromFile( PasFile );

      if Result <> '' then Exit;
    end;
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
  end;

end;

/// <summary>Counts the occurrences of a character in a string.</summary>
function CharCount( const AText: string; AChar: Char ): Integer;
begin

  Result            := 0;

  for var C in AText do
    if C = AChar then
      Inc( Result );

end;

function CleanCopyrightHolder( const AText: string ): string;
begin

  Result            := Trim( AText );

  // Leading markers and years, in any order: "(C) 2020-2026, ", "© 2020 ", ": "
  var Changed       := True;

  while Changed and ( Result <> '' ) do
  begin
    Changed         := False;

    if Result.StartsWith( '(c)', True ) then
    begin
      Result        := Trim( Result.Substring( 3 ) );
      Changed       := True;
    end
    else if CharInSet( Result[ 1 ], [ '0'..'9', '-', ',', ':', ' ' ] ) or ( Result[ 1 ] = #$00A9 ) or ( Result[ 1 ] = #$2013 ) then
    begin
      Result        := Trim( Result.Substring( 1 ) );
      Changed       := True;
    end;
  end;

  if Result.StartsWith( 'by ', True ) then
    Result          := Trim( Result.Substring( 3 ) );

  // Trailing comment markers and "All rights reserved"
  Result            := StringReplace( Result, '*)', '', [ rfReplaceAll ] );
  Result            := StringReplace( Result, '}', '', [ rfReplaceAll ] );

  var ArPos         := Pos( 'ALL RIGHTS', UpperCase( Result ) );

  if ArPos > 0 then
    Result          := Copy( Result, 1, ArPos - 1 );

  Result            := Trim( Result );

  // Surrounding parentheses and trailing punctuation
  if Result.StartsWith( '(' ) and Result.EndsWith( ')' ) then
    Result          := Copy( Result, 2, Result.Length - 2 )
  else if Result.StartsWith( '(' ) then
    Delete( Result, 1, 1 );

  Result            := Trim( Result );

  // A closing bracket goes only when unmatched: "Jane Doe (Acme Software)" keeps its own
  while ( Result.Length > 0 ) and ( CharInSet( Result[ Result.Length ], [ '.', ',', ';', ' ' ] ) or
    ( ( Result[ Result.Length ] = ')' ) and ( CharCount( Result, ')' ) > CharCount( Result, '(' ) ) ) ) do
    Delete( Result, Result.Length, 1 );

  // Must contain a letter to be a name
  if ( Result.Length <= 2 ) or ( not TRegEx.IsMatch( Result, '[A-Za-z]' ) ) then
    Result          := '';

end;

function TLibraryDiscovery.ExtractVendorFromFile( const APasFile: string ): string;
begin

  Result            := '';

  try
    var Lines       := ReadTextFileHead( APasFile, 8192 ).Split( [ #10 ] );

    for var I := 0 to Min( 29, High( Lines ) ) do
    begin
      var Line      := Trim( Lines[ I ] );

      // "Copyright (c) YYYY Name", "COPYRIGHT YYYY Name", or "© YYYY Name"
      var CopyrightPos := Pos( 'COPYRIGHT', UpperCase( Line ) );

      if CopyrightPos > 0 then
        Result      := CleanCopyrightHolder( Copy( Line, CopyrightPos + 9, Length( Line ) ) )
      else
      begin
        var SymbolPos := Pos( #$00A9, Line );

        if SymbolPos > 0 then
          Result    := CleanCopyrightHolder( Copy( Line, SymbolPos + 1, Length( Line ) ) );
      end;

      if Result <> '' then Exit;

      // "Author: Name"
      if Line.StartsWith( 'Author:', True ) then
      begin
        var After   := Trim( Copy( Line, Pos( ':', Line ) + 1, Length( Line ) ) );
        After       := StringReplace( After, '*)', '', [ ] );
        After       := Trim( StringReplace( After, '}', '', [ ] ) );

        if After.Length > 2 then
          Exit( After );
      end;
    end;
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read %s: %s', [ APasFile, E.Message ] ) );
    on E: EStreamError do
      Log( llWarning, Format( 'Could not read %s: %s', [ APasFile, E.Message ] ) );
  end;

end;

// ---------------------------------------------------------------------------
//  Version detection
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectVersion( const ADirectory: string ): string;
begin

  Result            := '';

  // A package's {$LIBVERSION '...'} directive, or a version number in its {$DESCRIPTION '...'}
  try
    for var DpkFile in TDirectory.GetFiles( ADirectory, '*.dpk', TSearchOption.soTopDirectoryOnly ) do
    begin
      var Content   := ReadTextFile( DpkFile );

      var LibVersion := TRegEx.Match( Content, '\{\$LIBVERSION\s+''([^'']+)''', [ roIgnoreCase ] );

      if LibVersion.Success then
        Exit( Trim( LibVersion.Groups[ 1 ].Value ) );

      var Description := TRegEx.Match( Content, '\{\$DESCRIPTION\s+''[^'']*?\bv?(\d+\.\d+(?:\.\d+){0,2})\b[^'']*''', [ roIgnoreCase ] );

      if Description.Success then
        Exit( Description.Groups[ 1 ].Value );
    end;
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read packages in %s: %s', [ ADirectory, E.Message ] ) );
    on E: EStreamError do
      Log( llWarning, Format( 'Could not read packages in %s: %s', [ ADirectory, E.Message ] ) );
  end;

end;

// ---------------------------------------------------------------------------
//  Common prefix computation
// ---------------------------------------------------------------------------

function TLibraryDiscovery.ComputePrefix( const AUnitNames: TArray<string> ): string;
begin

  Result            := '';

  if Length( AUnitNames ) = 0 then Exit;

  if Length( AUnitNames ) = 1 then
  begin
    // Single unit — use the full name as exact match, no prefix
    Result          := AUnitNames[ 0 ];
    Exit;
  end;

  // Find the longest common prefix of all unit names
  var First         := AUnitNames[ 0 ];

  for var CharIdx := 1 to First.Length do
  begin
    var AllMatch    := True;

    for var I := 1 to High( AUnitNames ) do
    begin
      if ( CharIdx > AUnitNames[ I ].Length ) or
        ( not SameText( First[ CharIdx ], AUnitNames[ I ][ CharIdx ] ) ) then
      begin
        AllMatch    := False;
        Break;
      end;
    end;

    if AllMatch then
      Result        := Copy( First, 1, CharIdx )
    else
      Break;
  end;

  // Ensure minimum prefix length
  if Result.Length < MinPrefixLength then
    Result          := '';

end;

end.

