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
      FRootSources  : TObjectDictionary<string, TDictionary<string, string>>; // library root → .pas file name → path
      FScanRoots    : TArray<string>;

    procedure BuildMacroTable( const ADelphiPath, ABDSVersion, APlatform: string );
    function ExpandMacros( const AValue: string ): string;
    function BuildUnitFileIndex( const ASearchPaths: TArray<string>; ACompilerPathCount: Integer;
      out AScanOrderStart: Integer ): TDictionary<string, TIndexEntry>;
    function FindUnitFile( const AUnitName: string; AIndex: TDictionary<string, TIndexEntry>; out AOrder: Integer ): string;
    function BuildDcuIndex( const ADirectories: TArray<string> ): TDictionary<string, string>;
    function FindDcuFile( const AUnitName: string; AIndex: TDictionary<string, string> ): string;
    function FindSourceUnderRoot( const ARoot, AUnitName: string ): string;
    function GetUnitNames( const ADirectory, AExtension: string ): TArray<string>;
    function GetCommonRootDirs: TArray<string>;
    function GetDelphiLibraryPaths( const ABDSVersion: string; const APlatform: string ): TArray<string>;
    function IsProjectDirectory( const ADirectory: string ): Boolean;
    function LooksLikeLibrary( const ADirectory: string ): Boolean;
    function IsGenericDirectoryName( const AName: string ): Boolean;
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

    /// <summary>
    ///   The folders whose top-level subfolders are scanned for .pas files after the project, search and
    ///   library paths: D:\ and the two Program Files folders by default. A .pas found only there is a
    ///   guess — the compiler never looks there — so it gives way to a .dcu on the search or library path.
    /// </summary>
    property ScanRoots: TArray<string> read FScanRoots write FScanRoots;
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
///   Returns the root of the library that owns a folder of compiled units, by walking up past
///   build-output folder names: platforms (Win64), configurations (Release), compiler versions
///   (37.0, D13, Delphi13, "Delphi 13 Florence", Studio37), and lib / library / packages / dcu / bin.
///   D:\Acme\37.0\Win64\Release gives D:\Acme.
///   Returns ADcuDirectory itself when every ancestor up to the root is such a name.
/// </summary>
/// <param name="ADcuDirectory">A folder containing .dcu files.</param>
/// <returns>The library root folder.</returns>
function DcuLibraryRoot( const ADcuDirectory: string ): string;

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
  /// <summary>A company name: words ending in a legal-form suffix ("Digital Metaphors Corporation", "Acme GmbH").</summary>
  CompanyNamePattern = '^[A-Za-z][A-Za-z0-9&.,'' -]*\s(Corporation|Corp\.?|Incorporated|Inc\.?|Limited|Ltd\.?|LLC|GmbH|AG|' +
    'S\.r\.l\.?|S\.A\.?|B\.V\.?)$';

  /// <summary>How many of a library's source files are read to vote on its vendor.</summary>
  MaxVendorFiles    = 200;

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
///   True for a folder name that build output is sorted into rather than a library's own name:
///   platforms, configurations, compiler versions and their code names, lib / dcu / bin folders.
/// </summary>
function IsBuildOutputFolderName( const AName: string ): Boolean;
begin

  Result            := TRegEx.IsMatch( AName,
    '^(win32|win64|release|debug|lib|libs|library|dcu|dcus|bin|obj|out|output|packages|package|' +
    'd\d+(_\d+)?|delphi\s*\d+(\.\d+)?(\s+[a-z]+)?|studio\s*\d+(\.\d+)?|bds\s*\d+(\.\d+)?|xe\d*|rx\d+|\d+(\.\d+)*|' +
    'rio|sydney|alexandria|athens|florence)$', [ roIgnoreCase ] );

end;

/// <summary>
///   True for a folder under the Delphi installation's own lib folder: its units are the RTL's (classified
///   by the RTL scan), never a library. Products installed elsewhere in the Delphi folder
///   ($(BDS)\RBuilder\Lib\Win64) are libraries like any other.
/// </summary>
function IsDelphiLibFolder( const ADirectory, ADelphiPath: string ): Boolean;
begin

  Result            := ( ADelphiPath <> '' ) and StartsText( IncludeTrailingPathDelimiter( TPath.Combine( ADelphiPath, 'lib' ) ),
    IncludeTrailingPathDelimiter( ADirectory ) );

end;

function DcuLibraryRoot( const ADcuDirectory: string ): string;
begin

  var Start         := ExcludeTrailingPathDelimiter( ADcuDirectory );
  Result            := Start;

  while IsBuildOutputFolderName( ExtractFileName( Result ) ) do
  begin
    // Never climb to a drive root: its other folders are unrelated libraries
    var Parent      := LibraryParentDirectory( Result );

    if Parent = '' then Exit( Start );

    Result          := Parent;
  end;

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
  FRootSources      := TObjectDictionary<string, TDictionary<string, string>>.Create( [ doOwnsValues ] );

  // D:\ top-level directories (a common location for Delphi libraries) and the Program Files folders
  FScanRoots        := [ 'D:\', 'C:\Program Files', 'C:\Program Files (x86)' ];

end;

destructor TLibraryDiscovery.Destroy;
begin

  FRootSources.Free;
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
  var DcuPaths      := TList<string>.Create; // The folders the compiler reads units from: search paths and library path
  try
    // The project directory first: the compiler always searches it, so a unit there needs no 'in' clause
    if ( AProjectDir <> '' ) and TDirectory.Exists( AProjectDir ) then
      AllPaths.Add( ExcludeTrailingPathDelimiter( AProjectDir ) );

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
        begin
          AllPaths.Add( Expanded );

          if ( not IsDelphiLibFolder( Expanded, ADelphiPath ) ) then
            DcuPaths.Add( Expanded );
        end
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
      begin
        AllPaths.Add( IP );

        if ( not IsDelphiLibFolder( IP, ADelphiPath ) ) then
          DcuPaths.Add( IP );
      end;

    // Common root directories — not where the compiler looks, so a .pas found only there is a guess
    var CompilerPathCount := AllPaths.Count;

    for var RD in GetCommonRootDirs do
      if ( not AllPaths.Contains( RD ) ) then
        AllPaths.Add( RD );

    Log( llInfo, Format( 'Searching %d directories for unclassified units...', [ AllPaths.Count ] ) );

    // Phase 1: Find .pas files for each unclassified unit, from a single index of the search tree
    var UnitToDir   := TDictionary<string, string>.Create; // unit name → directory (lower case)
    var UnitToActualDir := TDictionary<string, string>.Create; // unit name → directory as found on disk
    var UnitToDcuDir := TDictionary<string, string>.Create; // DCU-only unit → the folder holding its .dcu
    var ViaLibraryPath := TDictionary<string, Boolean>.Create; // Units reached through a DCU on the search or library path
    var ScanOrderStart: Integer;
    var FileIndex   := BuildUnitFileIndex( AllPaths.ToArray, CompilerPathCount, ScanOrderStart );
    var DcuIndex    := BuildDcuIndex( DcuPaths.ToArray );
    try
      var GuessesSkipped := 0;

      for var UnitName in AUnclassifiedUnits do
      begin
        var FoundOrder: Integer;
        var FoundFile := FindUnitFile( UnitName, FileIndex, FoundOrder );

        // Found only by scanning the drive, while the compiler reads its DCU from the search or library
        // path: the copy found is a stray (D:\USB Temp\daSQL.pas), so follow the DCU instead
        if ( FoundFile <> '' ) and ( FoundOrder >= ScanOrderStart ) and ( FindDcuFile( UnitName, DcuIndex ) <> '' ) then
        begin
          Inc( GuessesSkipped );
          FoundFile := '';
        end;

        if FoundFile <> '' then
        begin
          var Dir   := ExcludeTrailingPathDelimiter( ExtractFilePath( FoundFile ) );
          UnitToDir.AddOrSetValue( UnitName, LowerCase( Dir ) );
          UnitToActualDir.AddOrSetValue( UnitName, Dir );
        end;
      end;

      Log( llInfo, Format( 'Found .pas files for %d of %d unclassified units',
          [ UnitToDir.Count, Length( AUnclassifiedUnits ) ] ) );

      if GuessesSkipped > 0 then
        Log( llInfo, Format( '%d .pas files found only by the drive scan were passed over for the DCU on the search or library path',
            [ GuessesSkipped ] ) );

      // Phase 1b: a unit with no source on the search tree may be compiled from a DCU folder on the
      // library path. Its library is the folder above the build-output folders; its source, when the
      // library ships it, is somewhere under that root.
      var DcuFound  := 0;
      var DcuWithSource := 0;

      for var UnitName in AUnclassifiedUnits do
      begin
        var DcuFile := FindDcuFile( UnitName, DcuIndex );

        if DcuFile = '' then Continue;

        // Its DCU is where the compiler looks, however its source was found
        ViaLibraryPath.AddOrSetValue( UnitName, True );

        if UnitToDir.ContainsKey( UnitName ) then Continue;

        Inc( DcuFound );
        var DcuDir  := ExcludeTrailingPathDelimiter( ExtractFilePath( DcuFile ) );
        var Root    := DcuLibraryRoot( DcuDir );
        var Source  := FindSourceUnderRoot( Root, UnitName );

        if Source <> '' then
        begin
          Inc( DcuWithSource );
          var Dir   := ExcludeTrailingPathDelimiter( ExtractFilePath( Source ) );
          UnitToDir.AddOrSetValue( UnitName, LowerCase( Dir ) );
          UnitToActualDir.AddOrSetValue( UnitName, Dir );
        end
        else
        begin
          UnitToDir.AddOrSetValue( UnitName, LowerCase( Root ) );
          UnitToActualDir.AddOrSetValue( UnitName, Root );
          UnitToDcuDir.AddOrSetValue( UnitName, DcuDir );
        end;
      end;

      if DcuFound > 0 then
        Log( llInfo, Format( 'Found .dcu files for %d more units (%d with source under the library root, %d DCU only)',
            [ DcuFound, DcuWithSource, DcuFound - DcuWithSource ] ) );

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

            if UnitToActualDir.ContainsKey( FirstUnit ) then
              ActualDir := UnitToActualDir[ FirstUnit ];

            // The project's own directory — its units are own code
            if SameText( ExcludeTrailingPathDelimiter( ActualDir ),
              ExcludeTrailingPathDelimiter( AProjectDir ) ) then
            begin
              Log( llInfo, Format( 'Units in the project directory are own code: %s', [ ActualDir ] ) );
              OwnCodeList.AddRange( DirPair.Value );
              Continue;
            end;

            // A folder inside the project is own code unless it looks like a vendored library
            if StartsText( IncludeTrailingPathDelimiter( AProjectDir ), IncludeTrailingPathDelimiter( ActualDir ) ) and
              ( not LooksLikeLibrary( ActualDir ) ) then
            begin
              Log( llInfo, Format( 'Units in a project subfolder are own code: %s', [ ActualDir ] ) );
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

            // Skip directories that contain .dpr or .dproj files (other projects, not libraries) — unless the
            // compiler reaches the units through their DCUs on the library path: then the .dpr is the one that
            // builds them
            if IsProjectDirectory( ActualDir ) and ( not ViaLibraryPath.ContainsKey( FirstUnit ) ) then
            begin
              Log( llInfo, Format( 'Skipping project directory (contains .dpr): %s', [ ActualDir ] ) );
              Continue;
            end;

            Lib     := Default( TDiscoveredLibrary );
            Lib.Directory := ActualDir;
            Lib.Name := DetectLibraryName( ActualDir );
            Lib.Units := DirPair.Value.ToArray;
            Lib.Confirmed := False;

            // Binary-only when none of its units' source was found
            Lib.BinaryOnly := True;

            for var U in Lib.Units do
              if ( not UnitToDcuDir.ContainsKey( U ) ) then
                Lib.BinaryOnly := False;

            // Compute prefix from ALL units in the folder (the DCU folder for a binary-only library),
            // not just the unclassified ones
            var AllUnitNames: TArray<string>;

            if Lib.BinaryOnly then
              AllUnitNames := GetUnitNames( UnitToDcuDir[ FirstUnit ], '.dcu' )
            else
              AllUnitNames := GetUnitNames( ActualDir, '.pas' );

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

            if Lib.BinaryOnly then
              Log( llInfo, Format( 'Discovered library: %s (%d units, DCU only, dir: %s)',
                  [ Lib.Name, Length( Lib.Units ), Lib.Directory ] ) )
            else
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
                    Current.BinaryOnly := Current.BinaryOnly and Other.BinaryOnly;

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
      DcuIndex.Free;
      FileIndex.Free;
      UnitToDir.Free;
      UnitToActualDir.Free;
      UnitToDcuDir.Free;
      ViaLibraryPath.Free;
    end;

    AAutoOwnCodeUnits := OwnCodeList.ToArray;

    if OwnCodeList.Count > 0 then
      Log( llInfo, Format( 'Auto-detected %d own-code units', [ OwnCodeList.Count ] ) );
  finally
    DcuPaths.Free;
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
    'dev', 'bin', 'release', 'debug', 'pas', 'sources', 'windows', 'win32', 'win64', 'vcl', 'fmx'
    ];

  for var GN in GenericNames do
    if SameText( AName, GN ) then
      Exit( True );

  Result            := False;

end;

function TLibraryDiscovery.GetUnitNames( const ADirectory, AExtension: string ): TArray<string>;
begin

  Result            := nil;

  try
    var UnitFiles   := TDirectory.GetFiles( ADirectory, '*' + AExtension, TSearchOption.soTopDirectoryOnly );
    SetLength( Result, Length( UnitFiles ) );

    for var I := 0 to High( UnitFiles ) do
      Result[ I ]   := TPath.GetFileNameWithoutExtension( UnitFiles[ I ] );
  except
    on E: EInOutError do
      Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
  end;

end;

// ---------------------------------------------------------------------------
//  File search — one index over the search tree, built once per run
// ---------------------------------------------------------------------------

function TLibraryDiscovery.BuildUnitFileIndex( const ASearchPaths: TArray<string>; ACompilerPathCount: Integer;
  out AScanOrderStart: Integer ): TDictionary<string, TIndexEntry>;
begin

  var Index         := TDictionary<string, TIndexEntry>.Create;
  var Order         := 0;
  AScanOrderStart   := MaxInt;
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

    for var I := 0 to High( ASearchPaths ) do
    begin
      var SearchDir := ASearchPaths[ I ];

      // Entries from here on were found by the drive scan, not on a path the compiler searches
      if I = ACompilerPathCount then
        AScanOrderStart := Order;

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

function TLibraryDiscovery.FindUnitFile( const AUnitName: string; AIndex: TDictionary<string, TIndexEntry>; out AOrder: Integer ): string;
begin

  Result            := '';
  AOrder            := MaxInt;

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

  AOrder            := BestOrder;

end;

function TLibraryDiscovery.BuildDcuIndex( const ADirectories: TArray<string> ): TDictionary<string, string>;
begin

  // Only the folders themselves, as the compiler reads them: no parents or subfolders
  Result            := TDictionary<string, string>.Create;

  for var Dir in ADirectories do
    try
      for var DcuFile in TDirectory.GetFiles( Dir, '*.dcu', TSearchOption.soTopDirectoryOnly ) do
        Result.TryAdd( LowerCase( ExtractFileName( DcuFile ) ), DcuFile );
    except
      on EInOutError do
        ; // Access denied or vanished directory — nothing to index
      on EArgumentException do
        ; // Invalid characters in a configured path — nothing to index
    end;

  Log( llInfo, Format( 'Indexed %d .dcu files in %d search and library path folders', [ Result.Count, Length( ADirectories ) ] ) );

end;

function TLibraryDiscovery.FindDcuFile( const AUnitName: string; AIndex: TDictionary<string, string> ): string;
begin

  if AIndex.TryGetValue( LowerCase( AUnitName + '.dcu' ), Result ) then Exit;

  if ( not AIndex.TryGetValue( LowerCase( StripScopePrefix( AUnitName ) + '.dcu' ), Result ) ) then
    Result          := '';

end;

function TLibraryDiscovery.FindSourceUnderRoot( const ARoot, AUnitName: string ): string;
begin

  // Each root's tree is listed once per run, however many of its units are looked up
  var Sources: TDictionary<string, string>;
  var Key           := LowerCase( ARoot );

  if ( not FRootSources.TryGetValue( Key, Sources ) ) then
  begin
    Sources         := TDictionary<string, string>.Create;
    FRootSources.Add( Key, Sources );

    try
      for var PasFile in TDirectory.GetFiles( ARoot, '*.pas', TSearchOption.soAllDirectories ) do
        Sources.TryAdd( LowerCase( ExtractFileName( PasFile ) ), PasFile );
    except
      on E: EInOutError do
        Log( llWarning, Format( 'Could not search %s for source: %s', [ ARoot, E.Message ] ) );
      on E: EArgumentException do
        Log( llWarning, Format( 'Could not search %s for source: %s', [ ARoot, E.Message ] ) );
    end;
  end;

  if Sources.TryGetValue( LowerCase( AUnitName + '.pas' ), Result ) then Exit;

  if ( not Sources.TryGetValue( LowerCase( StripScopePrefix( AUnitName ) + '.pas' ), Result ) ) then
    Result          := '';

end;

function TLibraryDiscovery.GetCommonRootDirs: TArray<string>;
begin

  var Dirs          := TList<string>.Create;
  try
    for var RD in FScanRoots do
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

          // Skip design-time packages: the dcl prefix, or {$DESIGNONLY} whatever the name
          if DpkName.StartsWith( 'dcl', True ) then Continue;
          if Pos( '{$DESIGNONLY', UpperCase( ReadTextFileHead( DpkFile, 8192 ) ) ) > 0 then Continue;

          var CleanName := CleanPackageName( DpkName );

          if CleanName.Length >= 3 then
            Exit( CleanName );
        end;
    except
      on E: EInOutError do
        Log( llWarning, Format( 'Could not read directory %s: %s', [ SearchDir, E.Message ] ) );
      on E: EStreamError do
        Log( llWarning, Format( 'Could not read a package in %s: %s', [ SearchDir, E.Message ] ) );
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

  // The holder most files name wins, so one contributor's header does not name the whole library;
  // a tie goes to the name seen first
  var Votes         := TDictionary<string, Integer>.Create;
  var Spelling      := TDictionary<string, string>.Create;
  var Order         := TList<string>.Create;
  try
    try
      var Read      := 0;

      for var PasFile in TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly ) do
      begin
        if Read >= MaxVendorFiles then Break;

        Inc( Read );
        var Holder  := ExtractVendorFromFile( PasFile );

        if Holder = '' then Continue;

        var Key     := LowerCase( Holder );
        var Count   := 0;

        if ( not Votes.TryGetValue( Key, Count ) ) then
        begin
          Spelling.Add( Key, Holder );
          Order.Add( Key );
        end;

        Votes.AddOrSetValue( Key, Count + 1 );
      end;
    except
      on E: EInOutError do
        Log( llWarning, Format( 'Could not read directory %s: %s', [ ADirectory, E.Message ] ) );
    end;

    var Best        := 0;

    for var Key in Order do
      if Votes[ Key ] > Best then
      begin
        Best        := Votes[ Key ];
        Result      := Spelling[ Key ];
      end;
  finally
    Order.Free;
    Spelling.Free;
    Votes.Free;
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
  while ( Result.Length > 0 ) and ( CharInSet( Result[ Result.Length ], [ '.', ',', ';', ' ', '-' ] ) or ( Result[ Result.Length ] = #$2013 ) or
    ( ( Result[ Result.Length ] = ')' ) and ( CharCount( Result, ')' ) > CharCount( Result, '(' ) ) ) ) do
    Delete( Result, Result.Length, 1 );

  // Must contain a letter to be a name, and not be one letter repeated (ASCII-art lettering such as BBBBB)
  if ( Result.Length <= 2 ) or ( not TRegEx.IsMatch( Result, '[A-Za-z]' ) ) or
    TRegEx.IsMatch( StringReplace( Result, ' ', '', [ rfReplaceAll ] ), '^(.)\1+$' ) then
    Result          := '';

end;

function TLibraryDiscovery.ExtractVendorFromFile( const APasFile: string ): string;
begin

  Result            := '';

  try
    var Lines       := ReadTextFileHead( APasFile, 8192 ).Split( [ #10 ] );
    var Banner      := '';

    for var I := 0 to Min( 29, High( Lines ) ) do
    begin
      var Line      := Trim( Lines[ I ] );

      // "Copyright (c) YYYY Name", "COPYRIGHT YYYY Name", "Copyright:" with the holder on the next line, or
      // "© YYYY Name". The whole word, so the identifier FlblCopyRight is not a copyright line; and either
      // opening the comment or followed by (c), ©, a year or a colon, so the history line "Updated
      // copyright to say 2003" is not one either
      var Copyright := TRegEx.Match( Line, '^[\s{(*/\-|#;!]*copyright\b|\bcopyright\b(?=\s*(\(c\)|\x{00A9}|\d{4}|:))', [ roIgnoreCase ] );
      var Holder    := '';
      var Found     := Copyright.Success;

      if Found then
        Holder      := Copy( Line, Copyright.Index + Copyright.Length, Length( Line ) )
      else
      begin
        var SymbolPos := Pos( #$00A9, Line );
        Found       := SymbolPos > 0;

        if Found then
          Holder    := Copy( Line, SymbolPos + 1, Length( Line ) );
      end;

      if Found then
      begin
        // The holder ends at a wide gap: what follows is layout, such as the letters of an ASCII-art header
        Holder      := TRegEx.Replace( TrimLeft( Holder ), '\s{3,}.*$', '' );
        Result      := CleanCopyrightHolder( Holder );

        // "Copyright:" alone: the holder is on the next line
        if ( Result = '' ) and ( Trim( StringReplace( Holder, ':', '', [ ] ) ) = '' ) and ( I < High( Lines ) ) then
          Result    := CleanCopyrightHolder( TRegEx.Replace( Trim( Lines[ I + 1 ] ), '\s{3,}.*$', '' ) );

        // "Pierre le Riche, copyright 2004 - 2026": the holder before the word (the last segment, past any banner art)
        if ( Result = '' ) and Copyright.Success and ( Copyright.Index > 1 ) then
        begin
          var Before := TRegEx.Split( Trim( Copy( Line, 1, Copyright.Index - 1 ) ), '\s{3,}' );

          if Length( Before ) > 0 then
            Result  := CleanCopyrightHolder( TRegEx.Replace( Before[ High( Before ) ], '^[^A-Za-z]+|[\s,;:]+$', '' ) );
        end;
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

      // A company named on a banner line ("RRRRRR    Digital Metaphors Corporation    BB BB"), used when no
      // copyright line names a holder: banner headers put the name above a "Copyright (c) years" line
      if Banner = '' then
        for var Segment in TRegEx.Split( Line, '\s{3,}' ) do
        begin
          var Candidate := Trim( TRegEx.Replace( Segment, '^[^A-Za-z]+|[^A-Za-z.]+$', '' ) );

          if TRegEx.IsMatch( Candidate, CompanyNamePattern, [ roIgnoreCase ] ) then
          begin
            Banner  := Candidate;
            Break;
          end;
        end;
    end;

    Result          := Banner;
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

