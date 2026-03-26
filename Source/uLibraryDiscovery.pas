(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
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
    FLog: TProc<TLogLevel, string>;
    FFoundDirs: TDictionary<string, string>;  // directory → first unit found there

    function FindUnitFile( const AUnitName: string; const ASearchPaths: TArray<string> ): string;
    function GetCommonRootDirs: TArray<string>;
    function GetDelphiLibraryPaths( const ADelphiPath: string; const APlatform: string ): TArray<string>;
    function IsProjectDirectory( const ADirectory: string ): Boolean;
    function IsGenericDirectoryName( const AName: string ): Boolean;
    function GetAllPasUnitNames( const ADirectory: string ): TArray<string>;
    function DetectLicence( const ADirectory: string; out ALicenceFile: string ): string;
    function DetectVendor( const ADirectory: string ): string;
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
    ///   Searches project search paths and common root directories.
    /// </summary>
    function Discover( const AUnclassifiedUnits: TArray<string>;
      const ASearchPaths: TArray<string>;
      const AProjectDir: string;
      const ADelphiPath: string;
      const APlatform: string;
      out AAutoOwnCodeUnits: TArray<string> ): TArray<TDiscoveredLibrary>;
  end;

implementation

uses
  System.IOUtils, System.StrUtils, System.Math, System.Win.Registry, Winapi.Windows;

{ TLibraryDiscovery }

constructor TLibraryDiscovery.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;
  FFoundDirs := TDictionary<string, string>.Create;

end;

destructor TLibraryDiscovery.Destroy;
begin

  FFoundDirs.Free;
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
  const APlatform: string;
  out AAutoOwnCodeUnits: TArray<string> ): TArray<TDiscoveredLibrary>;
begin

  FFoundDirs.Clear;
  AAutoOwnCodeUnits := nil;

  var OwnCodeList := TList<string>.Create;

  // Build extended search paths: project search paths + common root dirs
  var AllPaths := TList<string>.Create;
  try
    for var P in ASearchPaths do
    begin
      var Expanded := P;

      // Resolve relative paths against the project directory
      if ( not TPath.IsPathRooted( Expanded ) ) and ( AProjectDir <> '' ) then
        Expanded := TPath.Combine( AProjectDir, Expanded );

      if TDirectory.Exists( Expanded ) then
        AllPaths.Add( Expanded );
    end;

    // Add Delphi IDE library paths from registry
    var IDEPaths := GetDelphiLibraryPaths( ADelphiPath, APlatform );

    for var IP in IDEPaths do
      if ( not AllPaths.Contains( IP ) ) and TDirectory.Exists( IP ) then
        AllPaths.Add( IP );

    // Add common root directories
    var RootDirs := GetCommonRootDirs;

    for var RD in RootDirs do
      if ( not AllPaths.Contains( RD ) ) then
        AllPaths.Add( RD );

    Log( llInfo, Format( 'Searching %d directories for unclassified units...', [ AllPaths.Count ] ) );

    // Phase 1: Find .pas files for each unclassified unit
    var UnitToDir := TDictionary<string, string>.Create;    // unit name → directory
    var UnitToFile := TDictionary<string, string>.Create;   // unit name → full .pas path
    try
      for var UnitName in AUnclassifiedUnits do
      begin
        var FoundFile := FindUnitFile( UnitName, AllPaths.ToArray );

        if FoundFile <> '' then
        begin
          var Dir := LowerCase( ExcludeTrailingPathDelimiter( ExtractFilePath( FoundFile ) ) );
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

            // Skip if this is the project's own directory — mark units as own code
            if SameText( ExcludeTrailingPathDelimiter( ActualDir ),
                         ExcludeTrailingPathDelimiter( AProjectDir ) ) then
            begin
              Log( llInfo, Format( 'Skipping project directory: %s', [ ActualDir ] ) );

              for var SkippedUnit in DirPair.Value do
                OwnCodeList.Add( SkippedUnit );

              Continue;
            end;

            // Skip directories that share the same parent as the project (related project code)
            var ProjectParent := ExcludeTrailingPathDelimiter( ExtractFilePath( ExcludeTrailingPathDelimiter( AProjectDir ) ) );
            var DirParent     := ExcludeTrailingPathDelimiter( ExtractFilePath( ExcludeTrailingPathDelimiter( ActualDir ) ) );

            if ( ProjectParent <> '' ) and SameText( ProjectParent, DirParent ) then
            begin
              Log( llInfo, Format( 'Auto-marking %d units from sibling directory as own code: %s',
                [ DirPair.Value.Count, ActualDir ] ) );

              for var SkippedUnit in DirPair.Value do
                OwnCodeList.Add( SkippedUnit );

              Continue;
            end;

            // Skip directories that contain .dpr or .dproj files (other projects, not libraries)
            if IsProjectDirectory( ActualDir ) then
            begin
              Log( llInfo, Format( 'Skipping project directory (contains .dpr): %s', [ ActualDir ] ) );
              Continue;
            end;

            Lib.Directory := ActualDir;

            // Use parent directory name if current name is generic
            var DirName := ExtractFileName( ActualDir );

            if IsGenericDirectoryName( DirName ) then
            begin
              var ParentPath := ExcludeTrailingPathDelimiter( ExtractFilePath( ExcludeTrailingPathDelimiter( ActualDir ) ) );
              var ParentName := ExtractFileName( ParentPath );

              if ( ParentName <> '' ) and ( not IsGenericDirectoryName( ParentName ) ) then
                Lib.Name := ParentName + ' - ' + DirName
              else
              begin
                // Go up one more level
                var GrandParentPath := ExcludeTrailingPathDelimiter( ExtractFilePath( ParentPath ) );
                var GrandParentName := ExtractFileName( GrandParentPath );

                if GrandParentName <> '' then
                  Lib.Name := GrandParentName + ' - ' + DirName
                else
                  Lib.Name := DirName;
              end;
            end
            else
              Lib.Name := DirName;
            Lib.Units     := DirPair.Value.ToArray;
            Lib.Confirmed := False;

            // Compute prefix from ALL .pas files in the directory, not just unclassified ones
            var AllUnitNames := GetAllPasUnitNames( ActualDir );

            if Length( AllUnitNames ) > 0 then
              Lib.SuggestedPrefix := ComputePrefix( AllUnitNames )
            else
              Lib.SuggestedPrefix := ComputePrefix( Lib.Units );

            // Detect metadata
            var LicFile := '';
            Lib.Licence     := DetectLicence( ActualDir, LicFile );
            Lib.LicenceFile := LicFile;
            Lib.Version     := DetectVersion( ActualDir );
            Lib.Vendor      := DetectVendor( ActualDir );

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
                  var OtherDir   := LowerCase( IncludeTrailingPathDelimiter( Other.Directory ) );

                  if OtherDir.StartsWith( CurrentDir ) or CurrentDir.StartsWith( OtherDir ) then
                  begin
                    // Merge Other into Current
                    var CombinedUnits := TList<string>.Create;
                    try
                      for var CU in Current.Units do
                        CombinedUnits.Add( CU );

                      for var CU in Other.Units do
                        CombinedUnits.Add( CU );

                      Current.Units := CombinedUnits.ToArray;
                    finally
                      CombinedUnits.Free;
                    end;

                    // Use the parent directory as the library directory and name
                    if CurrentDir.StartsWith( OtherDir ) then
                    begin
                      Current.Directory := Other.Directory;
                      Current.Name      := Other.Name;
                    end;

                    // Keep the richer metadata
                    if ( Current.Vendor = '' ) and ( Other.Vendor <> '' ) then
                      Current.Vendor := Other.Vendor;

                    if ( Current.Licence = '' ) and ( Other.Licence <> '' ) then
                      Current.Licence := Other.Licence;

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

            Result := Merged.ToArray;
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
      UnitToDir.Free;
      UnitToFile.Free;
    end;

  finally
    AllPaths.Free;
  end;

  AAutoOwnCodeUnits := OwnCodeList.ToArray;

  if OwnCodeList.Count > 0 then
    Log( llInfo, Format( 'Auto-detected %d own-code units from sibling directories', [ OwnCodeList.Count ] ) );

  OwnCodeList.Free;

end;

// ---------------------------------------------------------------------------
//  Delphi IDE library paths from registry
// ---------------------------------------------------------------------------

function TLibraryDiscovery.GetDelphiLibraryPaths( const ADelphiPath: string; const APlatform: string ): TArray<string>;
begin

  Result := nil;

  var Reg := TRegistry.Create( KEY_READ );
  try
    Reg.RootKey := HKEY_CURRENT_USER;

    // Find the highest BDS version
    if Reg.OpenKeyReadOnly( 'Software\Embarcadero\BDS' ) then
    begin
      var SubKeys := TStringList.Create;
      try
        Reg.GetKeyNames( SubKeys );
        Reg.CloseKey;

        var HighestVer        := '';
        var HighestVal: Double := 0.0;
        var FmtSettings       := TFormatSettings.Create( 'en-US' );

        for var I := 0 to SubKeys.Count - 1 do
        begin
          var NumVal: Double := 0.0;

          if TryStrToFloat( SubKeys[ I ], NumVal, FmtSettings ) then
            if NumVal > HighestVal then
            begin
              HighestVal := NumVal;
              HighestVer := SubKeys[ I ];
            end;
        end;

        if HighestVer <> '' then
        begin
          var Platform := APlatform;

          if Platform = '' then
            Platform := 'Win64';

          // Read the library search path from the IDE settings
          var LibKey := Format( 'Software\Embarcadero\BDS\%s\Library\%s', [ HighestVer, Platform ] );

          // Read custom IDE environment variables for path resolution
          var EnvVars := TDictionary<string, string>.Create;
          try
            var EnvKey := Format( 'Software\Embarcadero\BDS\%s\Environment Variables', [ HighestVer ] );

            if Reg.OpenKeyReadOnly( EnvKey ) then
            begin
              var ValueNames := TStringList.Create;
              try
                Reg.GetValueNames( ValueNames );

                for var VN := 0 to ValueNames.Count - 1 do
                  EnvVars.AddOrSetValue( ValueNames[ VN ], Reg.ReadString( ValueNames[ VN ] ) );
              finally
                ValueNames.Free;
              end;

              Reg.CloseKey;
              Log( llInfo, Format( 'Loaded %d IDE environment variables', [ EnvVars.Count ] ) );
            end;

            // Add standard BDS variables
            if ADelphiPath <> '' then
            begin
              EnvVars.AddOrSetValue( 'BDS', ADelphiPath );
              EnvVars.AddOrSetValue( 'BDSLIB', TPath.Combine( ADelphiPath, 'lib' ) );
              EnvVars.AddOrSetValue( 'BDSBIN', TPath.Combine( ADelphiPath, 'bin' ) );
              EnvVars.AddOrSetValue( 'BDSCOMMONDIR', TPath.Combine( GetEnvironmentVariable( 'PUBLIC' ), 'Documents\Embarcadero\Studio\' + HighestVer ) );
              EnvVars.AddOrSetValue( 'BDSUSERDIR', TPath.Combine( GetEnvironmentVariable( 'USERPROFILE' ), 'Documents\Embarcadero\Studio\' + HighestVer ) );
              EnvVars.AddOrSetValue( 'BDSCatalogRepository', TPath.Combine( GetEnvironmentVariable( 'USERPROFILE' ), 'Documents\Embarcadero\Studio\' + HighestVer + '\CatalogRepository' ) );
              EnvVars.AddOrSetValue( 'BDSCatalogRepositoryAllUsers', TPath.Combine( GetEnvironmentVariable( 'PUBLIC' ), 'Documents\Embarcadero\Studio\' + HighestVer + '\CatalogRepository' ) );
              EnvVars.AddOrSetValue( 'PLATFORM', Platform );
            end;

            if Reg.OpenKeyReadOnly( LibKey ) then
            begin
              if Reg.ValueExists( 'Search Path' ) then
              begin
                var PathStr := Reg.ReadString( 'Search Path' );

                // Resolve all $(VAR) references
                for var EnvPair in EnvVars do
                  PathStr := StringReplace( PathStr, '$(' + EnvPair.Key + ')', EnvPair.Value, [ rfReplaceAll, rfIgnoreCase ] );

                var Parts := PathStr.Split( [ ';' ] );
                var Paths := TList<string>.Create;
                try
                  for var P in Parts do
                  begin
                    var Trimmed := Trim( P );

                    if ( Trimmed <> '' ) and ( not Trimmed.Contains( '$(' ) ) then
                      Paths.Add( Trimmed );
                  end;

                  Result := Paths.ToArray;
                  Log( llInfo, Format( 'Found %d Delphi IDE library paths', [ Length( Result ) ] ) );
                finally
                  Paths.Free;
                end;
              end;

              Reg.CloseKey;
            end;

          finally
            EnvVars.Free;
          end;
        end;
      finally
        SubKeys.Free;
      end;
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

  Result := False;

  try
    // If the directory contains .dpk files, it's a library (packages = library distribution)
    // even if it also has .dpr files (demos, tests, examples)
    var DpkFiles := TDirectory.GetFiles( ADirectory, '*.dpk', TSearchOption.soTopDirectoryOnly );

    if Length( DpkFiles ) > 0 then
      Exit( False );

    // Check for .dpr files — indicates a standalone project, not a library
    var DprFiles := TDirectory.GetFiles( ADirectory, '*.dpr', TSearchOption.soTopDirectoryOnly );

    if Length( DprFiles ) > 0 then
    begin
      // Additional check: if there are many .pas files (10+) alongside the .dpr,
      // it's likely a library with a demo/test project, not a standalone app
      var PasFiles := TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly );

      if Length( PasFiles ) >= 10 then
        Exit( False );

      Exit( True );
    end;
  except
    // Access denied — treat as not a project directory
  end;

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

  Result := False;

end;

function TLibraryDiscovery.GetAllPasUnitNames( const ADirectory: string ): TArray<string>;
begin

  Result := nil;

  try
    var PasFiles := TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly );
    SetLength( Result, Length( PasFiles ) );

    for var I := 0 to High( PasFiles ) do
      Result[ I ] := TPath.GetFileNameWithoutExtension( PasFiles[ I ] );
  except
    // Access denied
  end;

end;

// ---------------------------------------------------------------------------
//  File search
// ---------------------------------------------------------------------------

function TLibraryDiscovery.FindUnitFile( const AUnitName: string;
  const ASearchPaths: TArray<string> ): string;
begin

  Result := '';

  // Try both the original name and the scope-stripped name
  var FileName := AUnitName + '.pas';
  var StrippedName := StripScopePrefix( AUnitName );
  var AltFileName := '';

  if StrippedName <> AUnitName then
    AltFileName := StrippedName + '.pas';

  for var SearchDir in ASearchPaths do
  begin
    // Try primary filename (e.g. Vcl.StyledTaskDialog.pas)
    var FullPath := TPath.Combine( SearchDir, FileName );

    if FileExists( FullPath ) then
      Exit( FullPath );

    // Try alternate (scope-stripped) filename (e.g. StyledTaskDialog.pas)
    if AltFileName <> '' then
    begin
      FullPath := TPath.Combine( SearchDir, AltFileName );

      if FileExists( FullPath ) then
        Exit( FullPath );
    end;

    // Also search the parent directory
    var ParentDir := ExcludeTrailingPathDelimiter( ExtractFilePath( ExcludeTrailingPathDelimiter( SearchDir ) ) );

    if ( ParentDir <> '' ) and ( ParentDir <> SearchDir ) then
    begin
      FullPath := TPath.Combine( ParentDir, FileName );

      if FileExists( FullPath ) then
        Exit( FullPath );

      if AltFileName <> '' then
      begin
        FullPath := TPath.Combine( ParentDir, AltFileName );

        if FileExists( FullPath ) then
          Exit( FullPath );
      end;
    end;

    // Also search one level of subdirectories
    if TDirectory.Exists( SearchDir ) then
    begin
      try
        var SubDirs := TDirectory.GetDirectories( SearchDir );

        for var SubDir in SubDirs do
        begin
          FullPath := TPath.Combine( SubDir, FileName );

          if FileExists( FullPath ) then
            Exit( FullPath );

          if AltFileName <> '' then
          begin
            FullPath := TPath.Combine( SubDir, AltFileName );

            if FileExists( FullPath ) then
              Exit( FullPath );
          end;
        end;
      except
        // Access denied or other I/O error — skip this directory
      end;
    end;
  end;

end;

function TLibraryDiscovery.GetCommonRootDirs: TArray<string>;
begin

  var Dirs := TList<string>.Create;
  try
    // Scan D:\ top-level directories (common location for Delphi libraries)
    if TDirectory.Exists( 'D:\' ) then
    begin
      try
        var SubDirs := TDirectory.GetDirectories( 'D:\' );

        for var D in SubDirs do
          Dirs.Add( D );
      except
        // Access denied
      end;
    end;

    // Scan C:\Program Files and C:\Program Files (x86)
    var ProgramDirs: TArray<string> := [
      'C:\Program Files',
      'C:\Program Files (x86)'
    ];

    for var PD in ProgramDirs do
    begin
      if TDirectory.Exists( PD ) then
      begin
        try
          var SubDirs := TDirectory.GetDirectories( PD );

          for var D in SubDirs do
            Dirs.Add( D );
        except
          // Access denied
        end;
      end;
    end;

    Result := Dirs.ToArray;
  finally
    Dirs.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  Licence detection
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectLicence( const ADirectory: string; out ALicenceFile: string ): string;
begin

  Result := '';
  ALicenceFile := '';

  var LicenceNames: TArray<string> := [
    'LICENSE', 'LICENSE.txt', 'LICENSE.md',
    'LICENCE', 'LICENCE.txt', 'LICENCE.md',
    'COPYING', 'COPYING.txt'
  ];

  for var LName in LicenceNames do
  begin
    var FullPath := TPath.Combine( ADirectory, LName );

    if FileExists( FullPath ) then
    begin
      ALicenceFile := FullPath;

      try
        var Lines := TFile.ReadAllLines( FullPath, TEncoding.UTF8 );
        var Preview := '';

        for var I := 0 to Min( 49, High( Lines ) ) do
          Preview := Preview + Lines[ I ] + ' ';

        Result := MapLicenceText( Preview );
      except
        // Can't read file — return empty
      end;

      Exit;
    end;
  end;

  // Also check parent directory (some libraries nest source in a subdirectory)
  var ParentDir := TDirectory.GetParent( ADirectory );

  if ParentDir <> '' then
  begin
    for var LName in LicenceNames do
    begin
      var FullPath := TPath.Combine( ParentDir, LName );

      if FileExists( FullPath ) then
      begin
        ALicenceFile := FullPath;

        try
          var Lines := TFile.ReadAllLines( FullPath, TEncoding.UTF8 );
          var Preview := '';

          for var I := 0 to Min( 49, High( Lines ) ) do
            Preview := Preview + Lines[ I ] + ' ';

          Result := MapLicenceText( Preview );
        except
        end;

        Exit;
      end;
    end;
  end;

end;

function TLibraryDiscovery.MapLicenceText( const AText: string ): string;
begin

  Result := '';

  var Upper := UpperCase( AText );

  if ( Pos( 'MIT LICENSE', Upper ) > 0 ) or ( Pos( 'PERMISSION IS HEREBY GRANTED', Upper ) > 0 ) then
    Exit( 'MIT' );

  if ( Pos( 'APACHE LICENSE', Upper ) > 0 ) and ( Pos( 'VERSION 2.0', Upper ) > 0 ) then
    Exit( 'Apache-2.0' );

  if ( Pos( 'BSD 3-CLAUSE', Upper ) > 0 ) or
     ( ( Pos( 'REDISTRIBUTION AND USE', Upper ) > 0 ) and ( Pos( 'THREE CONDITIONS', Upper ) > 0 ) ) then
    Exit( 'BSD-3-Clause' );

  if ( Pos( 'BSD 2-CLAUSE', Upper ) > 0 ) then
    Exit( 'BSD-2-Clause' );

  if ( Pos( 'GNU LESSER GENERAL PUBLIC LICENSE', Upper ) > 0 ) or ( Pos( 'LGPL', Upper ) > 0 ) then
  begin
    if Pos( 'VERSION 3', Upper ) > 0 then
      Exit( 'LGPL-3.0' )
    else
      Exit( 'LGPL-2.1' );
  end;

  if ( Pos( 'GNU GENERAL PUBLIC LICENSE', Upper ) > 0 ) or ( Pos( ' GPL ', Upper ) > 0 ) then
  begin
    if Pos( 'VERSION 3', Upper ) > 0 then
      Exit( 'GPL-3.0' )
    else if Pos( 'VERSION 2', Upper ) > 0 then
      Exit( 'GPL-2.0' )
    else
      Exit( 'GPL-3.0' );
  end;

  if ( Pos( 'MOZILLA PUBLIC LICENSE', Upper ) > 0 ) then
  begin
    if Pos( 'VERSION 2', Upper ) > 0 then
      Exit( 'MPL-2.0' )
    else
      Exit( 'MPL-1.1' );
  end;

  if Pos( 'UNLICENSE', Upper ) > 0 then
    Exit( 'Unlicense' );

  if ( Pos( 'BOOST SOFTWARE LICENSE', Upper ) > 0 ) then
    Exit( 'BSL-1.0' );

end;

// ---------------------------------------------------------------------------
//  Vendor/author detection from .pas header
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectVendor( const ADirectory: string ): string;
begin

  Result := '';

  // Try multiple .pas files in the directory until we find vendor info
  try
    var PasFiles := TDirectory.GetFiles( ADirectory, '*.pas', TSearchOption.soTopDirectoryOnly );

    for var PasFile in PasFiles do
    begin
      Result := ExtractVendorFromFile( PasFile );

      if Result <> '' then
      begin
        // Clean up common prefixes
        if Result.StartsWith( 'by ', True ) then
          Result := Trim( Copy( Result, 4, Length( Result ) ) );

        Exit;
      end;
    end;
  except
    // Access denied
  end;

end;

function TLibraryDiscovery.ExtractVendorFromFile( const APasFile: string ): string;
begin

  Result := '';

  try
    var Lines := TFile.ReadAllLines( APasFile, TEncoding.UTF8 );
    var MaxLines := Min( 29, High( Lines ) );

    for var I := 0 to MaxLines do
    begin
      var Line := Trim( Lines[ I ] );

      // Look for "Copyright (c) YYYY Name", "Copyright YYYY Name", or "© YYYY Name"
      var CopyrightPos := Pos( 'Copyright', Line );
      var CopyrightSymbolPos := Pos( '©', Line );

      // Handle © symbol appearing without "Copyright" word
      if ( CopyrightPos = 0 ) and ( CopyrightSymbolPos > 0 ) then
      begin
        var After := Trim( Copy( Line, CopyrightSymbolPos + 2, Length( Line ) ) );

        // Strip year(s) and delimiters
        while ( After.Length > 0 ) and ( CharInSet( After[ 1 ], [ '0'..'9', '-', ',', ' ' ] ) or ( Ord( After[ 1 ] ) = 8211 ) ) do
          Delete( After, 1, 1 );

        After := Trim( After );

        // Strip trailing comment markers
        After := StringReplace( After, '*)', '', [] );
        After := StringReplace( After, '}', '', [] );
        After := Trim( After );

        // Strip surrounding parentheses
        if After.StartsWith( '(' ) and After.EndsWith( ')' ) then
          After := Copy( After, 2, After.Length - 2 )
        else if After.StartsWith( '(' ) then
          Delete( After, 1, 1 );

        // Strip trailing period or closing paren
        After := Trim( After );

        while ( After.Length > 0 ) and CharInSet( After[ After.Length ], [ '.', ')' ] ) do
          Delete( After, After.Length, 1 );

        After := Trim( After );

        // Strip "All rights reserved" suffix
        var ArPos := Pos( '. All rights', After );

        if ArPos > 0 then
          After := Trim( Copy( After, 1, ArPos - 1 ) );

        if After.Length > 2 then
        begin
          Result := Trim( After );
          Exit;
        end;
      end;

      if CopyrightPos > 0 then
      begin
        var After := Copy( Line, CopyrightPos + 9, Length( Line ) );
        After := Trim( After );

        // Strip (c) or ©
        if After.StartsWith( '(c)' ) then
          After := Trim( Copy( After, 4, Length( After ) ) )
        else if After.StartsWith( '©' ) then
          After := Trim( Copy( After, 3, Length( After ) ) );

        // Strip year(s) like "2020" or "2020-2026" or "2020–2026" or "2020, 2026"
        while ( After.Length > 0 ) and ( CharInSet( After[ 1 ], [ '0'..'9', '-', ',', ' ' ] ) or ( After[ 1 ] = '–' ) ) do
          Delete( After, 1, 1 );

        After := Trim( After );

        // Strip trailing comment markers
        After := StringReplace( After, '*)', '', [] );
        After := StringReplace( After, '}', '', [] );
        After := Trim( After );

        // Strip surrounding parentheses
        if After.StartsWith( '(' ) and After.EndsWith( ')' ) then
          After := Copy( After, 2, After.Length - 2 )
        else if After.StartsWith( '(' ) then
          Delete( After, 1, 1 );

        // Strip trailing period or closing paren
        After := Trim( After );

        while ( After.Length > 0 ) and CharInSet( After[ After.Length ], [ '.', ')' ] ) do
          Delete( After, After.Length, 1 );

        After := Trim( After );

        // Strip "All rights reserved" suffix
        var ArPos2 := Pos( '. All rights', After );

        if ArPos2 > 0 then
          After := Trim( Copy( After, 1, ArPos2 - 1 ) );

        if After.Length > 2 then
        begin
          Result := Trim( After );
          Exit;
        end;
      end;

      // Look for "Author: Name"
      if Line.StartsWith( 'Author:', True ) or Line.StartsWith( '  Author:', True ) then
      begin
        var After := Trim( Copy( Line, Pos( ':', Line ) + 1, Length( Line ) ) );
        After := StringReplace( After, '*)', '', [] );
        After := StringReplace( After, '}', '', [] );
        After := Trim( After );

        if After.Length > 2 then
        begin
          Result := After;
          Exit;
        end;
      end;
    end;
  except
    // Can't read file — return empty
  end;

end;

// ---------------------------------------------------------------------------
//  Version detection
// ---------------------------------------------------------------------------

function TLibraryDiscovery.DetectVersion( const ADirectory: string ): string;
begin

  Result := '';

  // Look for .dpk files and try to extract version
  try
    var DpkFiles := TDirectory.GetFiles( ADirectory, '*.dpk', TSearchOption.soTopDirectoryOnly );

    for var DpkFile in DpkFiles do
    begin
      var Content := TFile.ReadAllText( DpkFile, TEncoding.UTF8 );

      // Look for version patterns like "version '1.2.3'" or version numbers in the filename
      var VerPos := Pos( '{$ver ', LowerCase( Content ) );

      if VerPos > 0 then
      begin
        var After := Copy( Content, VerPos + 6, 20 );
        var EndPos := Pos( '}', After );

        if EndPos > 0 then
        begin
          Result := Trim( Copy( After, 1, EndPos - 1 ) );
          Exit;
        end;
      end;
    end;
  except
    // Can't read directory — return empty
  end;

end;

// ---------------------------------------------------------------------------
//  Common prefix computation
// ---------------------------------------------------------------------------

function TLibraryDiscovery.ComputePrefix( const AUnitNames: TArray<string> ): string;
begin

  Result := '';

  if Length( AUnitNames ) = 0 then Exit;

  if Length( AUnitNames ) = 1 then
  begin
    // Single unit — use the full name as exact match, no prefix
    Result := AUnitNames[ 0 ];
    Exit;
  end;

  // Find the longest common prefix of all unit names
  var First := AUnitNames[ 0 ];

  for var CharIdx := 1 to First.Length do
  begin
    var AllMatch := True;

    for var I := 1 to High( AUnitNames ) do
    begin
      if ( CharIdx > AUnitNames[ I ].Length ) or
         ( not SameText( First[ CharIdx ], AUnitNames[ I ][ CharIdx ] ) ) then
      begin
        AllMatch := False;
        Break;
      end;
    end;

    if AllMatch then
      Result := Copy( First, 1, CharIdx )
    else
      Break;
  end;

  // Ensure minimum prefix length
  if Result.Length < MinPrefixLength then
    Result := '';

end;

end.
