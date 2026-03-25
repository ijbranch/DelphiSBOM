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
    function DetectLicence( const ADirectory: string; out ALicenceFile: string ): string;
    function DetectVendor( const APasFile: string ): string;
    function DetectVersion( const ADirectory: string ): string;
    function ComputePrefix( const AUnitNames: TArray<string> ): string;
    function MapLicenceText( const AText: string ): string;

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
      const AProjectDir: string ): TArray<TDiscoveredLibrary>;
  end;

implementation

uses
  System.IOUtils, System.StrUtils, System.Math;

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
  const AProjectDir: string ): TArray<TDiscoveredLibrary>;
begin

  FFoundDirs.Clear;

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

            Lib.Directory       := ActualDir;
            Lib.Name            := ExtractFileName( ActualDir );
            Lib.Units           := DirPair.Value.ToArray;
            Lib.SuggestedPrefix := ComputePrefix( Lib.Units );
            Lib.Confirmed       := False;

            // Skip if this is the project's own directory
            if SameText( ExcludeTrailingPathDelimiter( ActualDir ),
                         ExcludeTrailingPathDelimiter( AProjectDir ) ) then
              Continue;

            // Detect metadata
            var LicFile := '';
            Lib.Licence    := DetectLicence( ActualDir, LicFile );
            Lib.LicenceFile := LicFile;
            Lib.Version    := DetectVersion( ActualDir );

            if UnitToFile.ContainsKey( FirstUnit ) then
              Lib.Vendor := DetectVendor( UnitToFile[ FirstUnit ] );

            Log( llInfo, Format( 'Discovered library: %s (%d units, dir: %s)',
              [ Lib.Name, Length( Lib.Units ), Lib.Directory ] ) );

            Libraries.Add( Lib );
          end;

          Result := Libraries.ToArray;
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

end;

// ---------------------------------------------------------------------------
//  File search
// ---------------------------------------------------------------------------

function TLibraryDiscovery.FindUnitFile( const AUnitName: string;
  const ASearchPaths: TArray<string> ): string;
begin

  Result := '';

  var FileName := AUnitName + '.pas';

  for var SearchDir in ASearchPaths do
  begin
    var FullPath := TPath.Combine( SearchDir, FileName );

    if FileExists( FullPath ) then
      Exit( FullPath );

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

function TLibraryDiscovery.DetectVendor( const APasFile: string ): string;
begin

  Result := '';

  try
    var Lines := TFile.ReadAllLines( APasFile, TEncoding.UTF8 );
    var MaxLines := Min( 29, High( Lines ) );

    for var I := 0 to MaxLines do
    begin
      var Line := Trim( Lines[ I ] );

      // Look for "Copyright (c) YYYY Name" or "Copyright YYYY Name"
      var CopyrightPos := Pos( 'Copyright', Line );

      if CopyrightPos > 0 then
      begin
        var After := Copy( Line, CopyrightPos + 9, Length( Line ) );
        After := Trim( After );

        // Strip (c) or ©
        if After.StartsWith( '(c)' ) then
          After := Trim( Copy( After, 4, Length( After ) ) )
        else if After.StartsWith( '©' ) then
          After := Trim( Copy( After, 3, Length( After ) ) );

        // Strip year(s) like "2020" or "2020-2026" or "2020, 2026"
        while ( After.Length > 0 ) and ( CharInSet( After[ 1 ], [ '0'..'9', '-', ',', ' ' ] ) ) do
          Delete( After, 1, 1 );

        After := Trim( After );

        // Strip trailing comment markers
        After := StringReplace( After, '*)', '', [] );
        After := StringReplace( After, ')', '', [] );
        After := StringReplace( After, '}', '', [] );
        After := Trim( After );

        // Strip trailing period
        if After.EndsWith( '.' ) then
          After := Copy( After, 1, After.Length - 1 );

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
    var Ch := First[ CharIdx ];
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
