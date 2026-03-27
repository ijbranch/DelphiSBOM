(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSettings.pas — MRU (Most Recently Used) project list with per-project settings
*)
unit uSettings;

interface

uses
  System.SysUtils, System.Generics.Collections;

type
  TMRUEntry = record
    ProjectFile: string;
    ManifestFile: string;
    OutputDir: string;
    VersionOverride: string;
    DXComplyFile: string;
  end;

  /// <summary>
  ///   Manages a Most Recently Used project list persisted to an INI file
  ///   in %APPDATA%\DelphiSBOM\DelphiSBOM.ini.
  /// </summary>
  TMRUManager = class
  private
    FEntries: TList<TMRUEntry>;
    FSettingsFile: string;

    const MaxEntries = 10;
  public
    constructor Create;
    destructor Destroy; override;

    procedure Load;
    procedure Save;
    procedure AddOrPromote( const AEntry: TMRUEntry );
    function GetEntries: TArray<TMRUEntry>;
    function FindEntry( const AProjectFile: string ): TMRUEntry;

    class function GetSettingsPath: string; static;
  end;

implementation

uses
  System.Classes, System.IOUtils, System.IniFiles;

{ TMRUManager }

constructor TMRUManager.Create;
begin

  inherited Create;
  FEntries := TList<TMRUEntry>.Create;
  FSettingsFile := GetSettingsPath;

end;

destructor TMRUManager.Destroy;
begin

  FEntries.Free;
  inherited;

end;

class function TMRUManager.GetSettingsPath: string;
begin

  Result := TPath.Combine( TPath.Combine( TPath.GetHomePath, 'DelphiSBOM' ), 'DelphiSBOM.ini' );

end;

procedure TMRUManager.Load;
begin

  FEntries.Clear;

  if not FileExists( FSettingsFile ) then Exit;

  var Ini := TIniFile.Create( FSettingsFile );
  try
    var Count := Ini.ReadInteger( 'MRU', 'Count', 0 );

    for var I := 0 to Count - 1 do
    begin
      var ProjectFile := Ini.ReadString( 'MRU', Format( 'Item%d', [ I ] ), '' );

      if ( ProjectFile = '' ) or ( not FileExists( ProjectFile ) ) then Continue;

      var Entry: TMRUEntry;
      Entry.ProjectFile    := ProjectFile;

      var Section := 'MRU:' + ProjectFile;
      Entry.ManifestFile   := Ini.ReadString( Section, 'ManifestFile', '' );
      Entry.OutputDir      := Ini.ReadString( Section, 'OutputDir', '' );
      Entry.VersionOverride := Ini.ReadString( Section, 'VersionOverride', '' );
      Entry.DXComplyFile   := Ini.ReadString( Section, 'DXComplyFile', '' );

      FEntries.Add( Entry );
    end;
  finally
    Ini.Free;
  end;

end;

procedure TMRUManager.Save;
begin

  var Dir := ExtractFilePath( FSettingsFile );

  if not TDirectory.Exists( Dir ) then
    TDirectory.CreateDirectory( Dir );

  var Ini := TIniFile.Create( FSettingsFile );
  try
    // Erase all existing MRU:* sections (including orphans from removed entries)
    var AllSections := TStringList.Create;
    try
      Ini.ReadSections( AllSections );

      for var S := 0 to AllSections.Count - 1 do
        if AllSections[ S ].StartsWith( 'MRU:', True ) then
          Ini.EraseSection( AllSections[ S ] );
    finally
      AllSections.Free;
    end;

    Ini.EraseSection( 'MRU' );
    Ini.WriteInteger( 'MRU', 'Count', FEntries.Count );

    for var I := 0 to FEntries.Count - 1 do
    begin
      var Entry := FEntries[ I ];
      Ini.WriteString( 'MRU', Format( 'Item%d', [ I ] ), Entry.ProjectFile );

      var Section := 'MRU:' + Entry.ProjectFile;
      Ini.WriteString( Section, 'ManifestFile', Entry.ManifestFile );
      Ini.WriteString( Section, 'OutputDir', Entry.OutputDir );
      Ini.WriteString( Section, 'VersionOverride', Entry.VersionOverride );
      Ini.WriteString( Section, 'DXComplyFile', Entry.DXComplyFile );
    end;
  finally
    Ini.Free;
  end;

end;

procedure TMRUManager.AddOrPromote( const AEntry: TMRUEntry );
begin

  // Remove existing entry for same project (case-insensitive)
  for var I := FEntries.Count - 1 downto 0 do
    if SameText( FEntries[ I ].ProjectFile, AEntry.ProjectFile ) then
      FEntries.Delete( I );

  // Insert at front (most recent)
  FEntries.Insert( 0, AEntry );

  // Trim to max
  while FEntries.Count > MaxEntries do
    FEntries.Delete( FEntries.Count - 1 );

end;

function TMRUManager.GetEntries: TArray<TMRUEntry>;
begin

  Result := FEntries.ToArray;

end;

function TMRUManager.FindEntry( const AProjectFile: string ): TMRUEntry;
begin

  Result := Default( TMRUEntry );

  for var Entry in FEntries do
    if SameText( Entry.ProjectFile, AProjectFile ) then
      Exit( Entry );

end;

end.
