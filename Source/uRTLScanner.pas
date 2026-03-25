(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
  MIT Licence — see LICENCE file

  uRTLScanner.pas — Scans a Delphi installation to discover RTL/VCL/FMX unit names
*)
unit uRTLScanner;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  uTypes;

type
  /// <summary>
  ///   Scans the Delphi installation directory for .dcu files to build
  ///   a list of known RTL/VCL/FMX unit names.
  /// </summary>
  TRTLScanner = class
  private
    FLog: TProc<TLogLevel, string>;
    FRTLUnits: TDictionary<string, Boolean>;

    function DetectDelphiPathFromRegistry: string;
    function EnumerateBDSVersions: TArray<string>;
    procedure ScanDirectory( const APath: string );

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );
    destructor Destroy; override;

    /// <summary>
    ///   Scans for RTL units. If ADelphiPath is empty, auto-detects from registry.
    ///   APlatform should be 'Win32' or 'Win64'.
    ///   Returns True if scanning succeeded; False if Delphi install not found.
    /// </summary>
    function Scan( const ADelphiPath: string; const APlatform: string ): Boolean;

    /// <summary>
    ///   Returns True if the given unit name (case-insensitive) is a known RTL/VCL/FMX unit.
    /// </summary>
    function IsRTLUnit( const AUnitName: string ): Boolean;

    /// <summary>
    ///   Returns the number of RTL units discovered.
    /// </summary>
    function Count: Integer;
  end;

implementation

uses
  System.IOUtils, System.Win.Registry, Winapi.Windows;

{ TRTLScanner }

constructor TRTLScanner.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;
  FRTLUnits := TDictionary<string, Boolean>.Create;

end;

destructor TRTLScanner.Destroy;
begin

  FRTLUnits.Free;
  inherited;

end;

procedure TRTLScanner.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TRTLScanner.Scan( const ADelphiPath: string; const APlatform: string ): Boolean;
begin

  FRTLUnits.Clear;
  Result := False;

  var EffectivePath := ADelphiPath;

  if EffectivePath = '' then
  begin
    Log( llInfo, 'Auto-detecting Delphi installation from registry...' );
    EffectivePath := DetectDelphiPathFromRegistry;
  end;

  if EffectivePath = '' then
  begin
    Log( llWarning, 'Delphi installation not found — RTL unit classification unavailable. Specify the Delphi path manually.' );
    Exit;
  end;

  // Build the library path: <RootDir>\lib\<platform>\release
  var Platform := APlatform;

  if Platform = '' then
    Platform := 'Win64';

  var LibPath := TPath.Combine( TPath.Combine( TPath.Combine( EffectivePath, 'lib' ), Platform ), 'release' );

  if ( not TDirectory.Exists( LibPath ) ) then
  begin
    Log( llWarning, Format( 'RTL library path not found: %s', [ LibPath ] ) );
    Exit;
  end;

  Log( llInfo, Format( 'Scanning RTL units from %s', [ LibPath ] ) );

  ScanDirectory( LibPath );

  if FRTLUnits.Count > 0 then
  begin
    Log( llInfo, Format( 'Found %d RTL units', [ FRTLUnits.Count ] ) );
    Result := True;
  end
  else
    Log( llWarning, 'No .dcu files found in library path' );

end;

function TRTLScanner.IsRTLUnit( const AUnitName: string ): Boolean;
begin

  Result := FRTLUnits.ContainsKey( LowerCase( AUnitName ) );

end;

function TRTLScanner.Count: Integer;
begin

  Result := FRTLUnits.Count;

end;

procedure TRTLScanner.ScanDirectory( const APath: string );
begin

  var Files := TDirectory.GetFiles( APath, '*.dcu', TSearchOption.soTopDirectoryOnly );

  for var FileName in Files do
  begin
    var UnitName := TPath.GetFileNameWithoutExtension( FileName );
    FRTLUnits.AddOrSetValue( LowerCase( UnitName ), True );
  end;

end;

// ---------------------------------------------------------------------------
//  Registry detection — enumerate BDS versions, pick highest
// ---------------------------------------------------------------------------

function TRTLScanner.DetectDelphiPathFromRegistry: string;
begin

  Result := '';

  var Versions := EnumerateBDSVersions;

  if Length( Versions ) = 0 then
  begin
    Log( llWarning, 'No Delphi installations found in registry' );
    Exit;
  end;

  // Sort versions numerically descending and pick the highest
  var HighestVersion := '';
  var HighestValue   := 0.0;

  for var Ver in Versions do
  begin
    var NumVal: Double := 0.0;
    var FmtSettings := TFormatSettings.Create( 'en-US' );

    if TryStrToFloat( Ver, NumVal, FmtSettings ) then
    begin
      if NumVal > HighestValue then
      begin
        HighestValue   := NumVal;
        HighestVersion := Ver;
      end;
    end;
  end;

  if HighestVersion = '' then
  begin
    Log( llWarning, 'Could not determine Delphi version from registry keys' );
    Exit;
  end;

  Log( llInfo, Format( 'Detected Delphi version %s from registry', [ HighestVersion ] ) );

  // Read RootDir from the highest version key
  var Reg := TRegistry.Create( KEY_READ );
  try
    Reg.RootKey := HKEY_CURRENT_USER;

    var KeyPath := 'Software\Embarcadero\BDS\' + HighestVersion;

    if Reg.OpenKeyReadOnly( KeyPath ) then
    begin
      if Reg.ValueExists( 'RootDir' ) then
      begin
        Result := ExcludeTrailingPathDelimiter( Reg.ReadString( 'RootDir' ) );
        Log( llInfo, Format( 'Delphi root directory: %s', [ Result ] ) );
      end;

      Reg.CloseKey;
    end;
  finally
    Reg.Free;
  end;

  if Result = '' then
    Log( llWarning, Format( 'RootDir not found in registry key for version %s', [ HighestVersion ] ) );

end;

function TRTLScanner.EnumerateBDSVersions: TArray<string>;
begin

  var Versions := TList<string>.Create;
  try
    var Reg := TRegistry.Create( KEY_READ );
    try
      Reg.RootKey := HKEY_CURRENT_USER;

      if Reg.OpenKeyReadOnly( 'Software\Embarcadero\BDS' ) then
      begin
        var SubKeys := TStringList.Create;
        try
          Reg.GetKeyNames( SubKeys );

          for var I := 0 to SubKeys.Count - 1 do
            Versions.Add( SubKeys[ I ] );
        finally
          SubKeys.Free;
        end;

        Reg.CloseKey;
      end;
    finally
      Reg.Free;
    end;

    Result := Versions.ToArray;
  finally
    Versions.Free;
  end;

end;

end.
