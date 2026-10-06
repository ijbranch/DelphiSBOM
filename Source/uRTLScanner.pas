(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
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

    procedure ScanDirectory( const APath: string );

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );
    destructor Destroy; override;

    /// <summary>
    ///   Scans &lt;ADelphiPath&gt;\lib\&lt;APlatform&gt;\release for RTL units. The engine resolves
    ///   ADelphiPath (the project's Delphi version from the registry) before calling.
    /// </summary>
    /// <param name="ADelphiPath">Delphi installation root directory; empty means not installed.</param>
    /// <param name="APlatform">'Win32' or 'Win64'; empty means Win64.</param>
    /// <returns>True if RTL units were found; False if the installation or library path is missing.</returns>
    function Scan( const ADelphiPath: string; const APlatform: string ): Boolean;

    /// <summary>
    ///   Returns True if the given unit name (case-insensitive) is a known RTL/VCL/FMX unit.
    /// </summary>
    /// <param name="AUnitName">Unit name to test.</param>
    /// <returns>True when a matching .dcu was found by Scan.</returns>
    function IsRTLUnit( const AUnitName: string ): Boolean;

    /// <summary>
    ///   Returns the number of RTL units discovered.
    /// </summary>
    /// <returns>The count of distinct RTL unit names.</returns>
    function Count: Integer;
  end;

implementation

uses
  System.IOUtils;

{ TRTLScanner }

constructor TRTLScanner.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;
  FRTLUnits         := TDictionary<string, Boolean>.Create;

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
  Result            := False;

  if ADelphiPath = '' then
  begin
    Log( llWarning, 'Delphi installation not found — RTL unit classification unavailable. Specify the Delphi path manually.' );
    Exit;
  end;

  // Build the library path: <RootDir>\lib\<platform>\release
  var Platform      := APlatform;

  if Platform = '' then
    Platform        := 'Win64';

  var LibPath       := TPath.Combine( TPath.Combine( TPath.Combine( ADelphiPath, 'lib' ), Platform ), 'release' );

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
    Result          := True;
  end
  else
    Log( llWarning, 'No .dcu files found in library path' );

end;

function TRTLScanner.IsRTLUnit( const AUnitName: string ): Boolean;
begin

  Result            := FRTLUnits.ContainsKey( LowerCase( AUnitName ) );

end;

function TRTLScanner.Count: Integer;
begin

  Result            := FRTLUnits.Count;

end;

procedure TRTLScanner.ScanDirectory( const APath: string );
begin

  var Files         := TDirectory.GetFiles( APath, '*.dcu', TSearchOption.soTopDirectoryOnly );

  for var FileName in Files do
  begin
    var UnitName := TPath.GetFileNameWithoutExtension( FileName );
    FRTLUnits.AddOrSetValue( LowerCase( UnitName ), True );
  end;

end;

end.

