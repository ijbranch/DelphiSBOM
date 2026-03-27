(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uEvidenceMerger.pas — Imports binary evidence from DX.Comply SBOM output
  Parses DX.Comply's CycloneDX JSON to extract per-unit SHA-256 hashes
  and origin classifications from MAP file analysis.
*)
unit uEvidenceMerger;

interface

uses
  System.SysUtils,
  uTypes;

type
  /// <summary>
  ///   Loads binary evidence (hashes, origin classification) from a DX.Comply
  ///   CycloneDX SBOM file. The evidence can be merged into DelphiSBOM's output
  ///   to produce an enriched SBOM with both metadata and binary verification.
  /// </summary>
  TEvidenceMerger = class
  private
    FLog: TProc<TLogLevel, string>;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Loads unit evidence from a DX.Comply bom.json file.
    ///   Returns an array of TUnitEvidence with hashes and origin data.
    ///   Skips the application-level entry (the .exe) and processes only
    ///   library/framework components.
    /// </summary>
    function LoadEvidence( const ADXComplyFile: string ): TArray<TUnitEvidence>;
  end;

implementation

uses
  System.IOUtils, System.JSON, System.Generics.Collections;

{ TEvidenceMerger }

constructor TEvidenceMerger.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;

end;

procedure TEvidenceMerger.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TEvidenceMerger.LoadEvidence( const ADXComplyFile: string ): TArray<TUnitEvidence>;
begin

  Result := nil;

  if not FileExists( ADXComplyFile ) then
  begin
    Log( llWarning, Format( 'DX.Comply file not found: %s', [ ADXComplyFile ] ) );
    Exit;
  end;

  Log( llInfo, Format( 'Loading DX.Comply evidence from %s', [ ExtractFileName( ADXComplyFile ) ] ) );

  var Content := TFile.ReadAllText( ADXComplyFile, TEncoding.UTF8 );
  var JsonVal := TJSONObject.ParseJSONValue( Content );

  if not Assigned( JsonVal ) then
  begin
    Log( llError, 'Invalid JSON in DX.Comply file' );
    Exit;
  end;

  try
    if not ( JsonVal is TJSONObject ) then
    begin
      Log( llError, 'DX.Comply file root must be a JSON object' );
      Exit;
    end;

    var Root := JsonVal as TJSONObject;

    // Verify it's a CycloneDX file
    var BomFormat := Root.GetValue<string>( 'bomFormat', '' );

    if not SameText( BomFormat, 'CycloneDX' ) then
    begin
      Log( llWarning, Format( 'DX.Comply file does not appear to be CycloneDX (bomFormat=%s)', [ BomFormat ] ) );
      Exit;
    end;

    var CompArray: TJSONArray;

    if not Root.TryGetValue<TJSONArray>( 'components', CompArray ) then
    begin
      Log( llWarning, 'No components array in DX.Comply file' );
      Exit;
    end;

    var EvidenceList := TList<TUnitEvidence>.Create;
    try
      for var I := 0 to CompArray.Count - 1 do
      begin
        if not ( CompArray.Items[ I ] is TJSONObject ) then Continue;

        var CompObj := CompArray.Items[ I ] as TJSONObject;
        var CompType := CompObj.GetValue<string>( 'type', '' );

        // Skip the application entry (the .exe itself)
        if SameText( CompType, 'application' ) then Continue;

        var CompName := CompObj.GetValue<string>( 'name', '' );

        if CompName = '' then Continue;

        // Extract hash from hashes array
        var HashAlg   := '';
        var HashValue := '';
        var HashArray: TJSONArray;

        if CompObj.TryGetValue<TJSONArray>( 'hashes', HashArray ) then
          if HashArray.Count > 0 then
            if HashArray.Items[ 0 ] is TJSONObject then
            begin
              var HashObj := HashArray.Items[ 0 ] as TJSONObject;
              HashAlg   := HashObj.GetValue<string>( 'alg', '' );
              HashValue := HashObj.GetValue<string>( 'content', '' );
            end;

        // Extract origin from properties array
        var Origin := '';
        var PropsArray: TJSONArray;

        if CompObj.TryGetValue<TJSONArray>( 'properties', PropsArray ) then
          for var J := 0 to PropsArray.Count - 1 do
            if PropsArray.Items[ J ] is TJSONObject then
            begin
              var PropObj := PropsArray.Items[ J ] as TJSONObject;

              if PropObj.GetValue<string>( 'name', '' ).EndsWith( ':origin' ) then
              begin
                Origin := PropObj.GetValue<string>( 'value', '' );
                Break;
              end;
            end;

        // Strip .dcu extension to get the unit name for matching
        var UnitName := CompName;

        if UnitName.EndsWith( '.dcu', True ) then
          UnitName := UnitName.Substring( 0, UnitName.Length - 4 )
        else if UnitName.EndsWith( '.pas', True ) then
          UnitName := UnitName.Substring( 0, UnitName.Length - 4 );

        var Evidence: TUnitEvidence;
        Evidence.UnitName  := UnitName;
        Evidence.Algorithm := HashAlg;
        Evidence.HashValue := HashValue;
        Evidence.Origin    := Origin;

        EvidenceList.Add( Evidence );
      end;

      Result := EvidenceList.ToArray;
    finally
      EvidenceList.Free;
    end;

    Log( llInfo, Format( 'Loaded %d unit evidence entries from DX.Comply', [ Length( Result ) ] ) );

  finally
    JsonVal.Free;
  end;

end;

end.
