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
  System.IOUtils, System.JSON, System.Generics.Collections,
  uTextFiles;

/// <summary>
///   Reads a string member of a JSON object; returns '' when it is missing or not a string.
/// </summary>
function JsonString( AObject: TJSONObject; const AName: string ): string;
begin

  var Value         := AObject.GetValue( AName );

  if Value is TJSONString then
    Result          := Value.Value
  else
    Result          := '';

end;

{ TEvidenceMerger }

constructor TEvidenceMerger.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;

end;

procedure TEvidenceMerger.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TEvidenceMerger.LoadEvidence( const ADXComplyFile: string ): TArray<TUnitEvidence>;
begin

  Result            := nil;

  if not FileExists( ADXComplyFile ) then
  begin
    Log( llWarning, Format( 'DX.Comply file not found: %s', [ ADXComplyFile ] ) );
    Exit;
  end;

  Log( llInfo, Format( 'Loading DX.Comply evidence from %s', [ ExtractFileName( ADXComplyFile ) ] ) );

  var Content       := ReadTextFile( ADXComplyFile );
  var JsonVal       := TJSONObject.ParseJSONValue( Content );

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

    var Root        := JsonVal as TJSONObject;

    // Verify it's a CycloneDX file
    var BomFormat   := JsonString( Root, 'bomFormat' );

    if not SameText( BomFormat, 'CycloneDX' ) then
    begin
      Log( llWarning, Format( 'DX.Comply file does not appear to be CycloneDX (bomFormat=%s)', [ BomFormat ] ) );
      Exit;
    end;

    if not ( Root.GetValue( 'components' ) is TJSONArray ) then
    begin
      Log( llWarning, 'No components array in DX.Comply file' );
      Exit;
    end;

    var CompArray   := TJSONArray( Root.GetValue( 'components' ) );

    var EvidenceList := TList<TUnitEvidence>.Create;
    var IndexByUnit := TDictionary<string, Integer>.Create;
    try
      var Duplicates := 0;
      var Unsupported := 0;

      for var I := 0 to CompArray.Count - 1 do
      begin
        if not ( CompArray.Items[ I ] is TJSONObject ) then Continue;

        var CompObj := CompArray.Items[ I ] as TJSONObject;

        // Skip the application entry (the .exe itself)
        if SameText( JsonString( CompObj, 'type' ), 'application' ) then Continue;

        var CompName := JsonString( CompObj, 'name' );

        if CompName = '' then Continue;

        // Take the SHA-256 hash when one is listed, else the first algorithm CycloneDX defines
        var HashAlg := '';
        var HashValue := '';
        var HashVal := CompObj.GetValue( 'hashes' );

        if HashVal is TJSONArray then
          for var HashItem in TJSONArray( HashVal ) do
          begin
            if not ( HashItem is TJSONObject ) then Continue;

            var Alg := NormaliseHashAlgorithm( JsonString( TJSONObject( HashItem ), 'alg' ) );
            var HashContent := JsonString( TJSONObject( HashItem ), 'content' );

            if ( Alg = '' ) or ( HashContent = '' ) then
            begin
              Inc( Unsupported );
              Continue;
            end;

            if ( HashAlg = '' ) or ( ( Alg = 'SHA-256' ) and ( HashAlg <> 'SHA-256' ) ) then
            begin
              HashAlg := Alg;
              HashValue := HashContent;
            end;
          end;

        // Extract origin from properties array
        var Origin  := '';
        var PropsVal := CompObj.GetValue( 'properties' );

        if PropsVal is TJSONArray then
          for var PropItem in TJSONArray( PropsVal ) do
            if ( PropItem is TJSONObject ) and JsonString( TJSONObject( PropItem ), 'name' ).EndsWith( ':origin' ) then
            begin
              Origin := JsonString( TJSONObject( PropItem ), 'value' );
              Break;
            end;

        // Strip the .dcu / .pas extension to get the unit name for matching
        var UnitName := CompName;

        if UnitName.EndsWith( '.dcu', True ) or UnitName.EndsWith( '.pas', True ) then
          UnitName  := UnitName.Substring( 0, UnitName.Length - 4 );

        var Evidence: TUnitEvidence;
        Evidence.UnitName := UnitName;
        Evidence.Algorithm := HashAlg;
        Evidence.HashValue := HashValue;
        Evidence.Origin := Origin;

        // The same unit can be listed twice (.pas and .dcu) — keep one entry, preferring one with a hash
        var Existing := -1;

        if IndexByUnit.TryGetValue( LowerCase( UnitName ), Existing ) then
        begin
          Inc( Duplicates );

          if ( EvidenceList[ Existing ].HashValue = '' ) and ( HashValue <> '' ) then
            EvidenceList[ Existing ] := Evidence;

          Continue;
        end;

        IndexByUnit.Add( LowerCase( UnitName ), EvidenceList.Count );
        EvidenceList.Add( Evidence );
      end;

      Result        := EvidenceList.ToArray;

      if Duplicates > 0 then
        Log( llInfo, Format( 'Merged %d duplicate DX.Comply entries for the same unit', [ Duplicates ] ) );

      if Unsupported > 0 then
        Log( llWarning, Format( 'Ignored %d DX.Comply hashes with an algorithm CycloneDX 1.5 does not define', [ Unsupported ] ) );
    finally
      IndexByUnit.Free;
      EvidenceList.Free;
    end;

    Log( llInfo, Format( 'Loaded %d unit evidence entries from DX.Comply', [ Length( Result ) ] ) );

  finally
    JsonVal.Free;
  end;

end;

end.

