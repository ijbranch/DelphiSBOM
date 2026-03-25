(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
  MIT Licence — see LICENCE file

  uManifestLoader.pas — Loads and validates the components.json manifest
*)
unit uManifestLoader;

interface

uses
  System.SysUtils, System.Classes,
  uTypes;

type
  /// <summary>
  ///   Loads and validates a components.json manifest file.
  /// </summary>
  TManifestLoader = class
  private
    FLog: TProc<TLogLevel, string>;

    procedure ValidateComponent( const AComp: TComponentEntry; AIndex: Integer );
    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Loads a components.json file and returns the parsed manifest.
    ///   Raises an exception if the file is missing or has invalid JSON.
    ///   Logs warnings for schema issues that are non-fatal.
    /// </summary>
    function Load( const AManifestFile: string ): TManifest;

    /// <summary>
    ///   Validates a manifest without loading it for SBOM generation.
    ///   Returns True if valid (warnings are acceptable), False if errors found.
    /// </summary>
    function Validate( const AManifestFile: string ): Boolean;
  end;

implementation

uses
  System.IOUtils, System.JSON, System.Generics.Collections;

{ TManifestLoader }

constructor TManifestLoader.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;

end;

procedure TManifestLoader.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TManifestLoader.Load( const AManifestFile: string ): TManifest;
begin

  Result := Default( TManifest );

  if ( not FileExists( AManifestFile ) ) then
    raise Exception.CreateFmt( 'Manifest file not found: %s', [ AManifestFile ] );

  Log( llInfo, Format( 'Loading manifest from %s', [ ExtractFileName( AManifestFile ) ] ) );

  var Content := TFile.ReadAllText( AManifestFile, TEncoding.UTF8 );
  var JsonVal := TJSONObject.ParseJSONValue( Content );

  if ( not Assigned( JsonVal ) ) then
    raise Exception.Create( 'Invalid JSON in manifest file' );

  try
    if ( not ( JsonVal is TJSONObject ) ) then
      raise Exception.Create( 'Manifest root must be a JSON object' );

    var Root := JsonVal as TJSONObject;

    // Schema version
    var SchemaVer := Root.GetValue<string>( 'schema_version', '' );

    if SchemaVer = '' then
      Log( llWarning, 'Missing schema_version field' )
    else
      Result.SchemaVersion := SchemaVer;

    // Last updated
    Result.LastUpdated := Root.GetValue<string>( 'last_updated', '' );

    // Supplier
    var SupplierObj: TJSONObject;

    if Root.TryGetValue<TJSONObject>( 'supplier', SupplierObj ) then
    begin
      Result.Supplier.Name := SupplierObj.GetValue<string>( 'name', '' );
      Result.Supplier.URL  := SupplierObj.GetValue<string>( 'url', '' );

      if Result.Supplier.Name = '' then
        Log( llWarning, 'Supplier name is empty' );
    end
    else
      Log( llWarning, 'Missing supplier object in manifest' );

    // Components array
    var CompArray: TJSONArray;

    if Root.TryGetValue<TJSONArray>( 'components', CompArray ) then
    begin
      var CompList := TList<TComponentEntry>.Create;
      try
        for var I := 0 to CompArray.Count - 1 do
        begin
          var CompObj := CompArray.Items[ I ] as TJSONObject;
          var Entry: TComponentEntry;

          Entry.Name       := CompObj.GetValue<string>( 'name', '' );
          Entry.Version    := CompObj.GetValue<string>( 'version', '' );
          Entry.Vendor     := CompObj.GetValue<string>( 'vendor', '' );
          Entry.VendorURL  := CompObj.GetValue<string>( 'vendor_url', '' );
          Entry.Licence    := CompObj.GetValue<string>( 'licence', '' );
          Entry.LicenceURL := CompObj.GetValue<string>( 'licence_url', '' );
          Entry.CompType   := CompObj.GetValue<string>( 'type', 'library' );
          Entry.Notes      := CompObj.GetValue<string>( 'notes', '' );

          // Parse units_prefix array
          var PrefixArray: TJSONArray;

          if CompObj.TryGetValue<TJSONArray>( 'units_prefix', PrefixArray ) then
          begin
            SetLength( Entry.Prefixes, PrefixArray.Count );

            for var J := 0 to PrefixArray.Count - 1 do
              Entry.Prefixes[ J ] := PrefixArray.Items[ J ].Value;
          end;

          // Parse units_exact array
          var ExactArray: TJSONArray;

          if CompObj.TryGetValue<TJSONArray>( 'units_exact', ExactArray ) then
          begin
            SetLength( Entry.ExactUnits, ExactArray.Count );

            for var J := 0 to ExactArray.Count - 1 do
              Entry.ExactUnits[ J ] := ExactArray.Items[ J ].Value;
          end;

          ValidateComponent( Entry, I );
          CompList.Add( Entry );
        end;

        Result.Components := CompList.ToArray;
      finally
        CompList.Free;
      end;

      Log( llInfo, Format( 'Loaded %d components from manifest', [ Length( Result.Components ) ] ) );
    end
    else
      Log( llWarning, 'No components array found in manifest' );

  finally
    JsonVal.Free;
  end;

end;

function TManifestLoader.Validate( const AManifestFile: string ): Boolean;
begin

  Result := True;

  try
    Load( AManifestFile );
  except
    on E: Exception do
    begin
      Log( llError, Format( 'Validation failed: %s', [ E.Message ] ) );
      Result := False;
    end;
  end;

end;

procedure TManifestLoader.ValidateComponent( const AComp: TComponentEntry; AIndex: Integer );
begin

  var Prefix := Format( 'Component[%d] "%s"', [ AIndex, AComp.Name ] );

  if AComp.Name = '' then
    Log( llWarning, Format( '%s: missing name', [ Prefix ] ) );

  if AComp.Version = '' then
    Log( llWarning, Format( '%s: missing version', [ Prefix ] ) );

  if AComp.Vendor = '' then
    Log( llWarning, Format( '%s: missing vendor', [ Prefix ] ) );

  if AComp.Licence = '' then
    Log( llWarning, Format( '%s: missing licence', [ Prefix ] ) );

  // Validate component type
  var ValidTypes: TArray<string> := [ 'library', 'framework', 'application' ];
  var TypeValid := False;

  for var VT in ValidTypes do
    if SameText( AComp.CompType, VT ) then
    begin
      TypeValid := True;
      Break;
    end;

  if ( not TypeValid ) then
    Log( llWarning, Format( '%s: type "%s" is not a valid CycloneDX type (expected library, framework, or application)', [ Prefix, AComp.CompType ] ) );

  // Check that at least one matching rule exists
  if ( Length( AComp.Prefixes ) = 0 ) and ( Length( AComp.ExactUnits ) = 0 ) then
    Log( llWarning, Format( '%s: no units_prefix or units_exact defined — component will not match any units', [ Prefix ] ) );

  // Validate minimum prefix length
  for var P in AComp.Prefixes do
    if P.Length < MinPrefixLength then
      Log( llWarning, Format( '%s: prefix "%s" is shorter than %d characters — risk of false matches. Use units_exact instead.',
        [ Prefix, P, MinPrefixLength ] ) );

end;

end.
