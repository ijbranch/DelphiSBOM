(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uManifestLoader.pas — Loads, validates and updates the components.json manifest
*)
unit uManifestLoader;

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.Generics.Collections,
  uTypes;

type
  /// <summary>
  ///   Raised when an existing components.json cannot be parsed, so it is never overwritten.
  /// </summary>
  EManifestError = class( Exception );

  /// <summary>
  ///   Loads and validates a components.json manifest file.
  /// </summary>
  TManifestLoader = class
  private
    FLog: TProc<TLogLevel, string>;

    procedure ValidateComponent( const AComp: TComponentEntry; AIndex: Integer );
    function ReadString( AObject: TJSONObject; const AName, ADefault, AContext: string ): string;
    function ReadStringArray( AObject: TJSONObject; const AName, AContext: string ): TArray<string>;
    function LoadRootForUpdate( const AManifestFile: string ): TJSONObject;
    function GetOrAddArray( ARoot: TJSONObject; const AName: string ): TJSONArray;
    procedure SetLastUpdated( ARoot: TJSONObject );
    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Loads a components.json file and returns the parsed manifest.
    ///   Logs warnings for schema issues that are non-fatal.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <returns>The parsed manifest.</returns>
    /// <exception cref="EManifestError">The file is missing, is not valid JSON, or its root is not an object.</exception>
    function Load( const AManifestFile: string ): TManifest;

    /// <summary>
    ///   Validates a manifest without loading it for SBOM generation.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <returns>True if valid (warnings are acceptable), False if errors were found.</returns>
    function Validate( const AManifestFile: string ): Boolean;

    /// <summary>
    ///   Appends confirmed discovered libraries to components.json, creating the file with a
    ///   default skeleton when it does not exist.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <param name="ALibraries">Libraries to add; only those with Confirmed = True are written.</param>
    /// <exception cref="EManifestError">The existing file cannot be parsed; it is left untouched.</exception>
    procedure SaveDiscoveredLibraries( const AManifestFile: string;
      const ALibraries: TArray<TDiscoveredLibrary> );

    /// <summary>
    ///   Adds unit names to the own_code_units array in components.json, creating the file with a
    ///   default skeleton when it does not exist.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <param name="AUnitNames">Unit names to add; names already present are skipped.</param>
    /// <exception cref="EManifestError">The existing file cannot be parsed; it is left untouched.</exception>
    procedure SaveOwnCodeUnits( const AManifestFile: string;
      const AUnitNames: TArray<string> );

    /// <summary>
    ///   Sets string fields of one component in components.json (adding a field that is missing) and
    ///   saves the file, keeping everything else. Used to apply accepted online-check suggestions.
    /// </summary>
    /// <param name="AManifestFile">Full path of components.json.</param>
    /// <param name="AComponentName">The component's name (case-insensitive; the first match).</param>
    /// <param name="AFields">The keys and values to set, e.g. ('licence', 'GPL-3.0-only').</param>
    /// <exception cref="EManifestError">The file is not valid JSON, or has no component of that name.</exception>
    procedure SetComponentFields( const AManifestFile, AComponentName: string; const AFields: TArray<TPair<string, string>> );

    /// <summary>
    ///   Returns the default components.json skeleton text (pretty-printed JSON).
    /// </summary>
    /// <returns>The skeleton, with schema_version, last_updated, an empty supplier and no components.</returns>
    class function DefaultManifestText: string;
  end;

implementation

uses
  System.IOUtils,
  uTextFiles;

/// <summary>
///   Today's date as ISO 8601 (yyyy-mm-dd), independent of the locale.
/// </summary>
function TodayISO: string;
begin

  Result            := FormatDateTime( 'yyyy"-"mm"-"dd', Now, TFormatSettings.Create( 'en-US' ) );

end;

{ TManifestLoader }

constructor TManifestLoader.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;

end;

procedure TManifestLoader.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

class function TManifestLoader.DefaultManifestText: string;
begin

  var Root          := TJSONObject.Create;
  try
    Root.AddPair( 'schema_version', '1.0' );
    Root.AddPair( 'last_updated', TodayISO );

    var Supplier    := TJSONObject.Create;
    Root.AddPair( 'supplier', Supplier );
    Supplier.AddPair( 'name', '' );
    Supplier.AddPair( 'url', '' );

    Root.AddPair( 'components', TJSONArray.Create );
    Result          := Root.Format;
  finally
    Root.Free;
  end;

end;

function TManifestLoader.ReadString( AObject: TJSONObject; const AName, ADefault, AContext: string ): string;
begin

  var Value         := AObject.GetValue( AName );

  if ( not Assigned( Value ) ) or ( Value is TJSONNull ) then Exit( ADefault );

  // Strings, numbers ("version": 3.7) and booleans are all usable as text
  if ( Value is TJSONString ) or ( Value is TJSONNumber ) or ( Value is TJSONBool ) then
    Exit( Value.Value );

  Log( llWarning, Format( '%s: "%s" should be a string — ignored', [ AContext, AName ] ) );
  Result            := ADefault;

end;

function TManifestLoader.ReadStringArray( AObject: TJSONObject; const AName, AContext: string ): TArray<string>;
begin

  Result            := nil;

  var Value         := AObject.GetValue( AName );

  if ( not Assigned( Value ) ) or ( Value is TJSONNull ) then Exit;

  if ( not ( Value is TJSONArray ) ) then
  begin
    Log( llWarning, Format( '%s: "%s" should be an array — ignored', [ AContext, AName ] ) );
    Exit;
  end;

  var List          := TList<string>.Create;
  try
    for var Item in TJSONArray( Value ) do
    begin
      // An empty entry would match every unit as a prefix — never accept one
      if ( Item is TJSONString ) and ( Trim( Item.Value ) <> '' ) then
        List.Add( Trim( Item.Value ) )
      else
        Log( llWarning, Format( '%s: skipping empty or non-string entry in "%s"', [ AContext, AName ] ) );
    end;

    Result          := List.ToArray;
  finally
    List.Free;
  end;

end;

function TManifestLoader.Load( const AManifestFile: string ): TManifest;
begin

  Result            := Default( TManifest );

  if ( not FileExists( AManifestFile ) ) then
    raise EManifestError.CreateFmt( 'Manifest file not found: %s', [ AManifestFile ] );

  Log( llInfo, Format( 'Loading manifest from %s', [ ExtractFileName( AManifestFile ) ] ) );

  var Content       := ReadTextFile( AManifestFile );
  var JsonVal: TJSONValue;

  // The parser's own message says where: "... Path 'components', line 4, position 3"
  try
    JsonVal         := TJSONObject.ParseJSONValue( Content, False, True );
  except
    on E: EJSONParseException do
      raise EManifestError.CreateFmt( '%s is not valid JSON: %s', [ AManifestFile, E.Message ] );
  end;

  if ( not Assigned( JsonVal ) ) then
    raise EManifestError.CreateFmt( '%s is not valid JSON', [ AManifestFile ] );

  try
    if ( not ( JsonVal is TJSONObject ) ) then
      raise EManifestError.Create( 'Manifest root must be a JSON object' );

    var Root        := JsonVal as TJSONObject;

    // Schema version
    Result.SchemaVersion := ReadString( Root, 'schema_version', '', 'Manifest' );

    if Result.SchemaVersion = '' then
      Log( llWarning, 'Missing schema_version field' )
    else if Result.SchemaVersion <> '1.0' then
      Log( llWarning, Format( 'schema_version "%s" is not supported (expected "1.0") — reading it as 1.0', [ Result.SchemaVersion ] ) );

    // Last updated
    Result.LastUpdated := ReadString( Root, 'last_updated', '', 'Manifest' );

    if Result.LastUpdated = '' then
      Log( llWarning, 'Missing last_updated field' );

    // Supplier
    var SupplierVal := Root.GetValue( 'supplier' );

    if SupplierVal is TJSONObject then
    begin
      Result.Supplier.Name := ReadString( TJSONObject( SupplierVal ), 'name', '', 'Supplier' );
      Result.Supplier.URL := ReadString( TJSONObject( SupplierVal ), 'url', '', 'Supplier' );

      if Result.Supplier.Name = '' then
        Log( llWarning, 'Supplier name is empty' );
    end
    else
      Log( llWarning, 'Missing supplier object in manifest' );

    // Components array
    var CompVal     := Root.GetValue( 'components' );

    if CompVal is TJSONArray then
    begin
      var CompArray := TJSONArray( CompVal );
      var CompList  := TList<TComponentEntry>.Create;
      try
        for var I := 0 to CompArray.Count - 1 do
        begin
          if ( not ( CompArray.Items[ I ] is TJSONObject ) ) then
          begin
            Log( llWarning, Format( 'Component[%d] is not an object — skipped', [ I ] ) );
            Continue;
          end;

          var CompObj := CompArray.Items[ I ] as TJSONObject;
          var Context := Format( 'Component[%d]', [ I ] );
          var Entry := Default( TComponentEntry );

          Entry.Name := ReadString( CompObj, 'name', '', Context );
          Entry.Version := ReadString( CompObj, 'version', '', Context );
          Entry.Vendor := ReadString( CompObj, 'vendor', '', Context );
          Entry.VendorURL := ReadString( CompObj, 'vendor_url', '', Context );
          Entry.Licence := ReadString( CompObj, 'licence', '', Context );
          Entry.LicenceURL := ReadString( CompObj, 'licence_url', '', Context );
          Entry.CompType := ReadString( CompObj, 'type', 'library', Context );
          Entry.Notes := ReadString( CompObj, 'notes', '', Context );
          Entry.Prefixes := ReadStringArray( CompObj, 'units_prefix', Context );
          Entry.ExactUnits := ReadStringArray( CompObj, 'units_exact', Context );

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

    // own_code_units and own_code_prefixes
    Result.OwnCodeUnits := ReadStringArray( Root, 'own_code_units', 'Manifest' );

    if Length( Result.OwnCodeUnits ) > 0 then
      Log( llInfo, Format( 'Loaded %d own-code unit exclusions', [ Length( Result.OwnCodeUnits ) ] ) );

    Result.OwnCodePrefixes := ReadStringArray( Root, 'own_code_prefixes', 'Manifest' );

    for var P in Result.OwnCodePrefixes do
      if P.Length < MinPrefixLength then
        Log( llWarning, Format( 'own_code_prefixes: prefix "%s" is shorter than %d characters — risk of classifying third-party units as own code',
            [ P, MinPrefixLength ] ) );

    if Length( Result.OwnCodePrefixes ) > 0 then
      Log( llInfo, Format( 'Loaded %d own-code prefix rules', [ Length( Result.OwnCodePrefixes ) ] ) );
  finally
    JsonVal.Free;
  end;

end;

function TManifestLoader.Validate( const AManifestFile: string ): Boolean;
begin

  Result            := True;

  try
    Load( AManifestFile );
  except
    on E: EManifestError do
    begin
      Log( llError, Format( 'Validation failed: %s', [ E.Message ] ) );
      Result        := False;
    end;
    on E: EInOutError do
    begin
      Log( llError, Format( 'Validation failed: %s', [ E.Message ] ) );
      Result        := False;
    end;
    on E: EStreamError do
    begin
      Log( llError, Format( 'Validation failed: %s', [ E.Message ] ) );
      Result        := False;
    end;
  end;

end;

procedure TManifestLoader.ValidateComponent( const AComp: TComponentEntry; AIndex: Integer );
begin

  var Prefix        := Format( 'Component[%d] "%s"', [ AIndex, AComp.Name ] );

  if AComp.Name = '' then
    Log( llWarning, Format( '%s: missing name', [ Prefix ] ) );

  if AComp.Version = '' then
    Log( llWarning, Format( '%s: missing version', [ Prefix ] ) );

  if AComp.Vendor = '' then
    Log( llWarning, Format( '%s: missing vendor', [ Prefix ] ) );

  if AComp.Licence = '' then
    Log( llWarning, Format( '%s: missing licence', [ Prefix ] ) )
  else
  begin
    var Normalised  := '';

    // Commercial and Proprietary are the standard names for licences that have no SPDX identifier
    if ( ClassifyLicence( AComp.Licence, Normalised ) = lkName ) and ( not SameText( Normalised, 'Commercial' ) ) and
      ( not SameText( Normalised, 'Proprietary' ) ) then
      Log( llWarning, Format( '%s: licence "%s" is not a recognised SPDX identifier — it will be written as a licence name',
          [ Prefix, AComp.Licence ] ) );
  end;

  // Validate component type (the SBOM builder lower-cases it, and falls back to library)
  var ValidTypes: TArray<string> := [ 'library', 'framework', 'application' ];
  var TypeValid     := False;

  for var VT in ValidTypes do
    if SameText( AComp.CompType, VT ) then
    begin
      TypeValid     := True;
      Break;
    end;

  if ( not TypeValid ) then
    Log( llWarning, Format( '%s: type "%s" is not a valid CycloneDX type (expected library, framework, or application) — library will be used',
        [ Prefix, AComp.CompType ] ) );

  // Check that at least one matching rule exists
  if ( Length( AComp.Prefixes ) = 0 ) and ( Length( AComp.ExactUnits ) = 0 ) then
    Log( llWarning, Format( '%s: no units_prefix or units_exact defined — component will not match any units', [ Prefix ] ) );

  // Validate minimum prefix length
  for var P in AComp.Prefixes do
    if P.Length < MinPrefixLength then
      Log( llWarning, Format( '%s: prefix "%s" is shorter than %d characters — risk of false matches. Use units_exact instead.',
          [ Prefix, P, MinPrefixLength ] ) );

end;

// ---------------------------------------------------------------------------
//  Updating the manifest
// ---------------------------------------------------------------------------

function TManifestLoader.LoadRootForUpdate( const AManifestFile: string ): TJSONObject;
begin

  if ( not FileExists( AManifestFile ) ) then
  begin
    Log( llInfo, Format( 'Creating %s', [ AManifestFile ] ) );
    Exit( TJSONObject.ParseJSONValue( DefaultManifestText ) as TJSONObject );
  end;

  var Content       := ReadTextFile( AManifestFile );

  if Trim( Content ) = '' then
    Exit( TJSONObject.ParseJSONValue( DefaultManifestText ) as TJSONObject );

  // Never replace a file that does not parse: that would silently discard every entry in it
  var Parsed        := TJSONObject.ParseJSONValue( Content );

  if ( not Assigned( Parsed ) ) or ( not ( Parsed is TJSONObject ) ) then
  begin
    Parsed.Free;
    raise EManifestError.CreateFmt( '%s is not valid JSON — fix it (or run Validate Manifest) before saving. The file was not changed.',
      [ AManifestFile ] );
  end;

  Result            := Parsed as TJSONObject;

end;

function TManifestLoader.GetOrAddArray( ARoot: TJSONObject; const AName: string ): TJSONArray;
begin

  var Value         := ARoot.GetValue( AName );

  if Assigned( Value ) then
  begin
    if ( not ( Value is TJSONArray ) ) then
      raise EManifestError.CreateFmt( '"%s" in the manifest is not an array — fix it before saving. The file was not changed.', [ AName ] );

    Exit( TJSONArray( Value ) );
  end;

  Result            := TJSONArray.Create;
  ARoot.AddPair( AName, Result );

end;

procedure TManifestLoader.SetLastUpdated( ARoot: TJSONObject );
begin

  // Replace the value in place so the key keeps its position in the file
  var Pair          := ARoot.Get( 'last_updated' );

  if Assigned( Pair ) then
    Pair.JsonValue  := TJSONString.Create( TodayISO )
  else
    ARoot.AddPair( 'last_updated', TodayISO );

end;

procedure TManifestLoader.SaveDiscoveredLibraries( const AManifestFile: string;
  const ALibraries: TArray<TDiscoveredLibrary> );
begin

  var Root          := LoadRootForUpdate( AManifestFile );
  try
    var CompArray   := GetOrAddArray( Root, 'components' );
    var Added       := 0;

    // Add each confirmed library (skip duplicates by name)
    for var Lib in ALibraries do
    begin
      if ( not Lib.Confirmed ) then Continue;

      if Trim( Lib.Name ) = '' then
      begin
        Log( llWarning, Format( 'Skipping a library with no name (directory %s)', [ Lib.Directory ] ) );
        Continue;
      end;

      // Check if a component with the same name already exists
      var AlreadyExists := False;

      for var K := 0 to CompArray.Count - 1 do
        if ( CompArray.Items[ K ] is TJSONObject ) then
          if SameText( ReadString( CompArray.Items[ K ] as TJSONObject, 'name', '', 'Component' ), Lib.Name ) then
          begin
            AlreadyExists := True;
            Break;
          end;

      if AlreadyExists then
      begin
        Log( llInfo, Format( 'Component "%s" already exists in manifest — skipping', [ Lib.Name ] ) );
        Continue;
      end;

      var CompObj   := TJSONObject.Create;
      CompArray.AddElement( CompObj );

      CompObj.AddPair( 'name', Lib.Name );
      CompObj.AddPair( 'version', Lib.Version );
      CompObj.AddPair( 'vendor', Lib.Vendor );
      CompObj.AddPair( 'licence', Lib.Licence );
      CompObj.AddPair( 'type', 'library' );

      // Decide between units_prefix and units_exact
      if ( Lib.SuggestedPrefix.Length >= MinPrefixLength ) then
      begin
        var PrefixArr := TJSONArray.Create;
        CompObj.AddPair( 'units_prefix', PrefixArr );
        PrefixArr.Add( Lib.SuggestedPrefix );
      end
      else
      begin
        var ExactArr := TJSONArray.Create;
        CompObj.AddPair( 'units_exact', ExactArr );

        for var U in Lib.Units do
          ExactArr.Add( U );
      end;

      Inc( Added );
      Log( llInfo, Format( 'Added component "%s" to manifest', [ Lib.Name ] ) );
    end;

    SetLastUpdated( Root );
    WriteTextFileAtomic( AManifestFile, Root.Format );

    Log( llInfo, Format( 'Manifest saved to %s (%d components added)', [ AManifestFile, Added ] ) );
  finally
    Root.Free;
  end;

end;

procedure TManifestLoader.SetComponentFields( const AManifestFile, AComponentName: string; const AFields: TArray<TPair<string, string>> );
begin

  var Root          := LoadRootForUpdate( AManifestFile );
  try
    var CompArray   := GetOrAddArray( Root, 'components' );
    var Target: TJSONObject := nil;

    for var I := 0 to CompArray.Count - 1 do
      if ( CompArray.Items[ I ] is TJSONObject ) and
        SameText( ReadString( TJSONObject( CompArray.Items[ I ] ), 'name', '', 'Component' ), AComponentName ) then
      begin
        Target      := TJSONObject( CompArray.Items[ I ] );
        Break;
      end;

    if ( not Assigned( Target ) ) then
      raise EManifestError.CreateFmt( '%s has no component named "%s"', [ AManifestFile, AComponentName ] );

    // Replace in place, so the key keeps its position; add a missing key at the end
    for var Field in AFields do
    begin
      var Pair      := Target.Get( Field.Key );

      if Assigned( Pair ) then
        Pair.JsonValue := TJSONString.Create( Field.Value )
      else
        Target.AddPair( Field.Key, Field.Value );

      Log( llInfo, Format( 'components.json: %s %s set to "%s"', [ AComponentName, Field.Key, Field.Value ] ) );
    end;

    SetLastUpdated( Root );
    WriteTextFileAtomic( AManifestFile, Root.Format );
  finally
    Root.Free;
  end;

end;

procedure TManifestLoader.SaveOwnCodeUnits( const AManifestFile: string;
  const AUnitNames: TArray<string> );
begin

  var Root          := LoadRootForUpdate( AManifestFile );
  try
    var OwnCodeArray := GetOrAddArray( Root, 'own_code_units' );
    var Added       := 0;

    for var UnitName in AUnitNames do
    begin
      if Trim( UnitName ) = '' then Continue;

      var AlreadyExists := False;

      for var I := 0 to OwnCodeArray.Count - 1 do
        if SameText( OwnCodeArray.Items[ I ].Value, UnitName ) then
        begin
          AlreadyExists := True;
          Break;
        end;

      if ( not AlreadyExists ) then
      begin
        OwnCodeArray.Add( UnitName );
        Inc( Added );
      end;
    end;

    SetLastUpdated( Root );
    WriteTextFileAtomic( AManifestFile, Root.Format );

    Log( llInfo, Format( 'Saved %d new own-code units to manifest (%d already present)', [ Added, Length( AUnitNames ) - Added ] ) );
  finally
    Root.Free;
  end;

end;

end.

