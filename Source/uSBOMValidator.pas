(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMValidator.pas — Structural check of a written CycloneDX 1.5 JSON SBOM
  Idea after DX.Comply's schema validator (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uSBOMValidator;

interface

uses
  System.SysUtils;

/// <summary>
///   Checks a CycloneDX 1.5 JSON document against the rules of the schema that DelphiSBOM's output
///   can break. It is not a full schema validation; run an official validator for that.
/// </summary>
/// <param name="AJson">The document text.</param>
/// <returns>One message per problem, each naming its JSON path; empty when the document passes.</returns>
function CheckSBOM( const AJson: string ): TArray<string>;

implementation

uses
  System.JSON, System.RegularExpressions, System.Generics.Collections,
  uTypes;

const
  /// <summary>The CycloneDX 1.5 component type enum (case-sensitive).</summary>
  ComponentTypes    : array[ 0..11 ] of string = (
    'application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device',
    'device-driver', 'firmware', 'file', 'machine-learning-model', 'data'
    );

  /// <summary>The CycloneDX 1.5 composition aggregate enum.</summary>
  AggregateTypes    : array[ 0..9 ] of string = (
    'complete', 'incomplete', 'incomplete_first_party_only', 'incomplete_first_party_proprietary_only',
    'incomplete_first_party_opensource_only', 'incomplete_third_party_only', 'incomplete_third_party_proprietary_only',
    'incomplete_third_party_opensource_only', 'unknown', 'not_specified'
    );

  /// <summary>The CycloneDX 1.5 external reference type enum.</summary>
  ExternalReferenceTypes: array[ 0..38 ] of string = (
    'vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation',
    'support', 'distribution', 'distribution-intake', 'license', 'build-meta', 'build-system', 'release-notes',
    'security-contact', 'model-card', 'log', 'configuration', 'evidence', 'formulation', 'attestation',
    'threat-model', 'adversary-model', 'risk-assessment', 'vulnerability-assertion', 'exploitability-statement',
    'pentest-report', 'static-analysis-report', 'dynamic-analysis-report', 'runtime-analysis-report',
    'component-analysis-report', 'maturity-report', 'certification-report', 'codified-infrastructure',
    'quality-metrics', 'poam', 'other'
    );

type
  /// <summary>
  ///   One check of one document: collects the problems and the bom-refs it has seen.
  /// </summary>
  TSBOMCheck = class
  private
    FErrors: TList<string>;
    FRefs: TDictionary<string, Boolean>;

    procedure Error( const APath, AMessage: string );
    function InList( const AValue: string; const AList: array of string ): Boolean;
    procedure CheckComponent( const APath: string; AComponent: TJSONObject );
    procedure CheckComponents( const APath: string; AArray: TJSONValue );
    procedure CheckLicences( const APath: string; AValue: TJSONValue );
    procedure CheckHashes( const APath: string; AValue: TJSONValue );
    procedure CheckExternalReferences( const APath: string; AValue: TJSONValue );
    procedure CheckDependencies( AValue: TJSONValue );
    procedure CheckCompositions( AValue: TJSONValue );
  public
    constructor Create;
    destructor Destroy; override;

    procedure Run( const AJson: string );

    property Errors: TList<string> read FErrors;
  end;

/// <summary>The value of AName in AObject when it is a string, else ''; AFound reports whether the key exists.</summary>
function StringField( AObject: TJSONObject; const AName: string; out AFound: Boolean ): string;
begin

  Result            := '';
  var Value         := AObject.GetValue( AName );
  AFound            := Assigned( Value );

  if Value is TJSONString then
    Result          := TJSONString( Value ).Value;

end;

constructor TSBOMCheck.Create;
begin

  inherited Create;
  FErrors           := TList<string>.Create;
  FRefs             := TDictionary<string, Boolean>.Create;

end;

destructor TSBOMCheck.Destroy;
begin

  FRefs.Free;
  FErrors.Free;
  inherited;

end;

procedure TSBOMCheck.Error( const APath, AMessage: string );
begin

  FErrors.Add( APath + ': ' + AMessage );

end;

function TSBOMCheck.InList( const AValue: string; const AList: array of string ): Boolean;
begin

  for var S in AList do
    if S = AValue then
      Exit( True );

  Result            := False;

end;

procedure TSBOMCheck.Run( const AJson: string );
begin

  var Parsed        := TJSONObject.ParseJSONValue( AJson );
  try
    if ( not ( Parsed is TJSONObject ) ) then
    begin
      Error( '$', 'not a JSON object' );
      Exit;
    end;

    var Root        := TJSONObject( Parsed );
    var Found: Boolean;

    if StringField( Root, 'bomFormat', Found ) <> 'CycloneDX' then
      Error( 'bomFormat', 'must be "CycloneDX"' );

    if StringField( Root, 'specVersion', Found ) <> '1.5' then
      Error( 'specVersion', 'must be "1.5"' );

    var Serial      := StringField( Root, 'serialNumber', Found );

    if Found and ( not TRegEx.IsMatch( Serial, '^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' ) ) then
      Error( 'serialNumber', Format( '"%s" is not urn:uuid:<RFC 4122 UUID>', [ Serial ] ) );

    var Version     := Root.GetValue( 'version' );

    if Assigned( Version ) and ( ( not ( Version is TJSONNumber ) ) or ( TJSONNumber( Version ).AsDouble < 1 ) or
      ( Frac( TJSONNumber( Version ).AsDouble ) <> 0 ) ) then
      Error( 'version', 'must be an integer of at least 1' );

    var Metadata    := Root.GetValue( 'metadata' );

    if Metadata is TJSONObject then
    begin
      var Timestamp := StringField( TJSONObject( Metadata ), 'timestamp', Found );

      if Found and ( not TRegEx.IsMatch( Timestamp, '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$' ) ) then
        Error( 'metadata.timestamp', Format( '"%s" is not an ISO 8601 date-time', [ Timestamp ] ) );

      var Tools     := TJSONObject( Metadata ).GetValue( 'tools' );

      if Tools is TJSONObject then
        CheckComponents( 'metadata.tools.components', TJSONObject( Tools ).GetValue( 'components' ) );

      var Component := TJSONObject( Metadata ).GetValue( 'component' );

      if Component is TJSONObject then
        CheckComponent( 'metadata.component', TJSONObject( Component ) );
    end;

    CheckComponents( 'components', Root.GetValue( 'components' ) );

    // Every bom-ref has been collected; dependencies and compositions may now name any of them
    CheckDependencies( Root.GetValue( 'dependencies' ) );
    CheckCompositions( Root.GetValue( 'compositions' ) );
  finally
    Parsed.Free;
  end;

end;

procedure TSBOMCheck.CheckComponents( const APath: string; AArray: TJSONValue );
begin

  if ( not Assigned( AArray ) ) then Exit;

  if ( not ( AArray is TJSONArray ) ) then
  begin
    Error( APath, 'must be an array' );
    Exit;
  end;

  for var I := 0 to TJSONArray( AArray ).Count - 1 do
  begin
    var Item        := TJSONArray( AArray ).Items[ I ];
    var ItemPath    := Format( '%s[%d]', [ APath, I ] );

    if Item is TJSONObject then
      CheckComponent( ItemPath, TJSONObject( Item ) )
    else
      Error( ItemPath, 'must be an object' );
  end;

end;

procedure TSBOMCheck.CheckComponent( const APath: string; AComponent: TJSONObject );
begin

  var Found: Boolean;
  var CompType      := StringField( AComponent, 'type', Found );

  if ( not InList( CompType, ComponentTypes ) ) then
    Error( APath + '.type', Format( '"%s" is not a CycloneDX 1.5 component type', [ CompType ] ) );

  if Trim( StringField( AComponent, 'name', Found ) ) = '' then
    Error( APath + '.name', 'is missing or empty' );

  var Ref           := StringField( AComponent, 'bom-ref', Found );

  if Found then
  begin
    if Ref = '' then
      Error( APath + '.bom-ref', 'is empty' )
    else if ( not FRefs.TryAdd( Ref, True ) ) then
      Error( APath + '.bom-ref', Format( '"%s" is used more than once', [ Ref ] ) );
  end;

  var Purl          := StringField( AComponent, 'purl', Found );

  if Found and ( not TRegEx.IsMatch( Purl, '^pkg:[a-z][a-z0-9.+-]*/[^/]' ) ) then
    Error( APath + '.purl', Format( '"%s" is not a package URL (pkg:<type>/<name>)', [ Purl ] ) );

  CheckLicences( APath + '.licenses', AComponent.GetValue( 'licenses' ) );
  CheckHashes( APath + '.hashes', AComponent.GetValue( 'hashes' ) );
  CheckExternalReferences( APath + '.externalReferences', AComponent.GetValue( 'externalReferences' ) );

  var Supplier      := AComponent.GetValue( 'supplier' );

  if Assigned( Supplier ) and ( ( not ( Supplier is TJSONObject ) ) or
    ( Assigned( TJSONObject( Supplier ).GetValue( 'url' ) ) and ( not ( TJSONObject( Supplier ).GetValue( 'url' ) is TJSONArray ) ) ) or
    ( Assigned( TJSONObject( Supplier ).GetValue( 'contact' ) ) and ( not ( TJSONObject( Supplier ).GetValue( 'contact' ) is TJSONArray ) ) ) ) then
    Error( APath + '.supplier', 'must be an object whose url and contact are arrays' );

  CheckComponents( APath + '.components', AComponent.GetValue( 'components' ) );

end;

procedure TSBOMCheck.CheckLicences( const APath: string; AValue: TJSONValue );
begin

  if ( not Assigned( AValue ) ) then Exit;

  if ( not ( AValue is TJSONArray ) ) then
  begin
    Error( APath, 'must be an array' );
    Exit;
  end;

  for var I := 0 to TJSONArray( AValue ).Count - 1 do
  begin
    var ItemPath    := Format( '%s[%d]', [ APath, I ] );
    var Item        := TJSONArray( AValue ).Items[ I ];

    if ( not ( Item is TJSONObject ) ) then
    begin
      Error( ItemPath, 'must be an object' );
      Continue;
    end;

    var Licence     := TJSONObject( Item ).GetValue( 'license' );
    var Expression  := TJSONObject( Item ).GetValue( 'expression' );

    // Exactly one of the two
    if Assigned( Licence ) = Assigned( Expression ) then
    begin
      Error( ItemPath, 'must hold exactly one of license and expression' );
      Continue;
    end;

    if Assigned( Expression ) then
    begin
      if ( not ( Expression is TJSONString ) ) or ( Trim( TJSONString( Expression ).Value ) = '' ) then
        Error( ItemPath + '.expression', 'must be a non-empty string' );

      Continue;
    end;

    if ( not ( Licence is TJSONObject ) ) then
    begin
      Error( ItemPath + '.license', 'must be an object' );
      Continue;
    end;

    var HasId: Boolean;
    var HasName: Boolean;
    var Id          := StringField( TJSONObject( Licence ), 'id', HasId );
    StringField( TJSONObject( Licence ), 'name', HasName );

    if HasId = HasName then
      Error( ItemPath + '.license', 'must hold exactly one of id and name' )
    else if HasId then
    begin
      // license.id is the SPDX enum, case-sensitive
      var Canonical := '';

      if ( ClassifyLicence( Id, Canonical ) <> lkSPDX ) or ( Canonical <> Id ) then
        Error( ItemPath + '.license.id', Format( '"%s" is not an SPDX licence identifier as spelt in the SPDX list', [ Id ] ) );
    end;
  end;

end;

procedure TSBOMCheck.CheckHashes( const APath: string; AValue: TJSONValue );
begin

  if ( not Assigned( AValue ) ) then Exit;

  if ( not ( AValue is TJSONArray ) ) then
  begin
    Error( APath, 'must be an array' );
    Exit;
  end;

  for var I := 0 to TJSONArray( AValue ).Count - 1 do
  begin
    var ItemPath    := Format( '%s[%d]', [ APath, I ] );
    var Item        := TJSONArray( AValue ).Items[ I ];

    if ( not ( Item is TJSONObject ) ) then
    begin
      Error( ItemPath, 'must be an object' );
      Continue;
    end;

    var Found: Boolean;
    var Alg         := StringField( TJSONObject( Item ), 'alg', Found );
    var Content     := StringField( TJSONObject( Item ), 'content', Found );

    if ( Alg = '' ) or ( NormaliseHashAlgorithm( Alg ) <> Alg ) then
    begin
      Error( ItemPath + '.alg', Format( '"%s" is not a CycloneDX 1.5 hash algorithm', [ Alg ] ) );
      Continue;
    end;

    // Hex digits of the algorithm's digest length; BLAKE3 has no fixed length
    var Pattern     := '^[a-fA-F0-9]+$';

    if Alg = 'MD5' then
      Pattern       := '^[a-fA-F0-9]{32}$'
    else if Alg = 'SHA-1' then
      Pattern       := '^[a-fA-F0-9]{40}$'
    else if Alg.EndsWith( '-256' ) then
      Pattern       := '^[a-fA-F0-9]{64}$'
    else if Alg.EndsWith( '-384' ) then
      Pattern       := '^[a-fA-F0-9]{96}$'
    else if Alg.EndsWith( '-512' ) then
      Pattern       := '^[a-fA-F0-9]{128}$';

    if ( not TRegEx.IsMatch( Content, Pattern ) ) then
      Error( ItemPath + '.content', Format( 'is not a %s digest in hex', [ Alg ] ) );
  end;

end;

procedure TSBOMCheck.CheckExternalReferences( const APath: string; AValue: TJSONValue );
begin

  if ( not Assigned( AValue ) ) then Exit;

  if ( not ( AValue is TJSONArray ) ) then
  begin
    Error( APath, 'must be an array' );
    Exit;
  end;

  for var I := 0 to TJSONArray( AValue ).Count - 1 do
  begin
    var ItemPath    := Format( '%s[%d]', [ APath, I ] );
    var Item        := TJSONArray( AValue ).Items[ I ];

    if ( not ( Item is TJSONObject ) ) then
    begin
      Error( ItemPath, 'must be an object' );
      Continue;
    end;

    var Found: Boolean;
    var RefType     := StringField( TJSONObject( Item ), 'type', Found );

    if ( not InList( RefType, ExternalReferenceTypes ) ) then
      Error( ItemPath + '.type', Format( '"%s" is not a CycloneDX 1.5 external reference type', [ RefType ] ) );

    if Trim( StringField( TJSONObject( Item ), 'url', Found ) ) = '' then
      Error( ItemPath + '.url', 'is missing or empty' );
  end;

end;

procedure TSBOMCheck.CheckDependencies( AValue: TJSONValue );
begin

  if ( not Assigned( AValue ) ) then Exit;

  if ( not ( AValue is TJSONArray ) ) then
  begin
    Error( 'dependencies', 'must be an array' );
    Exit;
  end;

  var Owners        := TDictionary<string, Boolean>.Create;
  try
    for var I := 0 to TJSONArray( AValue ).Count - 1 do
    begin
      var ItemPath  := Format( 'dependencies[%d]', [ I ] );
      var Item      := TJSONArray( AValue ).Items[ I ];

      if ( not ( Item is TJSONObject ) ) then
      begin
        Error( ItemPath, 'must be an object' );
        Continue;
      end;

      var Found: Boolean;
      var Ref       := StringField( TJSONObject( Item ), 'ref', Found );

      if ( not FRefs.ContainsKey( Ref ) ) then
        Error( ItemPath + '.ref', Format( '"%s" is not the bom-ref of any component', [ Ref ] ) )
      else if ( not Owners.TryAdd( Ref, True ) ) then
        Error( ItemPath + '.ref', Format( '"%s" has more than one dependency entry', [ Ref ] ) );

      var DependsOn := TJSONObject( Item ).GetValue( 'dependsOn' );

      if ( not Assigned( DependsOn ) ) then Continue;

      if ( not ( DependsOn is TJSONArray ) ) then
      begin
        Error( ItemPath + '.dependsOn', 'must be an array' );
        Continue;
      end;

      for var J := 0 to TJSONArray( DependsOn ).Count - 1 do
      begin
        var Target  := TJSONArray( DependsOn ).Items[ J ].Value;

        if ( not FRefs.ContainsKey( Target ) ) then
          Error( Format( '%s.dependsOn[%d]', [ ItemPath, J ] ), Format( '"%s" is not the bom-ref of any component', [ Target ] ) );
      end;
    end;
  finally
    Owners.Free;
  end;

end;

procedure TSBOMCheck.CheckCompositions( AValue: TJSONValue );
begin

  if ( not Assigned( AValue ) ) then Exit;

  if ( not ( AValue is TJSONArray ) ) then
  begin
    Error( 'compositions', 'must be an array' );
    Exit;
  end;

  for var I := 0 to TJSONArray( AValue ).Count - 1 do
  begin
    var ItemPath    := Format( 'compositions[%d]', [ I ] );
    var Item        := TJSONArray( AValue ).Items[ I ];

    if ( not ( Item is TJSONObject ) ) then
    begin
      Error( ItemPath, 'must be an object' );
      Continue;
    end;

    var Found: Boolean;
    var Aggregate   := StringField( TJSONObject( Item ), 'aggregate', Found );

    if ( not InList( Aggregate, AggregateTypes ) ) then
      Error( ItemPath + '.aggregate', Format( '"%s" is not a CycloneDX 1.5 composition aggregate', [ Aggregate ] ) );

    // assemblies and dependencies both list bom-refs of this document
    var Fields: TArray<string> := [ 'assemblies', 'dependencies' ];

    for var Field in Fields do
    begin
      var Refs      := TJSONObject( Item ).GetValue( Field );

      if ( not Assigned( Refs ) ) then Continue;

      if ( not ( Refs is TJSONArray ) ) then
      begin
        Error( ItemPath + '.' + Field, 'must be an array' );
        Continue;
      end;

      for var J := 0 to TJSONArray( Refs ).Count - 1 do
        if ( not FRefs.ContainsKey( TJSONArray( Refs ).Items[ J ].Value ) ) then
          Error( Format( '%s.%s[%d]', [ ItemPath, Field, J ] ),
            Format( '"%s" is not the bom-ref of any component', [ TJSONArray( Refs ).Items[ J ].Value ] ) );
    end;
  end;

end;

function CheckSBOM( const AJson: string ): TArray<string>;
begin

  var Check         := TSBOMCheck.Create;
  try
    Check.Run( AJson );
    Result          := Check.Errors.ToArray;
  finally
    Check.Free;
  end;

end;

end.
