(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMValidator.pas — Structural check of a written CycloneDX 1.6 JSON SBOM, and its conformance to BSI TR-03183-2
  Idea after DX.Comply's schema validator (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uSBOMValidator;

interface

uses
  System.SysUtils;

/// <summary>
///   Checks a CycloneDX 1.6 JSON document against the rules of the schema that DelphiSBOM's output
///   can break. It is not a full schema validation; run an official validator for that.
/// </summary>
/// <param name="AJson">The document text.</param>
/// <returns>One message per problem, each naming its JSON path; empty when the document passes.</returns>
function CheckSBOM( const AJson: string ): TArray<string>;

/// <summary>
///   Checks a CycloneDX JSON document against the required data fields of BSI TR-03183-2 v2.1.0 (sections 4, 5.2.1
///   and 5.2.2, licence rules of 6.1, no vulnerabilities by 3.1).  The application component and every top-level
///   component are checked; the file fields (filename, SHA-512, executable, archive and structured properties) apply
///   to the application and to any component that names a file, since a statically linked library is a logical
///   component without file data (TR 3.2.1, 3.2.2).  Nested evidence components are parts of their parent and are
///   not checked.
/// </summary>
/// <param name="AJson">The document text.</param>
/// <returns>One finding per unmet requirement, each led by its rule ID (TR-&lt;section&gt;-&lt;field&gt;) and naming the
///   component; empty when the document conforms.</returns>
function CheckTR03183( const AJson: string ): TArray<string>;

implementation

uses
  System.JSON, System.RegularExpressions, System.Generics.Collections,
  uTypes;

const
  /// <summary>The CycloneDX 1.6 component type enum (case-sensitive).</summary>
  ComponentTypes    : array[ 0..12 ] of string = (
    'application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device',
    'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset'
    );

  /// <summary>The CycloneDX 1.6 composition aggregate enum (unchanged from 1.5).</summary>
  AggregateTypes    : array[ 0..9 ] of string = (
    'complete', 'incomplete', 'incomplete_first_party_only', 'incomplete_first_party_proprietary_only',
    'incomplete_first_party_opensource_only', 'incomplete_third_party_only', 'incomplete_third_party_proprietary_only',
    'incomplete_third_party_opensource_only', 'unknown', 'not_specified'
    );

  /// <summary>The CycloneDX 1.6 external reference type enum.</summary>
  ExternalReferenceTypes: array[ 0..42 ] of string = (
    'vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation',
    'support', 'source-distribution', 'distribution', 'distribution-intake', 'license', 'build-meta', 'build-system',
    'release-notes', 'security-contact', 'model-card', 'log', 'configuration', 'evidence', 'formulation', 'attestation',
    'threat-model', 'adversary-model', 'risk-assessment', 'vulnerability-assertion', 'exploitability-statement',
    'pentest-report', 'static-analysis-report', 'dynamic-analysis-report', 'runtime-analysis-report',
    'component-analysis-report', 'maturity-report', 'certification-report', 'codified-infrastructure',
    'quality-metrics', 'poam', 'electronic-signature', 'digital-signature', 'rfc-9116', 'other'
    );

  /// <summary>The CycloneDX 1.6 licence acknowledgement enum.</summary>
  LicenceAcknowledgements: array[ 0..1 ] of string = ( 'declared', 'concluded' );

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
    procedure CheckAcknowledgement( const APath: string; AOwner: TJSONObject );
    procedure CheckHashes( const APath: string; AValue: TJSONValue );
    procedure CheckExternalReferences( const APath: string; AValue: TJSONValue );
    procedure CheckEntity( const APath: string; AValue: TJSONValue );
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

    if StringField( Root, 'specVersion', Found ) <> '1.6' then
      Error( 'specVersion', 'must be "1.6"' );

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

      CheckEntity( 'metadata.manufacturer', TJSONObject( Metadata ).GetValue( 'manufacturer' ) );

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
    Error( APath + '.type', Format( '"%s" is not a CycloneDX 1.6 component type', [ CompType ] ) );

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

  CheckEntity( APath + '.supplier', AComponent.GetValue( 'supplier' ) );
  CheckEntity( APath + '.manufacturer', AComponent.GetValue( 'manufacturer' ) );
  CheckComponents( APath + '.components', AComponent.GetValue( 'components' ) );

end;

procedure TSBOMCheck.CheckEntity( const APath: string; AValue: TJSONValue );
begin

  // An organizationalEntity (supplier, manufacturer): url and contact are arrays when present
  if Assigned( AValue ) and ( ( not ( AValue is TJSONObject ) ) or
    ( Assigned( TJSONObject( AValue ).GetValue( 'url' ) ) and ( not ( TJSONObject( AValue ).GetValue( 'url' ) is TJSONArray ) ) ) or
    ( Assigned( TJSONObject( AValue ).GetValue( 'contact' ) ) and ( not ( TJSONObject( AValue ).GetValue( 'contact' ) is TJSONArray ) ) ) ) then
    Error( APath, 'must be an object whose url and contact are arrays' );

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

      // The schema's licenseChoice: a list of license objects, or one expression on its own
      if TJSONArray( AValue ).Count > 1 then
        Error( ItemPath + '.expression', 'must be the only item of licenses' );

      CheckAcknowledgement( ItemPath + '.acknowledgement', TJSONObject( Item ) );
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

    CheckAcknowledgement( ItemPath + '.license.acknowledgement', TJSONObject( Licence ) );
  end;

end;

procedure TSBOMCheck.CheckAcknowledgement( const APath: string; AOwner: TJSONObject );
begin

  var Found: Boolean;
  var Value         := StringField( AOwner, 'acknowledgement', Found );

  if Found and ( not InList( Value, LicenceAcknowledgements ) ) then
    Error( APath, Format( '"%s" is not a CycloneDX 1.6 licence acknowledgement (declared or concluded)', [ Value ] ) );

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
      Error( ItemPath + '.alg', Format( '"%s" is not a CycloneDX 1.6 hash algorithm', [ Alg ] ) );
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
      Error( ItemPath + '.type', Format( '"%s" is not a CycloneDX 1.6 external reference type', [ RefType ] ) );

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

      // The schema requires unique items
      var Targets   := TDictionary<string, Boolean>.Create;
      try
        for var J := 0 to TJSONArray( DependsOn ).Count - 1 do
        begin
          var Target := TJSONArray( DependsOn ).Items[ J ].Value;

          if ( not FRefs.ContainsKey( Target ) ) then
            Error( Format( '%s.dependsOn[%d]', [ ItemPath, J ] ), Format( '"%s" is not the bom-ref of any component', [ Target ] ) )
          else if ( not Targets.TryAdd( Target, True ) ) then
            Error( Format( '%s.dependsOn[%d]', [ ItemPath, J ] ), Format( '"%s" is listed more than once', [ Target ] ) );
        end;
      finally
        Targets.Free;
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
      Error( ItemPath + '.aggregate', Format( '"%s" is not a CycloneDX 1.6 composition aggregate', [ Aggregate ] ) );

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

type
  /// <summary>
  ///   One BSI TR-03183-2 check of one document: collects the findings, and the bom-refs that the dependency graph
  ///   and the compositions name.
  /// </summary>
  TTRCheck = class
  private
    FFindings: TList<string>;
    FGraphRefs: TDictionary<string, Boolean>;
    FCompositionRefs: TDictionary<string, Boolean>;

    procedure Finding( const ARule, AWhere, AMessage: string );
    procedure CollectRefs( ARoot: TJSONObject );
    procedure CheckComponent( const APath: string; AComponent: TJSONObject; AIsPrimary: Boolean );
    procedure CheckFileFields( const AWhere: string; AComponent: TJSONObject; AIsPrimary: Boolean );
  public
    constructor Create;
    destructor Destroy; override;

    procedure Run( const AJson: string );

    property Findings: TList<string> read FFindings;
  end;

/// <summary>Whether an organizationalEntity holds an email (in contact) or a URL, as the TR asks of a creator.</summary>
function EntityHasEmailOrURL( AValue: TJSONValue ): Boolean;
begin

  Result            := False;

  if ( not ( AValue is TJSONObject ) ) then Exit;

  var Urls          := TJSONObject( AValue ).GetValue( 'url' );

  if Urls is TJSONArray then
    for var Url in TJSONArray( Urls ) do
      if ( Url is TJSONString ) and ( Trim( TJSONString( Url ).Value ) <> '' ) then
        Exit( True );

  var Contacts      := TJSONObject( AValue ).GetValue( 'contact' );

  if Contacts is TJSONArray then
    for var Contact in TJSONArray( Contacts ) do
      if Contact is TJSONObject then
      begin
        var Found: Boolean;

        if Trim( StringField( TJSONObject( Contact ), 'email', Found ) ) <> '' then
          Exit( True );
      end;

end;

/// <summary>The value of the property AName in a component's properties, or '' when it has none.</summary>
function PropertyValue( AComponent: TJSONObject; const AName: string ): string;
begin

  Result            := '';
  var Props         := AComponent.GetValue( 'properties' );

  if ( not ( Props is TJSONArray ) ) then Exit;

  for var Prop in TJSONArray( Props ) do
    if Prop is TJSONObject then
    begin
      var Found: Boolean;

      if StringField( TJSONObject( Prop ), 'name', Found ) = AName then
        Exit( StringField( TJSONObject( Prop ), 'value', Found ) );
    end;

end;

/// <summary>Whether a specVersion string ('1.6', '1.10', '1.6.1', '2') is 1.6 or later.</summary>
function IsSpecVersionAtLeast16( const AVersion: string ): Boolean;
begin

  Result            := False;
  var Parts         := AVersion.Split( [ '.' ] );

  if ( Length( Parts ) < 1 ) or ( Length( Parts ) > 3 ) then Exit;

  var Numbers: TArray<Integer>;
  SetLength( Numbers, Length( Parts ) );

  for var I := 0 to High( Parts ) do
    if ( not TryStrToInt( Parts[ I ], Numbers[ I ] ) ) or ( Numbers[ I ] < 0 ) then Exit;

  var Minor         := 0;

  if Length( Numbers ) > 1 then
    Minor           := Numbers[ 1 ];

  Result            := ( Numbers[ 0 ] > 1 ) or ( ( Numbers[ 0 ] = 1 ) and ( Minor >= 6 ) );

end;

/// <summary>
///   Whether a licence expression has the syntax of SPDX Annex D: operands joined by AND / OR (upper case, as SPDX
///   asks), an operand optionally followed by WITH and an exception, brackets for grouping.  An operand is an SPDX
///   identifier shape (letters, digits, '.' and '-', an optional trailing '+'), a LicenseRef- identifier, or
///   DocumentRef-x:LicenseRef-y.  The SPDX licence list itself is not consulted, so a well-formed unknown identifier
///   passes; free text such as "Apache License 2.0 or later" does not.
/// </summary>
function IsLicenceExpression( const AExpression: string ): Boolean;
begin

  var Spaced        := StringReplace( StringReplace( AExpression, '(', ' ( ', [ rfReplaceAll ] ), ')', ' ) ', [ rfReplaceAll ] );
  var Tokens: TArray<string> := [ ];

  for var T in Spaced.Split( [ ' ', #9, #10, #13 ] ) do
    if T <> '' then
      Tokens        := Tokens + [ T ];

  var Index           := 0;

  var IsOperand :=
    function( const AToken: string ): Boolean
    begin
      Result        := TRegEx.IsMatch( AToken, '^([A-Za-z0-9.\-]+\+?|DocumentRef-[A-Za-z0-9.\-]+:LicenseRef-[A-Za-z0-9.\-]+)$' ) and
        ( AToken <> 'AND' ) and ( AToken <> 'OR' ) and ( AToken <> 'WITH' );
    end;

  // expression := term { ( AND | OR ) term };  term := '(' expression ')' | operand [ WITH operand ]
  var ParseExpression: TFunc<Boolean>;

  var ParseTerm :=
    function: Boolean
    begin
      Result        := False;

      if Index > High( Tokens ) then Exit;

      if Tokens[ Index ] = '(' then
      begin
        Inc( Index );

        if ( not ParseExpression() ) or ( Index > High( Tokens ) ) or ( Tokens[ Index ] <> ')' ) then Exit;

        Inc( Index );
        Exit( True );
      end;

      if ( not IsOperand( Tokens[ Index ] ) ) then Exit;

      Inc( Index );

      if ( Index <= High( Tokens ) ) and ( Tokens[ Index ] = 'WITH' ) then
      begin
        Inc( Index );

        if ( Index > High( Tokens ) ) or ( not IsOperand( Tokens[ Index ] ) ) then Exit;

        Inc( Index );
      end;

      Result        := True;
    end;

  ParseExpression :=
    function: Boolean
    begin
      Result        := ParseTerm();

      while Result and ( Index <= High( Tokens ) ) and ( ( Tokens[ Index ] = 'AND' ) or ( Tokens[ Index ] = 'OR' ) ) do
      begin
        Inc( Index );
        Result      := ParseTerm();
      end;
    end;

  Result            := ( Length( Tokens ) > 0 ) and ParseExpression() and ( Index > High( Tokens ) );

end;

constructor TTRCheck.Create;
begin

  inherited Create;
  FFindings         := TList<string>.Create;
  FGraphRefs        := TDictionary<string, Boolean>.Create;
  FCompositionRefs  := TDictionary<string, Boolean>.Create;

end;

destructor TTRCheck.Destroy;
begin

  FCompositionRefs.Free;
  FGraphRefs.Free;
  FFindings.Free;
  inherited;

end;

procedure TTRCheck.Finding( const ARule, AWhere, AMessage: string );
begin

  FFindings.Add( Format( '%s %s: %s', [ ARule, AWhere, AMessage ] ) );

end;

procedure TTRCheck.CollectRefs( ARoot: TJSONObject );
begin

  var Dependencies  := ARoot.GetValue( 'dependencies' );

  if Dependencies is TJSONArray then
    for var Item in TJSONArray( Dependencies ) do
      if Item is TJSONObject then
      begin
        var Found: Boolean;
        var Ref     := StringField( TJSONObject( Item ), 'ref', Found );

        if Ref <> '' then
          FGraphRefs.AddOrSetValue( Ref, True );
      end;

  var Compositions  := ARoot.GetValue( 'compositions' );

  if Compositions is TJSONArray then
    for var Item in TJSONArray( Compositions ) do
      if Item is TJSONObject then
      begin
        // Only "dependencies" states the completeness of a component's dependencies; "assemblies" is about its parts
        var Refs    := TJSONObject( Item ).GetValue( 'dependencies' );

        if Refs is TJSONArray then
          for var Ref in TJSONArray( Refs ) do
            if Ref is TJSONString then
              FCompositionRefs.AddOrSetValue( TJSONString( Ref ).Value, True );
      end;

end;

procedure TTRCheck.Run( const AJson: string );
begin

  var Parsed        := TJSONObject.ParseJSONValue( AJson );
  try
    if ( not ( Parsed is TJSONObject ) ) then
    begin
      Finding( 'TR-4-FORMAT', '$', 'not a JSON object' );
      Exit;
    end;

    var Root        := TJSONObject( Parsed );
    var Found: Boolean;
    var SpecVersion := StringField( Root, 'specVersion', Found );

    var BomFormat   := StringField( Root, 'bomFormat', Found );

    if BomFormat <> 'CycloneDX' then
      Finding( 'TR-4-FORMAT', 'bomFormat', Format( '"%s"; a CycloneDX SBOM must say "CycloneDX"', [ BomFormat ] ) )
    else if ( not IsSpecVersionAtLeast16( SpecVersion ) ) then
      Finding( 'TR-4-FORMAT', 'specVersion', Format( 'CycloneDX "%s"; version 1.6 or higher is required', [ SpecVersion ] ) );

    // Any vulnerability content counts; only an absent, null or empty list does not
    var Vulnerabilities := Root.GetValue( 'vulnerabilities' );

    if Assigned( Vulnerabilities ) and ( not ( Vulnerabilities is TJSONNull ) ) and
      ( not ( ( Vulnerabilities is TJSONArray ) and ( TJSONArray( Vulnerabilities ).Count = 0 ) ) ) then
      Finding( 'TR-3.1-VULNERABILITIES', 'vulnerabilities', 'an SBOM must not contain vulnerability information' );

    CollectRefs( Root );

    var Metadata    := Root.GetValue( 'metadata' );

    if ( not ( Metadata is TJSONObject ) ) then
      Finding( 'TR-5.2.1-CREATOR', 'metadata', 'missing, so the SBOM has no creator, timestamp or application component' )
    else
    begin
      if ( not EntityHasEmailOrURL( TJSONObject( Metadata ).GetValue( 'manufacturer' ) ) ) then
        Finding( 'TR-5.2.1-CREATOR', 'metadata.manufacturer', 'no email or URL of the SBOM''s creator (components.json: supplier.email or supplier.url)' );

      if Trim( StringField( TJSONObject( Metadata ), 'timestamp', Found ) ) = '' then
        Finding( 'TR-5.2.1-TIMESTAMP', 'metadata.timestamp', 'missing' );

      var Primary   := TJSONObject( Metadata ).GetValue( 'component' );

      if Primary is TJSONObject then
        CheckComponent( 'metadata.component', TJSONObject( Primary ), True )
      else
        Finding( 'TR-5.2.2-NAME', 'metadata.component', 'missing: the SBOM does not name its primary component' );
    end;

    var Components  := Root.GetValue( 'components' );

    if Components is TJSONArray then
      for var I := 0 to TJSONArray( Components ).Count - 1 do
        if TJSONArray( Components ).Items[ I ] is TJSONObject then
          CheckComponent( Format( 'components[%d]', [ I ] ), TJSONObject( TJSONArray( Components ).Items[ I ] ), False );
  finally
    Parsed.Free;
  end;

end;

procedure TTRCheck.CheckComponent( const APath: string; AComponent: TJSONObject; AIsPrimary: Boolean );
begin

  var Found: Boolean;
  var Name          := Trim( StringField( AComponent, 'name', Found ) );
  var Where         := Format( '%s "%s"', [ APath, Name ] );

  if Name = '' then
    Finding( 'TR-5.2.2-NAME', APath, 'no component name' );

  if Trim( StringField( AComponent, 'version', Found ) ) = '' then
    Finding( 'TR-5.2.2-VERSION', Where, 'no version' );

  if ( not EntityHasEmailOrURL( AComponent.GetValue( 'manufacturer' ) ) ) then
  begin
    if AIsPrimary then
      Finding( 'TR-5.2.2-CREATOR', Where, 'no email or URL of the creator (components.json: supplier.email or supplier.url)' )
    else
      Finding( 'TR-5.2.2-CREATOR', Where, 'no email or URL of the creator (components.json: creator_email or creator_url, ' +
        'or vendor_email / vendor_url when the vendor created it)' );
  end;

  // Dependencies: the component is in the graph, and its completeness is stated
  var Ref           := StringField( AComponent, 'bom-ref', Found );

  if ( Ref = '' ) or ( not FGraphRefs.ContainsKey( Ref ) ) then
    Finding( 'TR-5.2.2-DEPENDENCIES', Where, 'not in the dependency graph (every component needs an entry, an empty one included)' )
  else if ( not FCompositionRefs.ContainsKey( Ref ) ) then
    Finding( 'TR-5.2.2-DEPENDENCIES', Where, 'the completeness of its dependencies is not stated in compositions' );

  // Distribution licence: present, acknowledged "concluded", and named by an SPDX identifier or expression (6.1)
  var Licences      := AComponent.GetValue( 'licenses' );
  var Concluded     := False;

  if ( Licences is TJSONArray ) and ( TJSONArray( Licences ).Count > 0 ) then
  begin
    for var Item in TJSONArray( Licences ) do
    begin
      if ( not ( Item is TJSONObject ) ) then Continue;

      var Holder    := TJSONObject( Item );
      var Licence   := Holder.GetValue( 'license' );
      var Expression := StringField( Holder, 'expression', Found );

      if Found and ( not IsLicenceExpression( Expression ) ) then
        Finding( 'TR-6.1-LICENCE', Where, Format( 'licence "%s" is not an SPDX licence expression: identifiers joined by ' +
          'upper-case AND / OR / WITH, each an SPDX identifier or a LicenseRef- identifier', [ Expression ] ) );

      if Licence is TJSONObject then
      begin
        Holder      := TJSONObject( Licence );
        var LicenceName := StringField( Holder, 'name', Found );

        if Found then
          Finding( 'TR-6.1-LICENCE', Where, Format( 'licence "%s" is a name, not an identifier: use its SPDX identifier, a ' +
            'LicenseRef-scancode- key from ScanCode LicenseDB, or LicenseRef-<your name>-<licence>', [ LicenceName ] ) );
      end;

      if StringField( Holder, 'acknowledgement', Found ) = 'concluded' then
        Concluded   := True;
    end;

    if ( not Concluded ) then
      Finding( 'TR-5.2.2-LICENCE', Where, 'no licence acknowledged "concluded" (the distribution licence)' );
  end
  else if AIsPrimary then
    Finding( 'TR-5.2.2-LICENCE', Where, 'no distribution licence (components.json: application_licence)' )
  else
    Finding( 'TR-5.2.2-LICENCE', Where, 'no distribution licence (components.json: licence)' );

  // File data: the deployable file, and any component that names a file; a logical component has none (TR 3.2.1)
  if AIsPrimary or ( PropertyValue( AComponent, 'bsi:component:filename' ) <> '' ) then
    CheckFileFields( Where, AComponent, AIsPrimary );

end;

procedure TTRCheck.CheckFileFields( const AWhere: string; AComponent: TJSONObject; AIsPrimary: Boolean );
begin

  var Hint          := '';

  if AIsPrimary then
    Hint            := ' (no built binary was found: build Release first, or name the binary)';

  if Trim( PropertyValue( AComponent, 'bsi:component:filename' ) ) = '' then
    Finding( 'TR-5.2.2-FILENAME', AWhere, 'no bsi:component:filename' + Hint );

  // The SHA-512 of the deployable file sits in a distribution reference (TR Table 9)
  var HasHash       := False;
  var ExtRefs       := AComponent.GetValue( 'externalReferences' );

  if ExtRefs is TJSONArray then
    for var ExtRef in TJSONArray( ExtRefs ) do
    begin
      var Found: Boolean;

      if ( not ( ExtRef is TJSONObject ) ) or ( StringField( TJSONObject( ExtRef ), 'type', Found ) <> 'distribution' ) then Continue;

      var Hashes    := TJSONObject( ExtRef ).GetValue( 'hashes' );

      if Hashes is TJSONArray then
        for var Hash in TJSONArray( Hashes ) do
          if ( Hash is TJSONObject ) and ( StringField( TJSONObject( Hash ), 'alg', Found ) = 'SHA-512' ) then
            HasHash := True;
    end;

  if ( not HasHash ) then
    Finding( 'TR-5.2.2-HASH', AWhere, 'no SHA-512 of the deployable file in a distribution external reference' + Hint );

  var Value         := PropertyValue( AComponent, 'bsi:component:executable' );

  if ( Value <> 'executable' ) and ( Value <> 'non-executable' ) then
    Finding( 'TR-5.2.2-EXECUTABLE', AWhere, 'bsi:component:executable must be "executable" or "non-executable"' + Hint );

  Value             := PropertyValue( AComponent, 'bsi:component:archive' );

  if ( Value <> 'archive' ) and ( Value <> 'no archive' ) then
    Finding( 'TR-5.2.2-ARCHIVE', AWhere, 'bsi:component:archive must be "archive" or "no archive"' + Hint );

  Value             := PropertyValue( AComponent, 'bsi:component:structured' );

  if ( Value <> 'structured' ) and ( Value <> 'unstructured' ) then
    Finding( 'TR-5.2.2-STRUCTURED', AWhere, 'bsi:component:structured must be "structured" or "unstructured"' + Hint );

end;

function CheckTR03183( const AJson: string ): TArray<string>;
begin

  var Check         := TTRCheck.Create;
  try
    Check.Run( AJson );
    Result          := Check.Findings.ToArray;
  finally
    Check.Free;
  end;

end;

end.
