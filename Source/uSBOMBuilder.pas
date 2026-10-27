(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMBuilder.pas — Assembles and emits CycloneDX 1.6 JSON SBOM, with the data fields of BSI TR-03183-2 v2.1.0
  Dependency graph and compositions shape after DX.Comply (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uSBOMBuilder;

interface

uses
  System.SysUtils, System.Classes,
  uTypes;

type
  /// <summary>
  ///   Builds a CycloneDX 1.6 JSON SBOM from classified units and manifest data.
  /// </summary>
  TSBOMBuilder = class
  private
    FLog: TProc<TLogLevel, string>;
    /// <summary>The built binary the application component describes (FileName '' = none).</summary>
    FBinary: TBinaryInfo;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   The built binary: when its FileName is set, the application component gets its file name, its SHA-512 and the
    ///   BSI TR-03183-2 file properties.  Unset, they are left out rather than guessed.
    /// </summary>
    property Binary: TBinaryInfo read FBinary write FBinary;

    /// <summary>
    ///   Builds the SBOM JSON string from project info, classified units, and manifest.
    /// </summary>
    /// <param name="AProjectInfo">Parsed project metadata.</param>
    /// <param name="AClassifiedUnits">Classification of every project unit.</param>
    /// <param name="AManifest">The loaded components.json.</param>
    /// <param name="AVersionOverride">If non-empty, replaces the version from the .dproj.</param>
    /// <param name="AEvidence">Optional per-unit hashes from DX.Comply.</param>
    /// <param name="ALibraryDependencies">What each library uses, read from its source; an edge to a component
    ///   that is not in the SBOM is left out.</param>
    /// <returns>The pretty-printed CycloneDX 1.6 JSON document.</returns>
    function Build( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      const AVersionOverride: string;
      const AEvidence: TArray<TUnitEvidence>;
      const ALibraryDependencies: TArray<TLibraryDependency> = nil ): string;

    /// <summary>
    ///   Builds the SBOM and writes it as UTF-8 without a BOM to &lt;ProjectName&gt;.cdx.json.
    /// </summary>
    /// <param name="AProjectInfo">Parsed project metadata.</param>
    /// <param name="AClassifiedUnits">Classification of every project unit.</param>
    /// <param name="AManifest">The loaded components.json.</param>
    /// <param name="AVersionOverride">If non-empty, replaces the version from the .dproj.</param>
    /// <param name="AOutputDir">Output directory; empty means the project directory.</param>
    /// <param name="AEvidence">Optional per-unit hashes from DX.Comply.</param>
    /// <param name="ALibraryDependencies">What each library uses, read from its source.</param>
    /// <returns>The path of the written file.</returns>
    /// <exception cref="Exception">The output directory does not exist or the file cannot be written.</exception>
    function BuildAndSave( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      const AVersionOverride: string;
      const AOutputDir: string;
      const AEvidence: TArray<TUnitEvidence>;
      const ALibraryDependencies: TArray<TLibraryDependency> = nil ): string;
  end;

/// <summary>
///   Percent-encodes a purl name or version segment as the package-url specification requires:
///   unreserved characters (A-Z a-z 0-9 . - _ ~) are kept, everything else becomes %XX of its
///   UTF-8 bytes. Unlike form encoding, a space becomes %20, never '+'.
/// </summary>
/// <param name="AValue">The segment to encode.</param>
/// <returns>The encoded segment.</returns>
function PurlEncode( const AValue: string ): string;

implementation

uses
  System.JSON, System.IOUtils, System.DateUtils, System.Generics.Collections,
  uTextFiles;

function PurlEncode( const AValue: string ): string;
begin

  var Builder       := TStringBuilder.Create;
  try
    for var B in TEncoding.UTF8.GetBytes( AValue ) do
      if CharInSet( Char( B ), [ 'A'..'Z', 'a'..'z', '0'..'9', '.', '-', '_', '~' ] ) then
        Builder.Append( Char( B ) )
      else
        Builder.Append( '%' ).Append( IntToHex( B, 2 ) );

    Result          := Builder.ToString;
  finally
    Builder.Free;
  end;

end;

/// <summary>
///   A file name as a relative IRI-reference (RFC 3987): the characters an IRI may not hold (space, '"', '<', '>',
///   '\', '^', '`', '{', '|', '}', and '%', '#' and '?', which would change its meaning) become %XX of their UTF-8 bytes.
///   Other characters, non-ASCII ones included, are kept.
/// </summary>
function IriReferenceOf( const AFileName: string ): string;
begin

  var Builder       := TStringBuilder.Create;
  try
    for var C in AFileName do
      if CharInSet( C, [ ' ', '"', '<', '>', '\', '^', '`', '{', '|', '}', '%', '#', '?' ] ) or ( Ord( C ) < $20 ) then
        Builder.Append( '%' ).Append( IntToHex( Ord( C ), 2 ) )
      else
        Builder.Append( C );

    Result          := Builder.ToString;
  finally
    Builder.Free;
  end;

end;

/// <summary>
///   Returns the CycloneDX component type for a manifest value: lower-cased, and 'library' for
///   anything outside the enum (the schema enum is case-sensitive).
/// </summary>
function NormaliseComponentType( const AType: string ): string;
begin

  Result            := LowerCase( Trim( AType ) );

  if ( Result <> 'library' ) and ( Result <> 'framework' ) and ( Result <> 'application' ) then
    Result          := 'library';

end;

{ TSBOMBuilder }

constructor TSBOMBuilder.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog              := ALogProc;

end;

procedure TSBOMBuilder.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TSBOMBuilder.Build( const AProjectInfo: TProjectInfo;
  const AClassifiedUnits: TArray<TClassifiedUnit>;
  const AManifest: TManifest;
  const AVersionOverride: string;
  const AEvidence: TArray<TUnitEvidence>;
  const ALibraryDependencies: TArray<TLibraryDependency> ): string;

// Adds a "components" array of evidence sub-components (one per matched unit) to AOwner
  procedure AddEvidenceSubComponents( AOwner: TJSONObject; AClassification: TUnitClassification; AComponentIndex: Integer );
  begin

    if Length( AEvidence ) = 0 then Exit;

    var SubComps: TJSONArray := nil;

    for var CU in AClassifiedUnits do
    begin
      if CU.Classification <> AClassification then Continue;
      if ( AClassification = ucThirdParty ) and ( CU.ComponentIndex <> AComponentIndex ) then Continue;

      // Match on the name as written, or scope-stripped on both sides (SysUtils matches System.SysUtils)
      for var Ev in AEvidence do
        if SameText( Ev.UnitName, CU.OriginalName ) or SameText( StripScopePrefix( Ev.UnitName ), CU.UnitName ) then
        begin
          if ( not Assigned( SubComps ) ) then
          begin
            SubComps := TJSONArray.Create;
            AOwner.AddPair( 'components', SubComps );
          end;

          var SubComp := TJSONObject.Create;
          SubComps.AddElement( SubComp );
          SubComp.AddPair( 'type', 'library' );
          SubComp.AddPair( 'name', Ev.UnitName );

          if Length( Ev.Hashes ) > 0 then
          begin
            var HashArr := TJSONArray.Create;
            SubComp.AddPair( 'hashes', HashArr );

            for var Hash in Ev.Hashes do
            begin
              var HashObj := TJSONObject.Create;
              HashArr.AddElement( HashObj );
              HashObj.AddPair( 'alg', Hash.Algorithm );
              HashObj.AddPair( 'content', Hash.Content );
            end;
          end;

          if Ev.Origin <> '' then
          begin
            var PropArr := TJSONArray.Create;
            SubComp.AddPair( 'properties', PropArr );

            var PropObj := TJSONObject.Create;
            PropArr.AddElement( PropObj );
            PropObj.AddPair( 'name', 'dxcomply:origin' );
            PropObj.AddPair( 'value', Ev.Origin );
          end;

          Break;
        end;
    end;

  end;

  // Adds the component creator as "manufacturer" (CycloneDX 1.6). BSI TR-03183-2 asks for the creator's email, or a
  // URL when there is no email, so an email wins and the URL is written only without one
  procedure AddManufacturer( AOwner: TJSONObject; const AName, AEmail, AURL: string );
  begin

    var Email       := Trim( AEmail );

    if ( not IsEmailAddress( Email ) ) then
      Email         := '';

    var URL         := Trim( AURL );

    if ( Email = '' ) and ( URL = '' ) then Exit;

    var Manufacturer := TJSONObject.Create;
    AOwner.AddPair( 'manufacturer', Manufacturer );

    if Trim( AName ) <> '' then
      Manufacturer.AddPair( 'name', Trim( AName ) );

    if Email <> '' then
    begin
      var ContactArr := TJSONArray.Create;
      Manufacturer.AddPair( 'contact', ContactArr );

      var ContactObj := TJSONObject.Create;
      ContactArr.AddElement( ContactObj );
      ContactObj.AddPair( 'email', Email );
    end
    else
    begin
      var UrlArr    := TJSONArray.Create;
      Manufacturer.AddPair( 'url', UrlArr );
      UrlArr.Add( URL );
    end;

  end;

  // Adds "licenses": license.id is an SPDX enum, so only recognised identifiers go there.  Each entry is acknowledged
  // "concluded": the licence under which the component is distributed (BSI TR-03183-2 distribution licence)
  procedure AddLicences( AOwner: TJSONObject; const AValue, AURL: string );
  begin

    var Licence     := '';
    var LicenceKind := ClassifyLicence( AValue, Licence );

    case LicenceKind of
      lkSPDX, lkName:
        begin
          var LicArray := TJSONArray.Create;
          AOwner.AddPair( 'licenses', LicArray );

          var LicWrapper := TJSONObject.Create;
          LicArray.AddElement( LicWrapper );

          var LicObj := TJSONObject.Create;
          LicWrapper.AddPair( 'license', LicObj );

          if LicenceKind = lkSPDX then
            LicObj.AddPair( 'id', Licence )
          else
            LicObj.AddPair( 'name', Licence );

          LicObj.AddPair( 'acknowledgement', 'concluded' );

          if AURL <> '' then
            LicObj.AddPair( 'url', AURL );
        end;

      lkExpression:
        begin
          var LicArray := TJSONArray.Create;
          AOwner.AddPair( 'licenses', LicArray );

          var ExprObj := TJSONObject.Create;
          LicArray.AddElement( ExprObj );
          ExprObj.AddPair( 'expression', Licence );
          ExprObj.AddPair( 'acknowledgement', 'concluded' );
        end;
    end;

  end;

  // Adds one name/value pair to the component's "properties", creating the array on first use
  procedure AddProperty( AOwner: TJSONObject; const AName, AValue: string );
  begin

    var Props       := AOwner.GetValue( 'properties' ) as TJSONArray;

    if ( not Assigned( Props ) ) then
    begin
      Props         := TJSONArray.Create;
      AOwner.AddPair( 'properties', Props );
    end;

    var Prop        := TJSONObject.Create;
    Props.AddElement( Prop );
    Prop.AddPair( 'name', AName );
    Prop.AddPair( 'value', AValue );

  end;

  // Adds one hashes entry holding a SHA-512 digest
  procedure AddSHA512( AOwner: TJSONObject; const ADigest: string );
  begin

    var HashArr     := TJSONArray.Create;
    AOwner.AddPair( 'hashes', HashArr );

    var HashObj     := TJSONObject.Create;
    HashArr.AddElement( HashObj );
    HashObj.AddPair( 'alg', 'SHA-512' );
    HashObj.AddPair( 'content', ADigest );

  end;

begin

  // bom-refs must be unique in the document: a repeated one gets a #2, #3 ... suffix
  var UsedRefs      := TDictionary<string, Boolean>.Create;
  var LibraryRefs   := TList<string>.Create;
  var LibraryIndexes := TList<Integer>.Create; // The manifest index of each entry of LibraryRefs

  var UniqueRef     :=
    function( const ABase: string ): string
    begin
      Result        := ABase;
      var N         := 1;

      while UsedRefs.ContainsKey( Result ) do
      begin
        Inc( N );
        Result      := ABase + '#' + IntToStr( N );
      end;

      UsedRefs.Add( Result, True );
    end;

  // Every child is attached to its parent as soon as it is created, so an exception part-way
  // through leaves nothing unowned when Root is freed
  var Root          := TJSONObject.Create;
  try
    Root.AddPair( 'bomFormat', 'CycloneDX' );
    Root.AddPair( 'specVersion', '1.6' );
    var GuidStr     := TGUID.NewGuid.ToString;
    GuidStr         := StringReplace( GuidStr, '{', '', [ rfReplaceAll ] );
    GuidStr         := StringReplace( GuidStr, '}', '', [ rfReplaceAll ] );
    Root.AddPair( 'serialNumber', 'urn:uuid:' + LowerCase( GuidStr ) );
    Root.AddPair( 'version', TJSONNumber.Create( 1 ) );

    // Metadata
    var Metadata    := TJSONObject.Create;
    Root.AddPair( 'metadata', Metadata );

    // ISO 8601 UTC; the quoted separators keep the locale's time separator out of it
    var UtcNow      := TTimeZone.Local.ToUniversalTime( Now );
    Metadata.AddPair( 'timestamp', FormatDateTime( 'yyyy"-"mm"-"dd"T"hh":"nn":"ss"Z"', UtcNow, TFormatSettings.Create( 'en-US' ) ) );

    // Metadata > tools
    var ToolsObj    := TJSONObject.Create;
    Metadata.AddPair( 'tools', ToolsObj );

    var ToolsArray  := TJSONArray.Create;
    ToolsObj.AddPair( 'components', ToolsArray );

    var ToolComp    := TJSONObject.Create;
    ToolsArray.AddElement( ToolComp );
    ToolComp.AddPair( 'type', 'application' );
    ToolComp.AddPair( 'name', AppName );
    ToolComp.AddPair( 'version', AppVersion );

    var ToolSupplier := TJSONObject.Create;
    ToolComp.AddPair( 'supplier', ToolSupplier );
    ToolSupplier.AddPair( 'name', 'DelphiSBOM Contributors' );

    // Metadata > manufacturer: the creator of the SBOM (BSI TR-03183-2), who is the application's supplier
    AddManufacturer( Metadata, AManifest.Supplier.Name, AManifest.Supplier.Email, AManifest.Supplier.URL );

    // Metadata > component (the application being described)
    var EffectiveVersion := EffectiveProductVersion( AVersionOverride, AProjectInfo.ProjectVersion );
    var AppRef      := UniqueRef( 'application:' + AProjectInfo.ProjectName + '@' + EffectiveVersion );

    var MainComp    := TJSONObject.Create;
    Metadata.AddPair( 'component', MainComp );
    MainComp.AddPair( 'bom-ref', AppRef );
    MainComp.AddPair( 'type', 'application' );
    MainComp.AddPair( 'name', AProjectInfo.ProjectName );
    MainComp.AddPair( 'version', EffectiveVersion );

    if AManifest.Supplier.Name <> '' then
    begin
      var SupplierObj := TJSONObject.Create;
      MainComp.AddPair( 'supplier', SupplierObj );
      SupplierObj.AddPair( 'name', AManifest.Supplier.Name );

      if AManifest.Supplier.URL <> '' then
      begin
        var UrlArray := TJSONArray.Create;
        SupplierObj.AddPair( 'url', UrlArray );
        UrlArray.Add( AManifest.Supplier.URL );
      end;
    end;

    // The application's creator is its supplier
    AddManufacturer( MainComp, AManifest.Supplier.Name, AManifest.Supplier.Email, AManifest.Supplier.URL );
    AddLicences( MainComp, AManifest.ApplicationLicence, '' );

    // The deployable file (BSI TR-03183-2 section 8.1.6: a binary with statically linked libraries is an unstructured,
    // executable file).  Its SHA-512 goes in a distribution reference, where the TR's mapping puts it, whose url is the
    // file name (an IRI-reference) since the file has no download location of its own; component hashes carry it too
    if FBinary.FileName <> '' then
    begin
      AddSHA512( MainComp, FBinary.SHA512 );

      var ExtRefArray := TJSONArray.Create;
      MainComp.AddPair( 'externalReferences', ExtRefArray );

      var ExtRef    := TJSONObject.Create;
      ExtRefArray.AddElement( ExtRef );
      ExtRef.AddPair( 'type', 'distribution' );
      ExtRef.AddPair( 'url', IriReferenceOf( FBinary.FileName ) );
      AddSHA512( ExtRef, FBinary.SHA512 );

      AddProperty( MainComp, 'bsi:component:filename', FBinary.FileName );
      AddProperty( MainComp, 'bsi:component:executable', 'executable' );
      AddProperty( MainComp, 'bsi:component:archive', 'no archive' );
      AddProperty( MainComp, 'bsi:component:structured', 'unstructured' );
    end;

    // Components array
    var Components  := TJSONArray.Create;
    Root.AddPair( 'components', Components );

    // Add RTL as single aggregate component
    var DelphiVer   := AProjectInfo.DelphiVersion;

    if DelphiVer = '' then
      DelphiVer     := 'unknown';

    var RTLPurl     := 'pkg:delphi/embarcadero-rtl@' + PurlEncode( DelphiVer );
    var RTLRef      := UniqueRef( RTLPurl );

    var RTLComp     := TJSONObject.Create;
    Components.AddElement( RTLComp );
    RTLComp.AddPair( 'bom-ref', RTLRef );
    RTLComp.AddPair( 'type', 'framework' );
    RTLComp.AddPair( 'name', 'Embarcadero Delphi RTL' );
    RTLComp.AddPair( 'version', DelphiVer );

    var RTLSupplier := TJSONObject.Create;
    RTLComp.AddPair( 'supplier', RTLSupplier );
    RTLSupplier.AddPair( 'name', 'Embarcadero Technologies' );

    AddManufacturer( RTLComp, 'Embarcadero Technologies', '', RTLCreatorURL );
    AddLicences( RTLComp, RTLLicence, '' );
    RTLComp.AddPair( 'purl', RTLPurl );

    // Attach per-unit evidence from DX.Comply if available
    AddEvidenceSubComponents( RTLComp, ucRTL, -1 );

    // Add third-party components (deduplicated by component index)
    var AddedComponents := TDictionary<Integer, Boolean>.Create;
    try
      for var CU in AClassifiedUnits do
      begin
        if ( CU.Classification <> ucThirdParty ) or ( CU.ComponentIndex < 0 ) then Continue;

        if CU.ComponentIndex > High( AManifest.Components ) then
        begin
          Log( llError, Format( 'Unit %s refers to manifest component %d, which does not exist — skipped', [ CU.OriginalName, CU.ComponentIndex ] ) );
          Continue;
        end;

        if AddedComponents.ContainsKey( CU.ComponentIndex ) then Continue;

        AddedComponents.Add( CU.ComponentIndex, True );

        var Entry   := AManifest.Components[ CU.ComponentIndex ];

        // The purl names the component; a component without a name is referenced by its manifest row
        var Purl    := '';

        // A manifest purl (e.g. pkg:github/owner/repo@tag) replaces the generated pkg:delphi one
        if Entry.Purl <> '' then
          Purl      := Entry.Purl
        else if Trim( Entry.Name ) = '' then
          Log( llWarning, Format( 'Manifest component %d has no name — no purl emitted', [ CU.ComponentIndex ] ) )
        else if Entry.Version <> '' then
          Purl      := Format( 'pkg:delphi/%s@%s', [ PurlEncode( Entry.Name ), PurlEncode( Entry.Version ) ] )
        else
          Purl      := 'pkg:delphi/' + PurlEncode( Entry.Name );

        var CompRef: string;

        if Purl <> '' then
          CompRef   := UniqueRef( Purl )
        else
          CompRef   := UniqueRef( 'component:' + IntToStr( CU.ComponentIndex ) );

        LibraryRefs.Add( CompRef );
        LibraryIndexes.Add( CU.ComponentIndex );

        var CompObj := TJSONObject.Create;
        Components.AddElement( CompObj );

        CompObj.AddPair( 'bom-ref', CompRef );
        CompObj.AddPair( 'type', NormaliseComponentType( Entry.CompType ) );
        CompObj.AddPair( 'name', Entry.Name );

        if Entry.Version <> '' then
          CompObj.AddPair( 'version', Entry.Version );

        // CycloneDX's email is format idn-email, so a value that is not an email address is left out
        // (the manifest loader warns about it)
        var VendorEmail := Trim( Entry.VendorEmail );

        if not IsEmailAddress( VendorEmail ) then
          VendorEmail := '';

        if ( Entry.Vendor <> '' ) or ( VendorEmail <> '' ) then
        begin
          var VendorObj := TJSONObject.Create;
          CompObj.AddPair( 'supplier', VendorObj );

          if Entry.Vendor <> '' then
            VendorObj.AddPair( 'name', Entry.Vendor );

          if VendorEmail <> '' then
          begin
            var ContactArr := TJSONArray.Create;
            VendorObj.AddPair( 'contact', ContactArr );

            var ContactObj := TJSONObject.Create;
            ContactArr.AddElement( ContactObj );
            ContactObj.AddPair( 'email', VendorEmail );
          end;
        end;

        // The creator (BSI TR-03183-2 section 3.2.9 separates it from the vendor); without creator fields the vendor
        // is taken to be the creator, as it is for most libraries
        // A creator_email that is not an email address does not count, so the vendor still stands in for it
        if IsEmailAddress( Entry.CreatorEmail ) or ( Entry.CreatorURL <> '' ) then
          AddManufacturer( CompObj, '', Entry.CreatorEmail, Entry.CreatorURL )
        else
          AddManufacturer( CompObj, Entry.Vendor, Entry.VendorEmail, Entry.VendorURL );

        AddLicences( CompObj, Entry.Licence, Entry.LicenceURL );

        // External references
        if Entry.VendorURL <> '' then
        begin
          var ExtRefArray := TJSONArray.Create;
          CompObj.AddPair( 'externalReferences', ExtRefArray );

          var ExtRef := TJSONObject.Create;
          ExtRefArray.AddElement( ExtRef );
          ExtRef.AddPair( 'type', 'website' );
          ExtRef.AddPair( 'url', Entry.VendorURL );
        end;

        if Purl <> '' then
          CompObj.AddPair( 'purl', Purl );

        // Attach per-unit evidence from DX.Comply if available
        AddEvidenceSubComponents( CompObj, ucThirdParty, CU.ComponentIndex );
      end;
    finally
      AddedComponents.Free;
    end;

    // Dependency graph: the application uses the RTL and every library; the RTL uses nothing third-party.  Every
    // component has an entry, an empty dependsOn included, as CycloneDX 1.6 and BSI TR-03183-2 require; a library's
    // dependsOn lists what its source showed it using.  The composition below declares the graph incomplete, so an
    // empty list is not a claim that a library uses nothing
    var Dependencies := TJSONArray.Create;
    Root.AddPair( 'dependencies', Dependencies );

    var AppDeps     := TJSONObject.Create;
    Dependencies.AddElement( AppDeps );
    AppDeps.AddPair( 'ref', AppRef );

    var AppDependsOn := TJSONArray.Create;
    AppDeps.AddPair( 'dependsOn', AppDependsOn );
    AppDependsOn.Add( RTLRef );

    for var Ref in LibraryRefs do
      AppDependsOn.Add( Ref );

    var RTLDeps     := TJSONObject.Create;
    Dependencies.AddElement( RTLDeps );
    RTLDeps.AddPair( 'ref', RTLRef );
    RTLDeps.AddPair( 'dependsOn', TJSONArray.Create );

    // Library-to-library edges, only between components in this document
    for var L := 0 to LibraryIndexes.Count - 1 do
    begin
      var LibDeps   := TJSONObject.Create;
      Dependencies.AddElement( LibDeps );
      LibDeps.AddPair( 'ref', LibraryRefs[ L ] );

      var LibDependsOn := TJSONArray.Create;
      LibDeps.AddPair( 'dependsOn', LibDependsOn );

      for var Dependency in ALibraryDependencies do
      begin
        if Dependency.ComponentIndex <> LibraryIndexes[ L ] then Continue;

        for var Target in Dependency.DependsOn do
        begin
          var TargetRef := '';

          if Target = RTLComponentIndex then
            TargetRef := RTLRef
          else if Target <> LibraryIndexes[ L ] then
          begin
            var TargetPos := LibraryIndexes.IndexOf( Target );

            if TargetPos >= 0 then
              TargetRef := LibraryRefs[ TargetPos ];
          end;

          if TargetRef = '' then Continue;

          // dependsOn items must be unique (CycloneDX 1.6 schema)
          var Listed := False;

          for var Item in LibDependsOn do
            if Item.Value = TargetRef then
              Listed := True;

          if Listed then Continue;

          LibDependsOn.Add( TargetRef );
        end;

        Break;
      end;
    end;

    // The graph is incomplete: a library whose source was not read has no edges, and unclassified units are left
    // out.  It names every component so each one's completeness is stated (BSI TR-03183-2 section 5.2.2); DX.Comply
    // writes the same shape for the application alone
    var Compositions := TJSONArray.Create;
    Root.AddPair( 'compositions', Compositions );

    var Composition := TJSONObject.Create;
    Compositions.AddElement( Composition );
    Composition.AddPair( 'aggregate', 'incomplete' );

    var CompositionDeps := TJSONArray.Create;
    Composition.AddPair( 'dependencies', CompositionDeps );
    CompositionDeps.Add( AppRef );
    CompositionDeps.Add( RTLRef );

    for var Ref in LibraryRefs do
      CompositionDeps.Add( Ref );

    Result          := Root.Format;
  finally
    Root.Free;
    LibraryIndexes.Free;
    LibraryRefs.Free;
    UsedRefs.Free;
  end;

end;

function TSBOMBuilder.BuildAndSave( const AProjectInfo: TProjectInfo;
  const AClassifiedUnits: TArray<TClassifiedUnit>;
  const AManifest: TManifest;
  const AVersionOverride: string;
  const AOutputDir: string;
  const AEvidence: TArray<TUnitEvidence>;
  const ALibraryDependencies: TArray<TLibraryDependency> ): string;
begin

  var Json          := Build( AProjectInfo, AClassifiedUnits, AManifest, AVersionOverride, AEvidence, ALibraryDependencies );

  var EffectiveDir  := AOutputDir;

  if EffectiveDir = '' then
    EffectiveDir    := AProjectInfo.ProjectDir;

  if ( not TDirectory.Exists( EffectiveDir ) ) then
    raise Exception.CreateFmt( 'Output directory does not exist: %s', [ EffectiveDir ] );

  Result            := TPath.Combine( EffectiveDir, AProjectInfo.ProjectName + '.cdx.json' );

  // UTF-8 without a BOM (RFC 8259), written atomically so a failure keeps the previous SBOM intact
  try
    WriteTextFileAtomic( Result, Json );
  except
    on E: EInOutError do
      raise Exception.CreateFmt( 'Failed to write SBOM to %s: %s', [ Result, E.Message ] );
    on E: EStreamError do
      raise Exception.CreateFmt( 'Failed to write SBOM to %s: %s', [ Result, E.Message ] );
  end;

  Log( llInfo, Format( 'SBOM written to %s', [ Result ] ) );

end;

end.

