(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uSBOMBuilder.pas — Assembles and emits CycloneDX 1.5 JSON SBOM
*)
unit uSBOMBuilder;

interface

uses
  System.SysUtils, System.Classes,
  uTypes;

type
  /// <summary>
  ///   Builds a CycloneDX 1.5 JSON SBOM from classified units and manifest data.
  /// </summary>
  TSBOMBuilder = class
  private
    FLog: TProc<TLogLevel, string>;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string> );

    /// <summary>
    ///   Builds the SBOM JSON string from project info, classified units, and manifest.
    /// </summary>
    /// <param name="AProjectInfo">Parsed project metadata.</param>
    /// <param name="AClassifiedUnits">Classification of every project unit.</param>
    /// <param name="AManifest">The loaded components.json.</param>
    /// <param name="AVersionOverride">If non-empty, replaces the version from the .dproj.</param>
    /// <param name="AEvidence">Optional per-unit hashes from DX.Comply.</param>
    /// <returns>The pretty-printed CycloneDX 1.5 JSON document.</returns>
    function Build( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      const AVersionOverride: string;
      const AEvidence: TArray<TUnitEvidence> ): string;

    /// <summary>
    ///   Builds the SBOM and writes it as UTF-8 without a BOM to &lt;ProjectName&gt;.cdx.json.
    /// </summary>
    /// <param name="AProjectInfo">Parsed project metadata.</param>
    /// <param name="AClassifiedUnits">Classification of every project unit.</param>
    /// <param name="AManifest">The loaded components.json.</param>
    /// <param name="AVersionOverride">If non-empty, replaces the version from the .dproj.</param>
    /// <param name="AOutputDir">Output directory; empty means the project directory.</param>
    /// <param name="AEvidence">Optional per-unit hashes from DX.Comply.</param>
    /// <returns>The path of the written file.</returns>
    /// <exception cref="Exception">The output directory does not exist or the file cannot be written.</exception>
    function BuildAndSave( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      const AVersionOverride: string;
      const AOutputDir: string;
      const AEvidence: TArray<TUnitEvidence> ): string;
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
  const AEvidence: TArray<TUnitEvidence> ): string;

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

          if ( Ev.Algorithm <> '' ) and ( Ev.HashValue <> '' ) then
          begin
            var HashArr := TJSONArray.Create;
            SubComp.AddPair( 'hashes', HashArr );

            var HashObj := TJSONObject.Create;
            HashArr.AddElement( HashObj );
            HashObj.AddPair( 'alg', Ev.Algorithm );
            HashObj.AddPair( 'content', Ev.HashValue );
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

begin

  // bom-refs must be unique in the document: a repeated one gets a #2, #3 ... suffix
  var UsedRefs      := TDictionary<string, Boolean>.Create;
  var LibraryRefs   := TList<string>.Create;

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
    Root.AddPair( 'specVersion', '1.5' );
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

        var CompObj := TJSONObject.Create;
        Components.AddElement( CompObj );

        CompObj.AddPair( 'bom-ref', CompRef );
        CompObj.AddPair( 'type', NormaliseComponentType( Entry.CompType ) );
        CompObj.AddPair( 'name', Entry.Name );

        if Entry.Version <> '' then
          CompObj.AddPair( 'version', Entry.Version );

        if Entry.Vendor <> '' then
        begin
          var VendorObj := TJSONObject.Create;
          CompObj.AddPair( 'supplier', VendorObj );
          VendorObj.AddPair( 'name', Entry.Vendor );
        end;

        // Licences: license.id is an SPDX enum, so only recognised identifiers go there
        var Licence := '';
        var LicenceKind := ClassifyLicence( Entry.Licence, Licence );

        case LicenceKind of
          lkSPDX, lkName:
            begin
              var LicArray := TJSONArray.Create;
              CompObj.AddPair( 'licenses', LicArray );

              var LicWrapper := TJSONObject.Create;
              LicArray.AddElement( LicWrapper );

              var LicObj := TJSONObject.Create;
              LicWrapper.AddPair( 'license', LicObj );

              if LicenceKind = lkSPDX then
                LicObj.AddPair( 'id', Licence )
              else
                LicObj.AddPair( 'name', Licence );

              if Entry.LicenceURL <> '' then
                LicObj.AddPair( 'url', Entry.LicenceURL );
            end;

          lkExpression:
            begin
              var LicArray := TJSONArray.Create;
              CompObj.AddPair( 'licenses', LicArray );

              var ExprObj := TJSONObject.Create;
              LicArray.AddElement( ExprObj );
              ExprObj.AddPair( 'expression', Licence );
            end;
        end;

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

    // Dependency graph, two levels: the application uses the RTL and every library; the RTL uses
    // nothing third-party. A library's own dependencies are unknown, so it has no entry — an entry
    // with an empty dependsOn would claim it has none
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

    Result          := Root.Format;
  finally
    Root.Free;
    LibraryRefs.Free;
    UsedRefs.Free;
  end;

end;

function TSBOMBuilder.BuildAndSave( const AProjectInfo: TProjectInfo;
  const AClassifiedUnits: TArray<TClassifiedUnit>;
  const AManifest: TManifest;
  const AVersionOverride: string;
  const AOutputDir: string;
  const AEvidence: TArray<TUnitEvidence> ): string;
begin

  var Json          := Build( AProjectInfo, AClassifiedUnits, AManifest, AVersionOverride, AEvidence );

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

