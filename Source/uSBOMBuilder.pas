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
    ///   AVersionOverride, if non-empty, replaces the version from .dproj.
    /// </summary>
    function Build( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      ARTLScanAvailable: Boolean;
      const AVersionOverride: string ): string;

    /// <summary>
    ///   Builds and writes the SBOM to a file. Returns the output file path.
    /// </summary>
    function BuildAndSave( const AProjectInfo: TProjectInfo;
      const AClassifiedUnits: TArray<TClassifiedUnit>;
      const AManifest: TManifest;
      ARTLScanAvailable: Boolean;
      const AVersionOverride: string;
      const AOutputDir: string ): string;
  end;

implementation

uses
  System.JSON, System.IOUtils, System.DateUtils, System.Generics.Collections,
  System.NetEncoding;

{ TSBOMBuilder }

constructor TSBOMBuilder.Create( ALogProc: TProc<TLogLevel, string> );
begin

  inherited Create;
  FLog := ALogProc;

end;

procedure TSBOMBuilder.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TSBOMBuilder.Build( const AProjectInfo: TProjectInfo;
  const AClassifiedUnits: TArray<TClassifiedUnit>;
  const AManifest: TManifest;
  ARTLScanAvailable: Boolean;
  const AVersionOverride: string ): string;
begin

  var Root := TJSONObject.Create;
  try
    Root.AddPair( 'bomFormat', 'CycloneDX' );
    Root.AddPair( 'specVersion', '1.5' );
    var GuidStr := TGUID.NewGuid.ToString;
    GuidStr := StringReplace( GuidStr, '{', '', [ rfReplaceAll ] );
    GuidStr := StringReplace( GuidStr, '}', '', [ rfReplaceAll ] );
    Root.AddPair( 'serialNumber', 'urn:uuid:' + LowerCase( GuidStr ) );
    Root.AddPair( 'version', TJSONNumber.Create( 1 ) );

    // Metadata
    var Metadata := TJSONObject.Create;

    var UtcNow := TTimeZone.Local.ToUniversalTime( Now );
    Metadata.AddPair( 'timestamp', FormatDateTime( 'yyyy-mm-dd"T"hh:nn:ss"Z"', UtcNow ) );

    // Metadata > tools
    var ToolComp := TJSONObject.Create;
    ToolComp.AddPair( 'type', 'application' );
    ToolComp.AddPair( 'name', AppName );
    ToolComp.AddPair( 'version', AppVersion );

    var ToolSupplier := TJSONObject.Create;
    ToolSupplier.AddPair( 'name', 'DelphiSBOM Contributors' );
    ToolComp.AddPair( 'supplier', ToolSupplier );

    var ToolsArray := TJSONArray.Create;
    ToolsArray.AddElement( ToolComp );

    var ToolsObj := TJSONObject.Create;
    ToolsObj.AddPair( 'components', ToolsArray );
    Metadata.AddPair( 'tools', ToolsObj );

    // Metadata > component (the application being described)
    var MainComp := TJSONObject.Create;
    MainComp.AddPair( 'type', 'application' );
    MainComp.AddPair( 'name', AProjectInfo.ProjectName );

    var EffectiveVersion := AVersionOverride;

    if EffectiveVersion = '' then
      EffectiveVersion := AProjectInfo.ProjectVersion;

    if EffectiveVersion = '' then
      EffectiveVersion := '0.0.0.0';

    MainComp.AddPair( 'version', EffectiveVersion );

    if AManifest.Supplier.Name <> '' then
    begin
      var SupplierObj := TJSONObject.Create;
      SupplierObj.AddPair( 'name', AManifest.Supplier.Name );

      if AManifest.Supplier.URL <> '' then
      begin
        var UrlArray := TJSONArray.Create;
        UrlArray.Add( AManifest.Supplier.URL );
        SupplierObj.AddPair( 'url', UrlArray );
      end;

      MainComp.AddPair( 'supplier', SupplierObj );
    end;

    Metadata.AddPair( 'component', MainComp );
    Root.AddPair( 'metadata', Metadata );

    // Components array
    var Components := TJSONArray.Create;

    // Add RTL as single aggregate component
    var RTLComp := TJSONObject.Create;
    RTLComp.AddPair( 'type', 'framework' );
    RTLComp.AddPair( 'name', 'Embarcadero Delphi RTL' );

    var DelphiVer := AProjectInfo.DelphiVersion;

    if DelphiVer = '' then
      DelphiVer := 'unknown';

    RTLComp.AddPair( 'version', DelphiVer );

    var RTLSupplier := TJSONObject.Create;
    RTLSupplier.AddPair( 'name', 'Embarcadero Technologies' );
    RTLComp.AddPair( 'supplier', RTLSupplier );

    RTLComp.AddPair( 'purl', Format( 'pkg:delphi/embarcadero-rtl@%s', [ TNetEncoding.URL.Encode( DelphiVer ) ] ) );
    Components.AddElement( RTLComp );

    // Add third-party components (deduplicated by component index)
    var AddedComponents := TDictionary<Integer, Boolean>.Create;
    try
      for var CU in AClassifiedUnits do
      begin
        if ( CU.Classification <> ucThirdParty ) or ( CU.ComponentIndex < 0 ) then Continue;

        if AddedComponents.ContainsKey( CU.ComponentIndex ) then Continue;

        AddedComponents.Add( CU.ComponentIndex, True );

        var Entry := AManifest.Components[ CU.ComponentIndex ];
        var CompObj := TJSONObject.Create;

        CompObj.AddPair( 'type', Entry.CompType );
        CompObj.AddPair( 'name', Entry.Name );
        CompObj.AddPair( 'version', Entry.Version );

        if Entry.Vendor <> '' then
        begin
          var VendorObj := TJSONObject.Create;
          VendorObj.AddPair( 'name', Entry.Vendor );
          CompObj.AddPair( 'supplier', VendorObj );
        end;

        // Licences
        if Entry.Licence <> '' then
        begin
          var LicObj := TJSONObject.Create;

          if SameText( Entry.Licence, 'Commercial' ) then
            LicObj.AddPair( 'name', 'Commercial' )
          else
            LicObj.AddPair( 'id', Entry.Licence );

          if Entry.LicenceURL <> '' then
            LicObj.AddPair( 'url', Entry.LicenceURL );

          var LicWrapper := TJSONObject.Create;
          LicWrapper.AddPair( 'license', LicObj );

          var LicArray := TJSONArray.Create;
          LicArray.AddElement( LicWrapper );

          CompObj.AddPair( 'licenses', LicArray );
        end;

        // External references
        if Entry.VendorURL <> '' then
        begin
          var ExtRef := TJSONObject.Create;
          ExtRef.AddPair( 'type', 'website' );
          ExtRef.AddPair( 'url', Entry.VendorURL );

          var ExtRefArray := TJSONArray.Create;
          ExtRefArray.AddElement( ExtRef );

          CompObj.AddPair( 'externalReferences', ExtRefArray );
        end;

        // PURL
        var EncodedName := TNetEncoding.URL.Encode( Entry.Name );

        if Entry.Version <> '' then
          CompObj.AddPair( 'purl', Format( 'pkg:delphi/%s@%s', [ EncodedName, TNetEncoding.URL.Encode( Entry.Version ) ] ) )
        else
          CompObj.AddPair( 'purl', Format( 'pkg:delphi/%s', [ EncodedName ] ) );

        Components.AddElement( CompObj );
      end;
    finally
      AddedComponents.Free;
    end;

    Root.AddPair( 'components', Components );

    Result := Root.Format;

  finally
    Root.Free;
  end;

end;

function TSBOMBuilder.BuildAndSave( const AProjectInfo: TProjectInfo;
  const AClassifiedUnits: TArray<TClassifiedUnit>;
  const AManifest: TManifest;
  ARTLScanAvailable: Boolean;
  const AVersionOverride: string;
  const AOutputDir: string ): string;
begin

  var Json := Build( AProjectInfo, AClassifiedUnits, AManifest, ARTLScanAvailable, AVersionOverride );

  var EffectiveDir := AOutputDir;

  if EffectiveDir = '' then
    EffectiveDir := AProjectInfo.ProjectDir;

  if not TDirectory.Exists( EffectiveDir ) then
    raise Exception.CreateFmt( 'Output directory does not exist: %s', [ EffectiveDir ] );

  Result := TPath.Combine( EffectiveDir, AProjectInfo.ProjectName + '.cdx.json' );

  try
    TFile.WriteAllText( Result, Json, TEncoding.UTF8 );
  except
    on E: Exception do
      raise Exception.CreateFmt( 'Failed to write SBOM to %s: %s', [ Result, E.Message ] );
  end;

  Log( llInfo, Format( 'SBOM written to %s', [ Result ] ) );

end;

end.
