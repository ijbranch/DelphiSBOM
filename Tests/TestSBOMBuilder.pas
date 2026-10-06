(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSBOMBuilder.pas — Tests for uSBOMBuilder (CycloneDX 1.5 output)
*)
unit TestSBOMBuilder;

interface

uses
  System.JSON,
  DUnitX.TestFramework,
  uTypes;

type
  /// <summary>
  ///   Schema-relevant details of the generated CycloneDX 1.5 JSON: licences, purls, types,
  ///   timestamp, evidence and the written file's encoding.
  /// </summary>
  [TestFixture]
  TSBOMBuilderTests = class
  private
    FProject: TProjectInfo;
    FManifest: TManifest;
    FUnits: TArray<TClassifiedUnit>;

    function BuildJson( const AEvidence: TArray<TUnitEvidence> ): TJSONObject;
    function Component( ARoot: TJSONObject; AIndex: Integer ): TJSONObject;
  public
    [Setup]
    procedure Setup;

    /// <summary>
    ///   Proves purl segments are percent-encoded per the purl spec: a space becomes %20 (form encoding
    ///   gave '+', a literal plus in a purl) and reserved characters are escaped.
    /// </summary>
    [Test]
    procedure PurlEncodeFollowsPurlSpec;

    /// <summary>
    ///   Proves the application, the RTL and every library carry a bom-ref, all distinct, so the
    ///   dependency graph can name them.
    /// </summary>
    [Test]
    procedure EveryComponentHasAUniqueBomRef;

    /// <summary>
    ///   Proves the dependencies section links the application to the RTL and every library, and
    ///   declares the RTL with no dependencies; libraries' own dependencies are unknown, so they are
    ///   left out rather than declared empty (an empty list would claim they have none).
    /// </summary>
    [Test]
    procedure DependenciesLinkApplicationToEveryComponent;

    /// <summary>
    ///   Proves two manifest rows with the same name and version still get distinct bom-refs: a
    ///   duplicate bom-ref makes the SBOM invalid.
    /// </summary>
    [Test]
    procedure DuplicateComponentsGetDistinctRefs;

    /// <summary>
    ///   Proves a recognised SPDX licence is emitted as license.id in canonical case.
    /// </summary>
    [Test]
    procedure SPDXLicenceEmittedAsId;

    /// <summary>
    ///   Proves a licence that is not an SPDX identifier is emitted as license.name. Writing it to
    ///   license.id (an enum) made the whole SBOM fail schema validation.
    /// </summary>
    [Test]
    procedure UnknownLicenceEmittedAsName;

    /// <summary>
    ///   Proves an SPDX expression is emitted as a top-level "expression", not inside "license".
    /// </summary>
    [Test]
    procedure ExpressionEmittedAsExpression;

    /// <summary>
    ///   Proves the component type is lower-cased ("Library" is not in the case-sensitive enum) and an
    ///   unknown type falls back to "library".
    /// </summary>
    [Test]
    procedure ComponentTypeNormalised;

    /// <summary>
    ///   Proves the component purl encodes the name and the RTL purl carries the mapped BDS version.
    /// </summary>
    [Test]
    procedure PurlsEmitted;

    /// <summary>
    ///   Proves the timestamp is ISO 8601 UTC with ':' separators even when the locale's time separator
    ///   is '.', which FormatDateTime substituted for ':' before the fix.
    /// </summary>
    [Test]
    procedure TimestampIgnoresLocaleTimeSeparator;

    /// <summary>
    ///   Proves evidence named with a scope (System.SysUtils) attaches to a unit the .dpr lists unscoped
    ///   (SysUtils), with its origin carried as a dxcomply:origin property.
    /// </summary>
    [Test]
    procedure EvidenceMatchesScopeStrippedName;

    /// <summary>
    ///   Proves BuildAndSave writes UTF-8 without a BOM and the file parses as JSON.
    /// </summary>
    [Test]
    procedure SavedFileHasNoBom;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, System.RegularExpressions, System.Generics.Collections,
  uSBOMBuilder, TestSupport;

{ TSBOMBuilderTests }

procedure TSBOMBuilderTests.Setup;
begin

  FProject := Default( TProjectInfo );
  FProject.ProjectName   := 'App';
  FProject.DelphiVersion := '37.0';

  FManifest := Default( TManifest );
  SetLength( FManifest.Components, 3 );

  FManifest.Components[ 0 ].Name     := 'TMS VCL UI Pack';
  FManifest.Components[ 0 ].Version  := '13.0';
  FManifest.Components[ 0 ].Licence  := 'mit';
  FManifest.Components[ 0 ].CompType := 'Library';

  FManifest.Components[ 1 ].Name     := 'Closed';
  FManifest.Components[ 1 ].Version  := '1';
  FManifest.Components[ 1 ].Licence  := 'Proprietary';
  FManifest.Components[ 1 ].CompType := 'widget';

  FManifest.Components[ 2 ].Name     := 'Dual';
  FManifest.Components[ 2 ].Version  := '2';
  FManifest.Components[ 2 ].Licence  := 'MPL-1.1 OR LGPL-2.1-or-later';
  FManifest.Components[ 2 ].CompType := 'framework';

  SetLength( FUnits, 4 );

  for var I := 0 to 2 do
  begin
    FUnits[ I ].OriginalName   := 'Unit' + IntToStr( I );
    FUnits[ I ].UnitName       := FUnits[ I ].OriginalName;
    FUnits[ I ].Classification := ucThirdParty;
    FUnits[ I ].ComponentIndex := I;
  end;

  FUnits[ 3 ].OriginalName   := 'SysUtils';
  FUnits[ 3 ].UnitName       := 'SysUtils';
  FUnits[ 3 ].Classification := ucRTL;
  FUnits[ 3 ].ComponentIndex := -1;

end;

function TSBOMBuilderTests.BuildJson( const AEvidence: TArray<TUnitEvidence> ): TJSONObject;
begin

  var Builder := TSBOMBuilder.Create( NoLog() );
  try
    Result := TJSONObject.ParseJSONValue( Builder.Build( FProject, FUnits, FManifest, '', AEvidence ) ) as TJSONObject;
  finally
    Builder.Free;
  end;

end;

function TSBOMBuilderTests.Component( ARoot: TJSONObject; AIndex: Integer ): TJSONObject;
begin

  // components[ 0 ] is the RTL; manifest component N is components[ N + 1 ]
  Result := ARoot.GetValue<TJSONArray>( 'components' ).Items[ AIndex ] as TJSONObject;

end;

procedure TSBOMBuilderTests.PurlEncodeFollowsPurlSpec;
begin

  Assert.AreEqual( 'TMS%20VCL%20UI%20Pack', PurlEncode( 'TMS VCL UI Pack' ), False );
  Assert.AreEqual( 'a%2Bb%2Fc%40d', PurlEncode( 'a+b/c@d' ), False );
  Assert.AreEqual( 'Abc-1.2_x~', PurlEncode( 'Abc-1.2_x~' ), False );
  Assert.AreEqual( 'M%C3%BCller', PurlEncode( 'M' + #$00FC + 'ller' ), False );

end;

/// <summary>The bom-ref of a component object, or '' when it has none.</summary>
function BomRef( AObject: TJSONObject ): string;
begin

  Result := '';

  if Assigned( AObject ) then
    AObject.TryGetValue<string>( 'bom-ref', Result );

end;

procedure TSBOMBuilderTests.EveryComponentHasAUniqueBomRef;
begin

  var Root := BuildJson( nil );
  try
    var Refs := TList<string>.Create;
    try
      Refs.Add( BomRef( Root.GetValue<TJSONObject>( 'metadata.component' ) ) );

      for var I := 0 to Root.GetValue<TJSONArray>( 'components' ).Count - 1 do
        Refs.Add( BomRef( Component( Root, I ) ) );

      Assert.AreEqual<Integer>( 5, Refs.Count, 'Application, RTL and three libraries' );

      for var I := 0 to Refs.Count - 1 do
      begin
        Assert.AreNotEqual( '', Refs[ I ], Format( 'Component %d has no bom-ref', [ I ] ) );

        for var J := I + 1 to Refs.Count - 1 do
          Assert.AreNotEqual( Refs[ I ], Refs[ J ], 'Duplicate bom-ref' );
      end;
    finally
      Refs.Free;
    end;
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.DependenciesLinkApplicationToEveryComponent;
begin

  var Root := BuildJson( nil );
  try
    var AppRef := BomRef( Root.GetValue<TJSONObject>( 'metadata.component' ) );
    var Deps   := Root.GetValue<TJSONArray>( 'dependencies' );
    Assert.IsNotNull( Deps, 'No dependencies section' );

    var AppEntry: TJSONObject := nil;
    var RTLEntry: TJSONObject := nil;
    var RTLRef := BomRef( Component( Root, 0 ) );

    for var D in Deps do
    begin
      var Entry := D as TJSONObject;

      if Entry.GetValue<string>( 'ref' ) = AppRef then
        AppEntry := Entry
      else if Entry.GetValue<string>( 'ref' ) = RTLRef then
        RTLEntry := Entry
      else
        Assert.Fail( 'Unexpected dependency entry for ' + Entry.GetValue<string>( 'ref' ) );
    end;

    Assert.IsNotNull( AppEntry, 'No entry for the application' );
    var DependsOn := AppEntry.GetValue<TJSONArray>( 'dependsOn' );
    Assert.AreEqual<Integer>( 4, DependsOn.Count, 'The application depends on the RTL and three libraries' );

    for var I := 0 to 3 do
      Assert.AreEqual( BomRef( Component( Root, I ) ), DependsOn.Items[ I ].Value );

    Assert.IsNotNull( RTLEntry, 'No entry for the RTL' );
    Assert.AreEqual<Integer>( 0, RTLEntry.GetValue<TJSONArray>( 'dependsOn' ).Count, 'The RTL depends on nothing' );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.DuplicateComponentsGetDistinctRefs;
begin

  FManifest.Components[ 1 ].Name    := FManifest.Components[ 0 ].Name;
  FManifest.Components[ 1 ].Version := FManifest.Components[ 0 ].Version;

  var Root := BuildJson( nil );
  try
    Assert.AreNotEqual( '', BomRef( Component( Root, 1 ) ) );
    Assert.AreNotEqual( BomRef( Component( Root, 1 ) ), BomRef( Component( Root, 2 ) ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.SPDXLicenceEmittedAsId;
begin

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'MIT', Component( Root, 1 ).GetValue<string>( 'licenses[0].license.id' ), False );
    Assert.IsNull( Component( Root, 1 ).FindValue( 'licenses[0].license.name' ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.UnknownLicenceEmittedAsName;
begin

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'Proprietary', Component( Root, 2 ).GetValue<string>( 'licenses[0].license.name' ), False );
    Assert.IsNull( Component( Root, 2 ).FindValue( 'licenses[0].license.id' ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.ExpressionEmittedAsExpression;
begin

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'MPL-1.1 OR LGPL-2.1-or-later', Component( Root, 3 ).GetValue<string>( 'licenses[0].expression' ), False );
    Assert.IsNull( Component( Root, 3 ).FindValue( 'licenses[0].license' ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.ComponentTypeNormalised;
begin

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'library', Component( Root, 1 ).GetValue<string>( 'type' ), False );
    Assert.AreEqual( 'library', Component( Root, 2 ).GetValue<string>( 'type' ), False );
    Assert.AreEqual( 'framework', Component( Root, 3 ).GetValue<string>( 'type' ), False );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.PurlsEmitted;
begin

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'pkg:delphi/TMS%20VCL%20UI%20Pack@13.0', Component( Root, 1 ).GetValue<string>( 'purl' ), False );
    Assert.AreEqual( 'pkg:delphi/embarcadero-rtl@37.0', Component( Root, 0 ).GetValue<string>( 'purl' ), False );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.TimestampIgnoresLocaleTimeSeparator;
begin

  var SavedSeparator := FormatSettings.TimeSeparator;
  FormatSettings.TimeSeparator := '.';
  try
    var Root := BuildJson( nil );
    try
      var Timestamp := Root.GetValue<string>( 'metadata.timestamp' );

      Assert.IsTrue( TRegEx.IsMatch( Timestamp, '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' ), Timestamp );
    finally
      Root.Free;
    end;
  finally
    FormatSettings.TimeSeparator := SavedSeparator;
  end;

end;

procedure TSBOMBuilderTests.EvidenceMatchesScopeStrippedName;
begin

  var Evidence: TArray<TUnitEvidence>;
  SetLength( Evidence, 1 );
  Evidence[ 0 ].UnitName  := 'System.SysUtils';
  Evidence[ 0 ].Algorithm := 'SHA-256';
  Evidence[ 0 ].HashValue := 'abc123';
  Evidence[ 0 ].Origin    := 'Embarcadero RTL';

  var Root := BuildJson( Evidence );
  try
    var Rtl := Component( Root, 0 );

    Assert.AreEqual( 'System.SysUtils', Rtl.GetValue<string>( 'components[0].name' ), False );
    Assert.AreEqual( 'abc123', Rtl.GetValue<string>( 'components[0].hashes[0].content' ), False );
    Assert.AreEqual( 'Embarcadero RTL', Rtl.GetValue<string>( 'components[0].properties[0].value' ), False );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.SavedFileHasNoBom;
begin

  var Scratch := TScratchDir.Create;
  try
    var Builder := TSBOMBuilder.Create( NoLog() );
    try
      var FileName := Builder.BuildAndSave( FProject, FUnits, FManifest, '', Scratch.Path, nil );
      var Bytes := TFile.ReadAllBytes( FileName );

      Assert.AreEqual( Ord( '{' ), Integer( Bytes[ 0 ] ), 'No BOM' );

      var Parsed := TJSONObject.ParseJSONValue( TEncoding.UTF8.GetString( Bytes ) );
      try
        Assert.IsNotNull( Parsed, 'Output parses as JSON' );
      finally
        Parsed.Free;
      end;
    finally
      Builder.Free;
    end;
  finally
    Scratch.Free;
  end;

end;

end.
