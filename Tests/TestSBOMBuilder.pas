(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSBOMBuilder.pas — Tests for uSBOMBuilder (CycloneDX 1.6 output)
*)
unit TestSBOMBuilder;

interface

uses
  System.JSON,
  DUnitX.TestFramework,
  uTypes;

type
  /// <summary>
  ///   Schema-relevant details of the generated CycloneDX 1.6 JSON: licences, purls, types,
  ///   timestamp, evidence, the BSI TR-03183-2 fields and the written file's encoding.
  /// </summary>
  [TestFixture]
  TSBOMBuilderTests = class
  private
    FProject: TProjectInfo;
    FManifest: TManifest;
    FUnits: TArray<TClassifiedUnit>;
    /// <summary>The library uses passed to the builder (none unless a test sets them).</summary>
    FLibraryDependencies: TArray<TLibraryDependency>;
    /// <summary>The built binary passed to the builder (none unless a test sets it).</summary>
    FBinary: TBinaryInfo;

    /// <summary>Builds the SBOM from the fixture's project, units, manifest and library uses.</summary>
    /// <param name="AEvidence">The DX.Comply evidence to merge.</param>
    /// <returns>The parsed document; the caller frees it.</returns>
    function BuildJson( const AEvidence: TArray<TUnitEvidence> ): TJSONObject;
    function Component( ARoot: TJSONObject; AIndex: Integer ): TJSONObject;
  public
    /// <summary>
    ///   Gives every test the same project, three-library manifest and units, and clears the library uses and the
    ///   binary, since one fixture instance serves every test.
    /// </summary>
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
    ///   Proves the dependencies section links the application to the RTL and every library, and gives
    ///   the RTL and each library an entry of its own, empty when nothing is known of its uses: CycloneDX 1.6
    ///   and BSI TR-03183-2 require every component in the graph, and the composition says it is incomplete.
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
    ///   Proves a manifest purl replaces the generated pkg:delphi one, as the purl and as the bom-ref the
    ///   dependency graph names, so a library can be identified by its registered package type
    ///   (pkg:github/...); components without one keep the generated purl.
    /// </summary>
    [Test]
    procedure ManifestPurlOverridesTheGeneratedOne;

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
    ///   Proves a unit with several hashes gets them all, in order (SHA-256 and SHA-512): only one used
    ///   to be written, so a SHA-512 from DX.Comply was lost.
    /// </summary>
    [Test]
    procedure EvidenceWritesEveryHash;

    /// <summary>
    ///   Proves the SBOM states its dependency graph is incomplete (libraries' own dependencies are not
    ///   fully resolved): one composition, aggregate "incomplete", naming the application and every
    ///   component, so the completeness of each one's dependencies is stated (BSI TR-03183-2 5.2.2).
    /// </summary>
    [Test]
    procedure CompositionDeclaresTheGraphIncomplete;

    /// <summary>
    ///   Proves a library's uses become its own dependency entry, naming the other library and the RTL once
    ///   each, while an edge to a manifest row that is not in the SBOM, to itself, or a repeat, is left out; and
    ///   that a library with no edge left keeps an empty entry (the composition, not the entry, says how complete
    ///   it is).
    /// </summary>
    [Test]
    procedure LibraryUsesBecomeDependencyEntries;

    /// <summary>
    ///   Proves a manifest vendor_email becomes supplier.contact[0].email (trimmed), also without a
    ///   vendor name, and that a value which is not an email address is left out rather than making the
    ///   SBOM invalid (CycloneDX's email is format idn-email).
    /// </summary>
    [Test]
    procedure VendorEmailWrittenAsSupplierContact;

    /// <summary>
    ///   Proves the document is CycloneDX 1.6, the version BSI TR-03183-2 v2.1.0 requires at least, and that the
    ///   supplier is written as the SBOM's creator (metadata.manufacturer) with its email, not its URL, since the
    ///   TR asks for the email and takes a URL only without one.
    /// </summary>
    [Test]
    procedure SpecVersionAndSBOMCreator;

    /// <summary>
    ///   Proves each component's creator becomes its manufacturer: creator_email when given (and the vendor name
    ///   is then not claimed for it), else the vendor's email, else the vendor's URL; and that a creator email which
    ///   is not an email address falls back to the creator URL rather than making the SBOM invalid.
    /// </summary>
    [Test]
    procedure CreatorWrittenAsManufacturer;

    /// <summary>
    ///   Proves every licence the builder writes, as an id, a name or an expression, is acknowledged "concluded"
    ///   (the TR's distribution licence); that the application gets the manifest's application_licence; and that
    ///   the RTL gets the LicenseRef- identifier and Embarcadero's web page as its creator.
    /// </summary>
    [Test]
    procedure LicencesAcknowledgedAndRTLDescribed;

    /// <summary>
    ///   Proves a described binary gives the application its SHA-512 (in hashes and in a distribution reference
    ///   named by the file) and the four bsi:component properties of an unstructured executable, and that without
    ///   one none of them is written: a hash must never be invented.
    /// </summary>
    [Test]
    procedure BinaryWrittenAsFileFields;

    /// <summary>
    ///   Proves a creator_email that is not an email address, with no creator_url, does not count as a creator: the
    ///   vendor still stands in, so the component keeps a manufacturer rather than losing it.
    /// </summary>
    [Test]
    procedure InvalidCreatorEmailFallsBackToVendor;

    /// <summary>
    ///   Proves a binary whose name holds characters an IRI-reference may not (a space, '#') gets them percent-encoded
    ///   in the distribution reference's url, which the schema checks as iri-reference, while bsi:component:filename
    ///   keeps the name as it is.
    /// </summary>
    [Test]
    procedure BinaryNameEncodedAsIriReference;

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

  // One fixture instance serves every test, so what a test sets must not reach the next
  FLibraryDependencies := nil;
  FBinary := Default( TBinaryInfo );

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
    Builder.Binary := FBinary;
    Result := TJSONObject.ParseJSONValue( Builder.Build( FProject, FUnits, FManifest, '', AEvidence, FLibraryDependencies ) ) as TJSONObject;
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

    // One entry per component: the application, then the RTL and the three libraries in component order
    Assert.AreEqual<Integer>( 5, Deps.Count, 'An entry for the application and for each of the four components' );

    var AppEntry := Deps.Items[ 0 ] as TJSONObject;
    Assert.AreEqual( AppRef, AppEntry.GetValue<string>( 'ref' ), 'The application''s entry comes first' );

    var DependsOn := AppEntry.GetValue<TJSONArray>( 'dependsOn' );
    Assert.AreEqual<Integer>( 4, DependsOn.Count, 'The application depends on the RTL and three libraries' );

    for var I := 0 to 3 do
      Assert.AreEqual( BomRef( Component( Root, I ) ), DependsOn.Items[ I ].Value );

    // No library uses were read, so the RTL and every library have an empty entry
    for var I := 0 to 3 do
    begin
      var Entry := Deps.Items[ I + 1 ] as TJSONObject;
      Assert.AreEqual( BomRef( Component( Root, I ) ), Entry.GetValue<string>( 'ref' ) );
      Assert.AreEqual<Integer>( 0, Entry.GetValue<TJSONArray>( 'dependsOn' ).Count, Entry.GetValue<string>( 'ref' ) + ' lists uses' );
    end;
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

procedure TSBOMBuilderTests.ManifestPurlOverridesTheGeneratedOne;
begin

  FManifest.Components[ 0 ].Purl := 'pkg:github/tmssoftware/vcl-ui-pack@v13.0';

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'pkg:github/tmssoftware/vcl-ui-pack@v13.0', Component( Root, 1 ).GetValue<string>( 'purl' ) );
    Assert.AreEqual( 'pkg:github/tmssoftware/vcl-ui-pack@v13.0', BomRef( Component( Root, 1 ) ) );
    Assert.AreEqual( 'pkg:delphi/Closed@1', Component( Root, 2 ).GetValue<string>( 'purl' ), 'Others keep the generated purl' );

    var DependsOn := Root.GetValue<TJSONArray>( 'dependencies' ).Items[ 0 ].GetValue<TJSONArray>( 'dependsOn' );
    Assert.AreEqual( 'pkg:github/tmssoftware/vcl-ui-pack@v13.0', DependsOn.Items[ 1 ].Value, 'Dependency graph names the override' );
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
  Evidence[ 0 ].Hashes    := [ EvidenceHash( 'SHA-256', 'abc123' ) ];
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

procedure TSBOMBuilderTests.EvidenceWritesEveryHash;
begin

  var Evidence: TArray<TUnitEvidence>;
  SetLength( Evidence, 1 );
  Evidence[ 0 ].UnitName := 'SysUtils';
  Evidence[ 0 ].Hashes   := [ EvidenceHash( 'SHA-256', 'aaa' ), EvidenceHash( 'SHA-512', 'bbb' ) ];

  var Root := BuildJson( Evidence );
  try
    var Hashes := Component( Root, 0 ).GetValue<TJSONArray>( 'components[0].hashes' );

    Assert.AreEqual<Integer>( 2, Hashes.Count );
    Assert.AreEqual( 'SHA-256', Hashes.Items[ 0 ].GetValue<string>( 'alg' ) );
    Assert.AreEqual( 'aaa', Hashes.Items[ 0 ].GetValue<string>( 'content' ) );
    Assert.AreEqual( 'SHA-512', Hashes.Items[ 1 ].GetValue<string>( 'alg' ) );
    Assert.AreEqual( 'bbb', Hashes.Items[ 1 ].GetValue<string>( 'content' ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.CompositionDeclaresTheGraphIncomplete;
begin

  var Root := BuildJson( nil );
  try
    var Compositions := Root.GetValue<TJSONArray>( 'compositions' );
    Assert.IsNotNull( Compositions, 'No compositions section' );
    Assert.AreEqual<Integer>( 1, Compositions.Count );
    Assert.AreEqual( 'incomplete', Compositions.Items[ 0 ].GetValue<string>( 'aggregate' ) );

    var Refs := Compositions.Items[ 0 ].GetValue<TJSONArray>( 'dependencies' );
    Assert.AreEqual<Integer>( 5, Refs.Count, 'The application, the RTL and the three libraries' );
    Assert.AreEqual( BomRef( Root.GetValue<TJSONObject>( 'metadata.component' ) ), Refs.Items[ 0 ].Value, 'Names the application' );

    for var I := 0 to 3 do
      Assert.AreEqual( BomRef( Component( Root, I ) ), Refs.Items[ I + 1 ].Value, 'Names component ' + IntToStr( I ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.LibraryUsesBecomeDependencyEntries;
begin

  // A fourth manifest row that no unit uses, so it is not in the SBOM
  SetLength( FManifest.Components, 4 );
  FManifest.Components[ 3 ].Name    := 'Unused';
  FManifest.Components[ 3 ].Version := '1';

  SetLength( FLibraryDependencies, 2 );
  FLibraryDependencies[ 0 ].ComponentIndex := 0;
  FLibraryDependencies[ 0 ].DependsOn := [ 1, RTLComponentIndex, 3, 0, 1 ];
  FLibraryDependencies[ 1 ].ComponentIndex := 1;
  FLibraryDependencies[ 1 ].DependsOn := [ 3 ];

  var Root := BuildJson( nil );
  try
    var AppRef := BomRef( Root.GetValue<TJSONObject>( 'metadata.component' ) );
    var RTLRef := BomRef( Component( Root, 0 ) );
    var Lib0Ref := BomRef( Component( Root, 1 ) );
    var Lib1Ref := BomRef( Component( Root, 2 ) );
    var Lib0Entry: TJSONObject := nil;
    var Lib1Entry: TJSONObject := nil;

    for var D in Root.GetValue<TJSONArray>( 'dependencies' ) do
    begin
      var Ref := D.GetValue<string>( 'ref' );

      if Ref = Lib0Ref then
        Lib0Entry := D as TJSONObject
      else if Ref = Lib1Ref then
        Lib1Entry := D as TJSONObject
      else
        Assert.IsTrue( ( Ref = AppRef ) or ( Ref = RTLRef ) or ( Ref = BomRef( Component( Root, 3 ) ) ),
          'Unexpected dependency entry for ' + Ref );
    end;

    Assert.IsNotNull( Lib0Entry, 'No entry for the library whose uses were read' );
    var DependsOn := Lib0Entry.GetValue<TJSONArray>( 'dependsOn' );
    Assert.AreEqual<Integer>( 2, DependsOn.Count, 'The other library and the RTL, once each' );
    Assert.AreEqual( Lib1Ref, DependsOn.Items[ 0 ].Value );
    Assert.AreEqual( RTLRef, DependsOn.Items[ 1 ].Value );

    // Its only edge goes to a manifest row that is not in the SBOM, so its entry is empty
    Assert.IsNotNull( Lib1Entry, 'No entry for the library whose only edge was dropped' );
    Assert.AreEqual<Integer>( 0, Lib1Entry.GetValue<TJSONArray>( 'dependsOn' ).Count, 'The edge to the unused row is left out' );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.VendorEmailWrittenAsSupplierContact;
begin

  FManifest.Components[ 0 ].Vendor      := 'TMS Software';
  FManifest.Components[ 0 ].VendorEmail := ' info@tmssoftware.com ';
  FManifest.Components[ 1 ].VendorEmail := 'https://example.com';
  FManifest.Components[ 2 ].Vendor      := '';
  FManifest.Components[ 2 ].VendorEmail := 'dual@example.org';

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( 'TMS Software', Component( Root, 1 ).GetValue<string>( 'supplier.name' ) );
    Assert.AreEqual( 'info@tmssoftware.com', Component( Root, 1 ).GetValue<string>( 'supplier.contact[0].email' ), 'Trimmed' );
    Assert.IsNull( Component( Root, 2 ).GetValue( 'supplier' ), 'Not an email address: left out, and no vendor either' );
    Assert.IsNull( Component( Root, 3 ).FindValue( 'supplier.name' ), 'No vendor name' );
    Assert.AreEqual( 'dual@example.org', Component( Root, 3 ).GetValue<string>( 'supplier.contact[0].email' ), 'Email without a vendor name' );
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

/// <summary>The email of an organizationalEntity's first contact, or '' when it has none.</summary>
function ContactEmail( AEntity: TJSONObject ): string;
begin

  Result := '';
  var Contacts: TJSONArray;

  if Assigned( AEntity ) and AEntity.TryGetValue<TJSONArray>( 'contact', Contacts ) and ( Contacts.Count > 0 ) then
    Contacts.Items[ 0 ].TryGetValue<string>( 'email', Result );

end;

/// <summary>The first URL of an organizationalEntity, or '' when it has none.</summary>
function EntityURL( AEntity: TJSONObject ): string;
begin

  Result := '';
  var Urls: TJSONArray;

  if Assigned( AEntity ) and AEntity.TryGetValue<TJSONArray>( 'url', Urls ) and ( Urls.Count > 0 ) then
    Result := Urls.Items[ 0 ].Value;

end;

procedure TSBOMBuilderTests.SpecVersionAndSBOMCreator;
begin

  FManifest.Supplier.Name  := 'Me';
  FManifest.Supplier.URL   := 'https://example.com';
  FManifest.Supplier.Email := 'sbom@example.com';

  var Root := BuildJson( nil );
  try
    Assert.AreEqual( '1.6', Root.GetValue<string>( 'specVersion' ) );

    var Creator := Root.GetValue<TJSONObject>( 'metadata.manufacturer' );
    Assert.IsNotNull( Creator, 'No metadata.manufacturer' );
    Assert.AreEqual( 'Me', Creator.GetValue<string>( 'name' ) );
    Assert.AreEqual( 'sbom@example.com', ContactEmail( Creator ) );
    Assert.AreEqual( '', EntityURL( Creator ), 'The URL is written only without an email' );

    // The application's creator is the supplier too
    Assert.AreEqual( 'sbom@example.com', ContactEmail( Root.GetValue<TJSONObject>( 'metadata.component.manufacturer' ) ) );
  finally
    Root.Free;
  end;

  // Without an email, the URL names the creator
  FManifest.Supplier.Email := '';
  Root := BuildJson( nil );
  try
    Assert.AreEqual( 'https://example.com', EntityURL( Root.GetValue<TJSONObject>( 'metadata.manufacturer' ) ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.CreatorWrittenAsManufacturer;
begin

  FManifest.Components[ 0 ].Vendor       := 'Reseller';
  FManifest.Components[ 0 ].VendorEmail  := 'sales@reseller.example.com';
  FManifest.Components[ 0 ].CreatorEmail := 'author@example.com';

  FManifest.Components[ 1 ].Vendor      := 'Closed Ltd';
  FManifest.Components[ 1 ].VendorEmail := 'info@closed.example.com';
  FManifest.Components[ 1 ].VendorURL   := 'https://closed.example.com';

  FManifest.Components[ 2 ].VendorURL    := 'https://dual.example.com';
  FManifest.Components[ 2 ].CreatorEmail := 'not an email';
  FManifest.Components[ 2 ].CreatorURL   := 'https://author.example.com';

  var Root := BuildJson( nil );
  try
    var Creator := Component( Root, 1 ).GetValue<TJSONObject>( 'manufacturer' );
    Assert.AreEqual( 'author@example.com', ContactEmail( Creator ), 'creator_email wins over the vendor' );
    Assert.IsNull( Creator.GetValue( 'name' ), 'The vendor''s name is not claimed for a separate creator' );
    Assert.AreEqual( 'Reseller', Component( Root, 1 ).GetValue<string>( 'supplier.name' ), 'The supplier stays the vendor' );

    Creator := Component( Root, 2 ).GetValue<TJSONObject>( 'manufacturer' );
    Assert.AreEqual( 'Closed Ltd', Creator.GetValue<string>( 'name' ), 'Without creator fields the vendor is the creator' );
    Assert.AreEqual( 'info@closed.example.com', ContactEmail( Creator ) );
    Assert.AreEqual( '', EntityURL( Creator ), 'An email wins over a URL' );

    Creator := Component( Root, 3 ).GetValue<TJSONObject>( 'manufacturer' );
    Assert.AreEqual( '', ContactEmail( Creator ), 'A value that is not an email address is left out' );
    Assert.AreEqual( 'https://author.example.com', EntityURL( Creator ), 'The creator URL, not the vendor URL' );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.LicencesAcknowledgedAndRTLDescribed;
begin

  FManifest.ApplicationLicence := 'LicenseRef-Me-Commercial';

  var Root := BuildJson( nil );
  try
    // The application's licence, a LicenseRef- identifier, is an expression
    var AppLicences := Root.GetValue<TJSONArray>( 'metadata.component.licenses' );
    Assert.IsNotNull( AppLicences, 'The application has no licence' );
    Assert.AreEqual( 'LicenseRef-Me-Commercial', AppLicences.Items[ 0 ].GetValue<string>( 'expression' ) );
    Assert.AreEqual( 'concluded', AppLicences.Items[ 0 ].GetValue<string>( 'acknowledgement' ) );

    // The RTL
    var RTL := Component( Root, 0 );
    Assert.AreEqual( RTLLicence, RTL.GetValue<string>( 'licenses[0].expression' ) );
    Assert.AreEqual( 'concluded', RTL.GetValue<string>( 'licenses[0].acknowledgement' ) );
    Assert.AreEqual( RTLCreatorURL, EntityURL( RTL.GetValue<TJSONObject>( 'manufacturer' ) ) );

    // An SPDX id (TMS: mit), a name (Closed: Proprietary) and an expression (Dual)
    Assert.AreEqual( 'concluded', Component( Root, 1 ).GetValue<string>( 'licenses[0].license.acknowledgement' ), 'id' );
    Assert.AreEqual( 'concluded', Component( Root, 2 ).GetValue<string>( 'licenses[0].license.acknowledgement' ), 'name' );
    Assert.AreEqual( 'concluded', Component( Root, 3 ).GetValue<string>( 'licenses[0].acknowledgement' ), 'expression' );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.BinaryWrittenAsFileFields;
begin

  // Without a binary: no file data at all
  var Root := BuildJson( nil );
  try
    var App := Root.GetValue<TJSONObject>( 'metadata.component' );
    Assert.IsNull( App.GetValue( 'hashes' ), 'A hash was written without a binary' );
    Assert.IsNull( App.GetValue( 'externalReferences' ), 'A distribution reference was written without a binary' );
    Assert.IsNull( App.GetValue( 'properties' ), 'File properties were written without a binary' );
  finally
    Root.Free;
  end;

  var Digest := StringOfChar( 'd', 128 );
  FBinary.FileName := 'App.exe';
  FBinary.SHA512 := Digest;

  Root := BuildJson( nil );
  try
    var App := Root.GetValue<TJSONObject>( 'metadata.component' );
    Assert.AreEqual( 'SHA-512', App.GetValue<string>( 'hashes[0].alg' ) );
    Assert.AreEqual( Digest, App.GetValue<string>( 'hashes[0].content' ) );

    Assert.AreEqual( 'distribution', App.GetValue<string>( 'externalReferences[0].type' ) );
    Assert.AreEqual( 'App.exe', App.GetValue<string>( 'externalReferences[0].url' ) );
    Assert.AreEqual( 'SHA-512', App.GetValue<string>( 'externalReferences[0].hashes[0].alg' ) );
    Assert.AreEqual( Digest, App.GetValue<string>( 'externalReferences[0].hashes[0].content' ) );

    var Props := '';

    for var Prop in App.GetValue<TJSONArray>( 'properties' ) do
      Props := Props + Prop.GetValue<string>( 'name' ) + '=' + Prop.GetValue<string>( 'value' ) + '; ';

    Assert.AreEqual( 'bsi:component:filename=App.exe; bsi:component:executable=executable; bsi:component:archive=no archive; ' +
      'bsi:component:structured=unstructured; ', Props );

    // A linked library is a logical component: no file properties
    Assert.IsNull( Component( Root, 1 ).GetValue( 'properties' ), 'A library was given file properties' );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.InvalidCreatorEmailFallsBackToVendor;
begin

  FManifest.Components[ 0 ].Vendor       := 'TMS';
  FManifest.Components[ 0 ].VendorURL    := 'https://www.tmssoftware.com';
  FManifest.Components[ 0 ].CreatorEmail := 'TMS Software';

  var Root := BuildJson( nil );
  try
    var Creator := Component( Root, 1 ).GetValue<TJSONObject>( 'manufacturer' );
    Assert.IsNotNull( Creator, 'The component lost its manufacturer' );
    Assert.AreEqual( 'TMS', Creator.GetValue<string>( 'name' ) );
    Assert.AreEqual( 'https://www.tmssoftware.com', EntityURL( Creator ) );
  finally
    Root.Free;
  end;

end;

procedure TSBOMBuilderTests.BinaryNameEncodedAsIriReference;
begin

  FBinary.FileName := 'My App#1.exe';
  FBinary.SHA512 := StringOfChar( 'e', 128 );

  var Root := BuildJson( nil );
  try
    var App := Root.GetValue<TJSONObject>( 'metadata.component' );
    Assert.AreEqual( 'My%20App%231.exe', App.GetValue<string>( 'externalReferences[0].url' ) );
    Assert.AreEqual( 'My App#1.exe', App.GetValue<string>( 'properties[0].value' ), 'The file name property is the name itself' );
  finally
    Root.Free;
  end;

end;

end.
