(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSBOMValidator.pas — Tests for the structural check run on every written SBOM
*)
unit TestSBOMValidator;

interface

uses
  DUnitX.TestFramework,
  uTypes;

type
  /// <summary>
  ///   Each rule of the post-write check, proved by breaking one thing in an otherwise valid document.
  /// </summary>
  [TestFixture]
  TSBOMValidatorTests = class
  private
    function ErrorsFor( const AFind, AReplace: string ): TArray<string>;
    procedure AssertOneErrorContaining( const AFind, AReplace, AExpected: string );
  public
    /// <summary>
    ///   Proves the reference document, which uses every construct the builder emits, passes: a check
    ///   that flags valid output would fail every run.
    /// </summary>
    [Test]
    procedure ValidDocumentPasses;

    /// <summary>
    ///   Proves what the builder itself writes passes, evidence sub-components and the dependency
    ///   graph included.
    /// </summary>
    [Test]
    procedure BuilderOutputPasses;

    /// <summary>
    ///   Proves each broken rule is reported once, naming where in the document it is.
    /// </summary>
    /// <param name="AFind">Text of the valid document to replace.</param>
    /// <param name="AReplace">The broken text.</param>
    /// <param name="AExpected">Text the single error must contain.</param>
    [Test]
    [TestCase( 'format', '"bomFormat": "CycloneDX"|"bomFormat": "SPDX"|bomFormat', '|' )]
    [TestCase( 'spec version', '"specVersion": "1.5"|"specVersion": "1.4"|specVersion', '|' )]
    [TestCase( 'serial number', 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79|urn:uuid:not-a-uuid|serialNumber', '|' )]
    [TestCase( 'bom version', '"version": 1,|"version": 0,|version', '|' )]
    [TestCase( 'timestamp', '2026-10-07T01:02:03Z|07/10/2026|timestamp', '|' )]
    [TestCase( 'component type', '"type": "framework"|"type": "Framework"|components[0].type', '|' )]
    [TestCase( 'missing name', '"name": "Acme Widgets",|"name": "",|components[1].name', '|' )]
    [TestCase( 'licence id casing', '"id": "MIT"|"id": "mit"|components[1].licenses[0].license.id', '|' )]
    [TestCase( 'licence id and name', '"id": "MIT"|"id": "MIT", "name": "MIT"|components[1].licenses[0].license', '|' )]
    [TestCase( 'licence and expression', '{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }|' +
      '{ "expression": "MPL-1.1", "license": { "id": "MIT" } }|components[2].licenses[0]', '|' )]
    [TestCase( 'hash algorithm', '"alg": "SHA-256"|"alg": "SHA256"|components[0].components[0].hashes[0].alg', '|' )]
    [TestCase( 'hash length', '88de45b3a6f2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6|88de45|' +
      'components[0].components[0].hashes[0].content', '|' )]
    [TestCase( 'purl scheme', '"purl": "pkg:delphi/acme-widgets@2.1"|"purl": "file:Acme.Widgets.pas"|components[1].purl', '|' )]
    [TestCase( 'duplicate ref', '"name": "DelphiSBOM",|"bom-ref": "pkg:delphi/dual@3", "name": "DelphiSBOM",|bom-ref', '|' )]
    [TestCase( 'unknown dependency', '"dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/acme-widgets@2.1"|' +
      '"dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/nowhere@1"|dependencies[0].dependsOn', '|' )]
    [TestCase( 'unknown dependency owner', '{ "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] }|' +
      '{ "ref": "pkg:delphi/nowhere@1", "dependsOn": [] }|dependencies[1].ref', '|' )]
    [TestCase( 'external reference type', '"type": "website"|"type": "homepage"|externalReferences[0].type', '|' )]
    [TestCase( 'supplier contact', '"contact": [ { "email": "acme@example.com" } ]|"contact": { "email": "acme@example.com" }|' +
      'components[1].supplier', '|' )]
    [TestCase( 'composition aggregate', '"aggregate": "incomplete"|"aggregate": "partial"|compositions[0].aggregate', '|' )]
    [TestCase( 'unknown composition ref', '"dependencies": [ "application:App@1.0.0.0" ]|"dependencies": [ "application:Other@1" ]|' +
      'compositions[0].dependencies[0]', '|' )]
    procedure BrokenRuleIsReported( const AFind, AReplace, AExpected: string );

    /// <summary>
    ///   Proves text that is not a JSON object is reported rather than raising.
    /// </summary>
    [Test]
    procedure NotJsonIsReported;
  end;

implementation

uses
  System.SysUtils,
  uSBOMValidator, uSBOMBuilder, TestSupport;

const
  /// <summary>A valid CycloneDX 1.5 document using every construct DelphiSBOM emits.</summary>
  ValidDocument =
    '{ "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", ' +
    '"version": 1, ' +
    '"metadata": { "timestamp": "2026-10-07T01:02:03Z", ' +
    '  "tools": { "components": [ { "type": "application", "name": "DelphiSBOM", "version": "1.0.0" } ] }, ' +
    '  "component": { "bom-ref": "application:App@1.0.0.0", "type": "application", "name": "App", "version": "1.0.0.0", ' +
    '    "supplier": { "name": "Me", "url": [ "https://example.com" ] } } }, ' +
    '"components": [ ' +
    '  { "bom-ref": "pkg:delphi/embarcadero-rtl@37.0", "type": "framework", "name": "Embarcadero Delphi RTL", "version": "37.0", ' +
    '    "purl": "pkg:delphi/embarcadero-rtl@37.0", ' +
    '    "components": [ { "type": "library", "name": "System.SysUtils", ' +
    '      "hashes": [ { "alg": "SHA-256", "content": "88de45b3a6f2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6" } ], ' +
    '      "properties": [ { "name": "dxcomply:origin", "value": "Embarcadero RTL" } ] } ] }, ' +
    '  { "bom-ref": "pkg:delphi/acme-widgets@2.1", "type": "library", "name": "Acme Widgets", "version": "2.1", ' +
    '    "supplier": { "name": "Acme", "contact": [ { "email": "acme@example.com" } ] }, ' +
    '    "licenses": [ { "license": { "id": "MIT", "url": "https://example.com/l" } } ], ' +
    '    "externalReferences": [ { "type": "website", "url": "https://example.com" } ], ' +
    '    "purl": "pkg:delphi/acme-widgets@2.1" }, ' +
    '  { "bom-ref": "pkg:delphi/dual@3", "type": "library", "name": "Dual", "version": "3", ' +
    '    "licenses": [ { "expression": "MPL-1.1 OR LGPL-2.1-or-later" } ], "purl": "pkg:delphi/dual@3" }, ' +
    '  { "bom-ref": "pkg:delphi/closed@1", "type": "library", "name": "Closed", "version": "1", ' +
    '    "licenses": [ { "license": { "name": "Commercial" } } ], "purl": "pkg:delphi/closed@1" } ], ' +
    '"dependencies": [ ' +
    '  { "ref": "application:App@1.0.0.0", "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/acme-widgets@2.1", ' +
    '    "pkg:delphi/dual@3", "pkg:delphi/closed@1" ] }, ' +
    '  { "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] } ], ' +
    '"compositions": [ { "aggregate": "incomplete", "dependencies": [ "application:App@1.0.0.0" ] } ] }';

{ TSBOMValidatorTests }

function TSBOMValidatorTests.ErrorsFor( const AFind, AReplace: string ): TArray<string>;
begin

  Assert.IsTrue( Pos( AFind, ValidDocument ) > 0, 'Test data: text to replace not found: ' + AFind );
  Result := CheckSBOM( StringReplace( ValidDocument, AFind, AReplace, [] ) );

end;

procedure TSBOMValidatorTests.AssertOneErrorContaining( const AFind, AReplace, AExpected: string );
begin

  var Errors := ErrorsFor( AFind, AReplace );
  Assert.AreEqual<Integer>( 1, Length( Errors ), 'Errors: ' + string.Join( ' / ', Errors ) );
  Assert.IsTrue( Pos( AExpected, Errors[ 0 ] ) > 0, Format( '"%s" does not mention %s', [ Errors[ 0 ], AExpected ] ) );

end;

procedure TSBOMValidatorTests.ValidDocumentPasses;
begin

  var Errors := CheckSBOM( ValidDocument );
  Assert.AreEqual<Integer>( 0, Length( Errors ), string.Join( ' / ', Errors ) );

end;

procedure TSBOMValidatorTests.BuilderOutputPasses;
begin

  var Project := Default( TProjectInfo );
  Project.ProjectName   := 'App';
  Project.DelphiVersion := '37.0';

  var Manifest := Default( TManifest );
  Manifest.Supplier.Name := 'Me';
  Manifest.Supplier.URL  := 'https://example.com';
  SetLength( Manifest.Components, 3 );
  Manifest.Components[ 0 ].Name := 'Acme Widgets';
  Manifest.Components[ 0 ].Version := '2.1';
  Manifest.Components[ 0 ].Licence := 'mit';
  Manifest.Components[ 0 ].VendorURL := 'https://example.com';
  Manifest.Components[ 0 ].VendorEmail := 'acme@example.com';
  Manifest.Components[ 1 ].Name := 'Dual';
  Manifest.Components[ 1 ].Licence := 'MPL-1.1 OR LGPL-2.1-or-later';
  Manifest.Components[ 2 ].Name := 'Dual';
  Manifest.Components[ 2 ].Licence := 'Commercial';

  var Units: TArray<TClassifiedUnit>;
  SetLength( Units, 4 );

  for var I := 0 to 2 do
  begin
    Units[ I ].OriginalName := 'Unit' + IntToStr( I );
    Units[ I ].UnitName := Units[ I ].OriginalName;
    Units[ I ].Classification := ucThirdParty;
    Units[ I ].ComponentIndex := I;
  end;

  Units[ 3 ].OriginalName := 'System.SysUtils';
  Units[ 3 ].UnitName := 'SysUtils';
  Units[ 3 ].Classification := ucRTL;
  Units[ 3 ].ComponentIndex := -1;

  var Evidence: TArray<TUnitEvidence>;
  SetLength( Evidence, 1 );
  Evidence[ 0 ].UnitName  := 'System.SysUtils';
  Evidence[ 0 ].Hashes    := [ EvidenceHash( 'SHA-256', '88de45b3a6f2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6' ),
    EvidenceHash( 'SHA-512', StringOfChar( 'a', 128 ) ) ];
  Evidence[ 0 ].Origin    := 'Embarcadero RTL';

  var Builder := TSBOMBuilder.Create( NoLog() );
  try
    var Errors := CheckSBOM( Builder.Build( Project, Units, Manifest, '', Evidence ) );
    Assert.AreEqual<Integer>( 0, Length( Errors ), string.Join( ' / ', Errors ) );
  finally
    Builder.Free;
  end;

end;

procedure TSBOMValidatorTests.BrokenRuleIsReported( const AFind, AReplace, AExpected: string );
begin

  AssertOneErrorContaining( AFind, AReplace, AExpected );

end;

procedure TSBOMValidatorTests.NotJsonIsReported;
begin

  Assert.AreEqual<Integer>( 1, Length( CheckSBOM( 'not json' ) ) );
  Assert.AreEqual<Integer>( 1, Length( CheckSBOM( '[ 1, 2 ]' ) ) );

end;

end.
