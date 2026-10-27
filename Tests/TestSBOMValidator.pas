(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSBOMValidator.pas — Tests for the structural check run on every written SBOM, and the BSI TR-03183-2 check
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
    ///   graph, with a library's own entry, included.
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
    [TestCase( 'spec version', '"specVersion": "1.6"|"specVersion": "1.5"|specVersion', '|' )]
    [TestCase( 'serial number', 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79|urn:uuid:not-a-uuid|serialNumber', '|' )]
    [TestCase( 'bom version', '"version": 1,|"version": 0,|version', '|' )]
    [TestCase( 'timestamp', '2026-10-07T01:02:03Z|07/10/2026|timestamp', '|' )]
    [TestCase( 'component type', '"type": "framework"|"type": "Framework"|components[0].type', '|' )]
    [TestCase( 'missing name', '"name": "Acme Widgets",|"name": "",|components[1].name', '|' )]
    [TestCase( 'licence id casing', '"id": "MIT"|"id": "mit"|components[1].licenses[0].license.id', '|' )]
    [TestCase( 'licence id and name', '"id": "MIT"|"id": "MIT", "name": "MIT"|components[1].licenses[0].license', '|' )]
    [TestCase( 'licence and expression', '{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }|' +
      '{ "expression": "MPL-1.1", "license": { "id": "MIT" } }|components[2].licenses[0]', '|' )]
    [TestCase( 'expression not alone', '{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }|' +
      '{ "expression": "MPL-1.1 OR LGPL-2.1-or-later" }, { "license": { "id": "MIT" } }|components[2].licenses[0].expression', '|' )]
    [TestCase( 'licence acknowledgement', '"acknowledgement": "concluded", "url"|"acknowledgement": "assumed", "url"|' +
      'components[1].licenses[0].license.acknowledgement', '|' )]
    [TestCase( 'expression acknowledgement', '"expression": "LicenseRef-Me-Commercial", "acknowledgement": "concluded"|' +
      '"expression": "LicenseRef-Me-Commercial", "acknowledgement": "yes"|metadata.component.licenses[0].acknowledgement', '|' )]
    [TestCase( 'hash algorithm', '"alg": "SHA-256"|"alg": "SHA256"|components[0].components[0].hashes[0].alg', '|' )]
    [TestCase( 'hash length', '88de45b3a6f2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6|88de45|' +
      'components[0].components[0].hashes[0].content', '|' )]
    [TestCase( 'purl scheme', '"purl": "pkg:delphi/acme-widgets@2.1"|"purl": "file:Acme.Widgets.pas"|components[1].purl', '|' )]
    [TestCase( 'duplicate ref', '"name": "DelphiSBOM",|"bom-ref": "pkg:delphi/dual@3", "name": "DelphiSBOM",|bom-ref', '|' )]
    [TestCase( 'unknown dependency', '"dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/acme-widgets@2.1"|' +
      '"dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/nowhere@1"|dependencies[0].dependsOn', '|' )]
    [TestCase( 'unknown dependency owner', '{ "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] }|' +
      '{ "ref": "pkg:delphi/nowhere@1", "dependsOn": [] }|dependencies[1].ref', '|' )]
    [TestCase( 'repeated dependency', '"dependsOn": [ "pkg:delphi/dual@3", "pkg:delphi/embarcadero-rtl@37.0" ]|' +
      '"dependsOn": [ "pkg:delphi/dual@3", "pkg:delphi/dual@3" ]|dependencies[2].dependsOn[1]', '|' )]
    [TestCase( 'external reference type', '"type": "website"|"type": "homepage"|externalReferences[0].type', '|' )]
    [TestCase( 'supplier contact', '"contact": [ { "email": "acme@example.com" } ]|"contact": { "email": "acme@example.com" }|' +
      'components[1].supplier', '|' )]
    [TestCase( 'manufacturer url', '"manufacturer": { "url": [ "https://acme.example.com" ] }|' +
      '"manufacturer": { "url": "https://acme.example.com" }|components[1].manufacturer', '|' )]
    [TestCase( 'sbom creator contact', '"manufacturer": { "name": "Me", "contact": [ { "email": "sbom@example.com" } ] }|' +
      '"manufacturer": { "name": "Me", "contact": { "email": "sbom@example.com" } }|metadata.manufacturer', '|' )]
    [TestCase( 'composition aggregate', '"aggregate": "incomplete"|"aggregate": "partial"|compositions[0].aggregate', '|' )]
    [TestCase( 'unknown composition ref', '"dependencies": [ "application:App@1.0.0.0"|"dependencies": [ "application:Other@1"|' +
      'compositions[0].dependencies[0]', '|' )]
    procedure BrokenRuleIsReported( const AFind, AReplace, AExpected: string );

    /// <summary>
    ///   Proves the external reference types new in CycloneDX 1.6 are accepted: the check must not reject a
    ///   source-distribution or rfc-9116 reference the TR's mapping asks for.
    /// </summary>
    [Test]
    procedure ExternalReferenceTypesOf16Pass;

    /// <summary>
    ///   Proves text that is not a JSON object is reported rather than raising.
    /// </summary>
    [Test]
    procedure NotJsonIsReported;
  end;

  /// <summary>
  ///   Each BSI TR-03183-2 rule, proved by removing or breaking one data field in an otherwise conforming document,
  ///   and the builder's output proved to conform when the manifest and the binary supply every field.
  /// </summary>
  [TestFixture]
  TTR03183Tests = class
  private
    /// <summary>Asserts that breaking the conforming document gives exactly one finding, led by ARule.</summary>
    /// <param name="AFind">Text of the conforming document to replace.</param>
    /// <param name="AReplace">The broken text.</param>
    /// <param name="ARule">The rule ID the finding must start with.</param>
    procedure AssertOneFinding( const AFind, AReplace, ARule: string );
    /// <summary>
    ///   Builds an SBOM whose manifest gives every creator and licence the TR requires: the supplier's email, an
    ///   application licence, a library whose vendor is its creator and one with a separate creator.
    /// </summary>
    /// <param name="ABinary">The binary to describe (FileName '' = none).</param>
    /// <returns>The SBOM's JSON text.</returns>
    function BuildConforming( const ABinary: TBinaryInfo ): string;
  public
    /// <summary>
    ///   Proves the reference document, which has every required field, gives no finding: a check that flags a
    ///   conforming SBOM would make every run look non-conformant.  It holds a nested evidence component with no
    ///   creator, version or licence, so it also proves nested components are not held to the component rules.
    /// </summary>
    [Test]
    procedure ConformingDocumentPasses;

    /// <summary>
    ///   Proves each requirement is reported once, by its rule ID, when only its data field is missing or wrong.
    /// </summary>
    /// <param name="AFind">Text of the conforming document to replace.</param>
    /// <param name="AReplace">The broken text.</param>
    /// <param name="ARule">The rule ID the single finding must start with.</param>
    [Test]
    [TestCase( 'format', '"specVersion": "1.6"|"specVersion": "1.5"|TR-4-FORMAT', '|' )]
    [TestCase( 'sbom creator', '"manufacturer": { "contact": [ { "email": "sbom@example.com" } ] }, |' +
      '"manufacturer": { "name": "Me" }, |TR-5.2.1-CREATOR', '|' )]
    [TestCase( 'timestamp', '"timestamp": "2026-10-07T01:02:03Z", |"timestamp": "", |TR-5.2.1-TIMESTAMP', '|' )]
    [TestCase( 'component creator', '"manufacturer": { "url": [ "https://acme.example.com" ] }, |' +
      '"manufacturer": { "url": [ ] }, |TR-5.2.2-CREATOR', '|' )]
    [TestCase( 'application creator', '"manufacturer": { "contact": [ { "email": "me@example.com" } ] }, |' +
      '|TR-5.2.2-CREATOR', '|' )]
    [TestCase( 'name', '"name": "Acme Widgets", |"name": "", |TR-5.2.2-NAME', '|' )]
    [TestCase( 'version', '"version": "2.1", |"version": "", |TR-5.2.2-VERSION', '|' )]
    [TestCase( 'not in graph', ',   { "ref": "pkg:delphi/acme-widgets@2.1", "dependsOn": [] }|' +
      '|TR-5.2.2-DEPENDENCIES', '|' )]
    [TestCase( 'completeness', ', "pkg:delphi/acme-widgets@2.1" ] } ] }|' +
      ' ] } ] }|TR-5.2.2-DEPENDENCIES', '|' )]
    [TestCase( 'no licence', '"licenses": [ { "license": { "id": "MIT", "acknowledgement": "concluded" } } ], |' +
      '|TR-5.2.2-LICENCE', '|' )]
    [TestCase( 'not concluded', '{ "id": "MIT", "acknowledgement": "concluded" }|{ "id": "MIT", "acknowledgement": "declared" }|' +
      'TR-5.2.2-LICENCE', '|' )]
    [TestCase( 'licence name', '{ "id": "MIT", "acknowledgement": "concluded" }|{ "name": "Commercial", "acknowledgement": "concluded" }|' +
      'TR-6.1-LICENCE', '|' )]
    [TestCase( 'filename', '{ "name": "bsi:component:filename", "value": "App.exe" }, |' +
      '|TR-5.2.2-FILENAME', '|' )]
    [TestCase( 'hash', '"hashes": [ { "alg": "SHA-512", "content": "deployable" } ]|"hashes": [ { "alg": "SHA-256", "content": "deployable" } ]|' +
      'TR-5.2.2-HASH', '|' )]
    [TestCase( 'executable', '"value": "executable"|"value": "yes"|TR-5.2.2-EXECUTABLE', '|' )]
    [TestCase( 'archive', '"value": "no archive"|"value": "none"|TR-5.2.2-ARCHIVE', '|' )]
    [TestCase( 'structured', '"value": "unstructured"|"value": "flat"|TR-5.2.2-STRUCTURED', '|' )]
    [TestCase( 'vulnerabilities', '"dependencies": [ |"vulnerabilities": [ { "id": "CVE-2026-0001" } ], "dependencies": [ |' +
      'TR-3.1-VULNERABILITIES', '|' )]
    [TestCase( 'vulnerabilities object', '"dependencies": [ |"vulnerabilities": { "id": "CVE-2026-0001" }, "dependencies": [ |' +
      'TR-3.1-VULNERABILITIES', '|' )]
    [TestCase( 'bom format', '"bomFormat": "CycloneDX"|"bomFormat": "SPDX"|TR-4-FORMAT', '|' )]
    [TestCase( 'free-text expression', '"expression": "LicenseRef-Me-Commercial"|"expression": "Apache License 2.0 or later"|' +
      'TR-6.1-LICENCE', '|' )]
    [TestCase( 'lower-case operator', '"expression": "LicenseRef-Me-Commercial"|"expression": "MIT or Apache-2.0"|' +
      'TR-6.1-LICENCE', '|' )]
    [TestCase( 'unbalanced bracket', '"expression": "LicenseRef-Me-Commercial"|"expression": "(MIT OR Apache-2.0"|' +
      'TR-6.1-LICENCE', '|' )]
    procedure MissingFieldIsReported( const AFind, AReplace, ARule: string );

    /// <summary>
    ///   Proves expressions of SPDX syntax pass the TR 6.1 check without consulting the SPDX list: compound ones with
    ///   brackets and WITH, an or-later '+', and a DocumentRef: a check that rejected these would flag correct SBOMs.
    /// </summary>
    /// <param name="AExpression">The expression the application's licence is given.</param>
    [Test]
    [TestCase( 'compound', 'MPL-1.1 OR (LGPL-2.1-or-later WITH LLVM-exception)' )]
    [TestCase( 'or later', 'GPL-2.0+ AND MIT' )]
    [TestCase( 'document ref', 'DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2' )]
    procedure SPDXExpressionsPass( const AExpression: string );

    /// <summary>
    ///   Proves spec versions 1.6 and later pass the format rule in any of their forms ('1.10', '1.6.1', '2') while
    ///   1.5 is still caught by MissingFieldIsReported: a version compared as text or as exactly two parts misjudges
    ///   these.
    /// </summary>
    /// <param name="AVersion">The specVersion to give the document.</param>
    [Test]
    [TestCase( 'two digit minor', '1.10' )]
    [TestCase( 'patch level', '1.6.1' )]
    [TestCase( 'major only', '2' )]
    procedure LaterSpecVersionsPass( const AVersion: string );

    /// <summary>
    ///   Proves a composition's "assemblies" does not state dependency completeness: with the refs moved from
    ///   "dependencies" to "assemblies", every component is reported (TR 5.2.2 asks about its dependencies, which
    ///   assemblies do not describe).
    /// </summary>
    [Test]
    procedure AssembliesDoNotStateCompleteness;

    /// <summary>
    ///   Proves a library that names a file (bsi:component:filename) is held to the file fields as well, while a
    ///   library without one is a logical component that needs none (TR 3.2.1): exactly the four missing file fields
    ///   are reported.
    /// </summary>
    [Test]
    procedure LibraryNamingAFileNeedsFileFields;

    /// <summary>
    ///   Proves what the builder writes conforms when the manifest gives every creator and licence and a binary is
    ///   described: the generator's own output must not fail the check it ships with.
    /// </summary>
    [Test]
    procedure BuilderOutputConforms;

    /// <summary>
    ///   Proves that without a binary the builder writes no file data and the check then reports exactly the five
    ///   file fields of the application, each by its rule ID, rather than passing a document that lacks them.
    /// </summary>
    [Test]
    procedure BuilderOutputWithoutBinaryLacksOnlyFileFields;
  end;

implementation

uses
  System.SysUtils,
  uSBOMValidator, uSBOMBuilder, TestSupport;

const
  /// <summary>A SHA-512 digest in hex: 128 digits.</summary>
  DeployableDigest =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  /// <summary>A valid CycloneDX 1.6 document using every construct DelphiSBOM emits.</summary>
  ValidDocument =
    '{ "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", ' +
    '"version": 1, ' +
    '"metadata": { "timestamp": "2026-10-07T01:02:03Z", ' +
    '  "tools": { "components": [ { "type": "application", "name": "DelphiSBOM", "version": "1.0.0" } ] }, ' +
    '  "manufacturer": { "name": "Me", "contact": [ { "email": "sbom@example.com" } ] }, ' +
    '  "component": { "bom-ref": "application:App@1.0.0.0", "type": "application", "name": "App", "version": "1.0.0.0", ' +
    '    "supplier": { "name": "Me", "url": [ "https://example.com" ] }, ' +
    '    "licenses": [ { "expression": "LicenseRef-Me-Commercial", "acknowledgement": "concluded" } ], ' +
    '    "hashes": [ { "alg": "SHA-512", "content": "' + DeployableDigest + '" } ], ' +
    '    "externalReferences": [ { "type": "distribution", "url": "App.exe", ' +
    '      "hashes": [ { "alg": "SHA-512", "content": "' + DeployableDigest + '" } ] } ], ' +
    '    "properties": [ { "name": "bsi:component:filename", "value": "App.exe" } ] } }, ' +
    '"components": [ ' +
    '  { "bom-ref": "pkg:delphi/embarcadero-rtl@37.0", "type": "framework", "name": "Embarcadero Delphi RTL", "version": "37.0", ' +
    '    "purl": "pkg:delphi/embarcadero-rtl@37.0", ' +
    '    "components": [ { "type": "library", "name": "System.SysUtils", ' +
    '      "hashes": [ { "alg": "SHA-256", "content": "88de45b3a6f2c1d0e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6" } ], ' +
    '      "properties": [ { "name": "dxcomply:origin", "value": "Embarcadero RTL" } ] } ] }, ' +
    '  { "bom-ref": "pkg:delphi/acme-widgets@2.1", "type": "library", "name": "Acme Widgets", "version": "2.1", ' +
    '    "supplier": { "name": "Acme", "contact": [ { "email": "acme@example.com" } ] }, ' +
    '    "manufacturer": { "url": [ "https://acme.example.com" ] }, ' +
    '    "licenses": [ { "license": { "id": "MIT", "acknowledgement": "concluded", "url": "https://example.com/l" } } ], ' +
    '    "externalReferences": [ { "type": "website", "url": "https://example.com" } ], ' +
    '    "purl": "pkg:delphi/acme-widgets@2.1" }, ' +
    '  { "bom-ref": "pkg:delphi/dual@3", "type": "library", "name": "Dual", "version": "3", ' +
    '    "licenses": [ { "expression": "MPL-1.1 OR LGPL-2.1-or-later" } ], "purl": "pkg:delphi/dual@3" }, ' +
    '  { "bom-ref": "pkg:delphi/closed@1", "type": "library", "name": "Closed", "version": "1", ' +
    '    "licenses": [ { "license": { "name": "Commercial" } } ], "purl": "pkg:delphi/closed@1" } ], ' +
    '"dependencies": [ ' +
    '  { "ref": "application:App@1.0.0.0", "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/acme-widgets@2.1", ' +
    '    "pkg:delphi/dual@3", "pkg:delphi/closed@1" ] }, ' +
    '  { "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] }, ' +
    '  { "ref": "pkg:delphi/acme-widgets@2.1", "dependsOn": [ "pkg:delphi/dual@3", "pkg:delphi/embarcadero-rtl@37.0" ] } ], ' +
    '"compositions": [ { "aggregate": "incomplete", "dependencies": [ "application:App@1.0.0.0", "pkg:delphi/acme-widgets@2.1" ] } ] }';

  /// <summary>
  ///   A document with every data field BSI TR-03183-2 v2.1.0 requires: the SBOM's creator and timestamp, an
  ///   application with its file fields, a logical library, and the RTL carrying a nested evidence component.
  /// </summary>
  ConformingDocument =
    '{ "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", ' +
    '"version": 1, ' +
    '"metadata": { "timestamp": "2026-10-07T01:02:03Z", ' +
    '  "manufacturer": { "contact": [ { "email": "sbom@example.com" } ] }, ' +
    '  "component": { "bom-ref": "application:App@1.0.0.0", "type": "application", "name": "App", "version": "1.0.0.0", ' +
    '    "manufacturer": { "contact": [ { "email": "me@example.com" } ] }, ' +
    '    "licenses": [ { "expression": "LicenseRef-Me-Commercial", "acknowledgement": "concluded" } ], ' +
    '    "externalReferences": [ { "type": "distribution", "url": "App.exe", ' +
    '      "hashes": [ { "alg": "SHA-512", "content": "deployable" } ] } ], ' +
    '    "properties": [ { "name": "bsi:component:filename", "value": "App.exe" }, ' +
    '      { "name": "bsi:component:executable", "value": "executable" }, ' +
    '      { "name": "bsi:component:archive", "value": "no archive" }, ' +
    '      { "name": "bsi:component:structured", "value": "unstructured" } ] } }, ' +
    '"components": [ ' +
    '  { "bom-ref": "pkg:delphi/embarcadero-rtl@37.0", "type": "framework", "name": "Embarcadero Delphi RTL", "version": "37.0", ' +
    '    "manufacturer": { "url": [ "https://www.embarcadero.com" ] }, ' +
    '    "licenses": [ { "expression": "LicenseRef-DelphiSBOM-Embarcadero-RAD-Studio-EULA", "acknowledgement": "concluded" } ], ' +
    '    "components": [ { "type": "library", "name": "System.SysUtils" } ] }, ' +
    '  { "bom-ref": "pkg:delphi/acme-widgets@2.1", "type": "library", "name": "Acme Widgets", "version": "2.1", ' +
    '    "manufacturer": { "url": [ "https://acme.example.com" ] }, ' +
    '    "licenses": [ { "license": { "id": "MIT", "acknowledgement": "concluded" } } ], ' +
    '    "purl": "pkg:delphi/acme-widgets@2.1" } ], ' +
    '"dependencies": [ ' +
    '  { "ref": "application:App@1.0.0.0", "dependsOn": [ "pkg:delphi/embarcadero-rtl@37.0", "pkg:delphi/acme-widgets@2.1" ] }, ' +
    '  { "ref": "pkg:delphi/embarcadero-rtl@37.0", "dependsOn": [] }, ' +
    '  { "ref": "pkg:delphi/acme-widgets@2.1", "dependsOn": [] } ], ' +
    '"compositions": [ { "aggregate": "incomplete", "dependencies": [ "application:App@1.0.0.0", "pkg:delphi/embarcadero-rtl@37.0"' +
    ', "pkg:delphi/acme-widgets@2.1" ] } ] }';

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

  var Dependencies: TArray<TLibraryDependency>;
  SetLength( Dependencies, 1 );
  Dependencies[ 0 ].ComponentIndex := 0;
  Dependencies[ 0 ].DependsOn := [ 1, RTLComponentIndex ];

  var Binary := Default( TBinaryInfo );
  Binary.FileName := 'App.exe';
  Binary.SHA512 := StringOfChar( 'c', 128 );

  var Builder := TSBOMBuilder.Create( NoLog() );
  try
    Builder.Binary := Binary;
    var Errors := CheckSBOM( Builder.Build( Project, Units, Manifest, '', Evidence, Dependencies ) );
    Assert.AreEqual<Integer>( 0, Length( Errors ), string.Join( ' / ', Errors ) );
  finally
    Builder.Free;
  end;

end;

procedure TSBOMValidatorTests.BrokenRuleIsReported( const AFind, AReplace, AExpected: string );
begin

  AssertOneErrorContaining( AFind, AReplace, AExpected );

end;

procedure TSBOMValidatorTests.ExternalReferenceTypesOf16Pass;
begin

  var Errors := ErrorsFor( '"externalReferences": [ { "type": "website", "url": "https://example.com" } ]',
    '"externalReferences": [ { "type": "source-distribution", "url": "https://example.com/src" }, ' +
    '{ "type": "rfc-9116", "url": "https://example.com/.well-known/security.txt" } ]' );
  Assert.AreEqual<Integer>( 0, Length( Errors ), string.Join( ' / ', Errors ) );

end;

procedure TSBOMValidatorTests.NotJsonIsReported;
begin

  Assert.AreEqual<Integer>( 1, Length( CheckSBOM( 'not json' ) ) );
  Assert.AreEqual<Integer>( 1, Length( CheckSBOM( '[ 1, 2 ]' ) ) );

end;

{ TTR03183Tests }

procedure TTR03183Tests.AssertOneFinding( const AFind, AReplace, ARule: string );
begin

  Assert.IsTrue( Pos( AFind, ConformingDocument ) > 0, 'Test data: text to replace not found: ' + AFind );

  var Findings := CheckTR03183( StringReplace( ConformingDocument, AFind, AReplace, [] ) );
  Assert.AreEqual<Integer>( 1, Length( Findings ), 'Findings: ' + string.Join( ' / ', Findings ) );
  Assert.IsTrue( Findings[ 0 ].StartsWith( ARule + ' ' ), Format( '"%s" does not start with %s', [ Findings[ 0 ], ARule ] ) );

end;

function TTR03183Tests.BuildConforming( const ABinary: TBinaryInfo ): string;
begin

  var Project := Default( TProjectInfo );
  Project.ProjectName   := 'App';
  Project.ProjectVersion := '1.2.0.0';
  Project.DelphiVersion := '37.0';

  var Manifest := Default( TManifest );
  Manifest.Supplier.Name := 'Me';
  Manifest.Supplier.Email := 'me@example.com';
  Manifest.ApplicationLicence := 'LicenseRef-Me-Commercial';
  SetLength( Manifest.Components, 2 );
  Manifest.Components[ 0 ].Name := 'Acme Widgets';
  Manifest.Components[ 0 ].Version := '2.1';
  Manifest.Components[ 0 ].Licence := 'MIT';
  Manifest.Components[ 0 ].Vendor := 'Acme';
  Manifest.Components[ 0 ].VendorURL := 'https://acme.example.com';
  Manifest.Components[ 1 ].Name := 'Forked';
  Manifest.Components[ 1 ].Version := '3';
  Manifest.Components[ 1 ].Licence := 'LicenseRef-scancode-proprietary-license';
  Manifest.Components[ 1 ].CreatorEmail := 'author@example.com';

  var Units: TArray<TClassifiedUnit>;
  SetLength( Units, 3 );

  for var I := 0 to 1 do
  begin
    Units[ I ].OriginalName := 'Unit' + IntToStr( I );
    Units[ I ].UnitName := Units[ I ].OriginalName;
    Units[ I ].Classification := ucThirdParty;
    Units[ I ].ComponentIndex := I;
  end;

  Units[ 2 ].OriginalName := 'System.SysUtils';
  Units[ 2 ].UnitName := 'SysUtils';
  Units[ 2 ].Classification := ucRTL;
  Units[ 2 ].ComponentIndex := -1;

  var Builder := TSBOMBuilder.Create( NoLog() );
  try
    Builder.Binary := ABinary;
    Result := Builder.Build( Project, Units, Manifest, '', nil, nil );
  finally
    Builder.Free;
  end;

end;

procedure TTR03183Tests.ConformingDocumentPasses;
begin

  var Findings := CheckTR03183( ConformingDocument );
  Assert.AreEqual<Integer>( 0, Length( Findings ), string.Join( ' / ', Findings ) );

end;

procedure TTR03183Tests.MissingFieldIsReported( const AFind, AReplace, ARule: string );
begin

  AssertOneFinding( AFind, AReplace, ARule );

end;

procedure TTR03183Tests.SPDXExpressionsPass( const AExpression: string );
begin

  var Document := StringReplace( ConformingDocument, '"expression": "LicenseRef-Me-Commercial"',
    '"expression": "' + AExpression + '"', [] );
  Assert.AreNotEqual( ConformingDocument, Document, 'Test data: the licence was not replaced' );

  var Findings := CheckTR03183( Document );
  Assert.AreEqual<Integer>( 0, Length( Findings ), string.Join( ' / ', Findings ) );

end;

procedure TTR03183Tests.LaterSpecVersionsPass( const AVersion: string );
begin

  var Findings := CheckTR03183( StringReplace( ConformingDocument, '"specVersion": "1.6"', '"specVersion": "' + AVersion + '"', [] ) );
  Assert.AreEqual<Integer>( 0, Length( Findings ), string.Join( ' / ', Findings ) );

end;

procedure TTR03183Tests.AssembliesDoNotStateCompleteness;
begin

  var Document := StringReplace( ConformingDocument, '"aggregate": "incomplete", "dependencies"', '"aggregate": "incomplete", "assemblies"', [] );
  Assert.AreNotEqual( ConformingDocument, Document, 'Test data: the composition was not changed' );

  var Findings := CheckTR03183( Document );
  Assert.AreEqual<Integer>( 3, Length( Findings ), 'Findings: ' + string.Join( ' / ', Findings ) );

  for var F in Findings do
    Assert.IsTrue( F.StartsWith( 'TR-5.2.2-DEPENDENCIES ' ) and F.Contains( 'completeness' ), F );

end;

procedure TTR03183Tests.LibraryNamingAFileNeedsFileFields;
begin

  var Document := StringReplace( ConformingDocument, '"purl": "pkg:delphi/acme-widgets@2.1" }',
    '"purl": "pkg:delphi/acme-widgets@2.1", "properties": [ { "name": "bsi:component:filename", "value": "Acme.bpl" } ] }', [] );
  Assert.AreNotEqual( ConformingDocument, Document, 'Test data: the library was not given a file name' );

  var Findings := CheckTR03183( Document );
  Assert.AreEqual<Integer>( 4, Length( Findings ), 'Findings: ' + string.Join( ' / ', Findings ) );

  var Rules := '';

  for var F in Findings do
  begin
    Assert.IsTrue( Pos( '"Acme Widgets"', F ) > 0, F + ' does not name the library' );
    Rules := Rules + Copy( F, 1, Pos( ' ', F ) - 1 ) + ' ';
  end;

  Assert.AreEqual( 'TR-5.2.2-HASH TR-5.2.2-EXECUTABLE TR-5.2.2-ARCHIVE TR-5.2.2-STRUCTURED ', Rules );

end;

procedure TTR03183Tests.BuilderOutputConforms;
begin

  var Binary := Default( TBinaryInfo );
  Binary.FileName := 'App.exe';
  Binary.SHA512 := StringOfChar( 'c', 128 );

  var Json := BuildConforming( Binary );
  var Findings := CheckTR03183( Json );
  Assert.AreEqual<Integer>( 0, Length( Findings ), string.Join( ' / ', Findings ) );

  // And it is still structurally valid
  var Errors := CheckSBOM( Json );
  Assert.AreEqual<Integer>( 0, Length( Errors ), string.Join( ' / ', Errors ) );

end;

procedure TTR03183Tests.BuilderOutputWithoutBinaryLacksOnlyFileFields;
begin

  var Findings := CheckTR03183( BuildConforming( Default( TBinaryInfo ) ) );
  Assert.AreEqual<Integer>( 5, Length( Findings ), 'Findings: ' + string.Join( ' / ', Findings ) );

  var Rules := '';

  for var F in Findings do
  begin
    Assert.IsTrue( F.Contains( 'metadata.component "App"' ), F + ' is not about the application' );
    Rules := Rules + Copy( F, 1, Pos( ' ', F ) - 1 ) + ' ';
  end;

  Assert.AreEqual( 'TR-5.2.2-FILENAME TR-5.2.2-HASH TR-5.2.2-EXECUTABLE TR-5.2.2-ARCHIVE TR-5.2.2-STRUCTURED ', Rules );

end;

end.
