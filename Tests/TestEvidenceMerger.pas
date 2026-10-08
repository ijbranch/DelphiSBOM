(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestEvidenceMerger.pas — Tests for uEvidenceMerger (DX.Comply bom.json import)
*)
unit TestEvidenceMerger;

interface

uses
  DUnitX.TestFramework,
  TestSupport;

type
  /// <summary>
  ///   Hash collection, algorithm normalisation and de-duplication when importing DX.Comply evidence.
  /// </summary>
  [TestFixture]
  TEvidenceMergerTests = class
  private
    FScratch: TScratchDir;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves every hash a component lists is kept, in DX.Comply's order, with a repeated algorithm
    ///   listed once: only one hash used to survive, so the SHA-512 that BSI TR-03183-2 asks for was
    ///   dropped. Also proves the origin property is read.
    /// </summary>
    [Test]
    procedure KeepsEveryHashAlgorithm;

    /// <summary>
    ///   Proves an algorithm spelled 'SHA256' is normalised to the CycloneDX 'SHA-256', and an algorithm
    ///   outside the CycloneDX enum is dropped rather than carried into the SBOM.
    /// </summary>
    [Test]
    procedure NormalisesAndDropsAlgorithms;

    /// <summary>
    ///   Proves a unit DX.Comply lists twice (.pas and .dcu) becomes one evidence entry, keeping the one
    ///   that has a hash; and that the application entry is skipped.
    /// </summary>
    [Test]
    procedure DeduplicatesPasAndDcu;
  end;

implementation

uses
  System.SysUtils,
  uTypes, uEvidenceMerger;

{ TEvidenceMergerTests }

procedure TEvidenceMergerTests.Setup;
begin

  FScratch := TScratchDir.Create;

end;

procedure TEvidenceMergerTests.TearDown;
begin

  FScratch.Free;

end;

procedure TEvidenceMergerTests.KeepsEveryHashAlgorithm;
begin

  var FileName := FScratch.PathOf( 'bom.json' );
  WriteUtf8File( FileName,
    '{ "bomFormat": "CycloneDX", "components": [ { "type": "library", "name": "System.SysUtils.dcu", ' +
    '"hashes": [ { "alg": "MD5", "content": "md5value" }, { "alg": "SHA-256", "content": "shavalue" }, ' +
    '{ "alg": "SHA-512", "content": "sha512value" }, { "alg": "SHA256", "content": "again" } ], ' +
    '"properties": [ { "name": "dxcomply:origin", "value": "Embarcadero RTL" } ] } ] }' );

  var Merger := TEvidenceMerger.Create( NoLog() );
  try
    var Evidence := Merger.LoadEvidence( FileName );

    Assert.AreEqual<NativeInt>( 1, Length( Evidence ) );
    Assert.AreEqual( 'System.SysUtils', Evidence[ 0 ].UnitName, False );
    Assert.AreEqual<NativeInt>( 3, Length( Evidence[ 0 ].Hashes ), 'MD5, SHA-256 and SHA-512; the second SHA-256 is not repeated' );
    Assert.AreEqual( 'MD5', Evidence[ 0 ].Hashes[ 0 ].Algorithm );
    Assert.AreEqual( 'md5value', Evidence[ 0 ].Hashes[ 0 ].Content );
    Assert.AreEqual( 'SHA-256', Evidence[ 0 ].Hashes[ 1 ].Algorithm );
    Assert.AreEqual( 'shavalue', Evidence[ 0 ].Hashes[ 1 ].Content );
    Assert.AreEqual( 'SHA-512', Evidence[ 0 ].Hashes[ 2 ].Algorithm );
    Assert.AreEqual( 'sha512value', Evidence[ 0 ].Hashes[ 2 ].Content );
    Assert.AreEqual( 'Embarcadero RTL', Evidence[ 0 ].Origin, False );
  finally
    Merger.Free;
  end;

end;

procedure TEvidenceMergerTests.NormalisesAndDropsAlgorithms;
begin

  var FileName := FScratch.PathOf( 'bom.json' );
  WriteUtf8File( FileName,
    '{ "bomFormat": "CycloneDX", "components": [ ' +
    '{ "type": "library", "name": "UnitA.dcu", "hashes": [ { "alg": "SHA256", "content": "a" } ] }, ' +
    '{ "type": "library", "name": "UnitB.dcu", "hashes": [ { "alg": "CRC32", "content": "b" } ] } ] }' );

  var Merger := TEvidenceMerger.Create( NoLog() );
  try
    var Evidence := Merger.LoadEvidence( FileName );

    Assert.AreEqual<NativeInt>( 2, Length( Evidence ) );
    Assert.AreEqual<NativeInt>( 1, Length( Evidence[ 0 ].Hashes ) );
    Assert.AreEqual( 'SHA-256', Evidence[ 0 ].Hashes[ 0 ].Algorithm );
    Assert.AreEqual<NativeInt>( 0, Length( Evidence[ 1 ].Hashes ), 'CRC32 is not a CycloneDX algorithm' );
  finally
    Merger.Free;
  end;

end;

procedure TEvidenceMergerTests.DeduplicatesPasAndDcu;
begin

  var FileName := FScratch.PathOf( 'bom.json' );
  WriteUtf8File( FileName,
    '{ "bomFormat": "CycloneDX", "components": [ ' +
    '{ "type": "application", "name": "App.exe", "hashes": [ { "alg": "SHA-256", "content": "exe" } ] }, ' +
    '{ "type": "library", "name": "OtlTask.pas" }, ' +
    '{ "type": "library", "name": "OtlTask.dcu", "hashes": [ { "alg": "SHA-256", "content": "dcuhash" } ] } ] }' );

  var Merger := TEvidenceMerger.Create( NoLog() );
  try
    var Evidence := Merger.LoadEvidence( FileName );

    Assert.AreEqual<NativeInt>( 1, Length( Evidence ) );
    Assert.AreEqual( 'OtlTask', Evidence[ 0 ].UnitName, False );
    Assert.AreEqual<NativeInt>( 1, Length( Evidence[ 0 ].Hashes ) );
    Assert.AreEqual( 'dcuhash', Evidence[ 0 ].Hashes[ 0 ].Content );
  finally
    Merger.Free;
  end;

end;

end.
