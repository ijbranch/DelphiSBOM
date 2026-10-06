(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestManifestLoader.pas — Tests for uManifestLoader (loading, validation and safe saving)
*)
unit TestManifestLoader;

interface

uses
  DUnitX.TestFramework,
  TestSupport, uManifestLoader;

type
  /// <summary>
  ///   components.json loading, type-safe reads, and saves that never destroy an existing manifest.
  /// </summary>
  [TestFixture]
  TManifestLoaderTests = class
  private
    FScratch: TScratchDir;
    FLoader: TManifestLoader;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves saving into a manifest that is not valid JSON raises EManifestError and leaves the file
    ///   byte-for-byte unchanged. It used to be replaced by an empty object, losing every component.
    /// </summary>
    [Test]
    procedure UnparseableManifestIsNeverOverwritten;

    /// <summary>
    ///   Proves a "components" member that is not an array is refused instead of a second "components"
    ///   key being added beside it.
    /// </summary>
    [Test]
    procedure NonArrayComponentsRefused;

    /// <summary>
    ///   Proves saving to a missing manifest creates the full skeleton (schema_version, supplier,
    ///   components), removes duplicate unit names, and writes no BOM.
    /// </summary>
    [Test]
    procedure MissingManifestCreatedFromSkeleton;

    /// <summary>
    ///   Proves saving keeps existing content: components, supplier and own_code_prefixes survive an
    ///   own-code save, and last_updated is replaced in place.
    /// </summary>
    [Test]
    procedure SaveKeepsExistingContent;

    /// <summary>
    ///   Proves empty and non-string entries are dropped from prefix arrays. An empty prefix matched
    ///   every unit, silently classifying a whole project as one component or as own code.
    /// </summary>
    [Test]
    procedure EmptyAndNonStringPrefixesDropped;

    /// <summary>
    ///   Proves non-string scalar values are read safely: a numeric version becomes text and null is
    ///   treated as missing, rather than aborting the load.
    /// </summary>
    [Test]
    procedure NumericAndNullValuesReadSafely;

    /// <summary>
    ///   Proves Validate reports a syntax error as a failure (False) instead of raising.
    /// </summary>
    [Test]
    procedure ValidateReportsInvalidJson;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
  uTypes, uTextFiles;

{ TManifestLoaderTests }

procedure TManifestLoaderTests.Setup;
begin

  FScratch := TScratchDir.Create;
  FLoader  := TManifestLoader.Create( NoLog() );

end;

procedure TManifestLoaderTests.TearDown;
begin

  FLoader.Free;
  FScratch.Free;

end;

procedure TManifestLoaderTests.UnparseableManifestIsNeverOverwritten;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  var Broken := '{ "schema_version": "1.0", "components": [ { "name": "Keep" }, ] }';
  WriteUtf8File( FileName, Broken );

  Assert.WillRaise(
    procedure
    begin
      FLoader.SaveOwnCodeUnits( FileName, [ 'X' ] );
    end, EManifestError );

  Assert.WillRaise(
    procedure
    begin
      FLoader.SaveDiscoveredLibraries( FileName, nil );
    end, EManifestError );

  Assert.AreEqual( Broken, ReadTextFile( FileName ), False );

end;

procedure TManifestLoaderTests.NonArrayComponentsRefused;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  var Original := '{ "schema_version": "1.0", "components": { "name": "NotAnArray" } }';
  WriteUtf8File( FileName, Original );

  var Lib := Default( TDiscoveredLibrary );
  Lib.Name      := 'Lib';
  Lib.Confirmed := True;

  Assert.WillRaise(
    procedure
    begin
      FLoader.SaveDiscoveredLibraries( FileName, [ Lib ] );
    end, EManifestError );

  Assert.AreEqual( Original, ReadTextFile( FileName ), False );

end;

procedure TManifestLoaderTests.MissingManifestCreatedFromSkeleton;
begin

  var FileName := FScratch.PathOf( 'new\components.json' );
  ForceDirectories( ExtractFilePath( FileName ) );

  FLoader.SaveOwnCodeUnits( FileName, [ 'UnitA', 'UnitB', 'unita' ] );

  var Manifest := FLoader.Load( FileName );

  Assert.AreEqual( '1.0', Manifest.SchemaVersion, False );
  Assert.AreEqual<NativeInt>( 2, Length( Manifest.OwnCodeUnits ), 'Case-insensitive duplicate removed' );
  Assert.AreEqual( Ord( '{' ), Integer( TFile.ReadAllBytes( FileName )[ 0 ] ), 'No BOM' );
  Assert.Contains( ReadTextFile( FileName ), '"supplier"', False );
  Assert.Contains( ReadTextFile( FileName ), '"components"', False );

end;

procedure TManifestLoaderTests.SaveKeepsExistingContent;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  WriteUtf8File( FileName,
    '{ "schema_version": "1.0", "last_updated": "2000-01-01", "supplier": { "name": "Acme" }, ' +
    '"components": [ { "name": "Lib", "version": "1", "vendor": "V", "licence": "MIT", "type": "library", "units_prefix": [ "Lib" ] } ], ' +
    '"own_code_prefixes": [ "abc" ] }' );

  FLoader.SaveOwnCodeUnits( FileName, [ 'Mine' ] );

  var Manifest := FLoader.Load( FileName );

  Assert.AreEqual<NativeInt>( 1, Length( Manifest.Components ) );
  Assert.AreEqual( 'Acme', Manifest.Supplier.Name, False );
  Assert.AreEqual<NativeInt>( 1, Length( Manifest.OwnCodePrefixes ) );
  Assert.AreEqual( 'Mine', Manifest.OwnCodeUnits[ 0 ], False );
  Assert.AreNotEqual( '2000-01-01', Manifest.LastUpdated, False );

  // last_updated keeps its place, directly after schema_version
  var Text := ReadTextFile( FileName );
  Assert.IsTrue( Pos( '"last_updated"', Text ) < Pos( '"supplier"', Text ), 'last_updated moved to the end' );

end;

procedure TManifestLoaderTests.EmptyAndNonStringPrefixesDropped;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  WriteUtf8File( FileName,
    '{ "schema_version": "1.0", "components": [ { "name": "N", "units_prefix": [ "", 5, "Abc", "  " ], ' +
    '"units_exact": [ null, "Exact" ] } ], "own_code_prefixes": [ "" ], "own_code_units": [ "", "Own" ] }' );

  var Manifest := FLoader.Load( FileName );

  Assert.AreEqual<NativeInt>( 1, Length( Manifest.Components[ 0 ].Prefixes ) );
  Assert.AreEqual( 'Abc', Manifest.Components[ 0 ].Prefixes[ 0 ], False );
  Assert.AreEqual<NativeInt>( 1, Length( Manifest.Components[ 0 ].ExactUnits ) );
  Assert.AreEqual<NativeInt>( 0, Length( Manifest.OwnCodePrefixes ) );
  Assert.AreEqual<NativeInt>( 1, Length( Manifest.OwnCodeUnits ) );

end;

procedure TManifestLoaderTests.NumericAndNullValuesReadSafely;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  WriteUtf8File( FileName,
    '{ "schema_version": "1.0", "components": [ { "name": "N", "version": 3.7, "vendor": null, ' +
    '"licence": "MIT", "type": "library", "units_exact": [ "N" ] } ] }' );

  var Manifest := FLoader.Load( FileName );

  Assert.AreEqual( '3.7', Manifest.Components[ 0 ].Version, False );
  Assert.AreEqual( '', Manifest.Components[ 0 ].Vendor, False );

end;

procedure TManifestLoaderTests.ValidateReportsInvalidJson;
begin

  var FileName := FScratch.PathOf( 'components.json' );
  WriteUtf8File( FileName, '{ "schema_version": ' );

  Assert.IsFalse( FLoader.Validate( FileName ) );

  WriteUtf8File( FileName, '{ "schema_version": "1.0", "components": [] }' );

  Assert.IsTrue( FLoader.Validate( FileName ) );

end;

end.
