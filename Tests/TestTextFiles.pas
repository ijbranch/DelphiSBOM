(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestTextFiles.pas — Tests for uTextFiles (encoding detection and atomic writes)
*)
unit TestTextFiles;

interface

uses
  DUnitX.TestFramework,
  TestSupport;

type
  /// <summary>
  ///   Encoding detection on read (BOM, then UTF-8, then ANSI) and BOM-free atomic writes.
  /// </summary>
  [TestFixture]
  TTextFilesTests = class
  private
    FScratch: TScratchDir;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves an ANSI file holding non-ASCII bytes (a copyright sign, an umlaut) is decoded through the
    ///   ANSI fallback. Reading with an explicit TEncoding.UTF8 returned an empty string for such files.
    /// </summary>
    [Test]
    procedure AnsiFileDecodedViaFallback;

    /// <summary>
    ///   Proves UTF-8 without a BOM is decoded as UTF-8, not as ANSI (which would turn one umlaut into two characters).
    /// </summary>
    [Test]
    procedure Utf8WithoutBomDecodedAsUtf8;

    /// <summary>
    ///   Proves a BOM wins over content sniffing: a UTF-16 LE file with a BOM is decoded as UTF-16.
    /// </summary>
    [Test]
    procedure BomSelectsEncoding;

    /// <summary>
    ///   Proves a head read that cuts a two-byte UTF-8 sequence in half drops the partial character
    ///   instead of failing UTF-8 validation and decoding the whole buffer as ANSI.
    /// </summary>
    [Test]
    procedure HeadReadDropsCutMultiByteTail;

    /// <summary>
    ///   Proves WriteTextFileAtomic writes UTF-8 with no BOM (RFC 8259) and leaves no temporary file behind.
    /// </summary>
    [Test]
    procedure AtomicWriteHasNoBomAndNoTempFile;

    /// <summary>
    ///   Proves WriteTextFileAtomic replaces an existing file completely (no trailing bytes from a longer original).
    /// </summary>
    [Test]
    procedure AtomicWriteReplacesExistingFile;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
  uTextFiles;

const
  CopyrightSign = #$00A9;
  UUmlaut       = #$00FC;

{ TTextFilesTests }

procedure TTextFilesTests.Setup;
begin

  FScratch := TScratchDir.Create;

end;

procedure TTextFilesTests.TearDown;
begin

  FScratch.Free;

end;

procedure TTextFilesTests.AnsiFileDecodedViaFallback;
begin

  var Text := 'Copyright ' + CopyrightSign + ' 2020 M' + UUmlaut + 'ller';
  var FileName := FScratch.PathOf( 'ansi.txt' );
  WriteAnsiFile( FileName, Text );

  Assert.AreEqual( Text, ReadTextFile( FileName ), False );

end;

procedure TTextFilesTests.Utf8WithoutBomDecodedAsUtf8;
begin

  var Text := 'M' + UUmlaut + 'ller';
  var FileName := FScratch.PathOf( 'utf8.txt' );
  WriteUtf8File( FileName, Text );

  Assert.AreEqual( Text, ReadTextFile( FileName ), False );

end;

procedure TTextFilesTests.BomSelectsEncoding;
begin

  var Text := 'M' + UUmlaut + 'ller';
  var FileName := FScratch.PathOf( 'utf16.txt' );
  TFile.WriteAllText( FileName, Text, TEncoding.Unicode );

  Assert.AreEqual( Text, ReadTextFile( FileName ), False );

end;

procedure TTextFilesTests.HeadReadDropsCutMultiByteTail;
begin

  // 'M' is one byte and the umlaut two: a 2-byte head ends half-way through the umlaut
  var FileName := FScratch.PathOf( 'head.txt' );
  WriteUtf8File( FileName, 'M' + UUmlaut + 'ller' );

  Assert.AreEqual( 'M', ReadTextFileHead( FileName, 2 ), False );
  Assert.AreEqual( 'M' + UUmlaut, ReadTextFileHead( FileName, 3 ), False );

end;

procedure TTextFilesTests.AtomicWriteHasNoBomAndNoTempFile;
begin

  var FileName := FScratch.PathOf( 'out.json' );
  WriteTextFileAtomic( FileName, '{"a":"' + UUmlaut + '"}' );

  var Bytes := TFile.ReadAllBytes( FileName );

  Assert.AreEqual( Ord( '{' ), Integer( Bytes[ 0 ] ), 'First byte must be the JSON, not a BOM' );
  Assert.AreEqual<NativeInt>( 10, Length( Bytes ), 'UTF-8 length: 8 ASCII bytes + a 2-byte umlaut' );
  Assert.IsFalse( FileExists( FileName + '.tmp' ), 'Temporary file left behind' );

end;

procedure TTextFilesTests.AtomicWriteReplacesExistingFile;
begin

  var FileName := FScratch.PathOf( 'replace.txt' );
  WriteUtf8File( FileName, 'a much longer original content' );

  WriteTextFileAtomic( FileName, 'short' );

  Assert.AreEqual( 'short', ReadTextFile( FileName ), False );

end;

end.
