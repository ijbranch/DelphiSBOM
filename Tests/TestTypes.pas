(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestTypes.pas — Tests for the shared helpers in uTypes
*)
unit TestTypes;

interface

uses
  DUnitX.TestFramework;

type
  /// <summary>
  ///   Licence classification, hash algorithm normalisation, scope stripping and macro expansion.
  /// </summary>
  [TestFixture]
  TTypesTests = class
  public
    /// <summary>
    ///   Proves a recognised SPDX identifier is emitted as license.id in its canonical casing,
    ///   whatever casing the manifest used (the schema enum is case-sensitive).
    /// </summary>
    /// <param name="AInput">Licence value as written in components.json.</param>
    /// <param name="AExpected">Canonical SPDX identifier.</param>
    [Test]
    [TestCase( 'lower mit', 'mit,MIT' )]
    [TestCase( 'upper APACHE', 'APACHE-2.0,Apache-2.0' )]
    [TestCase( 'or-later form', 'lgpl-2.1-or-later,LGPL-2.1-or-later' )]
    procedure KnownIdIsSPDXInCanonicalCase( const AInput, AExpected: string );

    /// <summary>
    ///   Proves a value that is not an SPDX identifier (e.g. "MPL 1.1" with a space, or "Commercial")
    ///   is classified as a licence name — writing it to license.id made the SBOM schema-invalid.
    /// </summary>
    /// <param name="AInput">Licence value as written in components.json.</param>
    [Test]
    [TestCase( 'space instead of hyphen', 'MPL 1.1' )]
    [TestCase( 'commercial', 'Commercial' )]
    [TestCase( 'proprietary', 'Proprietary' )]
    procedure UnknownValueIsName( const AInput: string );

    /// <summary>
    ///   Proves an SPDX expression (OR / AND / WITH) is classified as an expression, case-insensitively.
    /// </summary>
    [Test]
    procedure ExpressionIsRecognised;

    /// <summary>
    ///   Proves an empty or blank licence is classified as none, so no licenses array is emitted.
    /// </summary>
    [Test]
    procedure BlankIsNone;

    /// <summary>
    ///   Proves hash algorithm spellings are mapped onto the CycloneDX 1.5 enum, and an algorithm
    ///   outside the enum maps to '' so it can be dropped rather than invalidate the SBOM.
    /// </summary>
    [Test]
    procedure HashAlgorithmsNormalised;

    /// <summary>
    ///   Proves the scope prefixes added in the audit (FireDAC., Web., Soap.) are stripped, and a name
    ///   with no known scope is returned unchanged.
    /// </summary>
    [Test]
    procedure ScopePrefixesStripped;

    /// <summary>
    ///   Proves every $(Name) reference is passed to the resolver and replaced by its result,
    ///   that text around references is kept, and an unterminated reference is left as written.
    /// </summary>
    [Test]
    procedure MacroReferencesExpanded;

    /// <summary>
    ///   Proves the email plausibility check accepts addresses and rejects what a vendor_email field is
    ///   likely to hold by mistake: a URL, a name, two '@', a missing local part or an undotted domain.
    /// </summary>
    /// <param name="AValue">The value to check.</param>
    /// <param name="AExpected">Whether it should be accepted.</param>
    [Test]
    [TestCase( 'address', 'info@example.com,True' )]
    [TestCase( 'subdomain and plus', 'a.b+sbom@mail.example.co.uk,True' )]
    [TestCase( 'url', 'https://example.com,False' )]
    [TestCase( 'name', 'Acme Pty Ltd,False' )]
    [TestCase( 'space', 'info @example.com,False' )]
    [TestCase( 'two at signs', 'a@b@example.com,False' )]
    [TestCase( 'no local part', '@example.com,False' )]
    [TestCase( 'undotted domain', 'info@localhost,False' )]
    [TestCase( 'trailing dot', 'info@example.,False' )]
    [TestCase( 'empty', ',False' )]
    procedure EmailAddressesRecognised( const AValue: string; AExpected: Boolean );
  end;

implementation

uses
  System.SysUtils,
  uTypes;

{ TTypesTests }

procedure TTypesTests.KnownIdIsSPDXInCanonicalCase( const AInput, AExpected: string );
begin

  var Normalised := '';

  Assert.AreEqual<TLicenceKind>( lkSPDX, ClassifyLicence( AInput, Normalised ) );
  Assert.AreEqual( AExpected, Normalised, False );

end;

procedure TTypesTests.UnknownValueIsName( const AInput: string );
begin

  var Normalised := '';

  Assert.AreEqual<TLicenceKind>( lkName, ClassifyLicence( AInput, Normalised ) );
  Assert.AreEqual( AInput, Normalised, False );

end;

procedure TTypesTests.ExpressionIsRecognised;
begin

  var Normalised := '';

  Assert.AreEqual<TLicenceKind>( lkExpression, ClassifyLicence( 'MPL-1.1 OR LGPL-2.1-or-later', Normalised ) );
  Assert.AreEqual<TLicenceKind>( lkExpression, ClassifyLicence( 'Apache-2.0 with LLVM-exception', Normalised ) );
  Assert.AreEqual<TLicenceKind>( lkExpression, ClassifyLicence( 'MIT and BSD-3-Clause', Normalised ) );

end;

procedure TTypesTests.BlankIsNone;
begin

  var Normalised := '';

  Assert.AreEqual<TLicenceKind>( lkNone, ClassifyLicence( '', Normalised ) );
  Assert.AreEqual<TLicenceKind>( lkNone, ClassifyLicence( '   ', Normalised ) );

end;

procedure TTypesTests.HashAlgorithmsNormalised;
begin

  Assert.AreEqual( 'SHA-256', NormaliseHashAlgorithm( 'SHA256' ), False );
  Assert.AreEqual( 'SHA-256', NormaliseHashAlgorithm( 'sha-256' ), False );
  Assert.AreEqual( 'SHA-1', NormaliseHashAlgorithm( 'sha1' ), False );
  Assert.AreEqual( 'SHA3-512', NormaliseHashAlgorithm( 'sha3-512' ), False );
  Assert.AreEqual( '', NormaliseHashAlgorithm( 'CRC32' ), False );
  Assert.AreEqual( '', NormaliseHashAlgorithm( '' ), False );

end;

procedure TTypesTests.ScopePrefixesStripped;
begin

  Assert.AreEqual( 'Comp.Client', StripScopePrefix( 'FireDAC.Comp.Client' ), False );
  Assert.AreEqual( 'HTTPApp', StripScopePrefix( 'Web.HTTPApp' ), False );
  Assert.AreEqual( 'SOAPHTTPClient', StripScopePrefix( 'Soap.SOAPHTTPClient' ), False );
  Assert.AreEqual( 'Generics.Collections', StripScopePrefix( 'System.Generics.Collections' ), False );
  Assert.AreEqual( 'OtlTask', StripScopePrefix( 'OtlTask' ), False );

end;

procedure TTypesTests.MacroReferencesExpanded;
begin

  var Resolver: TFunc<string, string> :=
    function( AName: string ): string
    begin
      Result := '<' + UpperCase( AName ) + '>';
    end;

  Assert.AreEqual( 'C:\<BDS>\lib\<PLATFORM>', ExpandMacroReferences( 'C:\$(BDS)\lib\$(Platform)', Resolver ), False );
  Assert.AreEqual( 'no macros', ExpandMacroReferences( 'no macros', Resolver ), False );
  Assert.AreEqual( 'open $(BDS', ExpandMacroReferences( 'open $(BDS', Resolver ), False );

end;

procedure TTypesTests.EmailAddressesRecognised( const AValue: string; AExpected: Boolean );
begin

  Assert.AreEqual( AExpected, IsEmailAddress( AValue ), AValue );

end;

end.
