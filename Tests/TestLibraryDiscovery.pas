(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestLibraryDiscovery.pas — Tests for the library-naming and vendor helpers in uLibraryDiscovery
*)
unit TestLibraryDiscovery;

interface

uses
  DUnitX.TestFramework;

type
  /// <summary>
  ///   Which parent directory may name a library, and how a copyright line becomes a vendor name.
  /// </summary>
  [TestFixture]
  TLibraryDiscoveryTests = class
  public
    /// <summary>
    ///   Proves the parent of a library that sits directly under a drive or share root is not searched
    ///   for packages: the root holds unrelated checkouts, and E:\EurekaLog was named "rbEDB" after
    ///   E:\ElevateDB\rbEDB2337.dpk.
    /// </summary>
    /// <param name="ADirectory">A library directory whose parent is a root.</param>
    [Test]
    [TestCase( 'drive child', 'E:\EurekaLog' )]
    [TestCase( 'drive child with delimiter', 'D:\gllLoggerPro\' )]
    [TestCase( 'drive root itself', 'E:\' )]
    [TestCase( 'share child', '\\server\share\Lib' )]
    procedure RootParentIsNotSearched( const ADirectory: string );

    /// <summary>
    ///   Proves a library deeper than one level below a root still has its parent searched, so
    ///   Source\ beside Packages\ keeps taking the package's name.
    /// </summary>
    [Test]
    procedure NestedParentIsSearched;

    /// <summary>
    ///   Proves a closing bracket that belongs to the holder's name survives, while trailing
    ///   punctuation and an unmatched bracket are still stripped. "Jane Doe (Acme Software). All
    ///   rights reserved." came out as "Jane Doe (Acme Software" because every trailing ')' was cut.
    /// </summary>
    /// <param name="AInput">Text after the copyright marker.</param>
    /// <param name="AExpected">Holder's name.</param>
    [Test]
    [TestCase( 'bracketed company then rights', 'Jane Doe (Acme Software). All rights reserved.|Jane Doe (Acme Software)', '|' )]
    [TestCase( 'bracketed country', '2024 Acme Widgets (UK)|Acme Widgets (UK)', '|' )]
    [TestCase( 'unmatched closer', '2024 Jane Doe)|Jane Doe', '|' )]
    [TestCase( 'years and full stop', '(c) 2020-2026 Acme Ltd.|Acme Ltd', '|' )]
    [TestCase( 'whole name bracketed', '(Acme Widgets)|Acme Widgets', '|' )]
    procedure HolderNameKeepsItsBrackets( const AInput, AExpected: string );
  end;

implementation

uses
  uLibraryDiscovery;

procedure TLibraryDiscoveryTests.RootParentIsNotSearched( const ADirectory: string );
begin

  Assert.AreEqual( '', LibraryParentDirectory( ADirectory ), 'Parent of ' + ADirectory );

end;

procedure TLibraryDiscoveryTests.NestedParentIsSearched;
begin

  Assert.AreEqual( 'D:\Libs\Acme', LibraryParentDirectory( 'D:\Libs\Acme\Source' ) );
  Assert.AreEqual( 'D:\Libs', LibraryParentDirectory( 'D:\Libs\Acme\' ) );

end;

procedure TLibraryDiscoveryTests.HolderNameKeepsItsBrackets( const AInput, AExpected: string );
begin

  Assert.AreEqual( AExpected, CleanCopyrightHolder( AInput ) );

end;

end.
