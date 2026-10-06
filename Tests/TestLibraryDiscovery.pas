(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestLibraryDiscovery.pas — Tests for the library-naming and vendor helpers in uLibraryDiscovery
*)
unit TestLibraryDiscovery;

interface

uses
  DUnitX.TestFramework,
  uTypes, TestSupport;

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
    [TestCase( 'drive child with delimiter', 'D:\LoggerPro\' )]
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

    /// <summary>
    ///   Proves a folder of compiled units maps to the library that owns it, past every kind of
    ///   build-output folder name: version, platform and configuration folders, lib / dcu folders and
    ///   compiler-named folders. A library consumed only as DCUs was unresolved because discovery
    ///   looked for .pas files in the DCU folder itself.
    /// </summary>
    /// <param name="ADcuDirectory">A folder of .dcu files.</param>
    /// <param name="AExpected">The library root.</param>
    [Test]
    [TestCase( 'version platform config', 'D:\Acme\37.0\Win64\Release|D:\Acme', '|' )]
    [TestCase( 'lib platform config', 'C:\Libs\Acme Widgets\Lib\Win32\Debug|C:\Libs\Acme Widgets', '|' )]
    [TestCase( 'compiler folder', 'C:\Vendor\Acme UI Pack\Delphi13\Win64\Release|C:\Vendor\Acme UI Pack', '|' )]
    [TestCase( 'short compiler folder', 'C:\Acme\Lib\D13\Win64|C:\Acme', '|' )]
    [TestCase( 'studio folder', 'C:\Acme 7\Lib\Win64\Release\Studio37|C:\Acme 7', '|' )]
    [TestCase( 'dcu folder', 'E:\Work\Acme\dcu\Win64|E:\Work\Acme', '|' )]
    [TestCase( 'already a root', 'E:\Work\Acme|E:\Work\Acme', '|' )]
    [TestCase( 'only build names to the drive', 'E:\Lib\Win64\Release|E:\Lib\Win64\Release', '|' )]
    procedure DcuFolderMapsToLibraryRoot( const ADcuDirectory, AExpected: string );
  end;

  /// <summary>
  ///   Runs library discovery over a scratch layout where units are reachable only through folders of
  ///   compiled units, the way the IDE library path points at a library's DCUs:
  ///   Libs\BinLib (licence, DCUs only), Libs\SrcLib (DCUs on the path, source in the library root).
  /// </summary>
  [TestFixture]
  TDcuDiscoveryTests = class
  private
    FScratch: TScratchDir;
    FTag: string;
    FLibraries: TArray<TDiscoveredLibrary>;

    function FindLibraryWith( const AUnitName: string; out ALibrary: TDiscoveredLibrary ): Boolean;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves a unit present only as a .dcu is discovered as a library rooted above its build
    ///   folders, with the root's licence and name, and flagged as binary-only.
    /// </summary>
    [Test]
    procedure DcuOnlyUnitIsDiscoveredAtLibraryRoot;

    /// <summary>
    ///   Proves a unit whose DCU folder is on the path but whose source sits in the library root is
    ///   attributed to the source folder, so vendor detection reads its header, and is not binary-only.
    /// </summary>
    [Test]
    procedure DcuUnitWithSourceUnderRootUsesTheSource;

    /// <summary>
    ///   Proves a unit with neither a .pas nor a .dcu anywhere searched stays unresolved rather than
    ///   being attached to some library.
    /// </summary>
    [Test]
    procedure UnitWithNothingOnDiskStaysUnresolved;

    /// <summary>
    ///   Proves a library reached through its DCU folder is discovered although its root holds a .dpr
    ///   (the project that builds the DCUs). The rule that skips folders with a .dpr as "another
    ///   project" hid a FastMM5 checkout whose root holds the .dpr that builds its DCU.
    /// </summary>
    [Test]
    procedure DcuBuildProjectDoesNotHideTheLibrary;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
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

procedure TLibraryDiscoveryTests.DcuFolderMapsToLibraryRoot( const ADcuDirectory, AExpected: string );
begin

  Assert.AreEqual( AExpected, DcuLibraryRoot( ADcuDirectory ) );

end;

{ TDcuDiscoveryTests }

procedure TDcuDiscoveryTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;

  // Unique unit names so nothing elsewhere on the machine can be matched by discovery
  FTag := 'Dsbd' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  var BinDcuDir := FScratch.PathOf( 'Libs\BinLib\37.0\Win64\Release' );
  var SrcDcuDir := FScratch.PathOf( 'Libs\SrcLib\Lib\Win64\Release' );

  // A .dcu is binary; discovery only needs the file to exist
  WriteUtf8File( TPath.Combine( BinDcuDir, FTag + 'Bin.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Libs\BinLib\LICENSE' ),
    'MIT License' + sLineBreak + 'Permission is hereby granted, free of charge, to any person obtaining a copy' );

  // A library whose root holds the .dpr that builds its DCUs (as a FastMM5 checkout can)
  var BuiltDcuDir := FScratch.PathOf( 'Libs\BuiltLib\37.0\Win64\Release' );
  WriteUtf8File( TPath.Combine( BuiltDcuDir, FTag + 'Built.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Libs\BuiltLib\' + FTag + 'Built.pas' ), 'unit ' + FTag + 'Built; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'Libs\BuiltLib\BuiltLibDCU.dpr' ), 'program BuiltLibDCU; begin end.' );

  // The same, with the source folder also searched, so the .pas is found before the DCU (FastMM5 under D:\)
  var Built2DcuDir := FScratch.PathOf( 'Libs\Built2Lib\37.0\Win64\Release' );
  WriteUtf8File( TPath.Combine( Built2DcuDir, FTag + 'Built2.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Libs\Built2Lib\' + FTag + 'Built2.pas' ), 'unit ' + FTag + 'Built2; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'Libs\Built2Lib\Built2LibDCU.dpr' ), 'program Built2LibDCU; begin end.' );

  WriteUtf8File( TPath.Combine( SrcDcuDir, FTag + 'Src.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Libs\SrcLib\Source\' + FTag + 'Src.pas' ),
    '// Copyright (c) 2024 Acme Widgets Ltd.' + sLineBreak + 'unit ' + FTag + 'Src; interface implementation end.' );

  var Discovery := TLibraryDiscovery.Create( NoLog() );
  try
    var AutoOwn: TArray<string>;
    FLibraries := Discovery.Discover( [ FTag + 'Bin', FTag + 'Src', FTag + 'Built', FTag + 'Built2', FTag + 'Missing' ],
      [ BinDcuDir, SrcDcuDir, BuiltDcuDir, FScratch.PathOf( 'Libs\Built2Lib' ), Built2DcuDir ],
      FScratch.PathOf( 'Work\App' ), '', '', 'Win64', AutoOwn );
  finally
    Discovery.Free;
  end;

end;

procedure TDcuDiscoveryTests.TearDownFixture;
begin

  FScratch.Free;

end;

function TDcuDiscoveryTests.FindLibraryWith( const AUnitName: string; out ALibrary: TDiscoveredLibrary ): Boolean;
begin

  for var Lib in FLibraries do
    for var U in Lib.Units do
      if SameText( U, AUnitName ) then
      begin
        ALibrary := Lib;
        Exit( True );
      end;

  Result := False;

end;

procedure TDcuDiscoveryTests.DcuOnlyUnitIsDiscoveredAtLibraryRoot;
begin

  var Lib: TDiscoveredLibrary;
  Assert.IsTrue( FindLibraryWith( FTag + 'Bin', Lib ), 'DCU-only unit not discovered' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\BinLib' ), Lib.Directory );
  Assert.AreEqual( 'BinLib', Lib.Name );
  Assert.AreEqual( 'MIT', Lib.Licence );
  Assert.IsTrue( Lib.BinaryOnly, 'Not flagged as binary-only' );

end;

procedure TDcuDiscoveryTests.DcuUnitWithSourceUnderRootUsesTheSource;
begin

  var Lib: TDiscoveredLibrary;
  Assert.IsTrue( FindLibraryWith( FTag + 'Src', Lib ), 'DCU unit with source not discovered' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\SrcLib\Source' ), Lib.Directory );
  Assert.AreEqual( 'Acme Widgets Ltd', Lib.Vendor );
  Assert.IsFalse( Lib.BinaryOnly, 'Flagged as binary-only although its source was found' );

end;

procedure TDcuDiscoveryTests.UnitWithNothingOnDiskStaysUnresolved;
begin

  var Lib: TDiscoveredLibrary;
  Assert.IsFalse( FindLibraryWith( FTag + 'Missing', Lib ), 'A unit with no file was attached to ' + Lib.Name );
  Assert.AreEqual<Integer>( 4, Length( FLibraries ), 'Exactly the four scratch libraries' );

end;

procedure TDcuDiscoveryTests.DcuBuildProjectDoesNotHideTheLibrary;
begin

  var Lib: TDiscoveredLibrary;
  Assert.IsTrue( FindLibraryWith( FTag + 'Built', Lib ), 'Library skipped as a project because its root builds the DCUs' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\BuiltLib' ), Lib.Directory );

  Assert.IsTrue( FindLibraryWith( FTag + 'Built2', Lib ), 'Library skipped as a project when its source was found before its DCU' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\Built2Lib' ), Lib.Directory );

end;

end.
