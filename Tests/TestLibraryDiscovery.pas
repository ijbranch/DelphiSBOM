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
    [TestCase( 'trailing dash', '2015 Jane Doe -|Jane Doe', '|' )]
    [TestCase( 'banner lettering', 'RRRRRR|', '|' )]
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
    [TestCase( 'packages and named release', 'D:\Acme\packages\Delphi 13 Florence\Win64\Release|D:\Acme', '|' )]
    [TestCase( 'library folder', 'D:\Acme4D\Library\Delphi13\Win64\Release|D:\Acme4D', '|' )]
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

  /// <summary>
  ///   Discovery cases found by running DelphiSBOM over a suite of real projects, on one scratch layout:
  ///   a stray copy of a library unit in a junk folder of the scanned drive, a library installed inside
  ///   the Delphi folder, the Delphi folder's own lib, an identifier that contains "Copyright", a
  ///   design-only package beside the runtime one, and a library whose source sits in a "windows" folder.
  /// </summary>
  [TestFixture]
  TDiscoveryCaseTests = class
  private
    FScratch: TScratchDir;
    FTag: string;
    FLibraries: TArray<TDiscoveredLibrary>;

    function LibraryOf( const AUnitName: string ): TDiscoveredLibrary;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves a .pas found only by scanning the drive gives way to the unit's DCU on the library path:
    ///   ReportBuilder's daSQL was attributed to a stray copy in D:\USB Temp (named "USB Temp", vendor "BBBBB").
    /// </summary>
    [Test]
    procedure DriveScanCopyGivesWayToTheLibraryPath;

    /// <summary>
    ///   Proves a library installed inside the Delphi folder is found through its DCUs: ReportBuilder lives in
    ///   $(BDS)\RBuilder\Lib\Win64, and excluding the whole Delphi folder left its 408 units unresolved.
    /// </summary>
    [Test]
    procedure LibraryInsideTheDelphiFolderIsFound;

    /// <summary>
    ///   Proves the Delphi folder's own lib folder is still left out: its units are the RTL's, classified
    ///   by the RTL scan, never a library.
    /// </summary>
    [Test]
    procedure DelphiLibFolderIsNotALibrary;

    /// <summary>
    ///   Proves "Copyright" inside an identifier is not a copyright line: Indy's "FlblCopyRight : TLabel;"
    ///   gave the vendor "TLabel".
    /// </summary>
    [Test]
    procedure CopyrightInsideAnIdentifierIsNotAVendor;

    /// <summary>
    ///   Proves a design-only package does not name the library when a runtime package sits beside it:
    ///   a database library was named after its design package.
    /// </summary>
    [Test]
    procedure DesignOnlyPackageDoesNotNameTheLibrary;

    /// <summary>
    ///   Proves a platform-named source folder ("windows") is passed over for the library's own folder
    ///   name: a grid library was named "windows".
    /// </summary>
    [Test]
    procedure PlatformFolderDoesNotNameTheLibrary;

    /// <summary>
    ///   Proves an ASCII-art header's letters are not taken for the copyright holder: ReportBuilder's
    ///   "Copyright (c) 1996-2011        BBBBB" gave the vendor "BBBBB".
    /// </summary>
    [Test]
    procedure AsciiArtIsNotAVendor;

    /// <summary>
    ///   Proves the holder is read from the line after a bare "Copyright:", and a revision-history
    ///   sentence that mentions copyright is passed over: Indy gave the vendor "to say 2003" from
    ///   "Updated copyright to say 2003." instead of its "Copyright:" block.
    /// </summary>
    [Test]
    procedure CopyrightBlockBeatsHistoryProse;

    /// <summary>
    ///   Proves the vendor is the holder most of the library's files name, and a company name on an
    ///   ASCII-art banner counts when the copyright line itself only has years: ReportBuilder's banner
    ///   names Digital Metaphors Corporation in 538 of 561 files, yet the first file with any name — one
    ///   contributor's — made the vendor.
    /// </summary>
    [Test]
    procedure VendorIsWhatMostFilesSay;

    /// <summary>
    ///   Proves a holder written before the word ("Pierre le Riche, copyright 2004 - 2026") is read, rather
    ///   than a company on a later line: FastMM5's vendor came out as its sponsor, "gs-soft AG".
    /// </summary>
    [Test]
    procedure HolderBeforeTheWordIsRead;
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

{ TDiscoveryCaseTests }

procedure TDiscoveryCaseTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FTag := 'Dsbg' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  var Unit_ :=
    function( const AName, AHeader: string ): string
    begin
      Result := AHeader + 'unit ' + FTag + AName + '; interface implementation end.';
    end;

  // A stray copy in a junk folder of the scanned "drive"; the real library is on the library path as DCUs
  WriteUtf8File( FScratch.PathOf( 'Drive\USB Temp\' + FTag + 'Stray.pas' ), Unit_( 'Stray', '// Copyright BBBBB' + sLineBreak ) );
  var StrayDcuDir := FScratch.PathOf( 'Libs\RealLib\Lib\Win64\Release' );
  WriteUtf8File( TPath.Combine( StrayDcuDir, FTag + 'Stray.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Libs\RealLib\Source\' + FTag + 'Stray.pas' ), Unit_( 'Stray', '// Copyright (c) 2024 Real Ltd' + sLineBreak ) );

  // A library installed inside the Delphi folder, and the Delphi folder's own lib
  var RbDcuDir  := FScratch.PathOf( 'Studio\RBuilder\Lib\Win64' );
  WriteUtf8File( TPath.Combine( RbDcuDir, FTag + 'Rb.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'Studio\RBuilder\Source\' + FTag + 'Rb.pas' ), Unit_( 'Rb', '' ) );
  var RtlDcuDir := FScratch.PathOf( 'Studio\lib\Win64\release' );
  WriteUtf8File( TPath.Combine( RtlDcuDir, FTag + 'Rtl.dcu' ), 'not a real dcu' );

  // An identifier that contains "Copyright"
  WriteUtf8File( FScratch.PathOf( 'Libs\IdLib\' + FTag + 'Id.pas' ),
    Unit_( 'Id', 'type' + sLineBreak + '  TAbout = class' + sLineBreak + '    FlblCopyRight : TLabel;' + sLineBreak + '  end;' + sLineBreak ) );

  // A design-only package that sorts before the runtime one
  WriteUtf8File( FScratch.PathOf( 'Libs\PkgLib\' + FTag + 'Pkg.pas' ), Unit_( 'Pkg', '' ) );
  WriteUtf8File( FScratch.PathOf( 'Libs\PkgLib\AcmeDesign.dpk' ), 'package AcmeDesign;' + sLineBreak + '{$DESIGNONLY}' + sLineBreak + 'end.' );
  WriteUtf8File( FScratch.PathOf( 'Libs\PkgLib\AcmeRun.dpk' ), 'package AcmeRun;' + sLineBreak + '{$RUNONLY}' + sLineBreak + 'end.' );

  // Source in a platform-named folder
  WriteUtf8File( FScratch.PathOf( 'Libs\InfoThing\source\windows\' + FTag + 'Info.pas' ), Unit_( 'Info', '' ) );

  // An ASCII-art header
  WriteUtf8File( FScratch.PathOf( 'Libs\ArtLib\' + FTag + 'Art.pas' ), Unit_( 'Art',
    '{ RRRRRR                  Acme Report Library                  BBBBB' + sLineBreak +
    '  RR   RR                   Copyright (c) 1996-2011                    BBBBB   }' + sLineBreak ) );

  // History prose in the first file, a "Copyright:" block with the holder on the next line in the second
  WriteUtf8File( FScratch.PathOf( 'Libs\BlockLib\' + FTag + 'Block1.pas' ), Unit_( 'Block1',
    '{ Rev 1.3  6/16/2003' + sLineBreak + '  Updated copyright to say 2003. }' + sLineBreak ) );
  WriteUtf8File( FScratch.PathOf( 'Libs\BlockLib\' + FTag + 'Block2.pas' ), Unit_( 'Block2',
    '{ Copyright:' + sLineBreak + '   (c) 1993-2005, Jane Doe and the Acme Crew. All rights reserved. }' + sLineBreak ) );

  // The holder before the word, a sponsor company on a later line
  WriteUtf8File( FScratch.PathOf( 'Libs\HolderLib\' + FTag + 'Holder.pas' ), Unit_( 'Holder',
    '(*' + sLineBreak + '  Jane le Doe, copyright 2004 - 2026, all rights reserved' + sLineBreak + sLineBreak + 'Sponsored by:' + sLineBreak +
    '  acme-soft AG' + sLineBreak + '*)' + sLineBreak ) );

  // One contributor's file sorts first; the other three carry the publisher's banner
  WriteUtf8File( FScratch.PathOf( 'Libs\VoteLib\' + FTag + 'Vote0.pas' ), Unit_( 'Vote0',
    '// Copyright (c) 2003 Jane Contributor' + sLineBreak ) );

  for var N := 1 to 3 do
    WriteUtf8File( FScratch.PathOf( Format( 'Libs\VoteLib\%sVote%d.pas', [ FTag, N ] ) ), Unit_( 'Vote' + IntToStr( N ),
      '{ RRRRRR                  Acme Report Library                  BBBBB' + sLineBreak +
      '  RR   RR                 Acme Metaphors Corporation            BB   BB' + sLineBreak +
      '  RR   RR                   Copyright (c) 1996-2011            BBBBB   }' + sLineBreak ) );

  var Discovery := TLibraryDiscovery.Create( NoLog() );
  try
    Discovery.ScanRoots := [ FScratch.PathOf( 'Drive' ) ];

    var AutoOwn: TArray<string>;
    FLibraries := Discovery.Discover(
      [ FTag + 'Stray', FTag + 'Rb', FTag + 'Rtl', FTag + 'Id', FTag + 'Pkg', FTag + 'Info', FTag + 'Art', FTag + 'Block1',
        FTag + 'Block2', FTag + 'Vote0', FTag + 'Holder' ],
      [ StrayDcuDir, RbDcuDir, RtlDcuDir, FScratch.PathOf( 'Libs\IdLib' ), FScratch.PathOf( 'Libs\PkgLib' ),
        FScratch.PathOf( 'Libs\InfoThing\source\windows' ), FScratch.PathOf( 'Libs\ArtLib' ), FScratch.PathOf( 'Libs\BlockLib' ),
        FScratch.PathOf( 'Libs\VoteLib' ), FScratch.PathOf( 'Libs\HolderLib' ) ],
      FScratch.PathOf( 'Work\App' ), FScratch.PathOf( 'Studio' ), '', 'Win64', AutoOwn );
  finally
    Discovery.Free;
  end;

end;

procedure TDiscoveryCaseTests.TearDownFixture;
begin

  FScratch.Free;

end;

function TDiscoveryCaseTests.LibraryOf( const AUnitName: string ): TDiscoveredLibrary;
begin

  for var Lib in FLibraries do
    for var U in Lib.Units do
      if SameText( U, FTag + AUnitName ) then
        Exit( Lib );

  Result := Default( TDiscoveredLibrary );

end;

procedure TDiscoveryCaseTests.DriveScanCopyGivesWayToTheLibraryPath;
begin

  var Lib := LibraryOf( 'Stray' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\RealLib\Source' ), Lib.Directory );
  Assert.AreEqual( 'Real Ltd', Lib.Vendor );

end;

procedure TDiscoveryCaseTests.LibraryInsideTheDelphiFolderIsFound;
begin

  var Lib := LibraryOf( 'Rb' );
  Assert.AreEqual( FScratch.PathOf( 'Studio\RBuilder\Source' ), Lib.Directory );
  Assert.AreEqual( 'RBuilder', Lib.Name );

end;

procedure TDiscoveryCaseTests.DelphiLibFolderIsNotALibrary;
begin

  Assert.AreEqual( '', LibraryOf( 'Rtl' ).Directory, 'A unit of the Delphi lib folder was attached to a library' );

end;

procedure TDiscoveryCaseTests.CopyrightInsideAnIdentifierIsNotAVendor;
begin

  var Lib := LibraryOf( 'Id' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\IdLib' ), Lib.Directory, 'Library not discovered' );
  Assert.AreEqual( '', Lib.Vendor );

end;

procedure TDiscoveryCaseTests.DesignOnlyPackageDoesNotNameTheLibrary;
begin

  Assert.AreEqual( 'AcmeRun', LibraryOf( 'Pkg' ).Name );

end;

procedure TDiscoveryCaseTests.PlatformFolderDoesNotNameTheLibrary;
begin

  Assert.AreEqual( 'InfoThing', LibraryOf( 'Info' ).Name );

end;

procedure TDiscoveryCaseTests.AsciiArtIsNotAVendor;
begin

  var Lib := LibraryOf( 'Art' );
  Assert.AreEqual( FScratch.PathOf( 'Libs\ArtLib' ), Lib.Directory, 'Library not discovered' );
  Assert.AreEqual( '', Lib.Vendor );

end;

procedure TDiscoveryCaseTests.CopyrightBlockBeatsHistoryProse;
begin

  Assert.AreEqual( 'Jane Doe and the Acme Crew', LibraryOf( 'Block2' ).Vendor );

end;

procedure TDiscoveryCaseTests.VendorIsWhatMostFilesSay;
begin

  Assert.AreEqual( 'Acme Metaphors Corporation', LibraryOf( 'Vote0' ).Vendor );

end;

procedure TDiscoveryCaseTests.HolderBeforeTheWordIsRead;
begin

  Assert.AreEqual( 'Jane le Doe', LibraryOf( 'Holder' ).Vendor );

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
