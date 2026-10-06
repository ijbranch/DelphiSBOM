(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestMapFile.pas — Tests for reading linked units from a .map file, and the engine's use of them
*)
unit TestMapFile;

interface

uses
  DUnitX.TestFramework,
  uTypes, TestSupport;

type
  /// <summary>
  ///   Parsing the two places a Delphi .map file names units.
  /// </summary>
  [TestFixture]
  TMapFileTests = class
  public
    /// <summary>
    ///   Proves units are read from the M= entries of the segment map, including dotted names, each
    ///   once and in first-seen order although a unit owns several segments.
    /// </summary>
    [Test]
    procedure SegmentEntriesGiveUnitsOnceInOrder;

    /// <summary>
    ///   Proves "Line numbers for" headers add units, and that the unit is the name before the
    ///   bracket, not the source file inside it: uSettings(System.Generics.Collections.pas) is a
    ///   generic instantiated in uSettings, not a use of System.Generics.Collections.
    /// </summary>
    [Test]
    procedure LineNumberHeadersNameTheUnitNotTheFile;

    /// <summary>
    ///   Proves names are de-duplicated case-insensitively, keeping the first casing seen.
    /// </summary>
    [Test]
    procedure DuplicatesDifferingInCaseAreMerged;

    /// <summary>
    ///   Proves text with no unit entries (a publics-only map, or not a map at all) gives no units,
    ///   so the reader can refuse it rather than produce an empty SBOM.
    /// </summary>
    [Test]
    procedure TextWithoutEntriesGivesNothing;

    /// <summary>
    ///   Proves a missing file raises, rather than silently falling back to the uses clause.
    /// </summary>
    [Test]
    procedure MissingFileRaises;
  end;

  /// <summary>
  ///   Runs the pipeline on a scratch project with a MAP file that differs from its uses clause.
  /// </summary>
  [TestFixture]
  TMapEngineTests = class
  private
    FScratch: TScratchDir;
    FComInitialised: Boolean;
    FTag: string;
    FResult: TSBOMResult;

    function HasUnit( const AUnitName: string ): Boolean;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves a unit the linker used but the uses clause does not name (used indirectly) is
    ///   classified, which the uses clause alone can never find.
    /// </summary>
    [Test]
    procedure IndirectlyUsedUnitIsClassified;

    /// <summary>
    ///   Proves a uses-clause unit the linker did not use (an inactive {$IFDEF} branch) is left out.
    /// </summary>
    [Test]
    procedure UnlinkedUsesUnitIsLeftOut;

    /// <summary>
    ///   Proves the program's own entry in the map is not reported as a unit, and the result records
    ///   that the list came from the MAP file.
    /// </summary>
    [Test]
    procedure ProgramIsNotAUnitAndSourceIsRecorded;

    /// <summary>
    ///   Proves a unit in a subfolder of the project is own code, not a library named after the
    ///   subfolder ("Forms"), while a subfolder carrying a licence is still a vendored library.
    /// </summary>
    [Test]
    procedure ProjectSubfolderIsOwnCodeUnlessVendored;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, Winapi.ActiveX,
  uMapFile, uSBOMEngine;

const
  /// <summary>An excerpt in the shape the Delphi 13 linker writes.</summary>
  SampleMap =
    ' Start         Length     Name                   Class' + sLineBreak +
    ' 0001:00401000 00123456H .text                   CODE' + sLineBreak +
    '' + sLineBreak +
    'Detailed map of segments' + sLineBreak +
    '' + sLineBreak +
    ' 0001:00000000 0001A84C C=CODE     S=.text    G=(none)   M=System   ALIGN=4' + sLineBreak +
    ' 0001:0001A84C 00001854 C=CODE     S=.text    G=(none)   M=SysInit  ALIGN=4' + sLineBreak +
    ' 0001:0001C0A0 00004030 C=CODE     S=.text    G=(none)   M=System.Types ALIGN=4' + sLineBreak +
    ' 0002:00000000 00000100 C=DATA     S=.data    G=DGROUP   M=System   ALIGN=8' + sLineBreak +
    ' 0001:00020D60 00000060 C=CODE     S=.text    G=(none)   M=Acme.Widgets ALIGN=4' + sLineBreak +
    '' + sLineBreak +
    '  Address             Publics by Name' + sLineBreak +
    ' 0001:00001234       System.TObject.Create' + sLineBreak +
    '' + sLineBreak +
    'Line numbers for uSettings(uSettings.pas) segment .text' + sLineBreak +
    '    45 0001:00001000    46 0001:00001010' + sLineBreak +
    'Line numbers for uSettings(System.Generics.Collections.pas) segment .text' + sLineBreak +
    '  2100 0001:00002000' + sLineBreak +
    'Line numbers for uExtra(uExtra.pas) segment .text' + sLineBreak;

{ TMapFileTests }

procedure TMapFileTests.SegmentEntriesGiveUnitsOnceInOrder;
begin

  var Units := ParseMapUnitNames( SampleMap );
  Assert.IsTrue( Length( Units ) >= 4, 'Too few units' );
  Assert.AreEqual( 'System', Units[ 0 ] );
  Assert.AreEqual( 'SysInit', Units[ 1 ] );
  Assert.AreEqual( 'System.Types', Units[ 2 ] );
  Assert.AreEqual( 'Acme.Widgets', Units[ 3 ] );

end;

procedure TMapFileTests.LineNumberHeadersNameTheUnitNotTheFile;
begin

  var Units := ParseMapUnitNames( SampleMap );
  Assert.AreEqual( 'System|SysInit|System.Types|Acme.Widgets|uSettings|uExtra', string.Join( '|', Units ) );

end;

procedure TMapFileTests.DuplicatesDifferingInCaseAreMerged;
begin

  var Units := ParseMapUnitNames(
    ' 0001:00000000 00000010 C=CODE S=.text G=(none) M=Acme.Core ALIGN=4' + sLineBreak +
    ' 0001:00000010 00000010 C=CODE S=.text G=(none) M=ACME.CORE ALIGN=4' + sLineBreak +
    'Line numbers for acme.core(Acme.Core.pas) segment .text' + sLineBreak );

  Assert.AreEqual( 'Acme.Core', string.Join( '|', Units ) );

end;

procedure TMapFileTests.TextWithoutEntriesGivesNothing;
begin

  Assert.AreEqual<Integer>( 0, Length( ParseMapUnitNames(
    '  Address             Publics by Name' + sLineBreak + ' 0001:00001234       System.TObject.Create' + sLineBreak ) ) );
  Assert.AreEqual<Integer>( 0, Length( ParseMapUnitNames( 'not a map file' ) ) );

end;

procedure TMapFileTests.MissingFileRaises;
begin

  Assert.WillRaise(
    procedure
    begin
      ReadMapUnitNames( TPath.Combine( TPath.GetTempPath, 'no-such-' + TGUID.NewGuid.ToString + '.map' ) );
    end, Exception );

end;

{ TMapEngineTests }

procedure TMapEngineTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );
  FTag := 'Dsbm' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  // The uses clause names Listed and Conditional; the linker used Listed and Indirect
  WriteUtf8File( FScratch.PathOf( 'App\App.dpr' ),
    'program App;' + sLineBreak + 'uses' + sLineBreak +
    Format( '  System.SysUtils, %0:sListed in ''%0:sListed.pas'', %0:sConditional;', [ FTag ] ) + sLineBreak + 'begin end.' );
  WriteUtf8File( FScratch.PathOf( 'App\' + FTag + 'Listed.pas' ), 'unit ' + FTag + 'Listed; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'App\' + FTag + 'Indirect.pas' ), 'unit ' + FTag + 'Indirect; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'App\Forms\' + FTag + 'SubForm.pas' ), 'unit ' + FTag + 'SubForm; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'App\AcmeLib\' + FTag + 'Vendored.pas' ), 'unit ' + FTag + 'Vendored; interface implementation end.' );
  WriteUtf8File( FScratch.PathOf( 'App\AcmeLib\LICENSE' ),
    'MIT License' + sLineBreak + 'Permission is hereby granted, free of charge, to any person obtaining a copy' );

  var MapFile := FScratch.PathOf( 'App\App.map' );
  WriteUtf8File( MapFile,
    'Detailed map of segments' + sLineBreak +
    ' 0001:00000000 00000010 C=CODE S=.text G=(none) M=System ALIGN=4' + sLineBreak +
    ' 0001:00000010 00000010 C=CODE S=.text G=(none) M=System.SysUtils ALIGN=4' + sLineBreak +
    Format( ' 0001:00000020 00000010 C=CODE S=.text G=(none) M=%sListed ALIGN=4', [ FTag ] ) + sLineBreak +
    Format( ' 0001:00000030 00000010 C=CODE S=.text G=(none) M=%sIndirect ALIGN=4', [ FTag ] ) + sLineBreak +
    Format( ' 0001:00000034 00000010 C=CODE S=.text G=(none) M=%sSubForm ALIGN=4', [ FTag ] ) + sLineBreak +
    Format( ' 0001:00000038 00000010 C=CODE S=.text G=(none) M=%sVendored ALIGN=4', [ FTag ] ) + sLineBreak +
    ' 0001:00000040 00000010 C=CODE S=.text G=(none) M=App ALIGN=4' + sLineBreak );

  var Options := Default( TSBOMOptions );
  Options.ProjectFile := FScratch.PathOf( 'App\App.dpr' );
  Options.OutputDir   := FScratch.PathOf( 'App' );
  Options.MapFile     := MapFile;

  var Engine := TSBOMEngine.Create( NoLog() );
  try
    FResult := Engine.Execute( Options );
  finally
    Engine.Free;
  end;

end;

procedure TMapEngineTests.TearDownFixture;
begin

  FScratch.Free;

  if FComInitialised then
    CoUninitialize;

end;

function TMapEngineTests.HasUnit( const AUnitName: string ): Boolean;
begin

  for var CU in FResult.ClassifiedUnits do
    if SameText( CU.OriginalName, AUnitName ) then
      Exit( True );

  Result := False;

end;

procedure TMapEngineTests.IndirectlyUsedUnitIsClassified;
begin

  Assert.IsTrue( FResult.Success, 'Run failed: ' + FResult.ErrorMessage );
  Assert.IsTrue( HasUnit( FTag + 'Indirect' ), 'Indirectly used unit missing' );

  // Its source is in the project folder, so it is own code
  for var CU in FResult.ClassifiedUnits do
    if SameText( CU.OriginalName, FTag + 'Indirect' ) then
      Assert.AreEqual( Ord( ucOwnCode ), Ord( CU.Classification ), 'Indirect unit classification' );

end;

procedure TMapEngineTests.UnlinkedUsesUnitIsLeftOut;
begin

  Assert.IsTrue( HasUnit( FTag + 'Listed' ), 'Linked uses-clause unit missing' );
  Assert.IsFalse( HasUnit( FTag + 'Conditional' ), 'Unlinked uses-clause unit still listed' );

end;

procedure TMapEngineTests.ProgramIsNotAUnitAndSourceIsRecorded;
begin

  Assert.IsFalse( HasUnit( 'App' ), 'The program was listed as a unit' );
  Assert.AreEqual( 'MAP file App.map', FResult.UnitSource );

end;

procedure TMapEngineTests.ProjectSubfolderIsOwnCodeUnlessVendored;
begin

  for var CU in FResult.ClassifiedUnits do
    if SameText( CU.OriginalName, FTag + 'SubForm' ) then
      Assert.AreEqual( Ord( ucOwnCode ), Ord( CU.Classification ), 'Subfolder unit classification' );

  var Found := False;

  for var Lib in FResult.DiscoveredLibraries do
    for var U in Lib.Units do
    begin
      Assert.AreNotEqual( FTag + 'SubForm', U, 'Subfolder unit offered as a library' );

      if SameText( U, FTag + 'Vendored' ) then
      begin
        Found := True;
        Assert.AreEqual( 'MIT', Lib.Licence, 'Vendored library licence' );
      end;
    end;

  Assert.IsTrue( Found, 'Vendored library in a project subfolder not discovered' );

end;

end.
