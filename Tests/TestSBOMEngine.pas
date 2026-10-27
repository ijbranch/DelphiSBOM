(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSBOMEngine.pas — End-to-end tests of the pipeline through uSBOMEngine
*)
unit TestSBOMEngine;

interface

uses
  DUnitX.TestFramework,
  uTypes, TestSupport;

type
  /// <summary>
  ///   Runs the whole pipeline on a synthetic layout: Work\App (the project), Work\LibA (a licensed
  ///   library checked out beside it) and Work\Shared (the developer's own shared code, no licence).
  ///   Library discovery also searches the machine's common root folders; the unit names used here
  ///   are unique, so nothing found there can interfere.
  /// </summary>
  [TestFixture]
  TSBOMEngineTests = class
  private
    FScratch: TScratchDir;
    FComInitialised: Boolean;
    FResult: TSBOMResult;
    FManifestFile: string;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves the run succeeds and reports the manifest it used, which Save &amp; Regenerate and
    ///   Mark as Own Code must write to.
    /// </summary>
    [Test]
    procedure RunSucceedsAndReportsManifest;

    /// <summary>
    ///   Proves a licensed library beside the project is discovered as a third-party library with its
    ///   licence and vendor. The old sibling rule silently made it own code and removed it from the SBOM.
    /// </summary>
    [Test]
    procedure LicensedSiblingStaysThirdParty;

    /// <summary>
    ///   Proves an unlicensed sibling folder's unit is own code in the same run, and is saved to
    ///   own_code_units once the SBOM has been written.
    /// </summary>
    [Test]
    procedure UnlicensedSiblingIsOwnCodeAndSaved;

    /// <summary>
    ///   Proves the written SBOM carries the third-party component from the manifest with a name licence,
    ///   lower-cased type and encoded purl, and the RTL version mapped from ProjectVersion 20.4.
    /// </summary>
    [Test]
    procedure WrittenSBOMIsSchemaShaped;

    /// <summary>
    ///   Proves the post-write check runs on a normal run and finds nothing, and the version written
    ///   to the SBOM is recorded for the reports.
    /// </summary>
    [Test]
    procedure CleanRunPassesTheCheck;

    /// <summary>
    ///   Proves the requested reports are written beside the SBOM and describe this run.
    /// </summary>
    [Test]
    procedure ReportsAreWrittenBesideTheSBOM;
  end;

  /// <summary>
  ///   A run whose manifest has a row with no name, which the builder writes as an empty component name.
  /// </summary>
  [TestFixture]
  TSBOMEngineCheckTests = class
  private
    FScratch: TScratchDir;
    FComInitialised: Boolean;
    FResult: TSBOMResult;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves the check reports the invalid component in the written file, while the run still
    ///   succeeds and keeps the file so it can be inspected.
    /// </summary>
    [Test]
    procedure InvalidOutputIsReportedNotDiscarded;
  end;

  /// <summary>
  ///   Library uses read from source. Four manifest libraries are in the project: X (LibX, on the search path)
  ///   uses Y, the RTL, its own helper and a fifth manifest row that is not in the project; Y (LibY, on the search
  ///   path) uses nothing; D is compiled from LibD\Lib\Win64\Release, with its source under LibD\Source, and uses
  ///   Y; Z's source is in a folder the compiler does not search.
  /// </summary>
  [TestFixture]
  TSBOMEngineLibraryUsesTests = class
  private
    /// <summary>The fixture's folders: App, LibX, LibY, LibD and Elsewhere.</summary>
    FScratch: TScratchDir;
    /// <summary>True when SetupFixture initialised COM and TearDownFixture must uninitialise it.</summary>
    FComInitialised: Boolean;
    /// <summary>The result of the one engine run all tests read.</summary>
    FResult: TSBOMResult;
    /// <summary>Every line the run logged.</summary>
    FLog: string;
  public
    /// <summary>Writes the libraries, project and manifest, then runs the engine once.</summary>
    [SetupFixture]
    procedure SetupFixture;
    /// <summary>Uninitialises COM and removes the folders.</summary>
    [TearDownFixture]
    procedure TearDownFixture;

    /// <summary>
    ///   Proves the run records what X uses (the RTL, Y and the absent W, but not its own helper) and what D uses
    ///   (Y, read from the source under its DCU folder's library root), and nothing for Y or Z; that the written
    ///   SBOM gives X its own dependency entry naming the RTL and Y, W dropped; that Y (source read, no library
    ///   used) and Z (source not on the compiler's paths) have an empty entry, since every component must be in the
    ///   graph; that the result passes the post-write check; and that the log says how many sources were read.
    /// </summary>
    [Test]
    procedure LibraryUsesReachTheDependencyGraph;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, System.JSON, System.Generics.Collections, Winapi.ActiveX,
  uSBOMEngine, uManifestLoader, uTextFiles;

{ TSBOMEngineTests }

procedure TSBOMEngineTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );

  // Unique unit names so nothing elsewhere on the machine can be matched by discovery
  var Tag  := 'Dsbt' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );
  var Work := FScratch.PathOf( 'Work' );

  WriteUtf8File( TPath.Combine( Work, 'App\App.dpr' ),
    'program App;' + sLineBreak + 'uses' + sLineBreak +
    Format( '  System.SysUtils, %sLibMain, %sLibUtils, %sShared, TmsThing;', [ Tag, Tag, Tag ] ) + sLineBreak +
    'begin end.' );
  WriteUtf8File( TPath.Combine( Work, 'App\App.dproj' ),
    '<Project><PropertyGroup><ProjectVersion>20.4</ProjectVersion></PropertyGroup>' +
    '<PropertyGroup><DCC_UnitSearchPath>..\LibA;..\Shared</DCC_UnitSearchPath><VerInfo_MajorVer>3</VerInfo_MajorVer></PropertyGroup>' +
    '<ProjectExtensions><BorlandProject><Platforms><Platform value="Win64">True</Platform></Platforms></BorlandProject></ProjectExtensions></Project>' );

  WriteUtf8File( TPath.Combine( Work, 'LibA\' + Tag + 'LibMain.pas' ),
    '// Copyright (C) 2019-2024 Acme Widgets Ltd. All rights reserved.' + sLineBreak + 'unit ' + Tag + 'LibMain; interface implementation end.' );
  WriteUtf8File( TPath.Combine( Work, 'LibA\' + Tag + 'LibUtils.pas' ), 'unit ' + Tag + 'LibUtils; interface implementation end.' );
  WriteUtf8File( TPath.Combine( Work, 'LibA\LICENSE' ),
    'MIT License' + sLineBreak + 'Permission is hereby granted, free of charge, to any person obtaining a copy' );
  WriteUtf8File( TPath.Combine( Work, 'Shared\' + Tag + 'Shared.pas' ), 'unit ' + Tag + 'Shared; interface implementation end.' );

  FManifestFile := TPath.Combine( Work, 'App\components.json' );
  WriteUtf8File( FManifestFile,
    '{ "schema_version": "1.0", "last_updated": "2026-01-01", "supplier": { "name": "Me", "url": "https://example.com" }, ' +
    '"components": [ { "name": "TMS VCL UI Pack", "version": "13.0", "vendor": "TMS", "licence": "Proprietary", ' +
    '"type": "Library", "units_prefix": [ "TmsThing" ] } ] }' );

  var Options := Default( TSBOMOptions );
  Options.ProjectFile  := TPath.Combine( Work, 'App\App.dproj' );
  Options.ManifestFile := FManifestFile;
  Options.ReportFormats := [ rfMarkdown, rfHtml ];

  var Engine := TSBOMEngine.Create( NoLog() );
  try
    FResult := Engine.Execute( Options );
  finally
    Engine.Free;
  end;

end;

procedure TSBOMEngineTests.TearDownFixture;
begin

  if FComInitialised then
    CoUninitialize;

  FScratch.Free;

end;

procedure TSBOMEngineTests.RunSucceedsAndReportsManifest;
begin

  Assert.IsTrue( FResult.Success );
  Assert.AreEqual( FManifestFile, FResult.ManifestFile, False );

end;

procedure TSBOMEngineTests.LicensedSiblingStaysThirdParty;
begin

  Assert.AreEqual<NativeInt>( 1, Length( FResult.DiscoveredLibraries ) );
  Assert.AreEqual( 'LibA', FResult.DiscoveredLibraries[ 0 ].Name, False );
  Assert.AreEqual( 'MIT', FResult.DiscoveredLibraries[ 0 ].Licence, False );
  Assert.AreEqual( 'Acme Widgets Ltd', FResult.DiscoveredLibraries[ 0 ].Vendor, False );
  Assert.AreEqual<NativeInt>( 2, Length( FResult.DiscoveredLibraries[ 0 ].Units ) );

end;

procedure TSBOMEngineTests.UnlicensedSiblingIsOwnCodeAndSaved;
begin

  var SharedUnit := '';

  for var CU in FResult.ClassifiedUnits do
    if CU.OriginalName.EndsWith( 'Shared' ) then
    begin
      SharedUnit := CU.OriginalName;
      Assert.AreEqual<TUnitClassification>( ucOwnCode, CU.Classification, 'Reclassified in the same run' );
    end;

  Assert.AreNotEqual( '', SharedUnit, False, 'Shared unit was parsed' );

  var Loader := TManifestLoader.Create( NoLog() );
  try
    var Manifest := Loader.Load( FManifestFile );

    Assert.AreEqual<NativeInt>( 1, Length( Manifest.OwnCodeUnits ) );
    Assert.AreEqual( SharedUnit, Manifest.OwnCodeUnits[ 0 ], False );
    Assert.AreEqual<NativeInt>( 1, Length( Manifest.Components ), 'Existing component kept' );
  finally
    Loader.Free;
  end;

end;

procedure TSBOMEngineTests.WrittenSBOMIsSchemaShaped;
begin

  var Bytes := TFile.ReadAllBytes( FResult.OutputFile );

  Assert.AreEqual( Ord( '{' ), Integer( Bytes[ 0 ] ), 'No BOM' );

  var Root := TJSONObject.ParseJSONValue( TEncoding.UTF8.GetString( Bytes ) ) as TJSONObject;
  try
    var Components := Root.GetValue<TJSONArray>( 'components' );
    var Tms := Components.Items[ 1 ] as TJSONObject;

    Assert.AreEqual( '37.0', Components.Items[ 0 ].GetValue<string>( 'version' ), False );
    Assert.AreEqual( 'library', Tms.GetValue<string>( 'type' ), False );
    Assert.AreEqual( 'Proprietary', Tms.GetValue<string>( 'licenses[0].license.name' ), False );
    Assert.AreEqual( 'pkg:delphi/TMS%20VCL%20UI%20Pack@13.0', Tms.GetValue<string>( 'purl' ), False );
    Assert.AreEqual( '3.0.0.0', Root.GetValue<string>( 'metadata.component.version' ), False );
  finally
    Root.Free;
  end;

end;

procedure TSBOMEngineTests.CleanRunPassesTheCheck;
begin

  Assert.AreEqual<Integer>( 0, Length( FResult.ValidationErrors ), string.Join( ' / ', FResult.ValidationErrors ) );
  Assert.AreEqual( '3.0.0.0', FResult.ProductVersion );

end;

procedure TSBOMEngineTests.ReportsAreWrittenBesideTheSBOM;
begin

  Assert.AreEqual<Integer>( 2, Length( FResult.ReportFiles ) );

  for var F in FResult.ReportFiles do
  begin
    Assert.AreEqual( ExtractFilePath( FResult.OutputFile ), ExtractFilePath( F ), 'Report not beside the SBOM' );
    Assert.Contains( ReadTextFile( F ), 'TMS VCL UI Pack', 'Report does not describe the run: ' + F );
  end;

end;

{ TSBOMEngineCheckTests }

procedure TSBOMEngineCheckTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );

  var Tag := 'Dsbc' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  WriteUtf8File( FScratch.PathOf( 'App\App.dpr' ),
    'program App;' + sLineBreak + 'uses' + sLineBreak + '  ' + Tag + 'Thing;' + sLineBreak + 'begin end.' );
  WriteUtf8File( FScratch.PathOf( 'App\components.json' ),
    '{ "schema_version": "1.0", "components": [ { "name": "", "version": "1", "licence": "MIT", ' +
    '"units_exact": [ "' + Tag + 'Thing" ] } ] }' );

  var Options := Default( TSBOMOptions );
  Options.ProjectFile := FScratch.PathOf( 'App\App.dpr' );

  var Engine := TSBOMEngine.Create( NoLog() );
  try
    FResult := Engine.Execute( Options );
  finally
    Engine.Free;
  end;

end;

procedure TSBOMEngineCheckTests.TearDownFixture;
begin

  if FComInitialised then
    CoUninitialize;

  FScratch.Free;

end;

{ TSBOMEngineLibraryUsesTests }

procedure TSBOMEngineLibraryUsesTests.SetupFixture;
begin

  FScratch := TScratchDir.Create;
  FComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );

  // Unique unit names so nothing elsewhere on the machine can be matched
  var Tag := 'Dsbu' + Copy( StringReplace( TGUID.NewGuid.ToString, '-', '', [ rfReplaceAll ] ), 2, 8 );

  WriteUtf8File( FScratch.PathOf( 'App\App.dpr' ),
    'program App;' + sLineBreak + 'uses' + sLineBreak +
    Format( '  System.SysUtils, %0:sXMain, %0:sYCore, %0:sZOnly, %0:sDMain;', [ Tag ] ) + sLineBreak + 'begin end.' );
  WriteUtf8File( FScratch.PathOf( 'App\App.dproj' ),
    '<Project><PropertyGroup><ProjectVersion>20.4</ProjectVersion></PropertyGroup>' +
    '<PropertyGroup><DCC_UnitSearchPath>..\LibX;..\LibY;..\LibD\Lib\Win64\Release</DCC_UnitSearchPath></PropertyGroup>' +
    '<ProjectExtensions><BorlandProject><Platforms><Platform value="Win64">True</Platform></Platforms></BorlandProject></ProjectExtensions></Project>' );

  WriteUtf8File( FScratch.PathOf( 'LibX\' + Tag + 'XMain.pas' ),
    Format( 'unit %0:sXMain;' + sLineBreak + 'interface' + sLineBreak + 'uses System.SysUtils, %0:sYCore, %0:sWThing;' + sLineBreak +
    'implementation' + sLineBreak + 'uses %0:sXHelper;' + sLineBreak + 'end.', [ Tag ] ) );
  WriteUtf8File( FScratch.PathOf( 'LibY\' + Tag + 'YCore.pas' ), 'unit ' + Tag + 'YCore; interface implementation end.' );
  // D: only a .dcu where the compiler looks; its source is under the library root, above the build-output folders
  WriteUtf8File( FScratch.PathOf( 'LibD\Lib\Win64\Release\' + Tag + 'DMain.dcu' ), 'not a real dcu' );
  WriteUtf8File( FScratch.PathOf( 'LibD\Source\' + Tag + 'DMain.pas' ),
    Format( 'unit %0:sDMain; interface uses %0:sYCore; implementation end.', [ Tag ] ) );
  WriteUtf8File( FScratch.PathOf( 'Elsewhere\' + Tag + 'ZOnly.pas' ),
    Format( 'unit %0:sZOnly; interface uses %0:sYCore; implementation end.', [ Tag ] ) );

  var Rows := '';

  for var Lib in [ 'X', 'Y', 'Z', 'W', 'D' ] do
  begin
    if Rows <> '' then
      Rows := Rows + ', ';

    Rows := Rows + Format( '{ "name": "Lib %0:s", "version": "1", "vendor": "Acme", "licence": "MIT", "units_prefix": [ "%1:s%0:s" ] }',
      [ Lib, Tag ] );
  end;

  WriteUtf8File( FScratch.PathOf( 'App\components.json' ), '{ "schema_version": "1.0", "components": [ ' + Rows + ' ] }' );

  var Options := Default( TSBOMOptions );
  Options.ProjectFile := FScratch.PathOf( 'App\App.dproj' );

  var Engine := TSBOMEngine.Create(
    procedure( ALevel: TLogLevel; AMessage: string )
    begin
      FLog := FLog + AMessage + sLineBreak;
    end );
  try
    FResult := Engine.Execute( Options );
  finally
    Engine.Free;
  end;

end;

procedure TSBOMEngineLibraryUsesTests.TearDownFixture;
begin

  if FComInitialised then
    CoUninitialize;

  FScratch.Free;

end;

procedure TSBOMEngineLibraryUsesTests.LibraryUsesReachTheDependencyGraph;
begin

  Assert.IsTrue( FResult.Success, 'Run failed: ' + FResult.ErrorMessage );
  Assert.AreEqual<Integer>( 0, Length( FResult.ValidationErrors ), string.Join( ' / ', FResult.ValidationErrors ) );
  Assert.Contains( FLog, 'read the source of 3 of 4 third-party units' );

  // The run's own records, in project order: X (row 0) uses the RTL, Y (row 1) and W (row 3, dropped by the
  // builder), never itself; D (row 4) uses Y. Y used nothing, so it has no record
  var Records := '';

  for var Dependency in FResult.LibraryDependencies do
  begin
    Records := Records + IntToStr( Dependency.ComponentIndex ) + ':';

    for var T in Dependency.DependsOn do
      Records := Records + ' ' + IntToStr( T );

    Records := Records + '; ';
  end;

  Assert.AreEqual( '0: -1 1 3; 4: 1; ', Records );

  var Root := TJSONObject.ParseJSONValue( ReadTextFile( FResult.OutputFile ) ) as TJSONObject;
  try
    // bom-ref by component name
    var Refs := TDictionary<string, string>.Create;
    try
      for var C in Root.GetValue<TJSONArray>( 'components' ) do
        Refs.Add( C.GetValue<string>( 'name' ), C.GetValue<string>( 'bom-ref' ) );

      Assert.IsFalse( Refs.ContainsKey( 'Lib W' ), 'Test data: Lib W must not be in the SBOM' );

      var AppRef := Root.GetValue<string>( 'metadata.component.bom-ref' );
      var XDependsOn := '';
      var DDependsOn := '';

      for var D in Root.GetValue<TJSONArray>( 'dependencies' ) do
      begin
        var Ref := D.GetValue<string>( 'ref' );

        if Ref = Refs[ 'Lib X' ] then
        begin
          for var Target in D.GetValue<TJSONArray>( 'dependsOn' ) do
            XDependsOn := XDependsOn + Target.Value + ' ';
        end
        else if Ref = Refs[ 'Lib D' ] then
        begin
          for var Target in D.GetValue<TJSONArray>( 'dependsOn' ) do
            DDependsOn := DDependsOn + Target.Value + ' ';
        end
        else if ( Ref = Refs[ 'Lib Y' ] ) or ( Ref = Refs[ 'Lib Z' ] ) then
          Assert.AreEqual<Integer>( 0, D.GetValue<TJSONArray>( 'dependsOn' ).Count, Ref + ': nothing is known of its uses' )
        else if ( Ref <> AppRef ) and ( Ref <> Refs[ 'Embarcadero Delphi RTL' ] ) then
          Assert.Fail( 'Unexpected dependency entry for ' + Ref );
      end;

      Assert.AreEqual( Refs[ 'Embarcadero Delphi RTL' ] + ' ' + Refs[ 'Lib Y' ] + ' ', XDependsOn, 'In uses-clause order: the RTL, then Lib Y' );
      Assert.AreEqual( Refs[ 'Lib Y' ] + ' ', DDependsOn, 'Lib D, read from the source under its DCU folder''s library root' );
    finally
      Refs.Free;
    end;
  finally
    Root.Free;
  end;

end;

procedure TSBOMEngineCheckTests.InvalidOutputIsReportedNotDiscarded;
begin

  Assert.IsTrue( FResult.Success, 'Run failed: ' + FResult.ErrorMessage );
  Assert.IsTrue( FileExists( FResult.OutputFile ), 'SBOM discarded' );
  Assert.AreEqual<Integer>( 1, Length( FResult.ValidationErrors ), string.Join( ' / ', FResult.ValidationErrors ) );
  Assert.Contains( FResult.ValidationErrors[ 0 ], 'components[1].name' );

end;

end.
