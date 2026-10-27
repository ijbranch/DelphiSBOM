(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestProjectParser.pas — Tests for uProjectParser (.dpr/.dpk unit lists and .dproj evaluation)
*)
unit TestProjectParser;

interface

uses
  DUnitX.TestFramework,
  TestSupport;

type
  /// <summary>
  ///   ProjectVersion mapping, uses/contains clause parsing, and MSBuild-style .dproj evaluation.
  /// </summary>
  [TestFixture]
  TProjectParserTests = class
  private
    FScratch: TScratchDir;
    FComInitialised: Boolean;

    procedure WriteDproj( const AFileName: string );
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves each ProjectVersion range maps to the BDS version of the IDE that writes it. The old
    ///   map reported every 20.x project (Delphi 12 included) as Delphi 13 and every 19.x as Delphi 12.
    /// </summary>
    /// <param name="AProjectVersion">.dproj ProjectVersion value.</param>
    /// <param name="AExpected">Expected BDS version ('' for unknown).</param>
    [Test]
    [TestCase( 'D13 20.4', '20.4,37.0' )]
    [TestCase( 'D13 20.6', '20.6,37.0' )]
    [TestCase( 'D12 20.3', '20.3,23.0' )]
    [TestCase( 'D12 20.1', '20.1,23.0' )]
    [TestCase( 'D11 19.5', '19.5,22.0' )]
    [TestCase( 'D11 19.3', '19.3,22.0' )]
    [TestCase( '10.4 19.0', '19.0,21.0' )]
    [TestCase( '10.3 18.8', '18.8,20.0' )]
    [TestCase( '10.2 18.3', '18.3,19.0' )]
    procedure ProjectVersionMapsToBDSVersion( const AProjectVersion, AExpected: string );

    /// <summary>
    ///   Proves an unrecognised ProjectVersion maps to '' (reported as "unknown"), not echoed back as if it
    ///   were a Delphi version — the old map returned the input unchanged.
    /// </summary>
    [Test]
    procedure UnknownProjectVersionIsEmpty;

    /// <summary>
    ///   Proves an ANSI .dpr with a non-ASCII byte in a comment still yields its unit list
    ///   (it used to decode to an empty string, giving "No uses clause found").
    /// </summary>
    [Test]
    procedure AnsiDprParsed;

    /// <summary>
    ///   Proves in-file references are recognised whatever the layout — a newline and a tab before
    ///   'in', and no space between 'in' and the quote — and that a unit whose name ends in "in"
    ///   (Login) is not mistaken for one.
    /// </summary>
    [Test]
    procedure InReferencesDetectedAcrossLayouts;

    /// <summary>
    ///   Proves a comma inside a quoted in-file path does not split the entry in two.
    /// </summary>
    [Test]
    procedure CommaInsideQuotedPathKeepsEntryWhole;

    /// <summary>
    ///   Proves the target platform comes from the active platforms in ProjectExtensions (Win64 preferred),
    ///   not from the Win32 command-line default in the first PropertyGroup.
    /// </summary>
    [Test]
    procedure PlatformFromActivePlatforms;

    /// <summary>
    ///   Proves PropertyGroup Conditions are evaluated for Release on the target platform: the build number
    ///   comes from the Release|Win64 group, not the Base group, and a group whose Exists() is false is skipped.
    /// </summary>
    [Test]
    procedure VersionFromReleasePlatformGroup;

    /// <summary>
    ///   Proves DCC_UnitSearchPath is accumulated across groups with $(Platform)/$(Config) expanded,
    ///   the self-reference removed, and $(BDS) kept for library discovery to expand.
    /// </summary>
    [Test]
    procedure SearchPathsEvaluated;

    /// <summary>
    ///   Proves a .dproj whose MainSource is a .dpk is parsed through the package's contains clause,
    ///   with the contained units recorded as in-file units.
    /// </summary>
    [Test]
    procedure MainSourcePackageParsed;

    /// <summary>
    ///   Proves the binary of a Release build is located the way the compiler names it: DCC_ExeOutput with the
    ///   platform and configuration expanded, the main source's name, and the extension of the AppType (a library
    ///   is a .dll, a package a .bpl with its DllSuffix); no output folder means the project folder; and a package
    ///   left on the IDE's default folder, which a macro names, gives '' instead of a guessed path.
    /// </summary>
    /// <param name="AAppType">The .dproj's AppType.</param>
    /// <param name="AMainSource">The .dproj's MainSource.</param>
    /// <param name="AOutputXml">The output-folder and suffix elements of the .dproj.</param>
    /// <param name="AExpected">The expected path relative to the project folder, or '' for none.</param>
    [Test]
    [TestCase( 'application', 'Application|App.dpr|<DCC_ExeOutput>.\$(Platform)\$(Config)</DCC_ExeOutput>|Win64\Release\App.exe', '|' )]
    [TestCase( 'library', 'Library|Lib.dpr|<DCC_ExeOutput>..\Bin</DCC_ExeOutput>|..\Bin\Lib.dll', '|' )]
    [TestCase( 'no output folder', 'Console|Tool.dpr||Tool.exe', '|' )]
    [TestCase( 'package with suffix', 'Package|Pkg.dpk|<DCC_BplOutput>.\Bpl</DCC_BplOutput><DllSuffix>370</DllSuffix>|Bpl\Pkg370.bpl', '|' )]
    [TestCase( 'package on the IDE default', 'Package|Pkg.dpk||', '|' )]
    [TestCase( 'suffix macro', 'Package|Pkg.dpk|<DCC_BplOutput>.\Bpl</DCC_BplOutput><DllSuffix>$(Auto)</DllSuffix>|', '|' )]
    [TestCase( 'library with affixes', 'Library|Lib.dpr|<DCC_ExeOutput>Bin</DCC_ExeOutput><DllPrefix>pre</DllPrefix>' +
      '<DllSuffix>370</DllSuffix>|Bin\preLib370.dll', '|' )]
    [TestCase( 'unknown macro', 'Application|App.dpr|<DCC_ExeOutput>$(NoSuchDsblMacro)\Bin</DCC_ExeOutput>|', '|' )]
    procedure BinaryFileOfReleaseBuild( const AAppType, AMainSource, AOutputXml, AExpected: string );

    /// <summary>
    ///   Proves the output folder is the one of the Release build, not of another configuration, and that a {$E}
    ///   directive in the main source sets the extension (a control panel applet is a .cpl), even when the directive
    ///   sits among other directives.
    /// </summary>
    [Test]
    procedure BinaryFileFollowsReleaseAndExtensionDirective;

    /// <summary>
    ///   Proves ExtractUsedUnits reads both uses clauses of a unit, in order and each unit once, while a unit
    ///   named only in a comment, the word 'uses' in a string or a comment, and an 'in' file reference add nothing.
    /// </summary>
    [Test]
    procedure UsedUnitsComeFromEveryUsesClause;
  end;

implementation

uses
  System.SysUtils, Winapi.ActiveX,
  uTypes, uProjectParser;

{ TProjectParserTests }

procedure TProjectParserTests.Setup;
begin

  FScratch := TScratchDir.Create;

  // The .dproj is read with TXMLDocument (MSXML, COM)
  FComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );

end;

procedure TProjectParserTests.TearDown;
begin

  if FComInitialised then
    CoUninitialize;

  FScratch.Free;

end;

procedure TProjectParserTests.WriteDproj( const AFileName: string );
begin

  // Base + Release (Cfg_2) + Release|Win64 groups, as the IDE writes them, plus a group that must be skipped
  WriteUtf8File( AFileName,
    '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">' +
    '<PropertyGroup><ProjectVersion>20.3</ProjectVersion><MainSource>Pkg.dpk</MainSource>' +
    '<Config Condition="''$(Config)''==''''">Debug</Config><Platform Condition="''$(Platform)''==''''">Win32</Platform></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Config)''==''Base'' or ''$(Base)''!=''''"><Base>true</Base></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Config)''==''Release'' or ''$(Cfg_2)''!=''''"><Cfg_2>true</Cfg_2><Base>true</Base></PropertyGroup>' +
    '<PropertyGroup Condition="(''$(Platform)''==''Win64'' and ''$(Cfg_2)''==''true'') or ''$(Cfg_2_Win64)''!=''''">' +
    '<Cfg_2_Win64>true</Cfg_2_Win64></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Base)''!=''''"><VerInfo_MajorVer>2</VerInfo_MajorVer><VerInfo_Build>1</VerInfo_Build>' +
    '<DCC_UnitSearchPath>..\Lib;$(BDS)\source;$(DCC_UnitSearchPath)</DCC_UnitSearchPath></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Cfg_2_Win64)''!=''''"><VerInfo_Build>77</VerInfo_Build>' +
    '<DCC_UnitSearchPath>..\Lib\$(Platform)\$(Config);$(DCC_UnitSearchPath)</DCC_UnitSearchPath></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Cfg_2)''!='''' and Exists(''C:\definitely\not\here'')"><VerInfo_Build>999</VerInfo_Build></PropertyGroup>' +
    '<ProjectExtensions><BorlandProject><Platforms><Platform value="Win32">True</Platform>' +
    '<Platform value="Win64">True</Platform></Platforms></BorlandProject></ProjectExtensions>' +
    '</Project>' );

  WriteUtf8File( ExtractFilePath( AFileName ) + 'Pkg.dpk',
    'package Pkg;' + sLineBreak + 'requires rtl;' + sLineBreak + 'contains' + sLineBreak +
    '  PkgUnitA in ''PkgUnitA.pas'',' + sLineBreak + '  PkgUnitB in ''PkgUnitB.pas'';' + sLineBreak + 'end.' );

end;

procedure TProjectParserTests.ProjectVersionMapsToBDSVersion( const AProjectVersion, AExpected: string );
begin

  Assert.AreEqual( AExpected, MapProjectVersionToBDSVersion( AProjectVersion ), False );

end;

procedure TProjectParserTests.UnknownProjectVersionIsEmpty;
begin

  Assert.AreEqual( '', MapProjectVersionToBDSVersion( 'abc' ), False );
  Assert.AreEqual( '', MapProjectVersionToBDSVersion( '15.1' ), False );

end;

procedure TProjectParserTests.AnsiDprParsed;
begin

  var Dpr := FScratch.PathOf( 'AnsiApp.dpr' );
  WriteAnsiFile( Dpr,
    'program AnsiApp;' + sLineBreak +
    '// Autor: M' + #$00FC + 'ller ' + #$00A9 + sLineBreak +
    'uses' + sLineBreak + '  Vcl.Forms, UnitA, UnitB;' + sLineBreak +
    'begin end.' );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dpr );

    Assert.AreEqual<NativeInt>( 3, Length( Info.Units ) );
    Assert.AreEqual( 'UnitB', Info.Units[ 2 ], False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.InReferencesDetectedAcrossLayouts;
begin

  var Dpr := FScratch.PathOf( 'Layout.dpr' );
  WriteUtf8File( Dpr,
    'program Layout;' + sLineBreak +
    'uses' + sLineBreak +
    '  Vcl.Forms,' + sLineBreak +
    '  Unit1' + sLineBreak + #9 + 'in ''Unit1.pas'',' + sLineBreak +
    '  Unit2 in''Sub\Unit2.pas'' {Form2},' + sLineBreak +
    '  Login;' + sLineBreak +
    'begin end.' );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dpr );

    Assert.AreEqual<NativeInt>( 4, Length( Info.Units ), 'All four entries are units' );
    Assert.AreEqual( 'Login', Info.Units[ 3 ], False );
    Assert.AreEqual<NativeInt>( 2, Length( Info.OwnCodeUnits ), 'Unit1 and Unit2 have in-file references' );
    Assert.AreEqual( 'Unit1', Info.OwnCodeUnits[ 0 ], False );
    Assert.AreEqual( 'Unit2', Info.OwnCodeUnits[ 1 ], False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.CommaInsideQuotedPathKeepsEntryWhole;
begin

  var Dpr := FScratch.PathOf( 'Comma.dpr' );
  WriteUtf8File( Dpr,
    'program Comma;' + sLineBreak +
    'uses' + sLineBreak + '  First in ''a,b\First.pas'', Second;' + sLineBreak +
    'begin end.' );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dpr );

    Assert.AreEqual<NativeInt>( 2, Length( Info.Units ) );
    Assert.AreEqual( 'First', Info.Units[ 0 ], False );
    Assert.AreEqual( 'Second', Info.Units[ 1 ], False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.PlatformFromActivePlatforms;
begin

  var Dproj := FScratch.PathOf( 'Pkg.dproj' );
  WriteDproj( Dproj );

  var Parser := TProjectParser.Create( NoLog() );
  try
    Assert.AreEqual( 'Win64', Parser.Parse( Dproj ).TargetPlatform, False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.VersionFromReleasePlatformGroup;
begin

  var Dproj := FScratch.PathOf( 'Pkg.dproj' );
  WriteDproj( Dproj );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dproj );

    Assert.AreEqual( '2.0.0.77', Info.ProjectVersion, False );
    Assert.AreEqual( '23.0', Info.DelphiVersion, False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.SearchPathsEvaluated;
begin

  var Dproj := FScratch.PathOf( 'Pkg.dproj' );
  WriteDproj( Dproj );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dproj );

    Assert.AreEqual<NativeInt>( 3, Length( Info.SearchPaths ), string.Join( ';', Info.SearchPaths ) );
    Assert.AreEqual( '..\Lib\Win64\Release', Info.SearchPaths[ 0 ], False );
    Assert.AreEqual( '..\Lib', Info.SearchPaths[ 1 ], False );
    Assert.AreEqual( '$(BDS)\source', Info.SearchPaths[ 2 ], False );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.MainSourcePackageParsed;
begin

  var Dproj := FScratch.PathOf( 'Pkg.dproj' );
  WriteDproj( Dproj );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Info := Parser.Parse( Dproj );

    Assert.AreEqual<NativeInt>( 2, Length( Info.Units ) );
    Assert.AreEqual( 'PkgUnitA', Info.Units[ 0 ], False );
    Assert.AreEqual<NativeInt>( 2, Length( Info.OwnCodeUnits ) );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.BinaryFileOfReleaseBuild( const AAppType, AMainSource, AOutputXml, AExpected: string );
begin

  var Dproj := FScratch.PathOf( 'Bin.dproj' );
  WriteUtf8File( Dproj,
    '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">' +
    '<PropertyGroup><ProjectVersion>20.3</ProjectVersion><MainSource>' + AMainSource + '</MainSource>' +
    '<AppType>' + AAppType + '</AppType>' + AOutputXml + '</PropertyGroup>' +
    '<ProjectExtensions><BorlandProject><Platforms><Platform value="Win64">True</Platform></Platforms></BorlandProject>' +
    '</ProjectExtensions></Project>' );

  var Parser := TProjectParser.Create( NoLog() );
  try
    var Expected := '';

    if AExpected <> '' then
      Expected := ExpandFileName( FScratch.PathOf( AExpected ) );

    Assert.AreEqual( Expected, Parser.Parse( Dproj ).BinaryFile );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.BinaryFileFollowsReleaseAndExtensionDirective;
begin

  var Dproj := FScratch.PathOf( 'Applet.dproj' );
  WriteUtf8File( Dproj,
    '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">' +
    '<PropertyGroup><ProjectVersion>20.3</ProjectVersion><MainSource>Applet.dpr</MainSource><AppType>Library</AppType>' +
    '<Config Condition="''$(Config)''==''''">Debug</Config></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Config)''==''Debug''"><DCC_ExeOutput>DebugOut</DCC_ExeOutput></PropertyGroup>' +
    '<PropertyGroup Condition="''$(Config)''==''Release''"><DCC_ExeOutput>ReleaseOut</DCC_ExeOutput></PropertyGroup>' +
    '<ProjectExtensions><BorlandProject><Platforms><Platform value="Win64">True</Platform></Platforms></BorlandProject>' +
    '</ProjectExtensions></Project>' );
  WriteUtf8File( FScratch.PathOf( 'Applet.dpr' ),
    'library Applet;' + sLineBreak + '{$R *.res}' + sLineBreak + '{$E cpl}' + sLineBreak + 'uses' + sLineBreak + '  Unit1;' + sLineBreak +
    'begin end.' );

  var Parser := TProjectParser.Create( NoLog() );
  try
    Assert.AreEqual( ExpandFileName( FScratch.PathOf( 'ReleaseOut\Applet.cpl' ) ), Parser.Parse( Dproj ).BinaryFile );
  finally
    Parser.Free;
  end;

end;

procedure TProjectParserTests.UsedUnitsComeFromEveryUsesClause;
begin

  var Source := string.Join( sLineBreak, [
    'unit Widgets;',
    '// uses Commented;',
    'interface',
    'uses',
    '  System.SysUtils, {Braced,} OtlTask (* Starred, *),',
    '  Vendored in ''..\Vendor\Vendored.pas'';',
    'const Label = ''this unit uses Fake; not really'';',
    'implementation',
    'uses OtlTask, Winapi.Windows;',
    'end.' ] );

  var Units := ExtractUsedUnits( Source );

  Assert.AreEqual( 'System.SysUtils,OtlTask,Vendored,Winapi.Windows', string.Join( ',', Units ) );

end;

end.
