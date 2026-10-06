(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestReportWriter.pas — Tests for the Markdown and HTML reports
*)
unit TestReportWriter;

interface

uses
  DUnitX.TestFramework,
  uTypes, TestSupport;

type
  /// <summary>
  ///   The reports' content and escaping, from a hand-built run result.
  /// </summary>
  [TestFixture]
  TReportWriterTests = class
  private
    FResult: TSBOMResult;
  public
    [Setup]
    procedure Setup;

    /// <summary>
    ///   Proves the Markdown report lists each component used, with its version, supplier, licence
    ///   and unit count, and the units under it.
    /// </summary>
    [Test]
    procedure MarkdownListsComponentsAndTheirUnits;

    /// <summary>
    ///   Proves the summary counts, the unit source and the version written to the SBOM appear.
    /// </summary>
    [Test]
    procedure MarkdownShowsSummaryAndRunDetails;

    /// <summary>
    ///   Proves unclassified units and the libraries discovered for them are reported, a DCU-only
    ///   library marked as such, so the reader knows what is still missing from the SBOM.
    /// </summary>
    [Test]
    procedure MarkdownReportsWhatIsStillUnclassified;

    /// <summary>
    ///   Proves a pipe in a value is escaped, so it cannot split a Markdown table cell.
    /// </summary>
    [Test]
    procedure MarkdownEscapesTableCells;

    /// <summary>
    ///   Proves SBOM check problems are listed, and a clean run says the check passed.
    /// </summary>
    [Test]
    procedure CheckResultIsReported;

    /// <summary>
    ///   Proves the HTML report escapes markup in values (a component named "&lt;b&gt;" is shown,
    ///   not rendered) and is a complete document.
    /// </summary>
    [Test]
    procedure HtmlEscapesValuesAndIsComplete;

    /// <summary>
    ///   Proves WriteReports writes exactly the formats asked for beside the SBOM, without a BOM.
    /// </summary>
    [Test]
    procedure WriteReportsWritesRequestedFormats;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, System.Classes,
  uReportWriter;

{ TReportWriterTests }

procedure TReportWriterTests.Setup;
begin

  FResult := Default( TSBOMResult );
  FResult.Success := True;
  FResult.OutputFile := 'C:\Out\App.cdx.json';
  FResult.ProductVersion := '4.0.0.69';
  FResult.UnitSource := 'MAP file App.map';
  FResult.ProjectInfo.ProjectName := 'App';
  FResult.ProjectInfo.DelphiVersion := '37.0';
  FResult.ProjectInfo.TargetPlatform := 'Win64';

  SetLength( FResult.Manifest.Components, 2 );
  FResult.Manifest.Components[ 0 ].Name := 'Acme Widgets';
  FResult.Manifest.Components[ 0 ].Version := '2.1';
  FResult.Manifest.Components[ 0 ].Vendor := 'Acme Ltd';
  FResult.Manifest.Components[ 0 ].Licence := 'MIT';
  FResult.Manifest.Components[ 1 ].Name := 'Unused';

  SetLength( FResult.ClassifiedUnits, 5 );
  FResult.ClassifiedUnits[ 0 ].OriginalName := 'AcmeGrid';
  FResult.ClassifiedUnits[ 0 ].Classification := ucThirdParty;
  FResult.ClassifiedUnits[ 0 ].ComponentIndex := 0;
  FResult.ClassifiedUnits[ 1 ].OriginalName := 'AcmeChart';
  FResult.ClassifiedUnits[ 1 ].Classification := ucThirdParty;
  FResult.ClassifiedUnits[ 1 ].ComponentIndex := 0;
  FResult.ClassifiedUnits[ 2 ].OriginalName := 'System.SysUtils';
  FResult.ClassifiedUnits[ 2 ].Classification := ucRTL;
  FResult.ClassifiedUnits[ 2 ].ComponentIndex := -1;
  FResult.ClassifiedUnits[ 3 ].OriginalName := 'MainForm';
  FResult.ClassifiedUnits[ 3 ].Classification := ucOwnCode;
  FResult.ClassifiedUnits[ 3 ].ComponentIndex := -1;
  FResult.ClassifiedUnits[ 4 ].OriginalName := 'FastThing';
  FResult.ClassifiedUnits[ 4 ].Classification := ucUnclassified;
  FResult.ClassifiedUnits[ 4 ].ComponentIndex := -1;

  FResult.Summary.ThirdPartyCount := 2;
  FResult.Summary.RTLCount := 1;
  FResult.Summary.OwnCodeCount := 1;
  FResult.Summary.UnclassifiedCount := 1;

  SetLength( FResult.DiscoveredLibraries, 1 );
  FResult.DiscoveredLibraries[ 0 ].Name := 'FastThing';
  FResult.DiscoveredLibraries[ 0 ].Directory := 'D:\FastThing';
  FResult.DiscoveredLibraries[ 0 ].Licence := 'MPL-1.1';
  FResult.DiscoveredLibraries[ 0 ].Units := [ 'FastThing' ];
  FResult.DiscoveredLibraries[ 0 ].BinaryOnly := True;

end;

procedure TReportWriterTests.MarkdownListsComponentsAndTheirUnits;
begin

  var Md := BuildMarkdownReport( FResult );
  Assert.Contains( Md, '| Acme Widgets | 2.1 | Acme Ltd | MIT | 2 |' );
  Assert.Contains( Md, 'AcmeChart' );
  Assert.Contains( Md, 'AcmeGrid' );
  Assert.IsFalse( Md.Contains( 'Unused' ), 'A manifest component no unit uses was reported' );

end;

procedure TReportWriterTests.MarkdownShowsSummaryAndRunDetails;
begin

  var Md := BuildMarkdownReport( FResult );
  Assert.Contains( Md, '# App 4.0.0.69' );
  Assert.Contains( Md, 'MAP file App.map' );
  Assert.Contains( Md, 'App.cdx.json' );
  Assert.Contains( Md, '| Third-Party | 2 |' );
  Assert.Contains( Md, '| Unclassified | 1 |' );

end;

procedure TReportWriterTests.MarkdownReportsWhatIsStillUnclassified;
begin

  var Md := BuildMarkdownReport( FResult );
  Assert.Contains( Md, 'FastThing' );
  Assert.Contains( Md, '| FastThing | D:\FastThing | MPL-1.1 |' );
  Assert.Contains( Md, 'DCU only' );

end;

procedure TReportWriterTests.MarkdownEscapesTableCells;
begin

  FResult.Manifest.Components[ 0 ].Name := 'Acme | Widgets';

  Assert.Contains( BuildMarkdownReport( FResult ), '| Acme \| Widgets |' );

end;

procedure TReportWriterTests.CheckResultIsReported;
begin

  Assert.Contains( BuildMarkdownReport( FResult ), 'Passed' );

  FResult.ValidationErrors := [ 'components[1].purl: "file:x" is not a package URL' ];
  var Md := BuildMarkdownReport( FResult );
  Assert.Contains( Md, '1 problem' );
  Assert.Contains( Md, 'components[1].purl' );

end;

procedure TReportWriterTests.HtmlEscapesValuesAndIsComplete;
begin

  FResult.Manifest.Components[ 0 ].Name := '<b>Acme</b> & Co';

  var Html := BuildHtmlReport( FResult );
  Assert.IsTrue( Html.StartsWith( '<!DOCTYPE html>' ), 'Not a complete document' );
  Assert.Contains( Html, '</html>' );
  Assert.Contains( Html, '&lt;b&gt;Acme&lt;/b&gt; &amp; Co' );
  Assert.IsFalse( Html.Contains( '<b>Acme' ), 'Markup in a value was not escaped' );

end;

procedure TReportWriterTests.WriteReportsWritesRequestedFormats;
begin

  var Scratch := TScratchDir.Create;
  try
    FResult.OutputFile := Scratch.PathOf( 'App.cdx.json' );

    var Written := WriteReports( FResult, [ rfHtml ] );
    Assert.AreEqual<Integer>( 1, Length( Written ) );
    Assert.AreEqual( Scratch.PathOf( 'App.sbom-report.html' ), Written[ 0 ] );
    Assert.IsTrue( FileExists( Written[ 0 ] ), 'HTML report missing' );
    Assert.IsFalse( FileExists( Scratch.PathOf( 'App.sbom-report.md' ) ), 'Markdown report written although not asked for' );

    var Bytes := TFile.ReadAllBytes( Written[ 0 ] );
    Assert.IsFalse( ( Length( Bytes ) >= 3 ) and ( Bytes[ 0 ] = $EF ) and ( Bytes[ 1 ] = $BB ) and ( Bytes[ 2 ] = $BF ), 'Report has a BOM' );

    Assert.AreEqual<Integer>( 2, Length( WriteReports( FResult, [ rfMarkdown, rfHtml ] ) ) );
    Assert.AreEqual<Integer>( 0, Length( WriteReports( FResult, [] ) ) );
  finally
    Scratch.Free;
  end;

end;

end.
