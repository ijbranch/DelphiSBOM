(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uReportWriter.pas — Human-readable Markdown and HTML companions to the SBOM
  Idea after DX.Comply's report writers (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uReportWriter;

interface

uses
  System.SysUtils,
  uTypes;

/// <summary>
///   Builds the Markdown report of a successful run: run details, classification summary,
///   components with supplier and licence, the units of each, own code, unclassified units with the
///   libraries discovered for them, and any problems the SBOM check found.
/// </summary>
/// <param name="AResult">The run's results.</param>
/// <returns>The report text (GitHub-flavoured Markdown).</returns>
function BuildMarkdownReport( const AResult: TSBOMResult ): string;

/// <summary>
///   Builds the same report as a self-contained HTML page (inline styles, no scripts).
/// </summary>
/// <param name="AResult">The run's results.</param>
/// <returns>The HTML document.</returns>
function BuildHtmlReport( const AResult: TSBOMResult ): string;

/// <summary>
///   Writes the requested reports beside the SBOM as &lt;Project&gt;.sbom-report.md / .html, UTF-8
///   without a BOM, each atomically.
/// </summary>
/// <param name="AResult">The run's results; OutputFile names the SBOM written.</param>
/// <param name="AFormats">The reports to write.</param>
/// <returns>The paths written.</returns>
/// <exception cref="Exception">A report cannot be written.</exception>
function WriteReports( const AResult: TSBOMResult; AFormats: TReportFormats ): TArray<string>;

implementation

uses
  System.Classes, System.Generics.Collections, System.Generics.Defaults, System.StrUtils, System.DateUtils,
  uTextFiles;

type
  /// <summary>The kinds of block a report is made of.</summary>
  TBlockKind = ( bkHeading, bkParagraph, bkList, bkTable );

  /// <summary>One block of a report, rendered the same way in every format.</summary>
  TBlock = record
    Kind: TBlockKind;
    Level: Integer; // Heading level, 1..3
    Text: string; // Heading or paragraph text
    Items: TArray<string>; // List items
    Headers: TArray<string>; // Table header cells
    Rows: TArray<TArray<string>>; // Table body rows
  end;

/// <summary>An empty value shown as a dash, so a table cell is never blank.</summary>
function Cell( const AValue: string ): string;
begin

  if Trim( AValue ) = '' then
    Result          := '-'
  else
    Result          := AValue;

end;

/// <summary>The report's content, independent of format.</summary>
function BuildBlocks( const AResult: TSBOMResult ): TArray<TBlock>;
begin

  var Blocks        := TList<TBlock>.Create;
  try
    var AddHeading  :=
      procedure( ALevel: Integer; const AText: string )
      begin
        var B       := Default( TBlock );
        B.Kind      := bkHeading;
        B.Level     := ALevel;
        B.Text      := AText;
        Blocks.Add( B );
      end;

    var AddParagraph :=
      procedure( const AText: string )
      begin
        var B       := Default( TBlock );
        B.Kind      := bkParagraph;
        B.Text      := AText;
        Blocks.Add( B );
      end;

    var AddList     :=
      procedure( const AItems: TArray<string> )
      begin
        var B       := Default( TBlock );
        B.Kind      := bkList;
        B.Items     := AItems;
        Blocks.Add( B );
      end;

    var AddTable    :=
      procedure( const AHeaders: TArray<string>; const ARows: TArray<TArray<string>> )
      begin
        var B       := Default( TBlock );
        B.Kind      := bkTable;
        B.Headers   := AHeaders;
        B.Rows      := ARows;
        Blocks.Add( B );
      end;

    // Units of one classification (or of one component), sorted
    var UnitsOf     :=
      function( AClassification: TUnitClassification; AComponentIndex: Integer ): TArray<string>
      begin
        var Names   := TList<string>.Create;
        try
          for var CU in AResult.ClassifiedUnits do
            if ( CU.Classification = AClassification ) and
              ( ( AComponentIndex < 0 ) or ( CU.ComponentIndex = AComponentIndex ) ) then
              Names.Add( CU.OriginalName );

          Names.Sort( TIStringComparer.Ordinal );
          Result    := Names.ToArray;
        finally
          Names.Free;
        end;
      end;

    var ProjectName := AResult.ProjectInfo.ProjectName;
    AddHeading( 1, Trim( ProjectName + ' ' + AResult.ProductVersion ) + ' — SBOM report' );

    // Run details
    var Check: string;

    if Length( AResult.ValidationErrors ) = 0 then
      Check         := 'Passed'
    else if Length( AResult.ValidationErrors ) = 1 then
      Check         := '1 problem, listed below'
    else
      Check         := Format( '%d problems, listed below', [ Length( AResult.ValidationErrors ) ] );

    var Delphi      := Cell( AResult.ProjectInfo.DelphiVersion );

    if Delphi <> '-' then
      Delphi        := 'BDS ' + Delphi;

    if AResult.ProjectInfo.TargetPlatform <> '' then
      Delphi        := Delphi + ', ' + AResult.ProjectInfo.TargetPlatform;

    AddTable( [ 'Item', 'Value' ], [
        [ 'SBOM file', Cell( ExtractFileName( AResult.OutputFile ) ) ],
        [ 'Format', 'CycloneDX 1.5 JSON' ],
        [ 'Report written', FormatDateTime( 'yyyy"-"mm"-"dd hh":"nn', TTimeZone.Local.ToUniversalTime( Now ), TFormatSettings.Create( 'en-US' ) ) + ' UTC' ],
        [ 'Generated by', AppName + ' ' + AppVersion ],
        [ 'Delphi', Delphi ],
        [ 'Units from', Cell( AResult.UnitSource ) ],
        [ 'SBOM check', Check ]
        ] );

    // Summary
    AddHeading( 2, 'Summary' );
    AddTable( [ 'Classification', 'Units' ], [
        [ ClassificationNames[ ucRTL ], IntToStr( AResult.Summary.RTLCount ) ],
        [ ClassificationNames[ ucThirdParty ], IntToStr( AResult.Summary.ThirdPartyCount ) ],
        [ ClassificationNames[ ucOwnCode ], IntToStr( AResult.Summary.OwnCodeCount ) ],
        [ ClassificationNames[ ucUnclassified ], IntToStr( AResult.Summary.UnclassifiedCount ) ]
        ] );

    // Components: the RTL, then each manifest component a unit uses, in manifest order
    var Used        := TList<Integer>.Create;
    try
      for var I := 0 to High( AResult.Manifest.Components ) do
        if Length( UnitsOf( ucThirdParty, I ) ) > 0 then
          Used.Add( I );

      var Rows: TArray<TArray<string>> := [ [ 'Embarcadero Delphi RTL', Cell( AResult.ProjectInfo.DelphiVersion ),
          'Embarcadero Technologies', '-', IntToStr( AResult.Summary.RTLCount ) ] ];

      for var I in Used do
      begin
        var Entry := AResult.Manifest.Components[ I ];
        Rows        := Rows + [ [ Cell( Entry.Name ), Cell( Entry.Version ), Cell( Entry.Vendor ), Cell( Entry.Licence ),
            IntToStr( Length( UnitsOf( ucThirdParty, I ) ) ) ] ];
      end;

      AddHeading( 2, 'Components' );
      AddTable( [ 'Component', 'Version', 'Supplier', 'Licence', 'Units' ], Rows );

      if Used.Count > 0 then
      begin
        AddHeading( 2, 'Third-party units' );

        for var I in Used do
        begin
          var Entry := AResult.Manifest.Components[ I ];
          AddHeading( 3, Trim( Cell( Entry.Name ) + ' ' + Entry.Version ) );
          AddList( UnitsOf( ucThirdParty, I ) );
        end;
      end;
    finally
      Used.Free;
    end;

    // Own code
    var OwnCode     := UnitsOf( ucOwnCode, -1 );

    if Length( OwnCode ) > 0 then
    begin
      AddHeading( 2, Format( 'Own code (%d units)', [ Length( OwnCode ) ] ) );
      AddParagraph( string.Join( ', ', OwnCode ) );
    end;

    // What is not in the SBOM yet
    var Unclassified := UnitsOf( ucUnclassified, -1 );

    if Length( Unclassified ) > 0 then
    begin
      AddHeading( 2, Format( 'Unclassified units (%d)', [ Length( Unclassified ) ] ) );
      AddParagraph( 'These units are not in the SBOM. Add their libraries to components.json, or mark them as own code.' );
      AddList( Unclassified );

      if Length( AResult.DiscoveredLibraries ) > 0 then
      begin
        var LibRows: TArray<TArray<string>> := nil;

        for var Lib in AResult.DiscoveredLibraries do
        begin
          var Source := 'source';

          if Lib.BinaryOnly then
            Source  := 'DCU only';

          LibRows   := LibRows + [ [ Cell( Lib.Name ), Cell( Lib.Directory ), Cell( Lib.Licence ), Cell( Lib.Vendor ),
              IntToStr( Length( Lib.Units ) ), Source ] ];
        end;

        AddHeading( 3, 'Libraries found on disk for them' );
        AddTable( [ 'Library', 'Directory', 'Licence', 'Vendor', 'Units', 'Found as' ], LibRows );
      end;
    end;

    // Check problems
    if Length( AResult.ValidationErrors ) > 0 then
    begin
      AddHeading( 2, 'SBOM check problems' );
      AddList( AResult.ValidationErrors );
    end;

    Result          := Blocks.ToArray;
  finally
    Blocks.Free;
  end;

end;

/// <summary>Escapes a Markdown table cell or list item: a pipe would split the cell, a line break the row.</summary>
function MdEscape( const AValue: string ): string;
begin

  Result            := StringReplace( AValue, '|', '\|', [ rfReplaceAll ] );
  Result            := StringReplace( StringReplace( Result, #13, ' ', [ rfReplaceAll ] ), #10, ' ', [ rfReplaceAll ] );

end;

/// <summary>Escapes text for HTML element content and attribute values.</summary>
function HtmlEscape( const AValue: string ): string;
begin

  Result            := StringReplace( AValue, '&', '&amp;', [ rfReplaceAll ] );
  Result            := StringReplace( Result, '<', '&lt;', [ rfReplaceAll ] );
  Result            := StringReplace( Result, '>', '&gt;', [ rfReplaceAll ] );
  Result            := StringReplace( Result, '"', '&quot;', [ rfReplaceAll ] );

end;

function BuildMarkdownReport( const AResult: TSBOMResult ): string;
begin

  var SB            := TStringBuilder.Create;
  try
    for var B in BuildBlocks( AResult ) do
    begin
      case B.Kind of
        bkHeading:
          SB.Append( StringOfChar( '#', B.Level ) ).Append( ' ' ).Append( MdEscape( B.Text ) ).Append( sLineBreak );

        bkParagraph:
          SB.Append( MdEscape( B.Text ) ).Append( sLineBreak );

        bkList:
          for var Item in B.Items do
            SB.Append( '- ' ).Append( MdEscape( Item ) ).Append( sLineBreak );

        bkTable:
          begin
            SB.Append( '|' );

            for var H in B.Headers do
              SB.Append( ' ' ).Append( MdEscape( H ) ).Append( ' |' );

            SB.Append( sLineBreak ).Append( '|' );

            for var I := 0 to High( B.Headers ) do
              SB.Append( '---|' );

            SB.Append( sLineBreak );

            for var Row in B.Rows do
            begin
              SB.Append( '|' );

              for var C in Row do
                SB.Append( ' ' ).Append( MdEscape( C ) ).Append( ' |' );

              SB.Append( sLineBreak );
            end;
          end;
      end;

      SB.Append( sLineBreak );
    end;

    Result          := SB.ToString;
  finally
    SB.Free;
  end;

end;

function BuildHtmlReport( const AResult: TSBOMResult ): string;
begin

  var Blocks        := BuildBlocks( AResult );
  var SB            := TStringBuilder.Create;
  try
    SB.Append( '<!DOCTYPE html>' ).Append( sLineBreak );
    SB.Append( '<html lang="en">' ).Append( sLineBreak );
    SB.Append( '<head>' ).Append( sLineBreak );
    SB.Append( '<meta charset="utf-8">' ).Append( sLineBreak );
    SB.Append( '<meta name="viewport" content="width=device-width, initial-scale=1">' ).Append( sLineBreak );
    SB.Append( '<title>' ).Append( HtmlEscape( Blocks[ 0 ].Text ) ).Append( '</title>' ).Append( sLineBreak );
    SB.Append( '<style>' ).Append( sLineBreak );
    SB.Append( ':root { color-scheme: light dark; --fg: #1f2328; --bg: #ffffff; --muted: #59636e; --line: #d1d9e0; --head: #f6f8fa; }' ).Append( sLineBreak );
    SB.Append( '@media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --bg: #0d1117; --muted: #9198a1; --line: #3d444d; --head: #151b23; } }' ).Append(
      sLineBreak );
    SB.Append( 'body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, "Segoe UI", sans-serif; }' ).Append( sLineBreak );
    SB.Append( 'main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }' ).Append( sLineBreak );
    SB.Append( 'h1 { font-size: 1.6em; } h2 { margin-top: 1.8em; border-bottom: 1px solid var(--line); padding-bottom: .2em; }' ).Append( sLineBreak );
    SB.Append( '.scroll { overflow-x: auto; } table { border-collapse: collapse; margin: .5em 0; }' ).Append( sLineBreak );
    SB.Append( 'th, td { border: 1px solid var(--line); padding: 4px 10px; text-align: left; vertical-align: top; }' ).Append( sLineBreak );
    SB.Append( 'th { background: var(--head); } ul { columns: 18em; } p { color: var(--muted); }' ).Append( sLineBreak );
    SB.Append( '</style>' ).Append( sLineBreak );
    SB.Append( '</head>' ).Append( sLineBreak );
    SB.Append( '<body>' ).Append( sLineBreak );
    SB.Append( '<main>' ).Append( sLineBreak );

    for var B in Blocks do
      case B.Kind of
        bkHeading:
          SB.AppendFormat( '<h%d>%s</h%0:d>', [ B.Level, HtmlEscape( B.Text ) ] ).Append( sLineBreak );

        bkParagraph:
          SB.Append( '<p>' ).Append( HtmlEscape( B.Text ) ).Append( '</p>' ).Append( sLineBreak );

        bkList:
          begin
            SB.Append( '<ul>' ).Append( sLineBreak );

            for var Item in B.Items do
              SB.Append( '<li>' ).Append( HtmlEscape( Item ) ).Append( '</li>' ).Append( sLineBreak );

            SB.Append( '</ul>' ).Append( sLineBreak );
          end;

        bkTable:
          begin
            SB.Append( '<div class="scroll"><table>' ).Append( sLineBreak ).Append( '<thead><tr>' );

            for var H in B.Headers do
              SB.Append( '<th>' ).Append( HtmlEscape( H ) ).Append( '</th>' );

            SB.Append( '</tr></thead>' ).Append( sLineBreak ).Append( '<tbody>' ).Append( sLineBreak );

            for var Row in B.Rows do
            begin
              SB.Append( '<tr>' );

              for var C in Row do
                SB.Append( '<td>' ).Append( HtmlEscape( C ) ).Append( '</td>' );

              SB.Append( '</tr>' ).Append( sLineBreak );
            end;

            SB.Append( '</tbody>' ).Append( sLineBreak ).Append( '</table></div>' ).Append( sLineBreak );
          end;
      end;

    SB.Append( '</main>' ).Append( sLineBreak );
    SB.Append( '</body>' ).Append( sLineBreak );
    SB.Append( '</html>' ).Append( sLineBreak );

    Result          := SB.ToString;
  finally
    SB.Free;
  end;

end;

function WriteReports( const AResult: TSBOMResult; AFormats: TReportFormats ): TArray<string>;
begin

  Result            := nil;

  // App.cdx.json → App.sbom-report.md / .html, beside the SBOM
  var Base          := AResult.OutputFile;

  if EndsText( '.cdx.json', Base ) then
    Base            := Copy( Base, 1, Length( Base ) - Length( '.cdx.json' ) )
  else
    Base            := ChangeFileExt( Base, '' );

  if rfMarkdown in AFormats then
  begin
    WriteTextFileAtomic( Base + '.sbom-report.md', BuildMarkdownReport( AResult ) );
    Result          := Result + [ Base + '.sbom-report.md' ];
  end;

  if rfHtml in AFormats then
  begin
    WriteTextFileAtomic( Base + '.sbom-report.html', BuildHtmlReport( AResult ) );
    Result          := Result + [ Base + '.sbom-report.html' ];
  end;

end;

end.

