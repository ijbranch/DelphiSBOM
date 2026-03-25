(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
  MIT Licence — see LICENCE file

  uProjectParser.pas — Parses .dpr uses clause and .dproj XML metadata
*)
unit uProjectParser;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils,
  Xml.XMLIntf,
  uTypes;

type
  /// <summary>
  ///   Callback type for logging messages during parsing.
  /// </summary>
  TLogProc = TProc<TLogLevel, string>;

  /// <summary>
  ///   Parses Delphi .dpr and .dproj files to extract project metadata.
  /// </summary>
  TProjectParser = class
  private
    FLog: TLogProc;

    function ParseDprUses( const ADprFile: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
    function ExtractUsesBlock( const AContent: string ): string;
    function SplitUnitNames( const AUsesBlock: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
    procedure ParseDprojMetadata( const ADprojFile: string; var AInfo: TProjectInfo );
    function FindDprojFile( const ADprFile: string ): string;
    function FindNodeText( const ANode: IXMLNode; const AName: string ): string;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TLogProc );

    /// <summary>
    ///   Parses a .dpr or .dproj file and returns project information.
    ///   If a .dpr is provided, also looks for a matching .dproj for metadata.
    ///   If a .dproj is provided, looks for a matching .dpr for the uses clause.
    /// </summary>
    function Parse( const AProjectFile: string ): TProjectInfo;
  end;

implementation

uses
  System.Variants, System.StrUtils, System.Generics.Collections,
  Xml.XMLDoc;

{ Standalone helpers }

function IsValidUnitName( const AName: string ): Boolean;
begin

  Result := AName.Length > 0;

  if Result then
    for var Ch in AName do
      if ( not CharInSet( Ch, [ 'A'..'Z', 'a'..'z', '0'..'9', '_', '.' ] ) ) then
        Exit( False );

end;

{ TProjectParser }

constructor TProjectParser.Create( ALogProc: TLogProc );
begin

  inherited Create;
  FLog := ALogProc;

end;

procedure TProjectParser.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TProjectParser.Parse( const AProjectFile: string ): TProjectInfo;
begin

  Result := Default( TProjectInfo );

  if ( not FileExists( AProjectFile ) ) then
    raise Exception.CreateFmt( 'Project file not found: %s', [ AProjectFile ] );

  var Ext := LowerCase( ExtractFileExt( AProjectFile ) );
  var DprFile  := '';
  var DprojFile := '';

  if Ext = '.dpr' then
  begin
    DprFile   := AProjectFile;
    DprojFile := FindDprojFile( AProjectFile );
  end
  else if Ext = '.dproj' then
  begin
    DprojFile := AProjectFile;
    DprFile   := ChangeFileExt( AProjectFile, '.dpr' );

    if ( not FileExists( DprFile ) ) then
    begin
      Log( llWarning, 'No matching .dpr file found — unit list will be empty' );
      DprFile := '';
    end;
  end
  else
    raise Exception.CreateFmt( 'Unsupported file type: %s (expected .dpr or .dproj)', [ Ext ] );

  Result.ProjectFile := AProjectFile;
  Result.ProjectDir  := ExtractFilePath( AProjectFile );
  Result.ProjectName := ChangeFileExt( ExtractFileName( AProjectFile ), '' );

  if DprFile <> '' then
  begin
    Log( llInfo, Format( 'Parsing uses clause from %s', [ ExtractFileName( DprFile ) ] ) );
    Result.Units := ParseDprUses( DprFile, Result.OwnCodeUnits );
    Log( llInfo, Format( 'Found %d units in uses clause (%d own code)', [ Length( Result.Units ), Length( Result.OwnCodeUnits ) ] ) );
  end;

  if DprojFile <> '' then
  begin
    Log( llInfo, Format( 'Reading project metadata from %s', [ ExtractFileName( DprojFile ) ] ) );
    ParseDprojMetadata( DprojFile, Result );
  end
  else
    Log( llWarning, 'No .dproj file found — version and platform metadata unavailable' );

end;

function TProjectParser.FindDprojFile( const ADprFile: string ): string;
begin

  Result := ChangeFileExt( ADprFile, '.dproj' );

  if ( not FileExists( Result ) ) then
  begin
    Log( llWarning, 'No matching .dproj file found — version and platform metadata unavailable' );
    Result := '';
  end;

end;

// ---------------------------------------------------------------------------
//  .dpr parsing — extract unit names from the uses clause
// ---------------------------------------------------------------------------

function TProjectParser.ParseDprUses( const ADprFile: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
begin

  AOwnCodeUnits := nil;

  var Content := TFile.ReadAllText( ADprFile, TEncoding.UTF8 );
  var UsesBlock := ExtractUsesBlock( Content );

  if UsesBlock = '' then
  begin
    Log( llWarning, 'No uses clause found in .dpr file' );
    Exit( nil );
  end;

  Result := SplitUnitNames( UsesBlock, AOwnCodeUnits );

end;

function TProjectParser.ExtractUsesBlock( const AContent: string ): string;
begin

  Result := '';

  var LowerContent := LowerCase( AContent );
  var Pos1 := Pos( 'uses', LowerContent );

  if Pos1 = 0 then Exit;

  var StartPos := Pos1 + 4;
  var SemiPos  := PosEx( ';', AContent, StartPos );

  if SemiPos = 0 then Exit;

  Result := Copy( AContent, StartPos, SemiPos - StartPos );

end;

function TProjectParser.SplitUnitNames( const AUsesBlock: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
begin

  var Units := TList<string>.Create;
  var OwnCode := TList<string>.Create;
  try
    var Parts := AUsesBlock.Split( [ ',' ] );

    for var Part in Parts do
    begin
      var Trimmed := Trim( Part );

      if Trimmed = '' then Continue;

      // Detect and remove 'in ''<filename>''' reference — marks this as own code
      var InPos := Pos( ' in ', LowerCase( Trimmed ) );
      var IsOwnCode := InPos > 0;

      if IsOwnCode then
        Trimmed := Trim( Copy( Trimmed, 1, InPos - 1 ) );

      // Remove any compiler directives {$...}
      while Pos( '{$', Trimmed ) > 0 do
      begin
        var BraceStart := Pos( '{$', Trimmed );
        var BraceEnd   := PosEx( '}', Trimmed, BraceStart );

        if BraceEnd > 0 then
          Delete( Trimmed, BraceStart, BraceEnd - BraceStart + 1 )
        else
          Break;
      end;

      // Clean up whitespace and line breaks
      Trimmed := StringReplace( Trimmed, #13#10, ' ', [ rfReplaceAll ] );
      Trimmed := StringReplace( Trimmed, #10, ' ', [ rfReplaceAll ] );
      Trimmed := StringReplace( Trimmed, #13, ' ', [ rfReplaceAll ] );

      while Pos( '  ', Trimmed ) > 0 do
        Trimmed := StringReplace( Trimmed, '  ', ' ', [ rfReplaceAll ] );

      Trimmed := Trim( Trimmed );

      if ( Trimmed <> '' ) and IsValidUnitName( Trimmed ) then
      begin
        Units.Add( Trimmed );

        if IsOwnCode then
          OwnCode.Add( Trimmed );
      end;
    end;

    Result         := Units.ToArray;
    AOwnCodeUnits  := OwnCode.ToArray;
  finally
    OwnCode.Free;
    Units.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  .dproj parsing — extract version info, platform, search paths
// ---------------------------------------------------------------------------

function MapProjectVersionToDelphiVersion( const AProjVer: string ): string;
begin

  // MSBuild ProjectVersion → Delphi product version mapping
  if AProjVer.StartsWith( '20.' ) then Result := '37.0'    // Delphi 13 Florence
  else if AProjVer.StartsWith( '19.' ) then Result := '36.0'    // Delphi 12 Athens
  else if AProjVer.StartsWith( '18.8' ) then Result := '35.0'   // Delphi 11.3 Alexandria
  else if AProjVer.StartsWith( '18.' ) then Result := '35.0'    // Delphi 11 Alexandria
  else if AProjVer.StartsWith( '17.' ) then Result := '34.0'    // Delphi 10.4 Sydney
  else if AProjVer.StartsWith( '16.' ) then Result := '33.0'    // Delphi 10.3 Rio
  else if AProjVer.StartsWith( '15.' ) then Result := '32.0'    // Delphi 10.2 Tokyo
  else Result := AProjVer;  // Unknown — return as-is

end;

procedure TProjectParser.ParseDprojMetadata( const ADprojFile: string; var AInfo: TProjectInfo );
begin

  var Doc: IXMLDocument := TXMLDocument.Create( nil );

  Doc.LoadFromFile( ADprojFile );
  Doc.Active := True;

  var Root := Doc.DocumentElement;

  if ( not Assigned( Root ) ) then
  begin
    Log( llWarning, 'Empty or invalid .dproj XML' );
    Exit;
  end;

  // Extract ProjectVersion and map to Delphi product version
  var ProjectVersion := FindNodeText( Root, 'ProjectVersion' );

  if ProjectVersion <> '' then
  begin
    AInfo.DelphiVersion := MapProjectVersionToDelphiVersion( ProjectVersion );
    Log( llInfo, Format( 'Delphi version: %s (ProjectVersion %s)', [ AInfo.DelphiVersion, ProjectVersion ] ) );
  end;

  // Extract target platform
  var Platform := FindNodeText( Root, 'Platform' );

  if Platform = '' then
    Platform := 'Win64';

  AInfo.TargetPlatform := Platform;

  // Extract version info — try individual elements first, fall back to VerInfo_Keys
  var Major   := FindNodeText( Root, 'VerInfo_MajorVer' );
  var Minor   := FindNodeText( Root, 'VerInfo_MinorVer' );
  var VerRelease := FindNodeText( Root, 'VerInfo_Release' );
  var Build   := FindNodeText( Root, 'VerInfo_Build' );

  if ( Major <> '' ) or ( Minor <> '' ) then
  begin
    if Major = '' then Major := '0';
    if Minor = '' then Minor := '0';
    if VerRelease = '' then VerRelease := '0';
    if Build = '' then Build := '0';

    AInfo.ProjectVersion := Format( '%s.%s.%s.%s', [ Major, Minor, VerRelease, Build ] );
    Log( llInfo, Format( 'Project version: %s', [ AInfo.ProjectVersion ] ) );
  end
  else
  begin
    // Fallback: parse FileVersion from VerInfo_Keys string
    var VerInfoKeys := FindNodeText( Root, 'VerInfo_Keys' );

    if VerInfoKeys <> '' then
    begin
      var Parts := VerInfoKeys.Split( [ ';' ] );

      for var Part in Parts do
      begin
        if Part.StartsWith( 'FileVersion=' ) then
        begin
          AInfo.ProjectVersion := Part.Substring( 12 );
          Log( llInfo, Format( 'Project version (from VerInfo_Keys): %s', [ AInfo.ProjectVersion ] ) );
          Break;
        end;
      end;
    end;
  end;

  // Extract search paths
  var SearchPath := FindNodeText( Root, 'DCC_UnitSearchPath' );

  if SearchPath <> '' then
  begin
    AInfo.SearchPaths := SearchPath.Split( [ ';' ] );

    for var I := 0 to High( AInfo.SearchPaths ) do
      AInfo.SearchPaths[ I ] := Trim( AInfo.SearchPaths[ I ] );

    Log( llInfo, Format( 'Found %d search paths', [ Length( AInfo.SearchPaths ) ] ) );
  end;

end;

function TProjectParser.FindNodeText( const ANode: IXMLNode; const AName: string ): string;
begin

  Result := '';

  if ( not Assigned( ANode ) ) then Exit;

  for var I := 0 to ANode.ChildNodes.Count - 1 do
  begin
    var Child := ANode.ChildNodes[ I ];

    if SameText( Child.NodeName, AName ) then
    begin
      if ( not VarIsNull( Child.NodeValue ) ) then
        Result := VarToStr( Child.NodeValue );
      Exit;
    end;

    // Recurse into child nodes
    Result := FindNodeText( Child, AName );

    if Result <> '' then Exit;
  end;

end;

end.
