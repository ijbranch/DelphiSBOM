(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uProjectParser.pas — Parses the .dpr/.dpk unit list and .dproj XML metadata
*)
unit uProjectParser;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, System.Generics.Collections,
  Xml.XMLIntf,
  uTypes;

type
  /// <summary>
  ///   Callback type for logging messages during parsing.
  /// </summary>
  TLogProc = TProc<TLogLevel, string>;

  /// <summary>
  ///   Parses Delphi .dpr, .dpk and .dproj files to extract project metadata.
  /// </summary>
  TProjectParser = class
  private
    FLog: TLogProc;

    function ParseSourceUnits( const ASourceFile: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
    function ExtractClauseBlock( const AContent: string; const AKeyword: string ): string;
    function SplitUnitNames( const AClauseBlock: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
    procedure ParseDprojMetadata( const ADprojFile: string; var AInfo: TProjectInfo; out AMainSource: string );
    function SelectPlatform( const ARoot: IXMLNode ): string;
    procedure EvaluatePropertyGroups( const ARoot: IXMLNode; AProps: TDictionary<string, string> );
    function FindNodeText( const ANode: IXMLNode; const AName: string ): string;
    function FindNode( const ANode: IXMLNode; const AName: string ): IXMLNode;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TLogProc );

    /// <summary>
    ///   Parses a .dpr, .dpk or .dproj file and returns project information.
    ///   A .dpr/.dpk is paired with the .dproj of the same name for metadata; a .dproj locates its
    ///   source through its MainSource property, falling back to a .dpr or .dpk of the same name.
    /// </summary>
    /// <param name="AProjectFile">Full path of the project file.</param>
    /// <returns>The parsed project information.</returns>
    /// <exception cref="Exception">The file does not exist or has an unsupported extension.</exception>
    function Parse( const AProjectFile: string ): TProjectInfo;
  end;

/// <summary>
///   Maps an MSBuild ProjectVersion (from a .dproj) to the BDS version that wrote it, which is also
///   the registry key of that Delphi installation ('20.4' and later = '37.0', Delphi 13).
///   Returns an empty string for a ProjectVersion that is not recognised.
/// </summary>
/// <param name="AProjVer">The ProjectVersion element value, e.g. '20.4'.</param>
/// <returns>The BDS version, e.g. '37.0', or ''.</returns>
function MapProjectVersionToBDSVersion( const AProjVer: string ): string;

implementation

uses
  System.Variants, System.StrUtils, System.RegularExpressions, System.Generics.Defaults,
  Xml.XMLDoc,
  uTextFiles;

{ Standalone helpers }

/// <summary>
///   Removes all Pascal comments from source text, preserving string literals.
///   Handles // line comments, { } block comments, and (* *) block comments.
///   Compiler directives ({$...}) are block comments too and are removed.
/// </summary>
function StripComments( const ASource: string ): string;
begin

  var Len           := Length( ASource );
  var Builder       := TStringBuilder.Create( Len );
  try
    var I           := 1;

    while I <= Len do
    begin
      // String literal — copy through unchanged
      if ASource[ I ] = '''' then
      begin
        Builder.Append( ASource[ I ] );
        Inc( I );

        while I <= Len do
        begin
          Builder.Append( ASource[ I ] );

          if ASource[ I ] = '''' then
          begin
            Inc( I );
            Break;
          end;

          Inc( I );
        end;

        Continue;
      end;

      // Line comment //
      if ( I < Len ) and ( ASource[ I ] = '/' ) and ( ASource[ I + 1 ] = '/' ) then
      begin
        while ( I <= Len ) and ( ASource[ I ] <> #10 ) do
          Inc( I );

        Continue;
      end;

      // Block comment { }
      if ASource[ I ] = '{' then
      begin
        Inc( I );

        while ( I <= Len ) and ( ASource[ I ] <> '}' ) do
          Inc( I );

        if I <= Len then Inc( I ); // Skip closing }
        Builder.Append( ' ' );
        Continue;
      end;

      // Block comment (* *)
      if ( I < Len ) and ( ASource[ I ] = '(' ) and ( ASource[ I + 1 ] = '*' ) then
      begin
        Inc( I, 2 );

        while ( I < Len ) and not ( ( ASource[ I ] = '*' ) and ( ASource[ I + 1 ] = ')' ) ) do
          Inc( I );

        if I < Len then
          Inc( I, 2 ) // Skip closing *)
        else
          I         := Len + 1; // Unterminated comment runs to the end of the file

        Builder.Append( ' ' );
        Continue;
      end;

      Builder.Append( ASource[ I ] );
      Inc( I );
    end;

    Result          := Builder.ToString;
  finally
    Builder.Free;
  end;

end;

function IsValidUnitName( const AName: string ): Boolean;
begin

  Result            := ( AName.Length > 0 ) and ( not AName.StartsWith( '.' ) ) and ( not AName.EndsWith( '.' ) ) and ( not AName.Contains( '..' ) );

  if Result then
    for var Ch in AName do
      if ( not CharInSet( Ch, [ 'A'..'Z', 'a'..'z', '0'..'9', '_', '.' ] ) ) then
        Exit( False );

end;

/// <summary>
///   Splits text on commas that are not inside single-quoted string literals.
/// </summary>
function SplitOutsideQuotes( const AText: string ): TArray<string>;
begin

  var Parts         := TList<string>.Create;
  try
    var InString    := False;
    var Start       := 1;

    for var I := 1 to Length( AText ) do
    begin
      if AText[ I ] = '''' then
        InString    := not InString
      else if ( AText[ I ] = ',' ) and ( not InString ) then
      begin
        Parts.Add( Copy( AText, Start, I - Start ) );
        Start       := I + 1;
      end;
    end;

    Parts.Add( Copy( AText, Start, Length( AText ) - Start + 1 ) );
    Result          := Parts.ToArray;
  finally
    Parts.Free;
  end;

end;

function MapProjectVersionToBDSVersion( const AProjVer: string ): string;
begin

  Result            := '';

  var Value: Double;

  if ( not TryStrToFloat( Trim( AProjVer ), Value, TFormatSettings.Create( 'en-US' ) ) ) then Exit;

  // ProjectVersion values written by each IDE release; the BDS version is the registry key
  if Value >= 20.35 then
    Result          := '37.0' // Delphi 13 Florence     (20.4 and later)
  else if Value >= 20.05 then
    Result          := '23.0' // Delphi 12 Athens       (20.1 - 20.3)
  else if Value >= 19.25 then
    Result          := '22.0' // Delphi 11 Alexandria   (19.3 - 19.5)
  else if Value >= 18.95 then
    Result          := '21.0' // Delphi 10.4 Sydney     (19.0 - 19.2)
  else if Value >= 18.45 then
    Result          := '20.0' // Delphi 10.3 Rio        (18.5 - 18.8)
  else if Value >= 18.25 then
    Result          := '19.0' // Delphi 10.2 Tokyo      (18.3 - 18.4)
  else if Value >= 18.05 then
    Result          := '18.0' // Delphi 10.1 Berlin     (18.1 - 18.2)
  else if Value >= 17.95 then
    Result          := '17.0'; // Delphi 10 Seattle      (18.0)

end;

// ---------------------------------------------------------------------------
//  MSBuild Condition evaluation (the subset .dproj files use)
// ---------------------------------------------------------------------------

type
  /// <summary>
  ///   Evaluates an MSBuild Condition attribute: quoted operands with $(Property) expansion,
  ///   == and !=, and / or / !, parentheses, and the Exists() / HasTrailingSlash() functions.
  /// </summary>
  TConditionEvaluator = class
  private
    FText: string;
    FPos: Integer;
    FProps: TDictionary<string, string>;

    procedure SkipSpace;
    function PeekWord: string;
    function ParseOr: Boolean;
    function ParseAnd: Boolean;
    function ParseUnary: Boolean;
    function ParseOperand: string;
  public
    constructor Create( AProps: TDictionary<string, string> );

    /// <summary>
    ///   Returns the value of ACondition; raises EParserError for syntax it does not support.
    /// </summary>
    function Evaluate( const ACondition: string ): Boolean;
  end;

/// <summary>
///   Expands $(Name) references: defined properties first, then environment variables. An unknown
///   IDE macro ($(BDS...), $(Platform)-style names not yet defined) is kept literally so library
///   discovery can expand it later; any other unknown name expands to empty, as MSBuild does.
/// </summary>
function ExpandProperties( const AValue: string; AProps: TDictionary<string, string> ): string;
begin

  Result            := ExpandMacroReferences( AValue,
    function( AName: string ): string
    begin
      if AProps.TryGetValue( AName, Result ) then Exit;

      Result        := GetEnvironmentVariable( AName );

      if Result <> '' then Exit;

      if AName.StartsWith( 'BDS', True ) then
        Result      := '$(' + AName + ')'
      else
        Result      := '';
    end );

end;

constructor TConditionEvaluator.Create( AProps: TDictionary<string, string> );
begin

  inherited Create;
  FProps            := AProps;

end;

function TConditionEvaluator.Evaluate( const ACondition: string ): Boolean;
begin

  FText             := ACondition;
  FPos              := 1;

  Result            := ParseOr;
  SkipSpace;

  if FPos <= Length( FText ) then
    raise EParserError.CreateFmt( 'Unexpected text in condition: %s', [ Copy( FText, FPos, MaxInt ) ] );

end;

procedure TConditionEvaluator.SkipSpace;
begin

  while ( FPos <= Length( FText ) ) and CharInSet( FText[ FPos ], [ ' ', #9, #10, #13 ] ) do
    Inc( FPos );

end;

function TConditionEvaluator.PeekWord: string;
begin

  SkipSpace;
  var I             := FPos;

  while ( I <= Length( FText ) ) and CharInSet( FText[ I ], [ 'A'..'Z', 'a'..'z', '0'..'9', '_', '.' ] ) do
    Inc( I );

  Result            := Copy( FText, FPos, I - FPos );

end;

function TConditionEvaluator.ParseOr: Boolean;
begin

  Result            := ParseAnd;

  while SameText( PeekWord, 'or' ) do
  begin
    Inc( FPos, 2 );
    var Right       := ParseAnd;
    Result          := Result or Right;
  end;

end;

function TConditionEvaluator.ParseAnd: Boolean;
begin

  Result            := ParseUnary;

  while SameText( PeekWord, 'and' ) do
  begin
    Inc( FPos, 3 );
    var Right       := ParseUnary;
    Result          := Result and Right;
  end;

end;

function TConditionEvaluator.ParseUnary: Boolean;
begin

  SkipSpace;

  if ( FPos <= Length( FText ) ) and ( FText[ FPos ] = '!' ) and ( Copy( FText, FPos, 2 ) <> '!=' ) then
  begin
    Inc( FPos );
    Exit( not ParseUnary );
  end;

  if ( FPos <= Length( FText ) ) and ( FText[ FPos ] = '(' ) then
  begin
    Inc( FPos );
    Result          := ParseOr;
    SkipSpace;

    if ( FPos > Length( FText ) ) or ( FText[ FPos ] <> ')' ) then
      raise EParserError.Create( 'Missing ) in condition' );

    Inc( FPos );
    Exit;
  end;

  var Left          := ParseOperand;
  SkipSpace;
  var Op            := Copy( FText, FPos, 2 );

  if ( Op = '==' ) or ( Op = '!=' ) then
  begin
    Inc( FPos, 2 );
    var Right       := ParseOperand;
    Result          := SameText( Left, Right ) = ( Op = '==' );
  end
  else
    Result          := SameText( Left, 'true' );

end;

function TConditionEvaluator.ParseOperand: string;
begin

  SkipSpace;

  if FPos > Length( FText ) then
    raise EParserError.Create( 'Unexpected end of condition' );

  // Quoted string with property expansion
  if FText[ FPos ] = '''' then
  begin
    var Close       := PosEx( '''', FText, FPos + 1 );

    if Close = 0 then
      raise EParserError.Create( 'Unterminated string in condition' );

    Result          := ExpandProperties( Copy( FText, FPos + 1, Close - FPos - 1 ), FProps );
    FPos            := Close + 1;
    Exit;
  end;

  var Word          := PeekWord;

  if Word = '' then
    raise EParserError.CreateFmt( 'Unexpected character in condition: %s', [ FText[ FPos ] ] );

  Inc( FPos, Word.Length );
  SkipSpace;

  // Function call: Exists('...') or HasTrailingSlash('...')
  if ( FPos <= Length( FText ) ) and ( FText[ FPos ] = '(' ) then
  begin
    Inc( FPos );
    var Arg         := ParseOperand;
    SkipSpace;

    if ( FPos > Length( FText ) ) or ( FText[ FPos ] <> ')' ) then
      raise EParserError.Create( 'Missing ) after function argument' );

    Inc( FPos );

    if SameText( Word, 'Exists' ) then
      Result        := BoolToStr( ( Arg <> '' ) and ( FileExists( Arg ) or DirectoryExists( Arg ) ), True )
    else if SameText( Word, 'HasTrailingSlash' ) then
      Result        := BoolToStr( ( Arg <> '' ) and CharInSet( Arg[ Arg.Length ], [ '\', '/' ] ), True )
    else
      raise EParserError.CreateFmt( 'Unsupported condition function: %s', [ Word ] );

    Exit;
  end;

  Result            := Word;

end;

{ TProjectParser }

constructor TProjectParser.Create( ALogProc: TLogProc );
begin

  inherited Create;
  FLog              := ALogProc;

end;

procedure TProjectParser.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TProjectParser.Parse( const AProjectFile: string ): TProjectInfo;
begin

  Result            := Default( TProjectInfo );

  if ( not FileExists( AProjectFile ) ) then
    raise Exception.CreateFmt( 'Project file not found: %s', [ AProjectFile ] );

  var Ext           := LowerCase( ExtractFileExt( AProjectFile ) );
  var SourceFile    := '';
  var DprojFile     := '';

  if ( Ext = '.dpr' ) or ( Ext = '.dpk' ) then
  begin
    SourceFile      := AProjectFile;
    DprojFile       := ChangeFileExt( AProjectFile, '.dproj' );

    if ( not FileExists( DprojFile ) ) then
    begin
      Log( llWarning, 'No matching .dproj file found — version and platform metadata unavailable' );
      DprojFile     := '';
    end;
  end
  else if Ext = '.dproj' then
    DprojFile       := AProjectFile
  else
    raise Exception.CreateFmt( 'Unsupported file type: %s (expected .dpr, .dpk or .dproj)', [ Ext ] );

  Result.ProjectFile := AProjectFile;
  Result.ProjectDir := ExtractFilePath( AProjectFile );
  Result.ProjectName := ChangeFileExt( ExtractFileName( AProjectFile ), '' );

  if DprojFile <> '' then
  begin
    Log( llInfo, Format( 'Reading project metadata from %s', [ ExtractFileName( DprojFile ) ] ) );

    var MainSource  := '';
    ParseDprojMetadata( DprojFile, Result, MainSource );

    // A .dproj names its source file in MainSource; fall back to a .dpr or .dpk of the same name
    if SourceFile = '' then
    begin
      if MainSource <> '' then
        SourceFile  := TPath.Combine( Result.ProjectDir, MainSource );

      if ( SourceFile = '' ) or ( not FileExists( SourceFile ) ) then
        SourceFile  := ChangeFileExt( DprojFile, '.dpr' );

      if ( not FileExists( SourceFile ) ) then
        SourceFile  := ChangeFileExt( DprojFile, '.dpk' );

      if ( not FileExists( SourceFile ) ) then
      begin
        Log( llWarning, 'No .dpr or .dpk source found for the .dproj — unit list will be empty' );
        SourceFile  := '';
      end;
    end;
  end;

  if SourceFile <> '' then
  begin
    Log( llInfo, Format( 'Parsing unit list from %s', [ ExtractFileName( SourceFile ) ] ) );
    Result.Units    := ParseSourceUnits( SourceFile, Result.OwnCodeUnits );
    Log( llInfo, Format( 'Found %d units (%d with in-file references)', [ Length( Result.Units ), Length( Result.OwnCodeUnits ) ] ) );
  end;

end;

// ---------------------------------------------------------------------------
//  .dpr / .dpk parsing — extract unit names from the uses (or contains) clause
// ---------------------------------------------------------------------------

function TProjectParser.ParseSourceUnits( const ASourceFile: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
begin

  AOwnCodeUnits     := nil;

  var Content       := ReadTextFile( ASourceFile );
  var IsPackage     := SameText( ExtractFileExt( ASourceFile ), '.dpk' );
  var Keyword       := IfThen( IsPackage, 'contains', 'uses' );

  // Directives are stripped with comments, so every conditional branch contributes units
  if TRegEx.IsMatch( Content, '\{\$IF', [ roIgnoreCase ] ) then
    Log( llWarning, Format( '%s contains conditional directives — units from every {$IF...} branch are included',
        [ ExtractFileName( ASourceFile ) ] ) );

  if TRegEx.IsMatch( Content, '\{\$(I|INCLUDE)\s', [ roIgnoreCase ] ) then
    Log( llWarning, Format( '%s uses {$I} include files — units listed inside include files are not read',
        [ ExtractFileName( ASourceFile ) ] ) );

  var ClauseBlock   := ExtractClauseBlock( Content, Keyword );

  if ClauseBlock = '' then
  begin
    Log( llWarning, Format( 'No %s clause found in %s', [ Keyword, ExtractFileName( ASourceFile ) ] ) );
    Exit( nil );
  end;

  Result            := SplitUnitNames( ClauseBlock, AOwnCodeUnits );

end;

function TProjectParser.ExtractClauseBlock( const AContent: string; const AKeyword: string ): string;
begin

  Result            := '';

  // Strip comments first so the keyword in comments is not matched
  var Cleaned       := StripComments( AContent );
  var LowerContent  := LowerCase( Cleaned );
  var KeyLen        := AKeyword.Length;
  var SearchPos     := 1;

  // Find the keyword as a whole word (not part of an identifier)
  while SearchPos > 0 do
  begin
    var Pos1        := PosEx( AKeyword, LowerContent, SearchPos );

    if Pos1 = 0 then Exit;

    // Check word boundary: character before and after must not be alphanumeric/underscore
    var BeforeOk    := ( Pos1 = 1 ) or not CharInSet( LowerContent[ Pos1 - 1 ], [ 'a'..'z', '0'..'9', '_' ] );
    var AfterPos    := Pos1 + KeyLen;
    var AfterOk     := ( AfterPos > Length( LowerContent ) ) or not CharInSet( LowerContent[ AfterPos ], [ 'a'..'z', '0'..'9', '_' ] );

    if BeforeOk and AfterOk then
    begin
      // Find the terminating semicolon, skipping semicolons inside string literals
      var I         := AfterPos;
      var InString  := False;

      while I <= Length( Cleaned ) do
      begin
        if Cleaned[ I ] = '''' then
          InString  := not InString
        else if ( Cleaned[ I ] = ';' ) and ( not InString ) then
        begin
          Result    := Copy( Cleaned, AfterPos, I - AfterPos );
          Exit;
        end;

        Inc( I );
      end;

      Exit;
    end;

    SearchPos       := Pos1 + KeyLen;
  end;

end;

function TProjectParser.SplitUnitNames( const AClauseBlock: string; out AOwnCodeUnits: TArray<string> ): TArray<string>;
begin

  // Normalise all whitespace first, so 'Unit1<newline>  in ''Unit1.pas''' and tabs parse alike
  var Block         := TRegEx.Replace( AClauseBlock, '\s+', ' ' );

  // <UnitName> [in '<file name>']
  var EntryRegex    := TRegEx.Create( '^\s*([A-Za-z0-9_.]+)\s*(\bin\s*''[^'']*'')?\s*$', [ roIgnoreCase ] );

  var Units         := TList<string>.Create;
  var OwnCode       := TList<string>.Create;
  try
    for var Part in SplitOutsideQuotes( Block ) do
    begin
      if Trim( Part ) = '' then Continue;

      var Match     := EntryRegex.Match( Part );

      if ( not Match.Success ) or ( not IsValidUnitName( Match.Groups[ 1 ].Value ) ) then
      begin
        Log( llWarning, Format( 'Skipping unrecognised unit list entry: %s', [ Trim( Part ) ] ) );
        Continue;
      end;

      var UnitName  := Match.Groups[ 1 ].Value;
      Units.Add( UnitName );

      // An 'in ''<filename>''' reference marks the unit as compiled from project-supplied source
      if ( Match.Groups.Count > 2 ) and ( Match.Groups[ 2 ].Success ) and ( Match.Groups[ 2 ].Value <> '' ) then
        OwnCode.Add( UnitName );
    end;

    Result          := Units.ToArray;
    AOwnCodeUnits   := OwnCode.ToArray;
  finally
    OwnCode.Free;
    Units.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  .dproj parsing — evaluate PropertyGroups for Release + the target platform
// ---------------------------------------------------------------------------

procedure TProjectParser.ParseDprojMetadata( const ADprojFile: string; var AInfo: TProjectInfo; out AMainSource: string );
begin

  AMainSource       := '';

  var Doc: IXMLDocument := TXMLDocument.Create( nil );

  Doc.LoadFromFile( ADprojFile );
  Doc.Active        := True;

  var Root          := Doc.DocumentElement;

  if ( not Assigned( Root ) ) then
  begin
    Log( llWarning, 'Empty or invalid .dproj XML' );
    Exit;
  end;

  // ProjectVersion (lives outside the evaluated groups' interest — read it directly)
  var ProjectVersion := FindNodeText( Root, 'ProjectVersion' );

  if ProjectVersion <> '' then
  begin
    AInfo.DelphiVersion := MapProjectVersionToBDSVersion( ProjectVersion );

    if AInfo.DelphiVersion <> '' then
      Log( llInfo, Format( 'Delphi version: BDS %s (ProjectVersion %s)', [ AInfo.DelphiVersion, ProjectVersion ] ) )
    else
      Log( llWarning, Format( 'Unrecognised ProjectVersion %s — Delphi version unknown', [ ProjectVersion ] ) );
  end;

  AInfo.TargetPlatform := SelectPlatform( Root );

  // Evaluate every PropertyGroup the way MSBuild would for a Release build of that platform
  var Props         := TDictionary<string, string>.Create( TIStringComparer.Ordinal );
  try
    Props.AddOrSetValue( 'Config', 'Release' );
    Props.AddOrSetValue( 'Platform', AInfo.TargetPlatform );
    Props.AddOrSetValue( 'MSBuildProjectName', TPath.GetFileNameWithoutExtension( ADprojFile ) );
    Props.AddOrSetValue( 'MSBuildProjectDirectory', ExcludeTrailingPathDelimiter( ExtractFilePath( ADprojFile ) ) );

    EvaluatePropertyGroups( Root, Props );

    Log( llInfo, Format( 'Evaluated .dproj for Release|%s', [ AInfo.TargetPlatform ] ) );

    Props.TryGetValue( 'MainSource', AMainSource );

    // Version info — Delphi's defaults are 1.0.0.0 for any part not set
    var Major       := '';
    var Minor       := '';
    var VerRelease  := '';
    var Build       := '';

    Props.TryGetValue( 'VerInfo_MajorVer', Major );
    Props.TryGetValue( 'VerInfo_MinorVer', Minor );
    Props.TryGetValue( 'VerInfo_Release', VerRelease );
    Props.TryGetValue( 'VerInfo_Build', Build );

    if ( Major <> '' ) or ( Minor <> '' ) or ( VerRelease <> '' ) or ( Build <> '' ) then
    begin
      if Major = '' then Major := '1';
      if Minor = '' then Minor := '0';
      if VerRelease = '' then VerRelease := '0';
      if Build = '' then Build := '0';

      AInfo.ProjectVersion := Format( '%s.%s.%s.%s', [ Major, Minor, VerRelease, Build ] );
      Log( llInfo, Format( 'Project version: %s', [ AInfo.ProjectVersion ] ) );
    end
    else
    begin
      // Fallback: parse FileVersion from the VerInfo_Keys string
      var VerInfoKeys := '';

      if Props.TryGetValue( 'VerInfo_Keys', VerInfoKeys ) then
        for var Part in VerInfoKeys.Split( [ ';' ] ) do
          if Part.StartsWith( 'FileVersion=', True ) then
          begin
            AInfo.ProjectVersion := Part.Substring( 12 );
            Log( llInfo, Format( 'Project version (from VerInfo_Keys): %s', [ AInfo.ProjectVersion ] ) );
            Break;
          end;
    end;

    // Unit search paths — drop entries left empty or self-referencing after evaluation
    var SearchPath  := '';

    if Props.TryGetValue( 'DCC_UnitSearchPath', SearchPath ) and ( SearchPath <> '' ) then
    begin
      var Paths     := TList<string>.Create;
      try
        for var P in SearchPath.Split( [ ';' ] ) do
        begin
          var Trimmed := Trim( P );

          if ( Trimmed <> '' ) and ( not Trimmed.Contains( '$(DCC_UnitSearchPath)' ) ) and ( Paths.IndexOf( Trimmed ) < 0 ) then
            Paths.Add( Trimmed );
        end;

        AInfo.SearchPaths := Paths.ToArray;
      finally
        Paths.Free;
      end;

      Log( llInfo, Format( 'Found %d search paths', [ Length( AInfo.SearchPaths ) ] ) );
    end;
  finally
    Props.Free;
  end;

end;

function TProjectParser.SelectPlatform( const ARoot: IXMLNode ): string;
begin

  // The IDE records the active platforms in ProjectExtensions\BorlandProject\Platforms
  var Active        := TList<string>.Create;
  try
    var Platforms   := FindNode( ARoot, 'Platforms' );

    if Assigned( Platforms ) then
      for var I := 0 to Platforms.ChildNodes.Count - 1 do
      begin
        var Node    := Platforms.ChildNodes[ I ];

        if SameText( Node.NodeName, 'Platform' ) and Node.HasAttribute( 'value' ) and Node.IsTextElement and
          SameText( Trim( Node.Text ), 'True' ) then
          Active.Add( VarToStr( Node.Attributes[ 'value' ] ) );
      end;

    // Prefer Win64, then Win32, then whatever else is active
    var PreferenceOrder: TArray<string> := [ 'Win64', 'Win32' ];

    for var Preferred in PreferenceOrder do
      for var P in Active do
        if SameText( P, Preferred ) then
          Exit( Preferred );

    if Active.Count > 0 then
      Exit( Active[ 0 ] );
  finally
    Active.Free;
  end;

  // Fall back to the command-line default platform, then Win64
  Result            := Trim( FindNodeText( ARoot, 'Platform' ) );

  if Result = '' then
    Result          := 'Win64';

end;

procedure TProjectParser.EvaluatePropertyGroups( const ARoot: IXMLNode; AProps: TDictionary<string, string> );
begin

  var Evaluator     := TConditionEvaluator.Create( AProps );
  try
    for var I := 0 to ARoot.ChildNodes.Count - 1 do
    begin
      var Group     := ARoot.ChildNodes[ I ];

      if ( Group.NodeType <> ntElement ) or ( not SameText( Group.NodeName, 'PropertyGroup' ) ) then Continue;

      if Group.HasAttribute( 'Condition' ) then
      begin
        var Condition := VarToStr( Group.Attributes[ 'Condition' ] );

        try
          if ( not Evaluator.Evaluate( Condition ) ) then Continue;
        except
          on E: EParserError do
          begin
            Log( llWarning, Format( 'Skipping PropertyGroup with unsupported condition (%s): %s', [ E.Message, Condition ] ) );
            Continue;
          end;
        end;
      end;

      for var J := 0 to Group.ChildNodes.Count - 1 do
      begin
        var Prop    := Group.ChildNodes[ J ];

        if Prop.NodeType <> ntElement then Continue;

        if Prop.HasAttribute( 'Condition' ) then
        begin
          try
            if ( not Evaluator.Evaluate( VarToStr( Prop.Attributes[ 'Condition' ] ) ) ) then Continue;
          except
            on E: EParserError do
              Continue;
          end;
        end;

        var Value   := '';

        if Prop.IsTextElement then
          Value     := Prop.Text;

        AProps.AddOrSetValue( Prop.NodeName, ExpandProperties( Value, AProps ) );
      end;
    end;
  finally
    Evaluator.Free;
  end;

end;

function TProjectParser.FindNode( const ANode: IXMLNode; const AName: string ): IXMLNode;
begin

  Result            := nil;

  if ( not Assigned( ANode ) ) then Exit;

  for var I := 0 to ANode.ChildNodes.Count - 1 do
  begin
    var Child       := ANode.ChildNodes[ I ];

    if Child.NodeType <> ntElement then Continue;

    if SameText( Child.NodeName, AName ) then
      Exit( Child );

    Result          := FindNode( Child, AName );

    if Assigned( Result ) then Exit;
  end;

end;

function TProjectParser.FindNodeText( const ANode: IXMLNode; const AName: string ): string;
begin

  Result            := '';

  var Node          := FindNode( ANode, AName );

  if Assigned( Node ) and Node.IsTextElement then
    Result          := Node.Text;

end;

end.

