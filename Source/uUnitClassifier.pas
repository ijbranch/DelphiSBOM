(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uUnitClassifier.pas — Classifies units as RTL, third-party, own code, or unclassified
*)
unit uUnitClassifier;

interface

uses
  System.SysUtils,
  uTypes, uRTLScanner;

type
  /// <summary>
  ///   Classifies each unit from a project against the RTL scanner and
  ///   component manifest, following the priority order:
  ///   1. RTL/VCL  2. Third-party exact (units_exact)  3. Own code listed in own_code_units
  ///   4. Third-party prefix (units_prefix)  5. Own code by 'in' reference or own_code_prefixes
  ///   6. Unclassified.
  ///   Explicit lists beat heuristic prefixes; a vendored library compiled through an 'in'
  ///   reference still classifies as third-party when a manifest rule matches it.
  /// </summary>
  TUnitClassifier = class
  private
    FLog: TProc<TLogLevel, string>;
    FRTLScanner: TRTLScanner;
    FManifest: TManifest;
    FRTLScanAvailable: Boolean;
    FOwnCodeUnits: TArray<string>;

    function MatchExact( const AUnitName: string ): Integer;
    function MatchPrefix( const AUnitName: string ): Integer;
    function IsListedOwnCode( const AUnitName: string ): Boolean;
    function IsOwnCode( const AUnitName: string ): Boolean;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
  public
    constructor Create( ALogProc: TProc<TLogLevel, string>;
      ARTLScanner: TRTLScanner; const AManifest: TManifest; ARTLScanAvailable: Boolean;
      const AOwnCodeUnits: TArray<string> );

    /// <summary>
    ///   Classifies all units and returns the results.
    /// </summary>
    function Classify( const AUnits: TArray<string> ): TArray<TClassifiedUnit>;

    /// <summary>
    ///   Computes summary counts from classified units.
    /// </summary>
    class function Summarise( const AUnits: TArray<TClassifiedUnit> ): TClassificationSummary;
  end;

implementation

{ TUnitClassifier }

constructor TUnitClassifier.Create( ALogProc: TProc<TLogLevel, string>;
  ARTLScanner: TRTLScanner; const AManifest: TManifest; ARTLScanAvailable: Boolean;
  const AOwnCodeUnits: TArray<string> );
begin

  inherited Create;
  FLog              := ALogProc;
  FRTLScanner       := ARTLScanner;
  FManifest         := AManifest;
  FRTLScanAvailable := ARTLScanAvailable;
  FOwnCodeUnits     := AOwnCodeUnits;

end;

procedure TUnitClassifier.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TUnitClassifier.Classify( const AUnits: TArray<string> ): TArray<TClassifiedUnit>;
begin

  SetLength( Result, Length( AUnits ) );

  for var I := 0 to High( AUnits ) do
  begin
    var OriginalName := AUnits[ I ];
    var StrippedName := StripScopePrefix( OriginalName );

    Result[ I ].OriginalName := OriginalName;
    Result[ I ].UnitName := StrippedName;
    Result[ I ].ComponentIndex := -1;

    // Priority 1: RTL/VCL match
    if FRTLScanAvailable and FRTLScanner.IsRTLUnit( OriginalName ) then
    begin
      Result[ I ].Classification := ucRTL;
      Continue;
    end;

    // Also try the stripped name against RTL
    if FRTLScanAvailable and ( StrippedName <> OriginalName ) and FRTLScanner.IsRTLUnit( StrippedName ) then
    begin
      Result[ I ].Classification := ucRTL;
      Continue;
    end;

    // Priority 2a: Exact manifest match (try both original and stripped names)
    var CompIdx     := MatchExact( OriginalName );

    if CompIdx < 0 then
      CompIdx       := MatchExact( StrippedName );

    if CompIdx >= 0 then
    begin
      Result[ I ].Classification := ucThirdParty;
      Result[ I ].ComponentIndex := CompIdx;
      Continue;
    end;

    // Priority 3: Units the user explicitly listed as own code beat any prefix rule
    if IsListedOwnCode( OriginalName ) or IsListedOwnCode( StrippedName ) then
    begin
      Result[ I ].Classification := ucOwnCode;
      Continue;
    end;

    // Priority 4: Prefix manifest match (try both names)
    CompIdx         := MatchPrefix( OriginalName );

    if CompIdx < 0 then
      CompIdx       := MatchPrefix( StrippedName );

    if CompIdx >= 0 then
    begin
      Result[ I ].Classification := ucThirdParty;
      Result[ I ].ComponentIndex := CompIdx;
      Continue;
    end;

    // Priority 5: Own code ('in' file reference, or own_code_prefixes)
    if IsOwnCode( OriginalName ) or IsOwnCode( StrippedName ) then
    begin
      Result[ I ].Classification := ucOwnCode;
      Continue;
    end;

    // Priority 6: Unclassified
    Result[ I ].Classification := ucUnclassified;
  end;

  // Log summary
  var Summary       := Summarise( Result );

  Log( llInfo, Format( 'Classification: %d RTL, %d third-party, %d own code, %d unclassified',
      [ Summary.RTLCount, Summary.ThirdPartyCount, Summary.OwnCodeCount, Summary.UnclassifiedCount ] ) );

  if Summary.UnclassifiedCount > 0 then
    Log( llWarning, Format( '%d units could not be classified', [ Summary.UnclassifiedCount ] ) );

end;

function TUnitClassifier.MatchExact( const AUnitName: string ): Integer;
begin

  for var I := 0 to High( FManifest.Components ) do
    for var ExactName in FManifest.Components[ I ].ExactUnits do
      if SameText( AUnitName, ExactName ) then
        Exit( I );

  Result            := -1;

end;

function TUnitClassifier.MatchPrefix( const AUnitName: string ): Integer;
begin

  var LowerName     := LowerCase( AUnitName );

  // An empty prefix would match every unit — never use one
  for var I := 0 to High( FManifest.Components ) do
    for var Pfx in FManifest.Components[ I ].Prefixes do
      if ( Pfx <> '' ) and LowerName.StartsWith( LowerCase( Pfx ) ) then
        Exit( I );

  Result            := -1;

end;

function TUnitClassifier.IsListedOwnCode( const AUnitName: string ): Boolean;
begin

  // Units explicitly marked as own code in components.json
  for var ManifestOwn in FManifest.OwnCodeUnits do
    if SameText( AUnitName, ManifestOwn ) then
      Exit( True );

  Result            := False;

end;

function TUnitClassifier.IsOwnCode( const AUnitName: string ): Boolean;
begin

  // Units with 'in' file references from the .dpr / .dpk
  for var OwnUnit in FOwnCodeUnits do
    if SameText( AUnitName, OwnUnit ) then
      Exit( True );

  // Own-code prefix rules from components.json
  var LowerName     := LowerCase( AUnitName );

  for var Pfx in FManifest.OwnCodePrefixes do
    if ( Pfx <> '' ) and LowerName.StartsWith( LowerCase( Pfx ) ) then
      Exit( True );

  Result            := False;

end;

class function TUnitClassifier.Summarise( const AUnits: TArray<TClassifiedUnit> ): TClassificationSummary;
begin

  Result            := Default( TClassificationSummary );

  for var U in AUnits do
    case U.Classification of
      ucRTL: Inc( Result.RTLCount );
      ucThirdParty: Inc( Result.ThirdPartyCount );
      ucOwnCode: Inc( Result.OwnCodeCount );
      ucUnclassified: Inc( Result.UnclassifiedCount );
    end;

end;

end.

