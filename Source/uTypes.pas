(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uTypes.pas — Shared record and enumeration types used across all units
*)
unit uTypes;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections;

type
  /// <summary>
  ///   Classification category for a unit found in a Delphi project.
  /// </summary>
  TUnitClassification = ( ucRTL, ucThirdParty, ucOwnCode, ucUnclassified );

  /// <summary>
  ///   Log message severity level.
  /// </summary>
  TLogLevel = ( llInfo, llWarning, llError );

  /// <summary>
  ///   A single component entry from components.json.
  /// </summary>
  TComponentEntry = record
    Name: string;
    Version: string;
    Vendor: string;
    VendorURL: string;
    Licence: string;
    LicenceURL: string;
    CompType: string; // CycloneDX type: 'library', 'framework', 'application'
    Prefixes: TArray<string>;
    ExactUnits: TArray<string>;
    Notes: string;
    Purl: string; // Package URL override (empty = generated pkg:delphi/<name>@<version>)
  end;

  /// <summary>
  ///   The supplier (application publisher) from components.json root.
  /// </summary>
  TSupplierInfo = record
    Name: string;
    URL: string;
  end;

  /// <summary>
  ///   The complete parsed contents of a components.json manifest.
  /// </summary>
  TManifest = record
    SchemaVersion: string;
    LastUpdated: string;
    Supplier: TSupplierInfo;
    Components: TArray<TComponentEntry>;
    OwnCodeUnits: TArray<string>; // Units explicitly marked as own code by the user
    OwnCodePrefixes: TArray<string>; // Unit name prefixes that classify as own code (e.g. 'gll')
  end;

  /// <summary>
  ///   Metadata extracted from a Delphi .dpr and .dproj file.
  /// </summary>
  TProjectInfo = record
    ProjectName: string; // e.g. 'MyApp'
    ProjectFile: string; // Full path to .dpr or .dproj
    ProjectDir: string; // Directory containing the project file
    ProjectVersion: string; // From .dproj VerInfo (Major.Minor.Release.Build)
    DelphiVersion: string; // BDS version mapped from .dproj ProjectVersion (e.g. '37.0' = Delphi 13)
    TargetPlatform: string; // e.g. 'Win32', 'Win64'
    SearchPaths: TArray<string>; // DCC_UnitSearchPath entries (evaluated for Release + TargetPlatform)
    Units: TArray<string>; // Unit names from the .dpr uses clause (or the .dpk contains clause)
    OwnCodeUnits: TArray<string>; // Units with 'in' file references (own code)
  end;

  /// <summary>
  ///   A unit with its classification result and optional component link.
  /// </summary>
  TClassifiedUnit = record
    UnitName: string;
    OriginalName: string; // Name before scope prefix stripping
    Classification: TUnitClassification;
    ComponentIndex: Integer; // Index into TManifest.Components (-1 if not third-party)
  end;

  /// <summary>
  ///   Summary counts for the classification results.
  /// </summary>
  TClassificationSummary = record
    RTLCount: Integer;
    ThirdPartyCount: Integer;
    OwnCodeCount: Integer;
    UnclassifiedCount: Integer;
  end;

  /// <summary>
  ///   A third-party library discovered by scanning the file system.
  /// </summary>
  TDiscoveredLibrary = record
    Name: string; // Suggested library name (from directory name)
    Directory: string; // Full path to the library directory
    Version: string; // Detected version (may be empty)
    Vendor: string; // Detected author/copyright holder
    Licence: string; // Detected SPDX licence ID (may be empty)
    LicenceFile: string; // Path to licence file found
    SuggestedPrefix: string; // Computed common prefix for unit matching
    Units: TArray<string>; // Unit names found in this directory
    Confirmed: Boolean; // User has confirmed this entry
    BinaryOnly: Boolean; // Found only as .dcu files: no source under the library root
  end;

  /// <summary>
  ///   A companion report written beside the SBOM.
  /// </summary>
  TReportFormat = ( rfMarkdown, rfHtml );

  /// <summary>
  ///   The companion reports to write; empty writes none.
  /// </summary>
  TReportFormats = set of TReportFormat;

  /// <summary>
  ///   Binary evidence for a single unit, imported from DX.Comply SBOM output.
  ///   Contains the SHA-256 hash and origin classification from MAP file analysis.
  /// </summary>
  TUnitEvidence = record
    UnitName: string; // Unit name without .dcu extension (e.g. 'System.SysUtils')
    Algorithm: string; // Hash algorithm (e.g. 'SHA-256')
    HashValue: string; // Hash content
    Origin: string; // DX.Comply origin classification (e.g. 'Embarcadero RTL', 'Third party')
  end;

  /// <summary>
  ///   Complete results from a pipeline run, passed from uSBOMEngine to the form.
  /// </summary>
  TSBOMResult = record
    Success: Boolean;
    OutputFile: string; // Path to the generated .cdx.json
    ManifestFile: string; // Resolved components.json path used by this run
    ProjectInfo: TProjectInfo;
    Summary: TClassificationSummary;
    ClassifiedUnits: TArray<TClassifiedUnit>;
    Manifest: TManifest;
    RTLScanAvailable: Boolean; // False if RTL scanner could not find Delphi install
    DiscoveredLibraries: TArray<TDiscoveredLibrary>; // Libraries found by file system scan
    AutoOwnCodeUnits: TArray<string>; // Units found in the project dir or sibling own-code dirs (auto own-code)
    Evidence: TArray<TUnitEvidence>; // Binary evidence from DX.Comply (optional)
    ProductVersion: string; // The application version written to the SBOM
    UnitSource: string; // Where the unit list came from: the uses clause or a MAP file
    ValidationErrors: TArray<string>; // Problems the post-write check found in the SBOM (empty = passed)
    ReportFiles: TArray<string>; // Companion reports written
    ErrorMessage: string; // Populated only on failure
  end;

  /// <summary>
  ///   Input parameters for a pipeline run, populated from the form controls.
  /// </summary>
  TSBOMOptions = record
    ProjectFile: string; // Path to .dpr or .dproj
    ManifestFile: string; // Path to components.json (empty = auto-detect)
    OutputDir: string; // Output directory (empty = project directory)
    DelphiPath: string; // Delphi install path (empty = the project's Delphi version, from the registry)
    VersionOverride: string; // Version string override (empty = read from .dproj)
    DXComplyFile: string; // Path to DX.Comply bom.json (empty = no evidence merge)
    MapFile: string; // Path to a detailed .map file (empty = units from the uses clause)
    ReportFormats: TReportFormats; // Companion reports to write beside the SBOM
  end;

const
  /// <summary>
  ///   Display names for unit classification categories.
  /// </summary>
  ClassificationNames: array[ TUnitClassification ] of string = (
    'RTL/VCL',
    'Third-Party',
    'Own Code',
    'Unclassified'
    );

  /// <summary>
  ///   Log level prefixes for display.
  /// </summary>
  LogLevelPrefixes  : array[ TLogLevel ] of string = (
    '[INFO]',
    '[WARNING]',
    '[ERROR]'
    );

  /// <summary>
  ///   Known Delphi unit scope prefixes to strip before classification.
  /// </summary>
  ScopePrefixes     : array[ 0..14 ] of string = (
    'System.',
    'Vcl.',
    'Winapi.',
    'Data.',
    'Xml.',
    'Datasnap.',
    'FMX.',
    'REST.',
    'Net.',
    'Web.',
    'Soap.',
    'Bde.',
    'IBX.',
    'FireDAC.',
    'Posix.'
    );

  /// <summary>
  ///   Minimum allowed length for a units_prefix entry in components.json.
  /// </summary>
  MinPrefixLength   = 3;

  /// <summary>
  ///   Application version string.
  /// </summary>
  AppVersion        = '1.0.0';

  /// <summary>
  ///   Application display name.
  /// </summary>
  AppName           = 'DelphiSBOM';

/// <summary>
///   Strips the first matching Delphi scope prefix from a unit name.
///   Returns the stripped name, or the original if no prefix matched.
/// </summary>
function StripScopePrefix( const AUnitName: string ): string;

/// <summary>
///   Formats a log message with the appropriate level prefix.
/// </summary>
function FormatLogMessage( ALevel: TLogLevel; const AMessage: string ): string;

/// <summary>
///   Replaces every $(Name) reference in AValue with AResolve( Name ). The resolver returns the
///   replacement text; returning '$(' + Name + ')' leaves a reference in place.
/// </summary>
/// <param name="AValue">Text containing MSBuild-style $(Name) references.</param>
/// <param name="AResolve">Returns the replacement for a reference name.</param>
/// <returns>The expanded text.</returns>
function ExpandMacroReferences( const AValue: string; const AResolve: TFunc<string, string> ): string;

/// <summary>
///   The version the SBOM gives the application: the override when set, else the project's
///   version, else 0.0.0.0.
/// </summary>
/// <param name="AOverride">The user's version override (may be empty).</param>
/// <param name="AProjectVersion">The version read from the .dproj (may be empty).</param>
/// <returns>The version to emit.</returns>
function EffectiveProductVersion( const AOverride, AProjectVersion: string ): string;

type
  /// <summary>
  ///   How a licence value from components.json is emitted in CycloneDX 1.5.
  /// </summary>
  TLicenceKind = (
    lkNone, // No licence value
    lkSPDX, // A known SPDX identifier, emitted as license.id
    lkExpression, // An SPDX expression (contains OR / AND / WITH), emitted as expression
    lkName // Anything else (e.g. 'Commercial'), emitted as license.name
    );

/// <summary>
///   Classifies a licence value. license.id is an SPDX enum in the CycloneDX 1.5 schema, so only
///   recognised identifiers may go there; everything else must be an expression or a name.
/// </summary>
/// <param name="AValue">The licence value as written in components.json.</param>
/// <param name="ANormalised">The value to emit: canonical SPDX casing for lkSPDX, otherwise the trimmed input.</param>
/// <returns>The emission kind.</returns>
function ClassifyLicence( const AValue: string; out ANormalised: string ): TLicenceKind;

/// <summary>
///   Maps a hash algorithm name to the CycloneDX 1.5 enum spelling ('SHA256' and 'sha-256' both
///   become 'SHA-256'). Returns an empty string for an algorithm CycloneDX does not define.
/// </summary>
/// <param name="AAlgorithm">The algorithm name as found in the source data.</param>
/// <returns>The CycloneDX spelling, or '' when unsupported.</returns>
function NormaliseHashAlgorithm( const AAlgorithm: string ): string;

implementation

const
  /// <summary>
  ///   SPDX identifiers accepted as license.id: a practical subset of the SPDX licence list covering
  ///   licences found in the Delphi ecosystem. Deprecated identifiers remain valid in the schema enum.
  /// </summary>
  KnownSPDXIds      : array[ 0..71 ] of string = (
    '0BSD', 'AFL-3.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-1.1', 'Apache-2.0',
    'Artistic-2.0', 'BSD-1-Clause', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'BSD-4-Clause',
    'BSL-1.0', 'CC-BY-3.0', 'CC-BY-4.0', 'CC-BY-SA-4.0', 'CC0-1.0', 'CDDL-1.0', 'CDDL-1.1', 'CPL-1.0',
    'curl', 'ECL-2.0', 'EPL-1.0', 'EPL-2.0', 'EUPL-1.1', 'EUPL-1.2', 'GPL-1.0', 'GPL-2.0', 'GPL-2.0+',
    'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0+', 'GPL-3.0-only', 'GPL-3.0-or-later', 'ICU',
    'IJG', 'ISC', 'JSON', 'LGPL-2.0', 'LGPL-2.0+', 'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1',
    'LGPL-2.1+', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0', 'LGPL-3.0+', 'LGPL-3.0-only',
    'LGPL-3.0-or-later', 'Libpng', 'MIT', 'MIT-0', 'MPL-1.0', 'MPL-1.1', 'MPL-2.0',
    'MPL-2.0-no-copyleft-exception', 'MS-PL', 'MS-RL', 'NCSA', 'OpenSSL', 'PostgreSQL', 'Python-2.0',
    'Unicode-DFS-2016', 'Unlicense', 'UPL-1.0', 'W3C', 'WTFPL', 'X11', 'Zlib'
    );

  /// <summary>
  ///   Hash algorithm names defined by the CycloneDX 1.5 hash-alg enum.
  /// </summary>
  CycloneDXHashAlgorithms: array[ 0..11 ] of string = (
    'MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512',
    'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512', 'BLAKE3'
    );

function StripScopePrefix( const AUnitName: string ): string;
begin

  for var Prefix in ScopePrefixes do
    if AUnitName.StartsWith( Prefix, True ) then
      Exit( AUnitName.Substring( Prefix.Length ) );

  Result            := AUnitName;

end;

function FormatLogMessage( ALevel: TLogLevel; const AMessage: string ): string;
begin

  Result            := LogLevelPrefixes[ ALevel ] + ' ' + AMessage;

end;

function ExpandMacroReferences( const AValue: string; const AResolve: TFunc<string, string> ): string;
begin

  var Builder       := TStringBuilder.Create;
  try
    var I           := 1;
    var Len         := Length( AValue );

    while I <= Len do
    begin
      if ( I < Len ) and ( AValue[ I ] = '$' ) and ( AValue[ I + 1 ] = '(' ) then
      begin
        var Close   := Pos( ')', AValue, I + 2 );

        if Close > 0 then
        begin
          Builder.Append( AResolve( Copy( AValue, I + 2, Close - I - 2 ) ) );
          I         := Close + 1;
          Continue;
        end;
      end;

      Builder.Append( AValue[ I ] );
      Inc( I );
    end;

    Result          := Builder.ToString;
  finally
    Builder.Free;
  end;

end;

function EffectiveProductVersion( const AOverride, AProjectVersion: string ): string;
begin

  Result            := AOverride;

  if Result = '' then
    Result          := AProjectVersion;

  if Result = '' then
    Result          := '0.0.0.0';

end;

function ClassifyLicence( const AValue: string; out ANormalised: string ): TLicenceKind;
begin

  ANormalised       := Trim( AValue );

  if ANormalised = '' then Exit( lkNone );

  for var Id in KnownSPDXIds do
    if SameText( ANormalised, Id ) then
    begin
      ANormalised   := Id;
      Exit( lkSPDX );
    end;

  var Padded        := ' ' + UpperCase( ANormalised ) + ' ';

  if Padded.Contains( ' OR ' ) or Padded.Contains( ' AND ' ) or Padded.Contains( ' WITH ' ) then
    Exit( lkExpression );

  Result            := lkName;

end;

function NormaliseHashAlgorithm( const AAlgorithm: string ): string;
begin

  var Compact       := StringReplace( Trim( AAlgorithm ), '-', '', [ rfReplaceAll ] );

  for var Alg in CycloneDXHashAlgorithms do
    if SameText( Compact, StringReplace( Alg, '-', '', [ rfReplaceAll ] ) ) then
      Exit( Alg );

  Result            := '';

end;

end.

