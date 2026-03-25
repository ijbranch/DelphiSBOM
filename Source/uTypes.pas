(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
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
    Name       : string;
    Version    : string;
    Vendor     : string;
    VendorURL  : string;
    Licence    : string;
    LicenceURL : string;
    CompType   : string;   // CycloneDX type: 'library', 'framework', 'application'
    Prefixes   : TArray<string>;
    ExactUnits : TArray<string>;
    Notes      : string;
  end;

  /// <summary>
  ///   The supplier (application publisher) from components.json root.
  /// </summary>
  TSupplierInfo = record
    Name : string;
    URL  : string;
  end;

  /// <summary>
  ///   The complete parsed contents of a components.json manifest.
  /// </summary>
  TManifest = record
    SchemaVersion : string;
    LastUpdated   : string;
    Supplier      : TSupplierInfo;
    Components    : TArray<TComponentEntry>;
    OwnCodeUnits  : TArray<string>;  // Units explicitly marked as own code by the user
  end;

  /// <summary>
  ///   Metadata extracted from a Delphi .dpr and .dproj file.
  /// </summary>
  TProjectInfo = record
    ProjectName    : string;   // e.g. 'MyApp'
    ProjectFile    : string;   // Full path to .dpr or .dproj
    ProjectDir     : string;   // Directory containing the project file
    ProjectVersion : string;   // From .dproj VerInfo (Major.Minor.Release.Build)
    DelphiVersion  : string;   // From .dproj ProjectVersion element
    TargetPlatform : string;   // e.g. 'Win32', 'Win64'
    SearchPaths    : TArray<string>;  // DCC_UnitSearchPath entries
    Units          : TArray<string>;  // Unit names from the .dpr uses clause
    OwnCodeUnits   : TArray<string>;  // Units with 'in' file references (own code)
  end;

  /// <summary>
  ///   A unit with its classification result and optional component link.
  /// </summary>
  TClassifiedUnit = record
    UnitName       : string;
    OriginalName   : string;           // Name before scope prefix stripping
    Classification : TUnitClassification;
    ComponentIndex : Integer;          // Index into TManifest.Components (-1 if not third-party)
  end;

  /// <summary>
  ///   Summary counts for the classification results.
  /// </summary>
  TClassificationSummary = record
    RTLCount          : Integer;
    ThirdPartyCount   : Integer;
    OwnCodeCount      : Integer;
    UnclassifiedCount : Integer;
  end;

  /// <summary>
  ///   A third-party library discovered by scanning the file system.
  /// </summary>
  TDiscoveredLibrary = record
    Name            : string;          // Suggested library name (from directory name)
    Directory       : string;          // Full path to the library directory
    Version         : string;          // Detected version (may be empty)
    Vendor          : string;          // Detected author/copyright holder
    Licence         : string;          // Detected SPDX licence ID (may be empty)
    LicenceFile     : string;          // Path to licence file found
    SuggestedPrefix : string;          // Computed common prefix for unit matching
    Units           : TArray<string>;  // Unit names found in this directory
    Confirmed       : Boolean;         // User has confirmed this entry
  end;

  /// <summary>
  ///   Complete results from a pipeline run, passed from uSBOMEngine to the form.
  /// </summary>
  TSBOMResult = record
    Success             : Boolean;
    OutputFile          : string;         // Path to the generated .cdx.json
    ProjectInfo         : TProjectInfo;
    Summary             : TClassificationSummary;
    ClassifiedUnits     : TArray<TClassifiedUnit>;
    Manifest            : TManifest;
    RTLScanAvailable    : Boolean;        // False if RTL scanner could not find Delphi install
    DiscoveredLibraries : TArray<TDiscoveredLibrary>;  // Libraries found by file system scan
    ErrorMessage        : string;         // Populated only on failure
  end;

  /// <summary>
  ///   Input parameters for a pipeline run, populated from the form controls.
  /// </summary>
  TSBOMOptions = record
    ProjectFile     : string;   // Path to .dpr or .dproj
    ManifestFile    : string;   // Path to components.json (empty = auto-detect)
    OutputDir       : string;   // Output directory (empty = project directory)
    DelphiPath      : string;   // Delphi install path (empty = auto-detect from registry)
    VersionOverride : string;   // Version string override (empty = read from .dproj)
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
  LogLevelPrefixes: array[ TLogLevel ] of string = (
    '[INFO]',
    '[WARNING]',
    '[ERROR]'
  );

  /// <summary>
  ///   Known Delphi unit scope prefixes to strip before classification.
  /// </summary>
  ScopePrefixes: array[ 0..8 ] of string = (
    'System.',
    'Vcl.',
    'Winapi.',
    'Data.',
    'Xml.',
    'Datasnap.',
    'FMX.',
    'REST.',
    'Net.'
  );

  /// <summary>
  ///   Minimum allowed length for a units_prefix entry in components.json.
  /// </summary>
  MinPrefixLength = 3;

  /// <summary>
  ///   Application version string.
  /// </summary>
  AppVersion = '1.0.0';

  /// <summary>
  ///   Application display name.
  /// </summary>
  AppName = 'DelphiSBOM';

/// <summary>
///   Strips the first matching Delphi scope prefix from a unit name.
///   Returns the stripped name, or the original if no prefix matched.
/// </summary>
function StripScopePrefix( const AUnitName: string ): string;

/// <summary>
///   Formats a log message with the appropriate level prefix.
/// </summary>
function FormatLogMessage( ALevel: TLogLevel; const AMessage: string ): string;

implementation

function StripScopePrefix( const AUnitName: string ): string;
begin

  for var Prefix in ScopePrefixes do
    if AUnitName.StartsWith( Prefix, True ) then
      Exit( AUnitName.Substring( Prefix.Length ) );

  Result := AUnitName;

end;

function FormatLogMessage( ALevel: TLogLevel; const AMessage: string ): string;
begin

  Result := LogLevelPrefixes[ ALevel ] + ' ' + AMessage;

end;

end.

