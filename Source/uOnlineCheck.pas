(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uOnlineCheck.pas — Opt-in check of components.json against the libraries' GitHub repositories
  Runs only when asked (the Check Online button, or --check-online): DelphiSBOM makes no network
  connections otherwise. Findings are advice; nothing is written without the user choosing it.
*)
unit uOnlineCheck;

interface

uses
  System.SysUtils, System.Generics.Collections,
  uTypes;

type
  /// <summary>
  ///   Fetches a URL and returns the response body, setting AStatus to the HTTP status (0 when the
  ///   request could not be made). Injected so tests never touch the network.
  /// </summary>
  THttpGet = reference to function( const AUrl: string; out AStatus: Integer ): string;

  /// <summary>
  ///   How much a finding matters.
  /// </summary>
  TOnlineFindingKind = ( ofkInfo, ofkWarning );

  /// <summary>
  ///   One result of the online check for one component.
  /// </summary>
  TOnlineFinding = record
    /// <summary>The manifest component's name.</summary>
    Component: string;
    /// <summary>Information, or a difference that needs a decision.</summary>
    Kind: TOnlineFindingKind;
    /// <summary>What was found, for the user.</summary>
    Message: string;
    /// <summary>The components.json key a suggestion would set ('licence', 'version'); '' when there is none.</summary>
    Field: string;
    /// <summary>The value the suggestion would set.</summary>
    Suggested: string;
  end;

  /// <summary>
  ///   Checks manifest components whose vendor_url is a GitHub repository against GitHub's API:
  ///   licence (GitHub's licence-file detection), latest release or tag, and archived status.
  /// </summary>
  TOnlineChecker = class
  private
    FLog: TProc<TLogLevel, string>;
    FGet: THttpGet;
    FApiBase: string;
    FStopped: Boolean;
    FStopReason: string;

    procedure Log( ALevel: TLogLevel; const AMessage: string );
    function Fetch( const APath: string; out AStatus: Integer ): string;
    procedure CheckComponent( const AEntry: TComponentEntry; AFindings: TList<TOnlineFinding> );
  public
    /// <summary>
    ///   Creates a checker.
    /// </summary>
    /// <param name="ALogProc">Logging callback (may be nil).</param>
    /// <param name="AGet">The HTTP fetch to use; nil uses DefaultHttpGet.</param>
    constructor Create( ALogProc: TProc<TLogLevel, string>; AGet: THttpGet = nil );

    /// <summary>
    ///   Checks every component of the manifest. A component without a GitHub vendor_url gets an
    ///   information finding saying it was not checked. After GitHub refuses a request for its rate
    ///   limit, or cannot be reached, the remaining components are not requested.
    /// </summary>
    /// <param name="AManifest">The loaded components.json.</param>
    /// <returns>The findings, in manifest order.</returns>
    function Check( const AManifest: TManifest ): TArray<TOnlineFinding>;

    /// <summary>
    ///   The API root requested (https://api.github.com by default; the DELPHISBOM_GITHUB_API
    ///   environment variable overrides it, for tests against a local server).
    /// </summary>
    property ApiBase: string read FApiBase write FApiBase;
  end;

/// <summary>
///   Splits a GitHub repository URL (https://github.com/owner/repo, with or without .git, a trailing
///   slash or a deeper path) into owner and repository.
/// </summary>
/// <param name="AUrl">The URL.</param>
/// <param name="AOwner">The owner, when it returns True.</param>
/// <param name="ARepo">The repository, when it returns True.</param>
/// <returns>True for a github.com repository URL.</returns>
function ParseGitHubRepo( const AUrl: string; out AOwner, ARepo: string ): Boolean;

/// <summary>
///   The version a release tag names: everything from its first digit ('v3.7.8' gives '3.7.8',
///   'version_507' gives '507'); '' when the tag has no digit.
/// </summary>
/// <param name="ATag">The tag name.</param>
/// <returns>The version text.</returns>
function TagToVersion( const ATag: string ): string;

/// <summary>
///   True when two version strings have the same digits in the same order, ignoring punctuation:
///   '5.07' and the tag version '507' match. A loose test, so a match is reported, not a mismatch proved.
/// </summary>
/// <param name="AVersion">The manifest version.</param>
/// <param name="ATagVersion">The version from a release tag.</param>
/// <returns>True when the digits agree.</returns>
function VersionsMatch( const AVersion, ATagVersion: string ): Boolean;

/// <summary>
///   An HTTP GET with THTTPClient: GitHub's JSON media type, a User-Agent, timeouts, and the
///   GITHUB_TOKEN environment variable as a bearer token when set.
/// </summary>
/// <returns>The fetch function.</returns>
function DefaultHttpGet: THttpGet;

var
  /// <summary>
  ///   Test seam: when assigned, a checker created without its own fetch uses this instead of
  ///   DefaultHttpGet, so the command line can be tested without the network. Leave nil in production.
  /// </summary>
  OnlineHttpOverride: THttpGet;

implementation

uses
  System.JSON, System.RegularExpressions, System.Net.HttpClient, System.Net.URLClient, System.NetConsts;

function ParseGitHubRepo( const AUrl: string; out AOwner, ARepo: string ): Boolean;
begin

  AOwner            := '';
  ARepo             := '';

  var Match         := TRegEx.Match( Trim( AUrl ),
    '^https?://(www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?(/.*)?$', [ roIgnoreCase ] );

  Result            := Match.Success;

  if Result then
  begin
    AOwner          := Match.Groups[ 2 ].Value;
    ARepo           := Match.Groups[ 3 ].Value;
  end;

end;

function TagToVersion( const ATag: string ): string;
begin

  var Match         := TRegEx.Match( ATag, '\d.*$' );

  if Match.Success then
    Result          := Match.Value
  else
    Result          := '';

end;

function VersionsMatch( const AVersion, ATagVersion: string ): Boolean;
begin

  var Digits        := TRegEx.Replace( AVersion, '\D', '' );
  Result            := ( Digits <> '' ) and ( Digits = TRegEx.Replace( ATagVersion, '\D', '' ) );

end;

function DefaultHttpGet: THttpGet;
begin

  Result            :=
    function( const AUrl: string; out AStatus: Integer ): string
    begin
      var Client    := THTTPClient.Create;
      try
        Client.UserAgent := AppName + '/' + AppVersion;
        Client.Accept := 'application/vnd.github+json';
        Client.ConnectionTimeout := 10000;
        Client.ResponseTimeout := 20000;

        var Headers: TNetHeaders := nil;
        var Token   := GetEnvironmentVariable( 'GITHUB_TOKEN' );

        if Token <> '' then
          Headers   := [ TNameValuePair.Create( 'Authorization', 'Bearer ' + Token ) ];

        try
          var Response := Client.Get( AUrl, nil, Headers );
          AStatus   := Response.StatusCode;
          Result    := Response.ContentAsString( TEncoding.UTF8 );
        except
          on E: ENetException do
          begin
            AStatus := 0;
            Result  := E.Message;
          end;
        end;
      finally
        Client.Free;
      end;
    end;

end;

/// <summary>A finding.</summary>
function Finding( const AComponent: string; AKind: TOnlineFindingKind; const AMessage: string;
  const AField: string = ''; const ASuggested: string = '' ): TOnlineFinding;
begin

  Result.Component  := AComponent;
  Result.Kind       := AKind;
  Result.Message    := AMessage;
  Result.Field      := AField;
  Result.Suggested  := ASuggested;

end;

{ TOnlineChecker }

constructor TOnlineChecker.Create( ALogProc: TProc<TLogLevel, string>; AGet: THttpGet );
begin

  inherited Create;
  FLog              := ALogProc;
  FGet              := AGet;

  if ( not Assigned( FGet ) ) then
    FGet            := OnlineHttpOverride;

  if ( not Assigned( FGet ) ) then
    FGet            := DefaultHttpGet();

  FApiBase          := GetEnvironmentVariable( 'DELPHISBOM_GITHUB_API' );

  if FApiBase = '' then
    FApiBase        := 'https://api.github.com';

end;

procedure TOnlineChecker.Log( ALevel: TLogLevel; const AMessage: string );
begin

  if Assigned( FLog ) then
    FLog( ALevel, AMessage );

end;

function TOnlineChecker.Fetch( const APath: string; out AStatus: Integer ): string;
begin

  Result            := FGet( FApiBase + APath, AStatus );

  // GitHub answers 403 or 429 once the hourly limit is spent; 0 means it could not be reached at all
  if ( AStatus = 403 ) or ( AStatus = 429 ) then
  begin
    FStopped        := True;
    FStopReason     := 'GitHub refused the request (rate limit reached — set GITHUB_TOKEN for a higher limit)';
  end
  else if AStatus = 0 then
  begin
    FStopped        := True;
    FStopReason     := 'GitHub could not be reached: ' + Result;
  end;

end;

procedure TOnlineChecker.CheckComponent( const AEntry: TComponentEntry; AFindings: TList<TOnlineFinding> );
begin

  var Name          := AEntry.Name;
  var Owner, Repo: string;

  if Trim( AEntry.VendorURL ) = '' then
  begin
    AFindings.Add( Finding( Name, ofkInfo, 'no vendor_url — not checked' ) );
    Exit;
  end;

  if ( not ParseGitHubRepo( AEntry.VendorURL, Owner, Repo ) ) then
  begin
    AFindings.Add( Finding( Name, ofkInfo, Format( 'vendor_url %s is not a GitHub repository — not checked', [ AEntry.VendorURL ] ) ) );
    Exit;
  end;

  if FStopped then
  begin
    AFindings.Add( Finding( Name, ofkInfo, 'not checked — GitHub stopped answering earlier in this check' ) );
    Exit;
  end;

  // The repository: licence detection and archived flag
  var Status: Integer;
  var Body          := Fetch( Format( '/repos/%s/%s', [ Owner, Repo ] ), Status );

  if FStopped then
  begin
    AFindings.Add( Finding( Name, ofkWarning, FStopReason ) );
    Exit;
  end;

  if Status <> 200 then
  begin
    AFindings.Add( Finding( Name, ofkWarning, Format( 'GitHub repository %s/%s not found (HTTP %d) — check vendor_url', [ Owner, Repo, Status ] ) ) );
    Exit;
  end;

  var RepoJson      := TJSONObject.ParseJSONValue( Body );
  try
    if ( not ( RepoJson is TJSONObject ) ) then
    begin
      AFindings.Add( Finding( Name, ofkWarning, 'GitHub sent an answer that is not JSON' ) );
      Exit;
    end;

    var Spdx        := '';
    var LicenceValue := TJSONObject( RepoJson ).GetValue( 'license' );

    if LicenceValue is TJSONObject then
      TJSONObject( LicenceValue ).TryGetValue<string>( 'spdx_id', Spdx );

    var Manifest    := '';
    ClassifyLicence( AEntry.Licence, Manifest );

    if Spdx = '' then
      AFindings.Add( Finding( Name, ofkInfo, 'GitHub finds no licence file in the repository; the licence may be stated only in ' +
        'the source headers — check them' ) )
    else if SameText( Spdx, 'NOASSERTION' ) then
      AFindings.Add( Finding( Name, ofkInfo, 'GitHub finds a licence file it cannot identify — read it' ) )
    else if Manifest = '' then
      AFindings.Add( Finding( Name, ofkWarning, Format( 'GitHub detects the licence %s on the default branch; the manifest has none — ' +
        'set it if it applies to the version you use', [ Spdx ] ), 'licence', Spdx ) )
    else if SameText( Manifest, Spdx ) then
      AFindings.Add( Finding( Name, ofkInfo, Format( 'licence %s matches GitHub', [ Spdx ] ) ) )
    else if TRegEx.IsMatch( Manifest, '(^|[\s(])' + TRegEx.Escape( Spdx ) + '($|[\s)])', [ roIgnoreCase ] ) then
      AFindings.Add( Finding( Name, ofkInfo, Format( 'GitHub detects %s, one of the manifest''s licences (%s)', [ Spdx, Manifest ] ) ) )
    else
      AFindings.Add( Finding( Name, ofkWarning, Format( 'the manifest says %s, GitHub detects %s on the default branch — check which ' +
        'applies to the version you use', [ Manifest, Spdx ] ), 'licence', Spdx ) );

    var Archived    := False;
    TJSONObject( RepoJson ).TryGetValue<Boolean>( 'archived', Archived );

    if Archived then
      AFindings.Add( Finding( Name, ofkWarning, 'the repository is archived — it is no longer maintained' ) );
  finally
    RepoJson.Free;
  end;

  // The latest release, or the newest tag when there are no releases
  var Tag           := '';
  Body              := Fetch( Format( '/repos/%s/%s/releases/latest', [ Owner, Repo ] ), Status );

  if ( not FStopped ) and ( Status = 200 ) then
  begin
    var Release     := TJSONObject.ParseJSONValue( Body );
    try
      if Release is TJSONObject then
        TJSONObject( Release ).TryGetValue<string>( 'tag_name', Tag );
    finally
      Release.Free;
    end;
  end
  else if ( not FStopped ) and ( Status = 404 ) then
  begin
    Body            := Fetch( Format( '/repos/%s/%s/tags?per_page=1', [ Owner, Repo ] ), Status );

    if ( not FStopped ) and ( Status = 200 ) then
    begin
      var Tags      := TJSONObject.ParseJSONValue( Body );
      try
        if ( Tags is TJSONArray ) and ( TJSONArray( Tags ).Count > 0 ) and ( TJSONArray( Tags ).Items[ 0 ] is TJSONObject ) then
          TJSONObject( TJSONArray( Tags ).Items[ 0 ] ).TryGetValue<string>( 'name', Tag );
      finally
        Tags.Free;
      end;
    end;
  end;

  if FStopped then
  begin
    AFindings.Add( Finding( Name, ofkWarning, FStopReason ) );
    Exit;
  end;

  var TagVersion    := TagToVersion( Tag );

  if Tag = '' then
    AFindings.Add( Finding( Name, ofkInfo, 'no releases or tags on GitHub' ) )
  else if Trim( AEntry.Version ) = '' then
    AFindings.Add( Finding( Name, ofkWarning, Format( 'GitHub''s latest release is %s; the manifest has no version — set it only if ' +
      'that is the version you use', [ Tag ] ), 'version', TagVersion ) )
  else if VersionsMatch( AEntry.Version, TagVersion ) then
    AFindings.Add( Finding( Name, ofkInfo, Format( 'version %s is current (latest release %s)', [ AEntry.Version, Tag ] ) ) )
  else
    AFindings.Add( Finding( Name, ofkWarning, Format( 'GitHub''s latest release is %s; the manifest says %s — update the library, or ' +
      'the manifest if it is out of date', [ Tag, AEntry.Version ] ) ) );

  // The registered purl type for GitHub, for information: the SBOM keeps pkg:delphi
  if Tag <> '' then
    AFindings.Add( Finding( Name, ofkInfo, Format( 'GitHub purl: pkg:github/%s/%s@%s', [ Owner, Repo, Tag ] ) ) )
  else
    AFindings.Add( Finding( Name, ofkInfo, Format( 'GitHub purl: pkg:github/%s/%s', [ Owner, Repo ] ) ) );

end;

function TOnlineChecker.Check( const AManifest: TManifest ): TArray<TOnlineFinding>;
begin

  FStopped          := False;
  FStopReason       := '';

  var Findings      := TList<TOnlineFinding>.Create;
  try
    for var Entry in AManifest.Components do
      CheckComponent( Entry, Findings );

    Result          := Findings.ToArray;
  finally
    Findings.Free;
  end;

  var Warnings      := 0;

  for var F in Result do
    if F.Kind = ofkWarning then
      Inc( Warnings );

  Log( llInfo, Format( 'Online check: %d components, %d findings, %d to review', [ Length( AManifest.Components ), Length( Result ), Warnings ] ) );

end;

end.
