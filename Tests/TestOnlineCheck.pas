(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestOnlineCheck.pas — Tests for the opt-in online check, against a fake GitHub API (no network)
*)
unit TestOnlineCheck;

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  uTypes, uOnlineCheck;

type
  /// <summary>
  ///   URL parsing, tag versions, and the findings for each kind of repository, from canned responses.
  /// </summary>
  [TestFixture]
  TOnlineCheckTests = class
  private
    FResponses: TDictionary<string, TPair<Integer, string>>;
    FRequests: TList<string>;

    function FakeGet: THttpGet;
    procedure Respond( const APath: string; AStatus: Integer; const ABody: string );
    function Entry( const AName, AUrl, ALicence, AVersion: string ): TComponentEntry;
    function Run( const AEntries: TArray<TComponentEntry> ): TArray<TOnlineFinding>;
    function FindingsFor( const AFindings: TArray<TOnlineFinding>; const AComponent: string ): TArray<TOnlineFinding>;
    function HasFinding( const AFindings: TArray<TOnlineFinding>; const AComponent, AText: string;
      AKind: TOnlineFindingKind; const AField: string = ''; const ASuggested: string = '' ): Boolean;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    /// <summary>
    ///   Proves repository URLs are split into owner and repository however they are written, and that
    ///   a non-GitHub or owner-only URL is refused, so no request is made for it.
    /// </summary>
    /// <param name="AUrl">The vendor_url.</param>
    /// <param name="AExpected">"owner/repo", or "" when the URL is not a repository.</param>
    [Test]
    [TestCase( 'plain', 'https://github.com/pleriche/FastMM5|pleriche/FastMM5', '|' )]
    [TestCase( 'git suffix', 'https://github.com/acme/widgets.git|acme/widgets', '|' )]
    [TestCase( 'deeper path, www, http', 'http://www.github.com/acme/widgets/tree/master/src|acme/widgets', '|' )]
    [TestCase( 'trailing slash', 'https://github.com/acme/widgets/|acme/widgets', '|' )]
    [TestCase( 'other host', 'https://vendor.example.com/acme/widgets|', '|' )]
    [TestCase( 'owner only', 'https://github.com/acme|', '|' )]
    procedure RepoUrlsAreParsed( const AUrl, AExpected: string );

    /// <summary>
    ///   Proves a tag's version starts at its first digit, and versions compare by their digits only,
    ///   so FastMM5's tag version_507 matches the manifest's 5.07.
    /// </summary>
    [Test]
    procedure TagVersionsAndMatching;

    /// <summary>
    ///   Proves a repository with no licence file is reported as such (the licence is then only in the
    ///   source headers, as with FastMM5) with no suggestion, and a matching release is reported as current.
    /// </summary>
    [Test]
    procedure NoLicenceFileAndCurrentRelease;

    /// <summary>
    ///   Proves an empty licence and version get suggestions from GitHub's licence and, when there is
    ///   no release, the newest tag.
    /// </summary>
    [Test]
    procedure EmptyFieldsGetSuggestions;

    /// <summary>
    ///   Proves a licence that differs from GitHub's is a warning with GitHub's as the suggestion, an
    ///   archived repository is a warning, and a newer release is a warning with no suggestion — the
    ///   manifest must keep the version actually used.
    /// </summary>
    [Test]
    procedure DifferencesAreWarnings;

    /// <summary>
    ///   Proves a component without a vendor_url, or with one that is not GitHub, is reported as not
    ///   checked, and no request is made for it.
    /// </summary>
    [Test]
    procedure NonGitHubComponentsAreNotRequested;

    /// <summary>
    ///   Proves that after GitHub refuses a request for its rate limit, the check says so and makes no
    ///   further requests.
    /// </summary>
    [Test]
    procedure RateLimitStopsTheCheck;

    /// <summary>
    ///   Proves the GitHub purl is offered for information, with the tag found.
    /// </summary>
    [Test]
    procedure GitHubPurlIsOffered;

    /// <summary>
    ///   Proves the token's order of precedence: GITHUB_TOKEN when set, without consulting Git Credential
    ///   Manager; otherwise the stored credential; otherwise none.
    /// </summary>
    [Test]
    procedure TokenComesFromEnvironmentThenCredentialManager;

    /// <summary>
    ///   Proves the stored credential is never looked up when requests go anywhere but api.github.com, so
    ///   pointing DELPHISBOM_GITHUB_API elsewhere cannot send the user's GitHub token to that server.
    /// </summary>
    [Test]
    procedure CredentialIsNeverLookedUpForAnotherHost;

    /// <summary>
    ///   Proves the token is the password= line of "git credential fill" output, with LF or CRLF line ends,
    ///   and '' when there is none.
    /// </summary>
    [Test]
    procedure CredentialOutputIsParsed;

    /// <summary>
    ///   Proves a checker given its own fetch never consults the credential source, so tests and callers
    ///   that inject a fetch cannot read a real credential.
    /// </summary>
    [Test]
    procedure InjectedFetchNeverReadsACredential;
  end;

implementation

const
  Api = 'https://api.github.test';

{ TOnlineCheckTests }

procedure TOnlineCheckTests.Setup;
begin

  FResponses := TDictionary<string, TPair<Integer, string>>.Create;
  FRequests  := TList<string>.Create;

end;

procedure TOnlineCheckTests.TearDown;
begin

  FRequests.Free;
  FResponses.Free;

end;

function TOnlineCheckTests.FakeGet: THttpGet;
begin

  var Responses := FResponses;
  var Requests  := FRequests;

  Result :=
    function( const AUrl: string; out AStatus: Integer ): string
    begin
      Requests.Add( AUrl );
      var Response: TPair<Integer, string>;

      if Responses.TryGetValue( AUrl, Response ) then
      begin
        AStatus := Response.Key;
        Result  := Response.Value;
      end
      else
      begin
        AStatus := 404;
        Result  := '{ "message": "Not Found" }';
      end;
    end;

end;

procedure TOnlineCheckTests.Respond( const APath: string; AStatus: Integer; const ABody: string );
begin

  FResponses.AddOrSetValue( Api + APath, TPair<Integer, string>.Create( AStatus, ABody ) );

end;

function TOnlineCheckTests.Entry( const AName, AUrl, ALicence, AVersion: string ): TComponentEntry;
begin

  Result := Default( TComponentEntry );
  Result.Name      := AName;
  Result.VendorURL := AUrl;
  Result.Licence   := ALicence;
  Result.Version   := AVersion;

end;

function TOnlineCheckTests.Run( const AEntries: TArray<TComponentEntry> ): TArray<TOnlineFinding>;
begin

  var Manifest := Default( TManifest );
  Manifest.Components := AEntries;

  var Checker := TOnlineChecker.Create( nil, FakeGet() );
  try
    Checker.ApiBase := Api;
    Result := Checker.Check( Manifest );
  finally
    Checker.Free;
  end;

end;

function TOnlineCheckTests.FindingsFor( const AFindings: TArray<TOnlineFinding>; const AComponent: string ): TArray<TOnlineFinding>;
begin

  Result := nil;

  for var F in AFindings do
    if F.Component = AComponent then
      Result := Result + [ F ];

end;

function TOnlineCheckTests.HasFinding( const AFindings: TArray<TOnlineFinding>; const AComponent, AText: string;
  AKind: TOnlineFindingKind; const AField: string; const ASuggested: string ): Boolean;
begin

  for var F in FindingsFor( AFindings, AComponent ) do
    if ( Pos( LowerCase( AText ), LowerCase( F.Message ) ) > 0 ) and ( F.Kind = AKind ) and ( F.Field = AField ) and
      ( F.Suggested = ASuggested ) then
      Exit( True );

  Result := False;

end;

procedure TOnlineCheckTests.RepoUrlsAreParsed( const AUrl, AExpected: string );
begin

  var Owner, Repo: string;
  var Ok := ParseGitHubRepo( AUrl, Owner, Repo );

  if AExpected = '' then
    Assert.IsFalse( Ok, 'Accepted ' + AUrl )
  else
  begin
    Assert.IsTrue( Ok, 'Refused ' + AUrl );
    Assert.AreEqual( AExpected, Owner + '/' + Repo );
  end;

end;

procedure TOnlineCheckTests.TagVersionsAndMatching;
begin

  Assert.AreEqual( '3.7.8', TagToVersion( 'v3.7.8' ) );
  Assert.AreEqual( '507', TagToVersion( 'version_507' ) );
  Assert.AreEqual( '', TagToVersion( 'latest' ) );
  Assert.IsTrue( VersionsMatch( '5.07', '507' ), '5.07 and 507' );
  Assert.IsFalse( VersionsMatch( '3.7.8', '3.7.9' ), '3.7.8 and 3.7.9' );
  Assert.IsFalse( VersionsMatch( '', '1' ), 'empty version' );

end;

procedure TOnlineCheckTests.NoLicenceFileAndCurrentRelease;
begin

  Respond( '/repos/pleriche/FastMM5', 200, '{ "license": null, "archived": false }' );
  Respond( '/repos/pleriche/FastMM5/releases/latest', 200, '{ "tag_name": "version_507" }' );

  var Findings := Run( [ Entry( 'FastMM5', 'https://github.com/pleriche/FastMM5', 'GPL-3.0-only', '5.07' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'FastMM5', 'no licence file', ofkInfo ), 'No-licence-file finding' );
  Assert.IsTrue( HasFinding( Findings, 'FastMM5', 'current', ofkInfo ), 'Current-release finding' );

  for var F in Findings do
    Assert.AreEqual( '', F.Field, 'Unexpected suggestion: ' + F.Message );

end;

procedure TOnlineCheckTests.EmptyFieldsGetSuggestions;
begin

  Respond( '/repos/acme/threads', 200, '{ "license": { "spdx_id": "BSD-3-Clause" }, "archived": false }' );
  Respond( '/repos/acme/threads/tags?per_page=1', 200, '[ { "name": "v3.7.10" } ]' );

  var Findings := Run( [ Entry( 'Threads', 'https://github.com/acme/threads', '', '' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'Threads', 'BSD-3-Clause', ofkWarning, 'licence', 'BSD-3-Clause' ), 'Licence suggestion' );
  Assert.IsTrue( HasFinding( Findings, 'Threads', 'v3.7.10', ofkWarning, 'version', '3.7.10' ), 'Version suggestion' );

end;

procedure TOnlineCheckTests.DifferencesAreWarnings;
begin

  Respond( '/repos/acme/old', 200, '{ "license": { "spdx_id": "Apache-2.0" }, "archived": true }' );
  Respond( '/repos/acme/old/releases/latest', 200, '{ "tag_name": "v2.0" }' );

  var Findings := Run( [ Entry( 'Old', 'https://github.com/acme/old', 'MIT', '1.0' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'Old', 'Apache-2.0', ofkWarning, 'licence', 'Apache-2.0' ), 'Licence mismatch' );
  Assert.IsTrue( HasFinding( Findings, 'Old', 'archived', ofkWarning ), 'Archived warning' );
  Assert.IsTrue( HasFinding( Findings, 'Old', 'v2.0', ofkWarning ), 'Newer release warning without a suggestion' );

end;

procedure TOnlineCheckTests.NonGitHubComponentsAreNotRequested;
begin

  var Findings := Run( [ Entry( 'Shop', 'https://vendor.example.com', '', '' ), Entry( 'Bare', '', '', '' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'Shop', 'not a GitHub repository', ofkInfo ), 'Non-GitHub finding' );
  Assert.IsTrue( HasFinding( Findings, 'Bare', 'no vendor_url', ofkInfo ), 'No-URL finding' );
  Assert.AreEqual<Integer>( 0, FRequests.Count, 'Requests made: ' + string.Join( ', ', FRequests.ToArray ) );

end;

procedure TOnlineCheckTests.RateLimitStopsTheCheck;
begin

  Respond( '/repos/acme/one', 403, '{ "message": "API rate limit exceeded" }' );

  var Findings := Run( [ Entry( 'One', 'https://github.com/acme/one', '', '' ), Entry( 'Two', 'https://github.com/acme/two', '', '' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'One', 'rate limit', ofkWarning ), 'Rate-limit warning' );
  Assert.AreEqual<Integer>( 1, FRequests.Count, 'Requests after the rate limit: ' + string.Join( ', ', FRequests.ToArray ) );
  Assert.IsTrue( HasFinding( Findings, 'Two', 'not checked', ofkInfo ), 'Later component reported as not checked' );

end;

procedure TOnlineCheckTests.GitHubPurlIsOffered;
begin

  Respond( '/repos/pleriche/FastMM5', 200, '{ "license": null, "archived": false }' );
  Respond( '/repos/pleriche/FastMM5/releases/latest', 200, '{ "tag_name": "version_507" }' );

  var Findings := Run( [ Entry( 'FastMM5', 'https://github.com/pleriche/FastMM5', 'GPL-3.0-only', '5.07' ) ] );

  Assert.IsTrue( HasFinding( Findings, 'FastMM5', 'pkg:github/pleriche/FastMM5@version_507', ofkInfo ), 'GitHub purl' );

end;

procedure TOnlineCheckTests.TokenComesFromEnvironmentThenCredentialManager;
begin

  var Calls := 0;
  var Credential: TFunc<string> :=
    function: string
    begin
      Inc( Calls );
      Result := 'stored-token';
    end;
  var Source: string;

  Assert.AreEqual( 'env-token', ResolveGitHubToken( 'https://api.github.com', 'env-token', Credential, Source ) );
  Assert.AreEqual( 'GITHUB_TOKEN', Source );
  Assert.AreEqual( 0, Calls, 'Credential Manager consulted although GITHUB_TOKEN is set' );

  Assert.AreEqual( 'stored-token', ResolveGitHubToken( 'https://api.github.com/', '', Credential, Source ) );
  Assert.AreEqual( 'Git Credential Manager', Source );

  Assert.AreEqual( '', ResolveGitHubToken( 'https://api.github.com',  '',
    function: string
    begin
      Result := '';
    end, Source ) );
  Assert.AreEqual( 'none', Source );

  Assert.AreEqual( '', ResolveGitHubToken( 'https://api.github.com', '', nil, Source ) );
  Assert.AreEqual( 'none', Source );

end;

procedure TOnlineCheckTests.CredentialIsNeverLookedUpForAnotherHost;
begin

  var Calls := 0;
  var Credential: TFunc<string> :=
    function: string
    begin
      Inc( Calls );
      Result := 'stored-token';
    end;
  var Source: string;

  for var Base in [ 'http://127.0.0.1:5000', 'https://api.github.com.evil.example', 'https://example.com/api.github.com' ] do
  begin
    Assert.AreEqual( '', ResolveGitHubToken( Base, '', Credential, Source ), Base );
    Assert.AreEqual( 'none', Source, Base );
  end;

  Assert.AreEqual( 0, Calls, 'Credential looked up for a non-GitHub host' );

end;

procedure TOnlineCheckTests.CredentialOutputIsParsed;
begin

  Assert.AreEqual( 'abc123', ParseCredentialOutput( 'protocol=https' + #10 + 'host=github.com' + #10 + 'username=me' + #10 +
    'password=abc123' + #10 ) );
  Assert.AreEqual( 'abc123', ParseCredentialOutput( 'protocol=https' + #13#10 + 'password=abc123' + #13#10 ) );
  Assert.AreEqual( '', ParseCredentialOutput( 'protocol=https' + #10 + 'host=github.com' + #10 ) );
  Assert.AreEqual( '', ParseCredentialOutput( '' ) );

end;

procedure TOnlineCheckTests.InjectedFetchNeverReadsACredential;
begin

  var Saved: TFunc<string> := OnlineCredentialSource;
  var Calls := 0;
  OnlineCredentialSource :=
    function: string
    begin
      Inc( Calls );
      Result := 'stored-token';
    end;
  try
    Respond( '/repos/acme/widgets', 200, '{ "license": null, "archived": false }' );
    Run( [ Entry( 'Acme', 'https://github.com/acme/widgets', '', '' ) ] );
    Assert.AreEqual( 0, Calls, 'Credential read although a fetch was injected' );
  finally
    OnlineCredentialSource := Saved;
  end;

end;

end.
