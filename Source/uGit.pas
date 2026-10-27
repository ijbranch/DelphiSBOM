(*
  DelphiSBOM — CycloneDX 1.6 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uGit.pas — Runs git without a window, for the stored GitHub credential and the latest tag
  --version-from-git-tag follows DX.Comply (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uGit;

interface

/// <summary>
///   Runs git with AArguments in AWorkingDir, without a window and non-interactively
///   (GCM_INTERACTIVE=never, GIT_TERMINAL_PROMPT=0), writes AInput to its standard input, and returns
///   standard output and standard error together. Meant for commands with a short answer: the output
///   is read once git has exited, so it must fit the pipe buffer.
/// </summary>
/// <param name="AArguments">The command line after "git", e.g. 'describe --tags --abbrev=0'.</param>
/// <param name="AWorkingDir">The folder git runs in ('' = this process's current folder).</param>
/// <param name="AInput">Text sent to git's standard input as UTF-8 ('' = none).</param>
/// <param name="AOutput">What git wrote, decoded as UTF-8.</param>
/// <returns>True when git ran and exited with code 0 within ten seconds; False when it is not installed,
///   failed, or took longer.</returns>
function RunGit( const AArguments, AWorkingDir, AInput: string; out AOutput: string ): Boolean;

/// <summary>
///   The newest tag reachable from the checked-out commit in AWorkingDir ("git describe --tags --abbrev=0"),
///   or '' when git is not installed, the folder is not in a git work tree, or no tag is reachable.
/// </summary>
/// <param name="AWorkingDir">A folder inside the work tree.</param>
/// <returns>The tag name as git reports it, e.g. 'v1.2.3'.</returns>
function LatestGitTag( const AWorkingDir: string ): string;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Classes;

/// <summary>
///   This process's environment as a Unicode environment block, with AOverrides (NAME=value) replacing
///   any variable of the same name.
/// </summary>
function EnvironmentWith( const AOverrides: array of string ): string;
begin

  var Names         := TStringList.Create;
  try
    for var O in AOverrides do
      Names.Add( UpperCase( Copy( O, 1, Pos( '=', O ) ) ) );

    var Builder     := TStringBuilder.Create;
    try
      var Block     := GetEnvironmentStrings;
      try
        var P       := Block;

        while P^ <> #0 do
        begin
          var Entry := string( P );

          if Names.IndexOf( UpperCase( Copy( Entry, 1, Pos( '=', Entry ) ) ) ) < 0 then
            Builder.Append( Entry ).Append( #0 );

          Inc( P, Length( Entry ) + 1 );
        end;
      finally
        FreeEnvironmentStrings( Block );
      end;

      for var O in AOverrides do
        Builder.Append( O ).Append( #0 );

      Builder.Append( #0 );
      Result        := Builder.ToString;
    finally
      Builder.Free;
    end;
  finally
    Names.Free;
  end;

end;

function RunGit( const AArguments, AWorkingDir, AInput: string; out AOutput: string ): Boolean;
begin

  Result            := False;
  AOutput           := '';

  var Security: TSecurityAttributes;
  Security.nLength  := SizeOf( Security );
  Security.lpSecurityDescriptor := nil;
  Security.bInheritHandle := True;

  var InRead, InWrite, OutRead, OutWrite: THandle;

  if ( not CreatePipe( InRead, InWrite, @Security, 0 ) ) then Exit;
  try
    if ( not CreatePipe( OutRead, OutWrite, @Security, 0 ) ) then Exit;
    try
      // Only the child's ends are inherited
      SetHandleInformation( InWrite, HANDLE_FLAG_INHERIT, 0 );
      SetHandleInformation( OutRead, HANDLE_FLAG_INHERIT, 0 );

      var Startup   := Default( TStartupInfo );
      Startup.cb    := SizeOf( Startup );
      Startup.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
      Startup.wShowWindow := SW_HIDE;
      Startup.hStdInput := InRead;
      Startup.hStdOutput := OutWrite;
      Startup.hStdError := OutWrite;

      // Never a sign-in window or a terminal prompt: a missing credential must fail, not open a dialog
      var Environment := EnvironmentWith( [ 'GCM_INTERACTIVE=never', 'GIT_TERMINAL_PROMPT=0' ] );
      var Command   := 'git ' + AArguments;
      UniqueString( Command );

      var WorkingDir: PChar := nil;

      if AWorkingDir <> '' then
        WorkingDir  := PChar( AWorkingDir );

      var Process: TProcessInformation;

      if ( not CreateProcess( nil, PChar( Command ), nil, nil, True, CREATE_NO_WINDOW or CREATE_UNICODE_ENVIRONMENT,
        PChar( Environment ), WorkingDir, Startup, Process ) ) then Exit;
      try
        CloseHandle( InRead );
        InRead      := 0;
        CloseHandle( OutWrite );
        OutWrite    := 0;

        if AInput <> '' then
        begin
          var Request := UTF8Encode( AInput );
          var Written: DWORD;
          WriteFile( InWrite, Request[ 1 ], Length( Request ), Written, nil );
        end;

        CloseHandle( InWrite );
        InWrite     := 0;

        // The answer is far smaller than the pipe buffer, so the child never blocks writing it
        if WaitForSingleObject( Process.hProcess, 10000 ) <> WAIT_OBJECT_0 then
        begin
          TerminateProcess( Process.hProcess, 1 );
          Exit;
        end;

        var Bytes: TBytes := nil;
        var Buffer: array[ 0..4095 ] of Byte;
        var Read: DWORD;

        while ReadFile( OutRead, Buffer, SizeOf( Buffer ), Read, nil ) and ( Read > 0 ) do
        begin
          var Used  := Length( Bytes );
          SetLength( Bytes, Used + Integer( Read ) );
          Move( Buffer[ 0 ], Bytes[ Used ], Read );
        end;

        AOutput     := TEncoding.UTF8.GetString( Bytes );

        var ExitCode: DWORD;
        Result      := GetExitCodeProcess( Process.hProcess, ExitCode ) and ( ExitCode = 0 );
      finally
        CloseHandle( Process.hThread );
        CloseHandle( Process.hProcess );
      end;
    finally
      if OutRead <> 0 then CloseHandle( OutRead );
      if OutWrite <> 0 then CloseHandle( OutWrite );
    end;
  finally
    if InRead <> 0 then CloseHandle( InRead );
    if InWrite <> 0 then CloseHandle( InWrite );
  end;

end;

function LatestGitTag( const AWorkingDir: string ): string;
begin

  var Output: string;

  if ( not RunGit( 'describe --tags --abbrev=0', AWorkingDir, '', Output ) ) then Exit( '' );

  // One line: the tag
  Result            := Trim( Output );

  if Result.Contains( #10 ) then
    Result          := Trim( Copy( Result, 1, Pos( #10, Result ) - 1 ) );

end;

end.
