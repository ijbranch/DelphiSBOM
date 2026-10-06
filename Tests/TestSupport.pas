(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestSupport.pas — Shared helpers for the DUnitX suite: scratch directories and file writers
*)
unit TestSupport;

interface

uses
  System.SysUtils,
  uTypes;

type
  /// <summary>
  ///   A uniquely named scratch directory under %TEMP%, deleted when the object is freed.
  ///   Each test fixture creates one in its [Setup] so tests never share or leave files behind.
  /// </summary>
  TScratchDir = class
  private
    FPath: string;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    ///   Returns the full path of ARelative inside the scratch directory.
    /// </summary>
    /// <param name="ARelative">Relative path, e.g. 'App\App.dpr'.</param>
    /// <returns>The combined full path.</returns>
    function PathOf( const ARelative: string ): string;

    /// <summary>Full path of the scratch directory.</summary>
    property Path: string read FPath;
  end;

/// <summary>
///   Writes AText encoded in the system ANSI code page, without a BOM, creating parent directories.
/// </summary>
/// <param name="AFileName">Full path of the file to write.</param>
/// <param name="AText">The text to write.</param>
procedure WriteAnsiFile( const AFileName, AText: string );

/// <summary>
///   Writes AText as UTF-8 without a BOM, creating parent directories.
/// </summary>
/// <param name="AFileName">Full path of the file to write.</param>
/// <param name="AText">The text to write.</param>
procedure WriteUtf8File( const AFileName, AText: string );

/// <summary>
///   Returns a logging callback that discards every message.
/// </summary>
/// <returns>A no-op TProc&lt;TLogLevel, string&gt;.</returns>
function NoLog: TProc<TLogLevel, string>;

implementation

uses
  System.IOUtils;

{ TScratchDir }

constructor TScratchDir.Create;
begin

  inherited Create;
  FPath := TPath.Combine( TPath.GetTempPath, 'DelphiSBOMTests-' + TGUID.NewGuid.ToString );
  TDirectory.CreateDirectory( FPath );

end;

destructor TScratchDir.Destroy;
begin

  if TDirectory.Exists( FPath ) then
    TDirectory.Delete( FPath, True );

  inherited;

end;

function TScratchDir.PathOf( const ARelative: string ): string;
begin

  Result := TPath.Combine( FPath, ARelative );

end;

procedure WriteBytesFile( const AFileName: string; const ABytes: TBytes );
begin

  ForceDirectories( ExtractFilePath( AFileName ) );
  TFile.WriteAllBytes( AFileName, ABytes );

end;

procedure WriteAnsiFile( const AFileName, AText: string );
begin

  WriteBytesFile( AFileName, TEncoding.ANSI.GetBytes( AText ) );

end;

procedure WriteUtf8File( const AFileName, AText: string );
begin

  WriteBytesFile( AFileName, TEncoding.UTF8.GetBytes( AText ) );

end;

function NoLog: TProc<TLogLevel, string>;
begin

  Result :=
    procedure( ALevel: TLogLevel; AMessage: string )
    begin
    end;

end;

end.
