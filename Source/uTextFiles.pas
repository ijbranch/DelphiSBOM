(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uTextFiles.pas — Encoding-safe text file reading and atomic UTF-8 writing
*)
unit uTextFiles;

interface

uses
  System.SysUtils;

/// <summary>
///   Reads a whole text file, detecting its encoding: a BOM wins; otherwise the bytes are
///   decoded as UTF-8 when they are valid UTF-8, and as the system ANSI code page when not.
/// </summary>
/// <param name="AFileName">Full path of the file to read.</param>
/// <returns>The decoded file content, without any BOM.</returns>
/// <exception cref="EFOpenError">The file cannot be opened.</exception>
/// <remarks>
///   TFile.ReadAllText with an explicit TEncoding.UTF8 decodes an ANSI file containing a single
///   non-ASCII byte to an empty string (or raises), and older RTLs have no ANSI fallback at all.
/// </remarks>
function ReadTextFile( const AFileName: string ): string;

/// <summary>
///   Reads at most AMaxBytes from the start of a text file, with the same encoding detection as
///   ReadTextFile. A multi-byte UTF-8 sequence cut off by the limit is dropped, not treated as ANSI.
/// </summary>
/// <param name="AFileName">Full path of the file to read.</param>
/// <param name="AMaxBytes">Maximum number of bytes to read from the start of the file.</param>
/// <returns>The decoded head of the file.</returns>
/// <exception cref="EFOpenError">The file cannot be opened.</exception>
function ReadTextFileHead( const AFileName: string; AMaxBytes: Integer ): string;

/// <summary>
///   Writes text as UTF-8 without a BOM (RFC 8259 forbids a BOM in JSON). The content goes to a
///   temporary file beside the target, which then replaces the target, so a failed write never
///   leaves a truncated file behind.
/// </summary>
/// <param name="AFileName">Full path of the file to create or replace.</param>
/// <param name="AText">The text to write.</param>
/// <exception cref="EInOutError">The temporary file cannot be written or cannot replace the target.</exception>
procedure WriteTextFileAtomic( const AFileName: string; const AText: string );

implementation

uses
  System.Classes, System.IOUtils, Winapi.Windows;

/// <summary>
///   Returns True when ABytes[ AStart.. ] is well-formed UTF-8. When AAllowTruncatedTail is True,
///   an incomplete sequence at the very end is accepted (the buffer was cut short).
/// </summary>
function IsValidUTF8( const ABytes: TBytes; AStart: Integer; AAllowTruncatedTail: Boolean ): Boolean;
begin

  var I             := AStart;
  var Len           := Length( ABytes );

  while I < Len do
  begin
    var B           := ABytes[ I ];
    var Follow: Integer;

    if B < $80 then
      Follow        := 0
    else if ( B and $E0 ) = $C0 then
      Follow        := 1
    else if ( B and $F0 ) = $E0 then
      Follow        := 2
    else if ( B and $F8 ) = $F0 then
      Follow        := 3
    else
      Exit( False );

    if ( Follow = 1 ) and ( B < $C2 ) then Exit( False ); // Overlong two-byte form

    if I + Follow >= Len then
      Exit( AAllowTruncatedTail and ( Follow > 0 ) );

    for var J := 1 to Follow do
      if ( ABytes[ I + J ] and $C0 ) <> $80 then
        Exit( False );

    Inc( I, Follow + 1 );
  end;

  Result            := True;

end;

/// <summary>
///   Decodes a byte buffer using BOM detection, then UTF-8 validation, then ANSI.
/// </summary>
function DecodeBytes( const ABytes: TBytes; ATruncated: Boolean ): string;
begin

  var Encoding: TEncoding := nil;
  var BOMLength     := TEncoding.GetBufferEncoding( ABytes, Encoding, TEncoding.UTF8 );
  var Count         := Length( ABytes ) - BOMLength;

  if BOMLength > 0 then
    Exit( Encoding.GetString( ABytes, BOMLength, Count ) );

  if IsValidUTF8( ABytes, 0, ATruncated ) then
  begin
    // Drop an incomplete trailing sequence so the strict decoder does not reject the buffer
    if ATruncated then
    begin
      var Tail      := Length( ABytes ) - 1;

      while ( Tail >= 0 ) and ( ( ABytes[ Tail ] and $C0 ) = $80 ) do
        Dec( Tail );

      if ( Tail >= 0 ) and ( ABytes[ Tail ] >= $C0 ) then
      begin
        var Need    := 1;

        if ( ABytes[ Tail ] and $F0 ) = $E0 then
          Need      := 2
        else if ( ABytes[ Tail ] and $F8 ) = $F0 then
          Need      := 3;

        if Length( ABytes ) - 1 - Tail < Need then
          Count     := Tail;
      end;
    end;

    Exit( TEncoding.UTF8.GetString( ABytes, 0, Count ) );
  end;

  Result            := TEncoding.ANSI.GetString( ABytes, 0, Count );

end;

function ReadTextFile( const AFileName: string ): string;
begin

  Result            := DecodeBytes( TFile.ReadAllBytes( AFileName ), False );

end;

function ReadTextFileHead( const AFileName: string; AMaxBytes: Integer ): string;
begin

  var Stream        := TFileStream.Create( AFileName, fmOpenRead or fmShareDenyWrite );
  try
    var Size        := Stream.Size;
    var Truncated   := Size > AMaxBytes;

    if Truncated then
      Size          := AMaxBytes;

    var Bytes: TBytes;
    SetLength( Bytes, Size );

    if Size > 0 then
      Stream.ReadBuffer( Bytes[ 0 ], Size );

    Result          := DecodeBytes( Bytes, Truncated );
  finally
    Stream.Free;
  end;

end;

procedure WriteTextFileAtomic( const AFileName: string; const AText: string );
begin

  var TempFile      := AFileName + '.tmp';
  var Bytes         := TEncoding.UTF8.GetBytes( AText );

  TFile.WriteAllBytes( TempFile, Bytes );

  if ( not MoveFileEx( PChar( TempFile ), PChar( AFileName ), MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH ) ) then
  begin
    var LastError   := GetLastError;
    System.SysUtils.DeleteFile( TempFile );
    raise EInOutError.CreateFmt( 'Could not replace %s: %s', [ AFileName, SysErrorMessage( LastError ) ] );
  end;

end;

end.

