(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uMapFile.pas — Reads the units the linker actually used from a detailed Delphi .map file
  Approach after DX.Comply (Olaf Monien, MIT) — see THIRD-PARTY-NOTICES.md
*)
unit uMapFile;

interface

uses
  System.SysUtils;

/// <summary>
///   Extracts the unit names from the text of a Delphi .map file: every M=&lt;Unit&gt; entry of the
///   "Detailed map of segments" and every "Line numbers for &lt;Unit&gt;(&lt;File&gt;)" header. Each unit
///   appears once, in first-seen order, with its casing as written; names are compared case-insensitively.
/// </summary>
/// <param name="AMapText">The contents of the .map file.</param>
/// <returns>The linked unit names; empty when the text holds neither kind of entry.</returns>
function ParseMapUnitNames( const AMapText: string ): TArray<string>;

/// <summary>
///   Reads a .map file and returns the units the linker used (see ParseMapUnitNames).
/// </summary>
/// <param name="AMapFile">Full path of the .map file.</param>
/// <returns>The linked unit names.</returns>
/// <exception cref="Exception">The file does not exist, cannot be read, or lists no units (not a
///   detailed or segments map).</exception>
function ReadMapUnitNames( const AMapFile: string ): TArray<string>;

implementation

uses
  System.Generics.Collections, System.RegularExpressions,
  uTextFiles;

function ParseMapUnitNames( const AMapText: string ): TArray<string>;
begin

  // " 0001:00000000 0001A84C C=CODE S=.text G=(none) M=System.Types ALIGN=4"
  var SegmentEntry  := TRegEx.Create( '\bM=([A-Za-z_][A-Za-z0-9_\.]*)' );

  // "Line numbers for uSettings(System.Generics.Collections.pas) segment .text" — the unit is before the bracket
  var LineNumbers   := TRegEx.Create( '^\s*Line numbers for\s+([A-Za-z_][A-Za-z0-9_\.]*)\s*\(', [ roIgnoreCase ] );

  var Seen          := TDictionary<string, Boolean>.Create;
  var Units         := TList<string>.Create;
  try
    for var Line in AMapText.Split( [ #10 ] ) do
    begin
      var Match     := SegmentEntry.Match( Line );

      if ( not Match.Success ) then
        Match       := LineNumbers.Match( Line );

      if Match.Success then
      begin
        var UnitName := Match.Groups[ 1 ].Value;

        if Seen.TryAdd( LowerCase( UnitName ), True ) then
          Units.Add( UnitName );
      end;
    end;

    Result          := Units.ToArray;
  finally
    Units.Free;
    Seen.Free;
  end;

end;

function ReadMapUnitNames( const AMapFile: string ): TArray<string>;
begin

  if ( not FileExists( AMapFile ) ) then
    raise Exception.CreateFmt( 'MAP file not found: %s', [ AMapFile ] );

  Result            := ParseMapUnitNames( ReadTextFile( AMapFile ) );

  if Length( Result ) = 0 then
    raise Exception.CreateFmt( 'No units found in %s — build with a detailed map file (Project Options > Building > ' +
      'Delphi Compiler > Linking > Map file = Detailed)', [ AMapFile ] );

end;

end.
