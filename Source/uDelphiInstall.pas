(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uDelphiInstall.pas — Locates installed Delphi (BDS) versions from the registry
*)
unit uDelphiInstall;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   One installed Delphi (BDS) version found in the registry.
  /// </summary>
  TDelphiInstall = record
    /// <summary>BDS registry version, e.g. '37.0' for Delphi 13.</summary>
    BDSVersion: string;
    /// <summary>Installation root directory without a trailing delimiter.</summary>
    RootDir: string;
  end;

/// <summary>
///   Returns every installed BDS version whose RootDir still exists on disk, highest first.
///   Reads HKEY_CURRENT_USER first (written once the IDE has been run), then the installer's
///   HKEY_LOCAL_MACHINE key in the 32-bit registry view.
/// </summary>
/// <returns>The installations found; empty when none is installed.</returns>
function GetDelphiInstalls: TArray<TDelphiInstall>;

/// <summary>
///   Picks the installation to use for a project: the one matching APreferredVersion when it is
///   installed, otherwise the highest installed version.
/// </summary>
/// <param name="APreferredVersion">BDS version the project targets (e.g. '36.0'); may be empty.</param>
/// <param name="AInstall">The chosen installation.</param>
/// <param name="AExactMatch">True when the chosen installation is APreferredVersion.</param>
/// <returns>False when no Delphi installation is found.</returns>
function FindDelphiInstall( const APreferredVersion: string; out AInstall: TDelphiInstall; out AExactMatch: Boolean ): Boolean;

implementation

uses
  System.Classes, System.Generics.Collections, System.Generics.Defaults, System.Math, System.Win.Registry, Winapi.Windows;

const
  BDSKey            = 'Software\Embarcadero\BDS';

/// <summary>
///   Parses a BDS version key name ('37.0') to a number for ordering; returns -1 when not numeric.
/// </summary>
function VersionValue( const AVersion: string ): Double;
begin

  if ( not TryStrToFloat( AVersion, Result, TFormatSettings.Create( 'en-US' ) ) ) then
    Result          := -1;

end;

/// <summary>
///   Adds every BDS version under ARootKey whose RootDir exists to AList, skipping versions
///   already present (the first registry hive read wins).
/// </summary>
procedure CollectInstalls( ARootKey: HKEY; AAccess: LongWord; AList: TList<TDelphiInstall> );
begin

  var Reg           := TRegistry.Create( AAccess );
  try
    Reg.RootKey     := ARootKey;

    if ( not Reg.OpenKeyReadOnly( BDSKey ) ) then Exit;

    var SubKeys     := TStringList.Create;
    try
      Reg.GetKeyNames( SubKeys );
      Reg.CloseKey;

      for var Version in SubKeys do
      begin
        if VersionValue( Version ) < 0 then Continue;

        var AlreadyListed := False;

        for var Existing in AList do
          if SameText( Existing.BDSVersion, Version ) then
          begin
            AlreadyListed := True;
            Break;
          end;

        if AlreadyListed then Continue;

        if Reg.OpenKeyReadOnly( BDSKey + '\' + Version ) then
        begin
          try
            if Reg.ValueExists( 'RootDir' ) then
            begin
              var Install: TDelphiInstall;
              Install.BDSVersion := Version;
              Install.RootDir := ExcludeTrailingPathDelimiter( Reg.ReadString( 'RootDir' ) );

              if ( Install.RootDir <> '' ) and DirectoryExists( Install.RootDir ) then
                AList.Add( Install );
            end;
          finally
            Reg.CloseKey;
          end;
        end;
      end;
    finally
      SubKeys.Free;
    end;
  finally
    Reg.Free;
  end;

end;

function GetDelphiInstalls: TArray<TDelphiInstall>;
begin

  var List          := TList<TDelphiInstall>.Create;
  try
    CollectInstalls( HKEY_CURRENT_USER, KEY_READ, List );
    CollectInstalls( HKEY_LOCAL_MACHINE, KEY_READ or KEY_WOW64_32KEY, List );

    List.Sort( TComparer<TDelphiInstall>.Construct(
        function( const ALeft, ARight: TDelphiInstall ): Integer
        begin
          Result    := -CompareValue( VersionValue( ALeft.BDSVersion ), VersionValue( ARight.BDSVersion ) );
        end ) );

    Result          := List.ToArray;
  finally
    List.Free;
  end;

end;

function FindDelphiInstall( const APreferredVersion: string; out AInstall: TDelphiInstall; out AExactMatch: Boolean ): Boolean;
begin

  AInstall          := Default( TDelphiInstall );
  AExactMatch       := False;

  var Installs      := GetDelphiInstalls;

  if Length( Installs ) = 0 then Exit( False );

  for var Install in Installs do
    if SameText( Install.BDSVersion, APreferredVersion ) then
    begin
      AInstall      := Install;
      AExactMatch   := True;
      Exit( True );
    end;

  AInstall          := Installs[ 0 ];
  Result            := True;

end;

end.

