(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestDelphiInstall.pas — Tests for uDelphiInstall (registry detection invariants)
*)
unit TestDelphiInstall;

interface

uses
  DUnitX.TestFramework;

type
  /// <summary>
  ///   Invariants of installation detection that hold on any machine, with or without Delphi installed.
  /// </summary>
  [TestFixture]
  TDelphiInstallTests = class
  public
    /// <summary>
    ///   Proves every reported installation has an existing RootDir (an uninstalled version left in the
    ///   registry was picked before), no version is listed twice, and the list is ordered highest first.
    /// </summary>
    [Test]
    procedure InstallsExistUniqueAndOrdered;

    /// <summary>
    ///   Proves an installed version is chosen as an exact match when asked for, and that asking for a
    ///   version that is not installed falls back to the highest installed one. With no Delphi
    ///   installed, proves FindDelphiInstall reports False.
    /// </summary>
    [Test]
    procedure PreferredVersionThenHighest;
  end;

implementation

uses
  System.SysUtils,
  uDelphiInstall;

{ TDelphiInstallTests }

procedure TDelphiInstallTests.InstallsExistUniqueAndOrdered;
begin

  var Installs := GetDelphiInstalls;
  var Settings := TFormatSettings.Create( 'en-US' );
  var Install: TDelphiInstall;
  var Exact := False;

  // Detection and selection must agree: something is chosen exactly when something is installed
  Assert.AreEqual<Boolean>( Length( Installs ) > 0, FindDelphiInstall( '', Install, Exact ) );

  for var I := 0 to High( Installs ) do
  begin
    Assert.IsTrue( DirectoryExists( Installs[ I ].RootDir ), Installs[ I ].RootDir );

    for var J := I + 1 to High( Installs ) do
    begin
      Assert.AreNotEqual( Installs[ I ].BDSVersion, Installs[ J ].BDSVersion, False, 'Duplicate version' );
      Assert.IsTrue( StrToFloat( Installs[ I ].BDSVersion, Settings ) > StrToFloat( Installs[ J ].BDSVersion, Settings ), 'Not highest first' );
    end;
  end;

end;

procedure TDelphiInstallTests.PreferredVersionThenHighest;
begin

  var Installs := GetDelphiInstalls;
  var Install: TDelphiInstall;
  var Exact := False;

  if Length( Installs ) = 0 then
  begin
    Assert.IsFalse( FindDelphiInstall( '37.0', Install, Exact ) );
    Exit;
  end;

  // The lowest installed version is found as an exact match, not replaced by the highest
  var Lowest := Installs[ High( Installs ) ];

  Assert.IsTrue( FindDelphiInstall( Lowest.BDSVersion, Install, Exact ) );
  Assert.IsTrue( Exact );
  Assert.AreEqual( Lowest.RootDir, Install.RootDir, False );

  // A version that cannot be installed falls back to the highest
  Assert.IsTrue( FindDelphiInstall( '99.9', Install, Exact ) );
  Assert.IsFalse( Exact );
  Assert.AreEqual( Installs[ 0 ].BDSVersion, Install.BDSVersion, False );

end;

end.
