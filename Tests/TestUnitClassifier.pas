(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  TestUnitClassifier.pas — Tests for uUnitClassifier precedence rules
*)
unit TestUnitClassifier;

interface

uses
  DUnitX.TestFramework,
  uTypes;

type
  /// <summary>
  ///   Classification precedence between manifest rules and own-code rules. The RTL scan is
  ///   disabled so the tests do not depend on an installed Delphi.
  /// </summary>
  [TestFixture]
  TUnitClassifierTests = class
  private
    function Classify( const AManifest: TManifest; const AInFileUnits, AUnits: TArray<string> ): TArray<TClassifiedUnit>;
    function ComponentManifest( const APrefix: string ): TManifest;
  public
    /// <summary>
    ///   Proves a unit the user listed in own_code_units stays own code even when a units_prefix rule
    ///   also matches it (own VirtualTreesHelper against the VirtualTrees prefix).
    /// </summary>
    [Test]
    procedure ListedOwnCodeBeatsPrefix;

    /// <summary>
    ///   Proves a vendored library compiled through an 'in' reference still classifies as third-party
    ///   when a manifest prefix matches it — an 'in' reference alone is not proof of own code.
    /// </summary>
    [Test]
    procedure InFileUnitMatchingPrefixStaysThirdParty;

    /// <summary>
    ///   Proves units_exact beats own_code_units when both list the same unit.
    /// </summary>
    [Test]
    procedure ExactRuleBeatsListedOwnCode;

    /// <summary>
    ///   Proves an empty prefix never matches. Before the audit fix it matched every unit.
    /// </summary>
    [Test]
    procedure EmptyPrefixMatchesNothing;

    /// <summary>
    ///   Proves own-code rules also match the scope-stripped name (Vcl.MyHelpers listed as MyHelpers).
    /// </summary>
    [Test]
    procedure OwnCodeMatchesStrippedName;
  end;

implementation

uses
  System.SysUtils,
  uRTLScanner, uUnitClassifier, TestSupport;

{ TUnitClassifierTests }

function TUnitClassifierTests.Classify( const AManifest: TManifest; const AInFileUnits, AUnits: TArray<string> ): TArray<TClassifiedUnit>;
begin

  var Scanner := TRTLScanner.Create( NoLog() );
  try
    var Classifier := TUnitClassifier.Create( NoLog(), Scanner, AManifest, False, AInFileUnits );
    try
      Result := Classifier.Classify( AUnits );
    finally
      Classifier.Free;
    end;
  finally
    Scanner.Free;
  end;

end;

function TUnitClassifierTests.ComponentManifest( const APrefix: string ): TManifest;
begin

  Result := Default( TManifest );
  SetLength( Result.Components, 1 );
  Result.Components[ 0 ].Name     := 'VirtualTrees';
  Result.Components[ 0 ].Prefixes := [ APrefix ];

end;

procedure TUnitClassifierTests.ListedOwnCodeBeatsPrefix;
begin

  var Manifest := ComponentManifest( 'VirtualTrees' );
  Manifest.OwnCodeUnits := [ 'VirtualTreesHelper' ];

  var Units := Classify( Manifest, nil, [ 'VirtualTreesHelper', 'VirtualTrees.Types' ] );

  Assert.AreEqual<TUnitClassification>( ucOwnCode, Units[ 0 ].Classification );
  Assert.AreEqual<TUnitClassification>( ucThirdParty, Units[ 1 ].Classification );

end;

procedure TUnitClassifierTests.InFileUnitMatchingPrefixStaysThirdParty;
begin

  var Units := Classify( ComponentManifest( 'VirtualTrees' ), [ 'VirtualTrees' ], [ 'VirtualTrees', 'MyForm' ] );

  Assert.AreEqual<TUnitClassification>( ucThirdParty, Units[ 0 ].Classification );
  Assert.AreEqual<TUnitClassification>( ucUnclassified, Units[ 1 ].Classification );

end;

procedure TUnitClassifierTests.ExactRuleBeatsListedOwnCode;
begin

  var Manifest := Default( TManifest );
  SetLength( Manifest.Components, 1 );
  Manifest.Components[ 0 ].Name       := 'Lib';
  Manifest.Components[ 0 ].ExactUnits := [ 'Shared' ];
  Manifest.OwnCodeUnits               := [ 'Shared' ];

  var Units := Classify( Manifest, nil, [ 'Shared' ] );

  Assert.AreEqual<TUnitClassification>( ucThirdParty, Units[ 0 ].Classification );
  Assert.AreEqual( 0, Units[ 0 ].ComponentIndex );

end;

procedure TUnitClassifierTests.EmptyPrefixMatchesNothing;
begin

  var Manifest := ComponentManifest( '' );
  Manifest.OwnCodePrefixes := [ '' ];

  var Units := Classify( Manifest, nil, [ 'Anything', 'Else' ] );

  Assert.AreEqual<TUnitClassification>( ucUnclassified, Units[ 0 ].Classification );
  Assert.AreEqual<TUnitClassification>( ucUnclassified, Units[ 1 ].Classification );

end;

procedure TUnitClassifierTests.OwnCodeMatchesStrippedName;
begin

  var Manifest := Default( TManifest );
  Manifest.OwnCodeUnits := [ 'MyHelpers' ];

  var Units := Classify( Manifest, nil, [ 'Vcl.MyHelpers' ] );

  Assert.AreEqual<TUnitClassification>( ucOwnCode, Units[ 0 ].Classification );

end;

end.
