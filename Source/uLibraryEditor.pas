(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uLibraryEditor.pas — Modal editor for discovered library metadata
*)
unit uLibraryEditor;

interface

uses
  System.SysUtils, System.Classes,
  Vcl.Forms, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.Grids, Vcl.Graphics,
  uTypes;

type
  /// <summary>
  ///   Modal dialog for editing discovered library metadata before saving
  ///   to components.json. Users can modify Name, Version, Vendor, Licence,
  ///   and Prefix, and toggle which libraries to include.
  /// </summary>
  TLibraryEditorForm = class( TForm )
  private
    FGrid: TStringGrid;
    FMmoUnits: TMemo;
    FLblUnits: TLabel;
    FBtnOK: TButton;
    FBtnCancel: TButton;
    FLibraries: TArray<TDiscoveredLibrary>;

    procedure CreateUI;
    procedure PopulateGrid;
    procedure ReadGridBack;
    procedure GridSelectCell( Sender: TObject; ACol, ARow: Integer; var CanSelect: Boolean );
    procedure GridMouseUp( Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Integer );
    procedure UpdateUnitsDetail( ARow: Integer );

  public
    /// <summary>
    ///   Shows the editor modally. Returns True if user clicked OK.
    ///   ALibraries is updated in-place with edited values on OK.
    /// </summary>
    class function Execute( var ALibraries: TArray<TDiscoveredLibrary> ): Boolean;
  end;

implementation

const
  ColInclude   = 0;
  ColName      = 1;
  ColVersion   = 2;
  ColVendor    = 3;
  ColLicence   = 4;
  ColPrefix    = 5;
  ColUnits     = 6;
  ColDirectory = 7;
  ColCount     = 8;

{ TLibraryEditorForm }

class function TLibraryEditorForm.Execute( var ALibraries: TArray<TDiscoveredLibrary> ): Boolean;
begin

  var Form := TLibraryEditorForm.CreateNew( nil );
  try
    Form.FLibraries := Copy( ALibraries );
    Form.CreateUI;
    Form.PopulateGrid;

    Result := Form.ShowModal = mrOK;

    if Result then
    begin
      Form.ReadGridBack;
      ALibraries := Form.FLibraries;
    end;
  finally
    Form.Free;
  end;

end;

procedure TLibraryEditorForm.CreateUI;
begin

  Caption     := 'Edit Discovered Libraries';
  Width       := 1060;
  Height      := 650;
  Position    := poMainFormCenter;
  BorderStyle := bsSizeable;
  Font.Name   := 'Segoe UI';
  Font.Size   := 9;

  // Info label at top
  var LblInfo := TLabel.Create( Self );
  LblInfo.Parent     := Self;
  LblInfo.Align      := alTop;
  LblInfo.Height     := 32;
  LblInfo.Caption    := '  Edit library metadata before saving to components.json.  Click the Include column to toggle.';
  LblInfo.Layout     := tlCenter;
  LblInfo.Font.Color := clGrayText;

  // Button panel at bottom
  var PnlButtons := TPanel.Create( Self );
  PnlButtons.Parent     := Self;
  PnlButtons.Align      := alBottom;
  PnlButtons.Height     := 42;
  PnlButtons.BevelOuter := bvNone;
  PnlButtons.Caption    := '';

  FBtnOK := TButton.Create( Self );
  FBtnOK.Parent      := PnlButtons;
  FBtnOK.Caption     := 'OK';
  FBtnOK.Width       := 90;
  FBtnOK.Height      := 28;
  FBtnOK.Left        := PnlButtons.ClientWidth - 200;
  FBtnOK.Top         := 6;
  FBtnOK.Anchors     := [ akTop, akRight ];
  FBtnOK.Default     := True;
  FBtnOK.ModalResult := mrOK;

  FBtnCancel := TButton.Create( Self );
  FBtnCancel.Parent      := PnlButtons;
  FBtnCancel.Caption     := 'Cancel';
  FBtnCancel.Width       := 90;
  FBtnCancel.Height      := 28;
  FBtnCancel.Left        := PnlButtons.ClientWidth - 100;
  FBtnCancel.Top         := 6;
  FBtnCancel.Anchors     := [ akTop, akRight ];
  FBtnCancel.Cancel      := True;
  FBtnCancel.ModalResult := mrCancel;

  // Units detail panel at bottom (above buttons)
  var PnlUnits := TPanel.Create( Self );
  PnlUnits.Parent     := Self;
  PnlUnits.Align      := alBottom;
  PnlUnits.Height     := 100;
  PnlUnits.BevelOuter := bvNone;
  PnlUnits.Caption    := '';

  FLblUnits := TLabel.Create( Self );
  FLblUnits.Parent     := PnlUnits;
  FLblUnits.Align      := alTop;
  FLblUnits.Caption    := '  Units in selected library:';
  FLblUnits.Font.Style := [ fsBold ];

  FMmoUnits := TMemo.Create( Self );
  FMmoUnits.Parent     := PnlUnits;
  FMmoUnits.Align      := alClient;
  FMmoUnits.ReadOnly   := True;
  FMmoUnits.ScrollBars := ssVertical;
  FMmoUnits.Font.Name  := 'Consolas';
  FMmoUnits.Font.Size  := 9;

  // Splitter between grid and units detail
  var Splitter := TSplitter.Create( Self );
  Splitter.Parent := Self;
  Splitter.Align  := alBottom;
  Splitter.Height := 4;
  Splitter.Top    := PnlUnits.Top - 1;

  // Grid fills remaining space
  FGrid := TStringGrid.Create( Self );
  FGrid.Parent          := Self;
  FGrid.Align           := alClient;
  FGrid.FixedRows       := 1;
  FGrid.FixedCols       := 0;
  FGrid.DefaultRowHeight := 22;
  FGrid.ColCount        := ColCount;
  FGrid.RowCount        := 2;
  FGrid.Options         := [ goFixedVertLine, goFixedHorzLine, goVertLine, goHorzLine,
                             goEditing, goColSizing, goThumbTracking, goTabs ];
  FGrid.Font.Name       := 'Segoe UI';
  FGrid.Font.Size       := 9;

  // Column widths
  FGrid.ColWidths[ ColInclude ]  := 55;
  FGrid.ColWidths[ ColName ]     := 170;
  FGrid.ColWidths[ ColVersion ]  := 90;
  FGrid.ColWidths[ ColVendor ]   := 160;
  FGrid.ColWidths[ ColLicence ]  := 130;
  FGrid.ColWidths[ ColPrefix ]   := 130;
  FGrid.ColWidths[ ColUnits ]    := 55;
  FGrid.ColWidths[ ColDirectory ] := 250;

  // Headers
  FGrid.Cells[ ColInclude,  0 ] := 'Include';
  FGrid.Cells[ ColName,     0 ] := 'Name';
  FGrid.Cells[ ColVersion,  0 ] := 'Version';
  FGrid.Cells[ ColVendor,   0 ] := 'Vendor';
  FGrid.Cells[ ColLicence,  0 ] := 'Licence';
  FGrid.Cells[ ColPrefix,   0 ] := 'Prefix';
  FGrid.Cells[ ColUnits,    0 ] := 'Units';
  FGrid.Cells[ ColDirectory, 0 ] := 'Directory';

  // Events
  FGrid.OnSelectCell := GridSelectCell;
  FGrid.OnMouseUp    := GridMouseUp;

end;

procedure TLibraryEditorForm.PopulateGrid;
begin

  if Length( FLibraries ) = 0 then
  begin
    FGrid.RowCount := 2;
    FGrid.Cells[ ColName, 1 ] := '(No libraries discovered)';
    FGrid.Options  := FGrid.Options - [ goEditing ];
    FBtnOK.Enabled := False;
    Exit;
  end;

  FGrid.RowCount := Length( FLibraries ) + 1;

  for var I := 0 to High( FLibraries ) do
  begin
    var Row := I + 1;
    var Lib := FLibraries[ I ];

    if Lib.Confirmed then
      FGrid.Cells[ ColInclude, Row ] := 'Yes'
    else
      FGrid.Cells[ ColInclude, Row ] := 'No';

    FGrid.Cells[ ColName,      Row ] := Lib.Name;
    FGrid.Cells[ ColVersion,   Row ] := Lib.Version;
    FGrid.Cells[ ColVendor,    Row ] := Lib.Vendor;
    FGrid.Cells[ ColLicence,   Row ] := Lib.Licence;
    FGrid.Cells[ ColPrefix,    Row ] := Lib.SuggestedPrefix;
    FGrid.Cells[ ColUnits,     Row ] := IntToStr( Length( Lib.Units ) );
    FGrid.Cells[ ColDirectory, Row ] := Lib.Directory;
  end;

  // Show units for the first row
  if Length( FLibraries ) > 0 then
    UpdateUnitsDetail( 1 );

end;

procedure TLibraryEditorForm.ReadGridBack;
begin

  for var I := 0 to High( FLibraries ) do
  begin
    var Row := I + 1;

    FLibraries[ I ].Confirmed      := SameText( FGrid.Cells[ ColInclude, Row ], 'Yes' );
    FLibraries[ I ].Name           := Trim( FGrid.Cells[ ColName, Row ] );
    FLibraries[ I ].Version        := Trim( FGrid.Cells[ ColVersion, Row ] );
    FLibraries[ I ].Vendor         := Trim( FGrid.Cells[ ColVendor, Row ] );
    FLibraries[ I ].Licence        := Trim( FGrid.Cells[ ColLicence, Row ] );
    FLibraries[ I ].SuggestedPrefix := Trim( FGrid.Cells[ ColPrefix, Row ] );
    // Directory, Units, LicenceFile are read-only — preserved from original
  end;

end;

procedure TLibraryEditorForm.GridSelectCell( Sender: TObject; ACol, ARow: Integer; var CanSelect: Boolean );
begin

  CanSelect := True;

  // Disable inline editing for read-only columns
  if ACol in [ ColInclude, ColUnits, ColDirectory ] then
    FGrid.Options := FGrid.Options - [ goEditing ]
  else
    FGrid.Options := FGrid.Options + [ goEditing ];

  // Update units detail when row changes
  if ( ARow > 0 ) and ( ARow <= Length( FLibraries ) ) then
    UpdateUnitsDetail( ARow );

end;

procedure TLibraryEditorForm.GridMouseUp( Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer );
begin

  var ACol: Integer;
  var ARow: Integer;
  FGrid.MouseToCell( X, Y, ACol, ARow );

  // Toggle Include column on click
  if ( ACol = ColInclude ) and ( ARow > 0 ) and ( ARow <= Length( FLibraries ) ) then
  begin
    if SameText( FGrid.Cells[ ColInclude, ARow ], 'Yes' ) then
      FGrid.Cells[ ColInclude, ARow ] := 'No'
    else
      FGrid.Cells[ ColInclude, ARow ] := 'Yes';
  end;

end;

procedure TLibraryEditorForm.UpdateUnitsDetail( ARow: Integer );
begin

  FMmoUnits.Clear;

  var Idx := ARow - 1;

  if ( Idx < 0 ) or ( Idx > High( FLibraries ) ) then Exit;

  var Lib := FLibraries[ Idx ];

  FLblUnits.Caption := Format( '  Units in %s (%d):', [ Lib.Name, Length( Lib.Units ) ] );

  for var U in Lib.Units do
    FMmoUnits.Lines.Add( '  ' + U );

end;

end.
