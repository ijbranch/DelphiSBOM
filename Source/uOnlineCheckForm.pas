(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uOnlineCheckForm.pas — Shows the online check's findings; the user ticks the suggestions to apply
*)
unit uOnlineCheckForm;

interface

uses
  System.SysUtils, System.Classes,
  Vcl.Forms, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.CheckLst, Vcl.Graphics,
  uOnlineCheck;

type
  /// <summary>
  ///   Modal list of online-check findings. A finding with a suggested value can be ticked; nothing is
  ///   ticked to begin with, so nothing is written unless the user chooses it.
  /// </summary>
  TOnlineCheckForm = class( TForm )
  private
    FList: TCheckListBox;
    FBtnApply: TButton;
    FBtnClose: TButton;
    FFindings: TArray<TOnlineFinding>;

    procedure CreateUI;
    procedure Populate;
    procedure ListClickCheck( Sender: TObject );
    function Chosen: TArray<TOnlineFinding>;
  public
    /// <summary>
    ///   Shows the findings modally.
    /// </summary>
    /// <param name="AFindings">The online check's findings.</param>
    /// <param name="AChosen">The ticked findings when it returns True.</param>
    /// <returns>True when the user pressed Apply with at least one suggestion ticked.</returns>
    class function Execute( const AFindings: TArray<TOnlineFinding>; out AChosen: TArray<TOnlineFinding> ): Boolean;
  end;

implementation

uses
  System.UITypes;

{ TOnlineCheckForm }

class function TOnlineCheckForm.Execute( const AFindings: TArray<TOnlineFinding>; out AChosen: TArray<TOnlineFinding> ): Boolean;
begin

  AChosen           := nil;

  var Form          := TOnlineCheckForm.CreateNew( nil );
  try
    Form.FFindings  := AFindings;
    Form.CreateUI;
    Form.Populate;

    Result          := ( Form.ShowModal = mrOK );

    if Result then
    begin
      AChosen       := Form.Chosen;
      Result        := Length( AChosen ) > 0;
    end;
  finally
    Form.Free;
  end;

end;

procedure TOnlineCheckForm.CreateUI;
begin

  Caption           := 'Online Check';
  Width             := 1000;
  Height            := 520;
  Position          := poMainFormCenter;
  BorderStyle       := bsSizeable;
  Font.Name         := 'Segoe UI';
  Font.Size         := 9;

  var LblInfo       := TLabel.Create( Self );
  LblInfo.Parent    := Self;
  LblInfo.Align     := alTop;
  LblInfo.AlignWithMargins := True;
  LblInfo.WordWrap  := True;
  LblInfo.Caption   := 'What GitHub says about each component with a GitHub vendor_url. Tick a suggestion to write it to ' +
    'components.json — only when it applies to the version you actually use: GitHub reports its default branch and latest ' +
    'release, not your copy.';
  LblInfo.Font.Color := clGrayText;

  var PnlButtons    := TPanel.Create( Self );
  PnlButtons.Parent := Self;
  PnlButtons.Align  := alBottom;
  PnlButtons.Height := 42;
  PnlButtons.BevelOuter := bvNone;
  PnlButtons.Caption := '';

  FBtnApply         := TButton.Create( Self );
  FBtnApply.Parent  := PnlButtons;
  FBtnApply.Caption := 'Apply Ticked';
  FBtnApply.Width   := 110;
  FBtnApply.Height  := 28;
  FBtnApply.Left    := PnlButtons.ClientWidth - 220;
  FBtnApply.Top     := 6;
  FBtnApply.Anchors := [ akTop, akRight ];
  FBtnApply.ModalResult := mrOK;
  FBtnApply.Enabled := False;

  FBtnClose         := TButton.Create( Self );
  FBtnClose.Parent  := PnlButtons;
  FBtnClose.Caption := 'Close';
  FBtnClose.Width   := 90;
  FBtnClose.Height  := 28;
  FBtnClose.Left    := PnlButtons.ClientWidth - 100;
  FBtnClose.Top     := 6;
  FBtnClose.Anchors := [ akTop, akRight ];
  FBtnClose.Cancel  := True;
  FBtnClose.ModalResult := mrCancel;

  FList             := TCheckListBox.Create( Self );
  FList.Parent      := Self;
  FList.Align       := alClient;
  FList.AlignWithMargins := True;
  FList.OnClickCheck := ListClickCheck;

end;

procedure TOnlineCheckForm.Populate;
begin

  FList.Items.BeginUpdate;
  try
    for var F in FFindings do
    begin
      var Text      := F.Component + ': ' + F.Message;

      if F.Kind = ofkWarning then
        Text        := '[review] ' + Text
      else
        Text        := '[info] ' + Text;

      if F.Field <> '' then
        Text        := Text + Format( '  →  set %s to %s', [ F.Field, F.Suggested ] );

      var Index     := FList.Items.Add( Text );
      FList.ItemEnabled[ Index ] := F.Field <> '';
    end;
  finally
    FList.Items.EndUpdate;
  end;

  if FList.Count > 0 then
    FList.ItemIndex := 0;

end;

procedure TOnlineCheckForm.ListClickCheck( Sender: TObject );
begin

  // A disabled item (no suggestion) cannot be applied, whatever state it is put in
  var Any           := False;

  for var I := 0 to FList.Count - 1 do
    if FList.Checked[ I ] and FList.ItemEnabled[ I ] then
      Any           := True;

  FBtnApply.Enabled := Any;

end;

function TOnlineCheckForm.Chosen: TArray<TOnlineFinding>;
begin

  Result            := nil;

  for var I := 0 to FList.Count - 1 do
    if FList.Checked[ I ] and FList.ItemEnabled[ I ] and ( FFindings[ I ].Field <> '' ) then
      Result        := Result + [ FFindings[ I ] ];

end;

end.
