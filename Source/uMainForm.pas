(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian (GITLAK Software)
  MIT Licence — see LICENCE file

  uMainForm.pas — Main application form
*)
unit uMainForm;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.FileCtrl,
  uTypes;

type
  TMainForm = class;

  /// <summary>
  ///   Background thread for SBOM generation.
  /// </summary>
  TSBOMGenerateThread = class( TThread )
  private
    FForm: TMainForm;
    FOptions: TSBOMOptions;
    FResult: TSBOMResult;
    FLogLevel: TLogLevel;
    FLogMsg: string;

    procedure DoLog( ALevel: TLogLevel; const AMsg: string );
    procedure SyncLog;
    procedure SyncComplete;
  protected
    procedure Execute; override;
  public
    constructor Create( AForm: TMainForm; const AOptions: TSBOMOptions );
  end;

  /// <summary>
  ///   Background thread for manifest validation.
  /// </summary>
  TSBOMValidateThread = class( TThread )
  private
    FForm: TMainForm;
    FManifestPath: string;
    FLogLevel: TLogLevel;
    FLogMsg: string;

    procedure DoLog( ALevel: TLogLevel; const AMsg: string );
    procedure SyncLog;
    procedure SyncComplete;
  protected
    procedure Execute; override;
  public
    constructor Create( AForm: TMainForm; const AManifestPath: string );
  end;

  TMainForm = class( TForm )
    procedure FormCreate( Sender: TObject );
  private
    // Input controls
    FLblProject    : TLabel;
    FEdtProject    : TEdit;
    FBtnProject    : TButton;
    FLblManifest   : TLabel;
    FEdtManifest   : TEdit;
    FBtnManifest   : TButton;
    FLblOutputDir  : TLabel;
    FEdtOutputDir  : TEdit;
    FBtnOutputDir  : TButton;
    FLblDelphiPath : TLabel;
    FEdtDelphiPath : TEdit;
    FBtnDelphiPath : TButton;
    FLblVersion    : TLabel;
    FEdtVersion    : TEdit;

    // Action buttons
    FBtnGenerate : TButton;
    FBtnValidate : TButton;

    // Results panel
    FPnlResults      : TPanel;
    FPnlSummary      : TPanel;
    FSplitter        : TSplitter;
    FPnlUnclassified : TPanel;
    FMmoSummary      : TMemo;
    FLstUnclassified : TListBox;

    // Log panel
    FMmoLog : TMemo;

    // Dialogs
    FDlgOpenProject  : TOpenDialog;
    FDlgOpenManifest : TOpenDialog;

    FProcessing : Boolean;

    procedure CreateControls;
    procedure CreateInputRow( var ATop: Integer; const ACaption: string;
      out ALabel: TLabel; out AEdit: TEdit; out AButton: TButton;
      AOnClick: TNotifyEvent );

    procedure BtnProjectClick( Sender: TObject );
    procedure BtnManifestClick( Sender: TObject );
    procedure BtnOutputDirClick( Sender: TObject );
    procedure BtnDelphiPathClick( Sender: TObject );
    procedure BtnGenerateClick( Sender: TObject );
    procedure BtnValidateClick( Sender: TObject );

    procedure AutoPopulateDefaults;
    procedure DetectDelphiPath;
  public
    procedure SetProcessing( AValue: Boolean );
    procedure LogMessage( ALevel: TLogLevel; const AMessage: string );
    procedure DisplayResults( const AResult: TSBOMResult );
  end;

var
  MainForm: TMainForm;

implementation

uses
  System.IOUtils, System.Win.Registry,
  uSBOMEngine;

{$R *.dfm}

// ---------------------------------------------------------------------------
//  TSBOMGenerateThread
// ---------------------------------------------------------------------------

constructor TSBOMGenerateThread.Create( AForm: TMainForm; const AOptions: TSBOMOptions );
begin

  inherited Create( True );
  FreeOnTerminate := True;
  FForm    := AForm;
  FOptions := AOptions;

end;

procedure TSBOMGenerateThread.SyncLog;
begin

  FForm.LogMessage( FLogLevel, FLogMsg );

end;

procedure TSBOMGenerateThread.SyncComplete;
begin

  FForm.DisplayResults( FResult );
  FForm.SetProcessing( False );

end;

procedure TSBOMGenerateThread.DoLog( ALevel: TLogLevel; const AMsg: string );
begin

  FLogLevel := ALevel;
  FLogMsg   := AMsg;
  Synchronize( SyncLog );

end;

procedure TSBOMGenerateThread.Execute;
begin

  var Self_ := Self;
  var Engine := TSBOMEngine.Create(
    procedure ( ALevel: TLogLevel; AMsg: string )
    begin
      Self_.DoLog( ALevel, AMsg );
    end );
  try
    try
      FResult := Engine.Execute( FOptions );
    except
      on E: Exception do
      begin
        FResult              := Default( TSBOMResult );
        FResult.Success      := False;
        FResult.ErrorMessage := E.Message;

        FLogLevel := llError;
        FLogMsg   := E.Message;
        Synchronize( SyncLog );
      end;
    end;

    Synchronize( SyncComplete );
  finally
    Engine.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  TSBOMValidateThread
// ---------------------------------------------------------------------------

constructor TSBOMValidateThread.Create( AForm: TMainForm; const AManifestPath: string );
begin

  inherited Create( True );
  FreeOnTerminate := True;
  FForm         := AForm;
  FManifestPath := AManifestPath;

end;

procedure TSBOMValidateThread.SyncLog;
begin

  FForm.LogMessage( FLogLevel, FLogMsg );

end;

procedure TSBOMValidateThread.SyncComplete;
begin

  FForm.SetProcessing( False );

end;

procedure TSBOMValidateThread.DoLog( ALevel: TLogLevel; const AMsg: string );
begin

  FLogLevel := ALevel;
  FLogMsg   := AMsg;
  Synchronize( SyncLog );

end;

procedure TSBOMValidateThread.Execute;
begin

  var Self_ := Self;
  var Engine := TSBOMEngine.Create(
    procedure ( ALevel: TLogLevel; AMsg: string )
    begin
      Self_.DoLog( ALevel, AMsg );
    end );
  try
    try
      Engine.ValidateManifest( FManifestPath );
    except
      on E: Exception do
      begin
        FLogLevel := llError;
        FLogMsg   := E.Message;
        Synchronize( SyncLog );
      end;
    end;

    Synchronize( SyncComplete );
  finally
    Engine.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  TMainForm
// ---------------------------------------------------------------------------

procedure TMainForm.FormCreate( Sender: TObject );
begin

  Caption     := 'DelphiSBOM — CycloneDX SBOM Generator';
  FProcessing := False;

  CreateControls;
  DetectDelphiPath;

end;

procedure TMainForm.CreateControls;
begin

  var CurrentTop := 12;

  // Input rows
  CreateInputRow( CurrentTop, 'Project File:', FLblProject, FEdtProject, FBtnProject, BtnProjectClick );
  CreateInputRow( CurrentTop, 'Manifest:', FLblManifest, FEdtManifest, FBtnManifest, BtnManifestClick );
  CreateInputRow( CurrentTop, 'Output Dir:', FLblOutputDir, FEdtOutputDir, FBtnOutputDir, BtnOutputDirClick );
  CreateInputRow( CurrentTop, 'Delphi Path:', FLblDelphiPath, FEdtDelphiPath, FBtnDelphiPath, BtnDelphiPathClick );

  // Version override
  FLblVersion := TLabel.Create( Self );
  FLblVersion.Parent  := Self;
  FLblVersion.Left    := 12;
  FLblVersion.Top     := CurrentTop + 4;
  FLblVersion.Width   := 100;
  FLblVersion.Caption := 'Version Override:';

  FEdtVersion := TEdit.Create( Self );
  FEdtVersion.Parent    := Self;
  FEdtVersion.Left      := 120;
  FEdtVersion.Top       := CurrentTop;
  FEdtVersion.Width     := 200;
  FEdtVersion.TextHint  := 'blank = read from .dproj';

  Inc( CurrentTop, 34 );

  // Action buttons
  FBtnGenerate := TButton.Create( Self );
  FBtnGenerate.Parent  := Self;
  FBtnGenerate.Left    := 120;
  FBtnGenerate.Top     := CurrentTop;
  FBtnGenerate.Width   := 130;
  FBtnGenerate.Height  := 30;
  FBtnGenerate.Caption := 'Generate SBOM';
  FBtnGenerate.OnClick := BtnGenerateClick;

  FBtnValidate := TButton.Create( Self );
  FBtnValidate.Parent  := Self;
  FBtnValidate.Left    := 260;
  FBtnValidate.Top     := CurrentTop;
  FBtnValidate.Width   := 140;
  FBtnValidate.Height  := 30;
  FBtnValidate.Caption := 'Validate Manifest';
  FBtnValidate.OnClick := BtnValidateClick;

  Inc( CurrentTop, 42 );

  // Results panel
  FPnlResults := TPanel.Create( Self );
  FPnlResults.Parent     := Self;
  FPnlResults.Left       := 12;
  FPnlResults.Top        := CurrentTop;
  FPnlResults.Width      := ClientWidth - 24;
  FPnlResults.Height     := 200;
  FPnlResults.Anchors    := [ akLeft, akTop, akRight ];
  FPnlResults.BevelOuter := bvLowered;
  FPnlResults.Caption    := '';

  FPnlSummary := TPanel.Create( Self );
  FPnlSummary.Parent     := FPnlResults;
  FPnlSummary.Align      := alLeft;
  FPnlSummary.Width      := FPnlResults.Width div 2;
  FPnlSummary.BevelOuter := bvNone;
  FPnlSummary.Caption    := '';

  FMmoSummary := TMemo.Create( Self );
  FMmoSummary.Parent     := FPnlSummary;
  FMmoSummary.Align      := alClient;
  FMmoSummary.ReadOnly   := True;
  FMmoSummary.ScrollBars := ssVertical;
  FMmoSummary.Font.Name  := 'Consolas';
  FMmoSummary.Font.Size  := 9;

  FSplitter := TSplitter.Create( Self );
  FSplitter.Parent := FPnlResults;
  FSplitter.Left   := FPnlSummary.Width;
  FSplitter.Align  := alLeft;
  FSplitter.Width  := 5;

  FPnlUnclassified := TPanel.Create( Self );
  FPnlUnclassified.Parent     := FPnlResults;
  FPnlUnclassified.Align      := alClient;
  FPnlUnclassified.BevelOuter := bvNone;
  FPnlUnclassified.Caption    := '';

  var LblUnclassified := TLabel.Create( Self );
  LblUnclassified.Parent     := FPnlUnclassified;
  LblUnclassified.Align      := alTop;
  LblUnclassified.Caption    := '  Unclassified Units';
  LblUnclassified.Font.Style := [ fsBold ];

  FLstUnclassified := TListBox.Create( Self );
  FLstUnclassified.Parent := FPnlUnclassified;
  FLstUnclassified.Align  := alClient;

  Inc( CurrentTop, 210 );

  // Log panel
  var LblLog := TLabel.Create( Self );
  LblLog.Parent     := Self;
  LblLog.Left       := 12;
  LblLog.Top        := CurrentTop;
  LblLog.Caption    := 'Log';
  LblLog.Font.Style := [ fsBold ];

  Inc( CurrentTop, 20 );

  FMmoLog := TMemo.Create( Self );
  FMmoLog.Parent     := Self;
  FMmoLog.Left       := 12;
  FMmoLog.Top        := CurrentTop;
  FMmoLog.Width      := ClientWidth - 24;
  FMmoLog.Height     := ClientHeight - CurrentTop - 12;
  FMmoLog.Anchors    := [ akLeft, akTop, akRight, akBottom ];
  FMmoLog.ReadOnly   := True;
  FMmoLog.ScrollBars := ssBoth;
  FMmoLog.Font.Name  := 'Consolas';
  FMmoLog.Font.Size  := 9;

  // Dialogs
  FDlgOpenProject := TOpenDialog.Create( Self );
  FDlgOpenProject.Filter := 'Delphi Projects (*.dpr;*.dproj)|*.dpr;*.dproj|All Files (*.*)|*.*';
  FDlgOpenProject.Title  := 'Select Delphi Project';

  FDlgOpenManifest := TOpenDialog.Create( Self );
  FDlgOpenManifest.Filter := 'JSON Files (*.json)|*.json|All Files (*.*)|*.*';
  FDlgOpenManifest.Title  := 'Select components.json';

end;

procedure TMainForm.CreateInputRow( var ATop: Integer; const ACaption: string;
  out ALabel: TLabel; out AEdit: TEdit; out AButton: TButton;
  AOnClick: TNotifyEvent );
begin

  ALabel := TLabel.Create( Self );
  ALabel.Parent  := Self;
  ALabel.Left    := 12;
  ALabel.Top     := ATop + 4;
  ALabel.Width   := 100;
  ALabel.Caption := ACaption;

  AEdit := TEdit.Create( Self );
  AEdit.Parent  := Self;
  AEdit.Left    := 120;
  AEdit.Top     := ATop;
  AEdit.Width   := ClientWidth - 120 - 90 - 24;
  AEdit.Anchors := [ akLeft, akTop, akRight ];

  AButton := TButton.Create( Self );
  AButton.Parent  := Self;
  AButton.Left    := ClientWidth - 90 - 12;
  AButton.Top     := ATop;
  AButton.Width   := 90;
  AButton.Caption := 'Browse...';
  AButton.Anchors := [ akTop, akRight ];
  AButton.OnClick := AOnClick;

  Inc( ATop, 30 );

end;

// ---------------------------------------------------------------------------
//  Browse button handlers
// ---------------------------------------------------------------------------

procedure TMainForm.BtnProjectClick( Sender: TObject );
begin

  if FDlgOpenProject.Execute then
  begin
    FEdtProject.Text := FDlgOpenProject.FileName;
    AutoPopulateDefaults;
  end;

end;

procedure TMainForm.BtnManifestClick( Sender: TObject );
begin

  if FDlgOpenManifest.Execute then
    FEdtManifest.Text := FDlgOpenManifest.FileName;

end;

procedure TMainForm.BtnOutputDirClick( Sender: TObject );
begin

  var Dir: string := FEdtOutputDir.Text;

  if Vcl.FileCtrl.SelectDirectory( 'Select Output Directory', '', Dir ) then
    FEdtOutputDir.Text := Dir;

end;

procedure TMainForm.BtnDelphiPathClick( Sender: TObject );
begin

  var Dir: string := FEdtDelphiPath.Text;

  if Vcl.FileCtrl.SelectDirectory( 'Select Delphi Installation Directory', '', Dir ) then
    FEdtDelphiPath.Text := Dir;

end;

// ---------------------------------------------------------------------------
//  Action button handlers
// ---------------------------------------------------------------------------

procedure TMainForm.BtnGenerateClick( Sender: TObject );
begin

  if FProcessing then Exit;

  if Trim( FEdtProject.Text ) = '' then
  begin
    ShowMessage( 'Please select a project file first.' );
    Exit;
  end;

  SetProcessing( True );
  FMmoLog.Clear;
  FMmoSummary.Clear;
  FLstUnclassified.Clear;

  var Options: TSBOMOptions;
  Options.ProjectFile     := Trim( FEdtProject.Text );
  Options.ManifestFile    := Trim( FEdtManifest.Text );
  Options.OutputDir       := Trim( FEdtOutputDir.Text );
  Options.DelphiPath      := Trim( FEdtDelphiPath.Text );
  Options.VersionOverride := Trim( FEdtVersion.Text );

  TSBOMGenerateThread.Create( Self, Options ).Start;

end;

procedure TMainForm.BtnValidateClick( Sender: TObject );
begin

  if FProcessing then Exit;

  var ManifestPath := Trim( FEdtManifest.Text );

  if ManifestPath = '' then
  begin
    if Trim( FEdtProject.Text ) <> '' then
      ManifestPath := TPath.Combine( ExtractFilePath( FEdtProject.Text ), 'components.json' );
  end;

  if ( ManifestPath = '' ) or ( not FileExists( ManifestPath ) ) then
  begin
    ShowMessage( 'Please specify a manifest file to validate.' );
    Exit;
  end;

  SetProcessing( True );
  FMmoLog.Clear;

  TSBOMValidateThread.Create( Self, ManifestPath ).Start;

end;

// ---------------------------------------------------------------------------
//  UI helpers
// ---------------------------------------------------------------------------

procedure TMainForm.SetProcessing( AValue: Boolean );
begin

  FProcessing := AValue;

  FBtnGenerate.Enabled   := not AValue;
  FBtnValidate.Enabled   := not AValue;
  FBtnProject.Enabled    := not AValue;
  FBtnManifest.Enabled   := not AValue;
  FBtnOutputDir.Enabled  := not AValue;
  FBtnDelphiPath.Enabled := not AValue;
  FEdtProject.Enabled    := not AValue;
  FEdtManifest.Enabled   := not AValue;
  FEdtOutputDir.Enabled  := not AValue;
  FEdtDelphiPath.Enabled := not AValue;
  FEdtVersion.Enabled    := not AValue;

end;

procedure TMainForm.LogMessage( ALevel: TLogLevel; const AMessage: string );
begin

  FMmoLog.Lines.Add( FormatLogMessage( ALevel, AMessage ) );

end;

procedure TMainForm.DisplayResults( const AResult: TSBOMResult );
begin

  FMmoSummary.Clear;
  FLstUnclassified.Clear;

  if ( not AResult.Success ) then
  begin
    FMmoSummary.Lines.Add( 'SBOM generation failed.' );

    if AResult.ErrorMessage <> '' then
      FMmoSummary.Lines.Add( 'Error: ' + AResult.ErrorMessage );

    Exit;
  end;

  // Classification summary
  FMmoSummary.Lines.Add( 'Classification Summary' );
  FMmoSummary.Lines.Add( '══════════════════════' );
  FMmoSummary.Lines.Add( Format( 'RTL/VCL units:      %5d', [ AResult.Summary.RTLCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Third-party units:  %5d', [ AResult.Summary.ThirdPartyCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Own-code units:     %5d', [ AResult.Summary.OwnCodeCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Unclassified:       %5d', [ AResult.Summary.UnclassifiedCount ] ) );
  FMmoSummary.Lines.Add( '' );

  // Third-party components
  if Length( AResult.Manifest.Components ) > 0 then
  begin
    FMmoSummary.Lines.Add( 'Third-Party Components' );
    FMmoSummary.Lines.Add( '──────────────────────' );

    for var Comp in AResult.Manifest.Components do
      FMmoSummary.Lines.Add( Format( '  %s %s', [ Comp.Name, Comp.Version ] ) );
  end;

  // Unclassified units list
  for var CU in AResult.ClassifiedUnits do
    if CU.Classification = ucUnclassified then
      FLstUnclassified.Items.Add( CU.OriginalName );

  if ( not AResult.RTLScanAvailable ) then
    FLstUnclassified.Items.Insert( 0, '(RTL scanning was unavailable — some units may be RTL)' );

end;

procedure TMainForm.AutoPopulateDefaults;
begin

  if FEdtProject.Text = '' then Exit;

  var ProjectDir := ExtractFilePath( FEdtProject.Text );

  if FEdtManifest.Text = '' then
  begin
    var DefaultManifest := TPath.Combine( ProjectDir, 'components.json' );

    if FileExists( DefaultManifest ) then
      FEdtManifest.Text := DefaultManifest;
  end;

  if FEdtOutputDir.Text = '' then
    FEdtOutputDir.Text := ExcludeTrailingPathDelimiter( ProjectDir );

end;

procedure TMainForm.DetectDelphiPath;
begin

  var Reg := TRegistry.Create( KEY_READ );
  try
    Reg.RootKey := HKEY_CURRENT_USER;

    if Reg.OpenKeyReadOnly( 'Software\Embarcadero\BDS' ) then
    begin
      var SubKeys := TStringList.Create;
      try
        Reg.GetKeyNames( SubKeys );
        Reg.CloseKey;

        var HighestVer        := '';
        var HighestVal: Double := 0.0;
        var FmtSettings       := TFormatSettings.Create( 'en-US' );

        for var I := 0 to SubKeys.Count - 1 do
        begin
          var NumVal: Double := 0.0;

          if TryStrToFloat( SubKeys[ I ], NumVal, FmtSettings ) then
            if NumVal > HighestVal then
            begin
              HighestVal := NumVal;
              HighestVer := SubKeys[ I ];
            end;
        end;

        if ( HighestVer <> '' ) and Reg.OpenKeyReadOnly( 'Software\Embarcadero\BDS\' + HighestVer ) then
        begin
          if Reg.ValueExists( 'RootDir' ) then
            FEdtDelphiPath.Text := ExcludeTrailingPathDelimiter( Reg.ReadString( 'RootDir' ) );

          Reg.CloseKey;
        end;
      finally
        SubKeys.Free;
      end;
    end;
  finally
    Reg.Free;
  end;

end;

end.
