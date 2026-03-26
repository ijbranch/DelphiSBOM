(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  uMainForm.pas — Main application form
*)
unit uMainForm;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.FileCtrl,
  uTypes, uSettings;

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
    procedure FormDestroy( Sender: TObject );
    procedure FormCloseQuery( Sender: TObject; var CanClose: Boolean );
  private
    // Input controls
    FLblProject    : TLabel;
    FEdtProject    : TComboBox;
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
    FBtnViewSBOM : TButton;

    // Results panel
    FPnlResults      : TPanel;
    FPnlSummary      : TPanel;
    FSplitter        : TSplitter;
    FPnlDiscovery    : TPanel;
    FMmoSummary      : TMemo;
    FMmoDiscovery    : TMemo;
    FBtnSaveRegen    : TButton;
    FBtnMarkOwnCode  : TButton;

    // Log panel
    FMmoLog : TMemo;

    // Dialogs
    FDlgOpenProject  : TOpenDialog;
    FDlgOpenManifest : TOpenDialog;

    FProcessing        : Boolean;
    FLastResult        : TSBOMResult;
    FDiscoveredLibraries : TArray<TDiscoveredLibrary>;
    FMRUManager        : TMRUManager;

    procedure CreateControls;
    procedure CreateInputRow( var ATop: Integer; const ACaption: string;
      out ALabel: TLabel; out AEdit: TEdit; out AButton: TButton;
      AOnClick: TNotifyEvent );

    procedure LoadMRU;
    procedure SaveToMRU;
    procedure RestoreProjectSettings( const AProjectFile: string );
    procedure CboProjectSelect( Sender: TObject );

    procedure BtnProjectClick( Sender: TObject );
    procedure BtnManifestClick( Sender: TObject );
    procedure BtnOutputDirClick( Sender: TObject );
    procedure BtnDelphiPathClick( Sender: TObject );
    procedure BtnGenerateClick( Sender: TObject );
    procedure BtnValidateClick( Sender: TObject );

    procedure AutoPopulateDefaults;
    procedure CreateDefaultManifest( const APath: string );
    procedure DetectDelphiPath;
    procedure DisplayDiscoveredLibraries;
    procedure BtnSaveRegenClick( Sender: TObject );
    procedure BtnMarkOwnCodeClick( Sender: TObject );
    procedure BtnViewSBOMClick( Sender: TObject );
    function GetUnresolvedUnits: TArray<string>;
  public
    procedure SetProcessing( AValue: Boolean );
    procedure LogMessage( ALevel: TLogLevel; const AMessage: string );
    procedure DisplayResults( const AResult: TSBOMResult );
  end;

var
  MainForm: TMainForm;

implementation

uses
  System.IOUtils, System.Win.Registry, System.Generics.Collections,
  {$IFDEF USE_SYNEDIT}
  SynEdit, SynHighlighterJSON,
  {$ENDIF}
  uSBOMEngine, uManifestLoader;

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

  Caption      := 'DelphiSBOM - CycloneDX SBOM Generator';
  FProcessing  := False;
  OnCloseQuery := FormCloseQuery;

  FMRUManager := TMRUManager.Create;

  CreateControls;

  try
    DetectDelphiPath;
  except
    on E: Exception do
      LogMessage( llWarning, 'Could not auto-detect Delphi path: ' + E.Message );
  end;

  LoadMRU;

end;

procedure TMainForm.FormCloseQuery( Sender: TObject; var CanClose: Boolean );
begin

  if FProcessing then
  begin
    CanClose := False;
    ShowMessage( 'Please wait for the current operation to complete before closing.' );
  end;

end;

procedure TMainForm.FormDestroy( Sender: TObject );
begin

  FMRUManager.Free;

end;

procedure TMainForm.CreateControls;
begin

  var CurrentTop := 12;

  // Project file row — TComboBox for MRU dropdown
  FLblProject := TLabel.Create( Self );
  FLblProject.Parent  := Self;
  FLblProject.Left    := 12;
  FLblProject.Top     := CurrentTop + 4;
  FLblProject.Width   := 100;
  FLblProject.Caption := 'Project File:';

  FEdtProject := TComboBox.Create( Self );
  FEdtProject.Parent  := Self;
  FEdtProject.Left    := 120;
  FEdtProject.Top     := CurrentTop;
  FEdtProject.Width   := ClientWidth - 120 - 90 - 24;
  FEdtProject.Anchors := [ akLeft, akTop, akRight ];
  FEdtProject.Style   := csDropDown;
  FEdtProject.OnSelect := CboProjectSelect;

  FBtnProject := TButton.Create( Self );
  FBtnProject.Parent  := Self;
  FBtnProject.Left    := ClientWidth - 90 - 12;
  FBtnProject.Top     := CurrentTop;
  FBtnProject.Width   := 90;
  FBtnProject.Caption := 'Browse...';
  FBtnProject.Anchors := [ akTop, akRight ];
  FBtnProject.OnClick := BtnProjectClick;

  Inc( CurrentTop, 30 );

  // Remaining input rows
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

  FBtnViewSBOM := TButton.Create( Self );
  FBtnViewSBOM.Parent  := Self;
  FBtnViewSBOM.Left    := 410;
  FBtnViewSBOM.Top     := CurrentTop;
  FBtnViewSBOM.Width   := 120;
  FBtnViewSBOM.Height  := 30;
  FBtnViewSBOM.Caption := 'View SBOM File';
  FBtnViewSBOM.OnClick := BtnViewSBOMClick;
  FBtnViewSBOM.Enabled := False;

  Inc( CurrentTop, 42 );

  // Bottom area — contains results panel, splitter, and log panel
  // Using a wrapper panel with aligned children so the splitter works
  var PnlBottom := TPanel.Create( Self );
  PnlBottom.Parent     := Self;
  PnlBottom.Left       := 12;
  PnlBottom.Top        := CurrentTop;
  PnlBottom.Width      := ClientWidth - 24;
  PnlBottom.Height     := ClientHeight - CurrentTop - 12;
  PnlBottom.Anchors    := [ akLeft, akTop, akRight, akBottom ];
  PnlBottom.BevelOuter := bvNone;
  PnlBottom.Caption    := '';

  // Log panel (at the bottom, alBottom)
  var PnlLog := TPanel.Create( Self );
  PnlLog.Parent     := PnlBottom;
  PnlLog.Align      := alBottom;
  PnlLog.Height     := 200;
  PnlLog.BevelOuter := bvNone;
  PnlLog.Caption    := '';

  var LblLog := TLabel.Create( Self );
  LblLog.Parent     := PnlLog;
  LblLog.Align      := alTop;
  LblLog.Caption    := 'Log';
  LblLog.Font.Style := [ fsBold ];

  FMmoLog := TMemo.Create( Self );
  FMmoLog.Parent     := PnlLog;
  FMmoLog.Align      := alClient;
  FMmoLog.ReadOnly   := True;
  FMmoLog.ScrollBars := ssBoth;
  FMmoLog.Font.Name  := 'Consolas';
  FMmoLog.Font.Size  := 9;

  // Horizontal splitter between results and log
  var SplitterH := TSplitter.Create( Self );
  SplitterH.Parent := PnlBottom;
  SplitterH.Align  := alBottom;
  SplitterH.Height := 5;
  SplitterH.Top    := PnlLog.Top - 1;

  // Results panel (fills remaining space, alClient)
  FPnlResults := TPanel.Create( Self );
  FPnlResults.Parent     := PnlBottom;
  FPnlResults.Align      := alClient;
  FPnlResults.BevelOuter := bvLowered;
  FPnlResults.Caption    := '';

  FPnlSummary := TPanel.Create( Self );
  FPnlSummary.Parent     := FPnlResults;
  FPnlSummary.Align      := alLeft;
  FPnlSummary.Width      := 420;
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

  FPnlDiscovery := TPanel.Create( Self );
  FPnlDiscovery.Parent     := FPnlResults;
  FPnlDiscovery.Align      := alClient;
  FPnlDiscovery.BevelOuter := bvNone;
  FPnlDiscovery.Caption    := '';

  var LblDiscovery := TLabel.Create( Self );
  LblDiscovery.Parent     := FPnlDiscovery;
  LblDiscovery.Align      := alTop;
  LblDiscovery.Caption    := '  Discovered Libraries / Unclassified Units';
  LblDiscovery.Font.Style := [ fsBold ];

  // Button panel at bottom of discovery area
  var PnlDiscButtons := TPanel.Create( Self );
  PnlDiscButtons.Parent     := FPnlDiscovery;
  PnlDiscButtons.Align      := alBottom;
  PnlDiscButtons.Height     := 30;
  PnlDiscButtons.BevelOuter := bvNone;
  PnlDiscButtons.Caption    := '';

  FBtnSaveRegen := TButton.Create( Self );
  FBtnSaveRegen.Parent  := PnlDiscButtons;
  FBtnSaveRegen.Align   := alLeft;
  FBtnSaveRegen.Width   := 260;
  FBtnSaveRegen.Caption := 'Save Libraries && Regenerate SBOM';
  FBtnSaveRegen.OnClick := BtnSaveRegenClick;
  FBtnSaveRegen.Enabled := False;

  FBtnMarkOwnCode := TButton.Create( Self );
  FBtnMarkOwnCode.Parent  := PnlDiscButtons;
  FBtnMarkOwnCode.Align   := alClient;
  FBtnMarkOwnCode.Caption := 'Mark Unresolved as Own Code';
  FBtnMarkOwnCode.OnClick := BtnMarkOwnCodeClick;
  FBtnMarkOwnCode.Enabled := False;

  FMmoDiscovery := TMemo.Create( Self );
  FMmoDiscovery.Parent     := FPnlDiscovery;
  FMmoDiscovery.Align      := alClient;
  FMmoDiscovery.ReadOnly   := True;
  FMmoDiscovery.ScrollBars := ssVertical;
  FMmoDiscovery.Font.Name  := 'Consolas';
  FMmoDiscovery.Font.Size  := 9;

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
  FMmoDiscovery.Clear;
  FBtnSaveRegen.Enabled   := False;
  FBtnMarkOwnCode.Enabled := False;

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

  if AValue then
    Screen.Cursor := crHourGlass
  else
    Screen.Cursor := crDefault;

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
  FMmoDiscovery.Clear;
  FBtnSaveRegen.Enabled   := False;
  FBtnMarkOwnCode.Enabled := False;
  FBtnViewSBOM.Enabled    := False;
  FLastResult := AResult;

  if ( not AResult.Success ) then
  begin
    FMmoSummary.Lines.Add( 'SBOM generation failed.' );

    if AResult.ErrorMessage <> '' then
      FMmoSummary.Lines.Add( 'Error: ' + AResult.ErrorMessage );

    Exit;
  end;

  FBtnViewSBOM.Enabled := ( AResult.OutputFile <> '' ) and FileExists( AResult.OutputFile );

  // Save to MRU on successful generation
  SaveToMRU;

  // Classification summary
  FMmoSummary.Lines.Add( 'Classification Summary' );
  FMmoSummary.Lines.Add( '======================' );
  FMmoSummary.Lines.Add( Format( 'RTL/VCL units:      %5d', [ AResult.Summary.RTLCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Third-party units:  %5d', [ AResult.Summary.ThirdPartyCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Own-code units:     %5d', [ AResult.Summary.OwnCodeCount ] ) );
  FMmoSummary.Lines.Add( Format( 'Unclassified:       %5d', [ AResult.Summary.UnclassifiedCount ] ) );
  FMmoSummary.Lines.Add( '' );

  // Third-party components
  if Length( AResult.Manifest.Components ) > 0 then
  begin
    FMmoSummary.Lines.Add( 'Third-Party Components' );
    FMmoSummary.Lines.Add( '----------------------' );

    for var Comp in AResult.Manifest.Components do
      FMmoSummary.Lines.Add( Format( '  %s %s', [ Comp.Name, Comp.Version ] ) );
  end;

  if ( not AResult.RTLScanAvailable ) then
  begin
    FMmoDiscovery.Lines.Add( '[WARNING] RTL scanning was unavailable - some units may be RTL' );
    FMmoDiscovery.Lines.Add( '' );
  end;

  // Store discovered libraries and display them
  FDiscoveredLibraries := AResult.DiscoveredLibraries;

  // Mark all discovered libraries as confirmed by default
  for var I := 0 to High( FDiscoveredLibraries ) do
    FDiscoveredLibraries[ I ].Confirmed := True;

  DisplayDiscoveredLibraries;

end;

procedure TMainForm.DisplayDiscoveredLibraries;
begin

  FMmoDiscovery.Lines.BeginUpdate;
  try
    // Show discovered libraries
    if Length( FDiscoveredLibraries ) > 0 then
    begin
      FMmoDiscovery.Lines.Add( 'DISCOVERED LIBRARIES' );
      FMmoDiscovery.Lines.Add( '====================' );
      FMmoDiscovery.Lines.Add( 'The following libraries were found on disk.' );
      FMmoDiscovery.Lines.Add( 'Click "Save Libraries & Regenerate SBOM" to add them to components.json.' );
      FMmoDiscovery.Lines.Add( '' );

      for var I := 0 to High( FDiscoveredLibraries ) do
      begin
        var Lib := FDiscoveredLibraries[ I ];

        FMmoDiscovery.Lines.Add( Format( '-- %s --', [ Lib.Name ] ) );
        FMmoDiscovery.Lines.Add( Format( '  Directory: %s', [ Lib.Directory ] ) );

        if Lib.Version <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Version:   %s', [ Lib.Version ] ) );

        if Lib.Vendor <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Vendor:    %s', [ Lib.Vendor ] ) );

        if Lib.Licence <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Licence:   %s', [ Lib.Licence ] ) );

        if Lib.SuggestedPrefix <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Prefix:    %s', [ Lib.SuggestedPrefix ] ) );

        FMmoDiscovery.Lines.Add( Format( '  Units (%d):', [ Length( Lib.Units ) ] ) );

        for var U in Lib.Units do
          FMmoDiscovery.Lines.Add( '    ' + U );

        FMmoDiscovery.Lines.Add( '' );
      end;

      FBtnSaveRegen.Enabled := True;
    end;

    // Show remaining unclassified units (not found on disk)
    var UnfoundUnits := TList<string>.Create;
    try
      for var CU in FLastResult.ClassifiedUnits do
      begin
        if CU.Classification <> ucUnclassified then Continue;

        var Found := False;

        for var Lib in FDiscoveredLibraries do
          for var U in Lib.Units do
            if SameText( U, CU.OriginalName ) then
            begin
              Found := True;
              Break;
            end;

        if ( not Found ) then
          UnfoundUnits.Add( CU.OriginalName );
      end;

      if UnfoundUnits.Count > 0 then
      begin
        FMmoDiscovery.Lines.Add( 'UNRESOLVED UNITS' );
        FMmoDiscovery.Lines.Add( '================' );
        FMmoDiscovery.Lines.Add( 'No .pas files found. Click "Mark Unresolved as Own Code"' );
        FMmoDiscovery.Lines.Add( 'if these are your own project files:' );

        for var U in UnfoundUnits do
          FMmoDiscovery.Lines.Add( '  ' + U );

        FBtnMarkOwnCode.Enabled := True;
      end;
    finally
      UnfoundUnits.Free;
    end;

  finally
    FMmoDiscovery.Lines.EndUpdate;
  end;

end;

procedure TMainForm.BtnSaveRegenClick( Sender: TObject );
begin

  if Length( FDiscoveredLibraries ) = 0 then Exit;

  var ManifestPath := Trim( FEdtManifest.Text );

  if ManifestPath = '' then
  begin
    ShowMessage( 'No manifest file specified.' );
    Exit;
  end;

  // Save confirmed libraries to components.json
  var Loader := TManifestLoader.Create(
    procedure ( ALevel: TLogLevel; AMsg: string )
    begin
      LogMessage( ALevel, AMsg );
    end );
  try
    Loader.SaveDiscoveredLibraries( ManifestPath, FDiscoveredLibraries );
  finally
    Loader.Free;
  end;

  // Re-run generation
  LogMessage( llInfo, 'Regenerating SBOM with updated manifest...' );
  BtnGenerateClick( Self );

end;

procedure TMainForm.BtnViewSBOMClick( Sender: TObject );
begin

  if ( FLastResult.OutputFile = '' ) or ( not FileExists( FLastResult.OutputFile ) ) then
  begin
    ShowMessage( 'No SBOM file available.' );
    Exit;
  end;

  var ViewForm := TForm.Create( Self );
  try
    ViewForm.Caption    := 'SBOM - ' + ExtractFileName( FLastResult.OutputFile );
    ViewForm.Width      := 800;
    ViewForm.Height     := 600;
    ViewForm.Position   := poMainFormCenter;

    {$IFDEF USE_SYNEDIT}
    var Editor := TSynEdit.Create( ViewForm );
    Editor.Parent     := ViewForm;
    Editor.Align      := alClient;
    Editor.ReadOnly   := True;
    Editor.Font.Name  := 'Consolas';
    Editor.Font.Size  := 10;
    Editor.Gutter.ShowLineNumbers := True;

    var Highlighter := TSynJSONSyn.Create( ViewForm );
    Editor.Highlighter := Highlighter;

    Editor.Lines.LoadFromFile( FLastResult.OutputFile, TEncoding.UTF8 );
    {$ELSE}
    var Memo := TMemo.Create( ViewForm );
    Memo.Parent     := ViewForm;
    Memo.Align      := alClient;
    Memo.ReadOnly   := True;
    Memo.ScrollBars := ssBoth;
    Memo.Font.Name  := 'Consolas';
    Memo.Font.Size  := 10;
    Memo.Lines.LoadFromFile( FLastResult.OutputFile, TEncoding.UTF8 );
    {$ENDIF}

    var BtnClose := TButton.Create( ViewForm );
    BtnClose.Parent      := ViewForm;
    BtnClose.Align       := alBottom;
    BtnClose.Height      := 35;
    BtnClose.Caption     := 'Close';
    BtnClose.ModalResult := mrOK;

    ViewForm.ShowModal;
  finally
    ViewForm.Free;
  end;

end;

procedure TMainForm.BtnMarkOwnCodeClick( Sender: TObject );
begin

  var UnresolvedUnits := GetUnresolvedUnits;

  if Length( UnresolvedUnits ) = 0 then Exit;

  var ManifestPath := Trim( FEdtManifest.Text );

  if ManifestPath = '' then
  begin
    ShowMessage( 'No manifest file specified.' );
    Exit;
  end;

  var Loader := TManifestLoader.Create(
    procedure ( ALevel: TLogLevel; AMsg: string )
    begin
      LogMessage( ALevel, AMsg );
    end );
  try
    Loader.SaveOwnCodeUnits( ManifestPath, UnresolvedUnits );
  finally
    Loader.Free;
  end;

  LogMessage( llInfo, 'Regenerating SBOM with own-code units marked...' );
  BtnGenerateClick( Self );

end;

function TMainForm.GetUnresolvedUnits: TArray<string>;
begin

  var Unfound := TList<string>.Create;
  try
    for var CU in FLastResult.ClassifiedUnits do
    begin
      if CU.Classification <> ucUnclassified then Continue;

      var Found := False;

      for var Lib in FDiscoveredLibraries do
        for var U in Lib.Units do
          if SameText( U, CU.OriginalName ) then
          begin
            Found := True;
            Break;
          end;

      if ( not Found ) then
        Unfound.Add( CU.OriginalName );
    end;

    Result := Unfound.ToArray;
  finally
    Unfound.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  MRU management
// ---------------------------------------------------------------------------

procedure TMainForm.LoadMRU;
begin

  try
    FMRUManager.Load;
  except
    on E: Exception do
    begin
      LogMessage( llWarning, 'Could not load MRU list: ' + E.Message );
      Exit;
    end;
  end;

  FEdtProject.Items.Clear;

  for var Entry in FMRUManager.GetEntries do
    FEdtProject.Items.Add( Entry.ProjectFile );

end;

procedure TMainForm.SaveToMRU;
begin

  var Entry: TMRUEntry;
  Entry.ProjectFile    := Trim( FEdtProject.Text );
  Entry.ManifestFile   := Trim( FEdtManifest.Text );
  Entry.OutputDir      := Trim( FEdtOutputDir.Text );
  Entry.VersionOverride := Trim( FEdtVersion.Text );

  if Entry.ProjectFile = '' then Exit;

  FMRUManager.AddOrPromote( Entry );

  try
    FMRUManager.Save;
  except
    on E: Exception do
      LogMessage( llWarning, 'Could not save MRU list: ' + E.Message );
  end;

  // Refresh dropdown items
  var CurrentText := FEdtProject.Text;
  FEdtProject.Items.Clear;

  for var MRUEntry in FMRUManager.GetEntries do
    FEdtProject.Items.Add( MRUEntry.ProjectFile );

  FEdtProject.Text := CurrentText;

end;

procedure TMainForm.RestoreProjectSettings( const AProjectFile: string );
begin

  var Entry := FMRUManager.FindEntry( AProjectFile );

  if Entry.ProjectFile = '' then Exit;

  if Entry.ManifestFile <> '' then
    FEdtManifest.Text := Entry.ManifestFile;

  if Entry.OutputDir <> '' then
    FEdtOutputDir.Text := Entry.OutputDir;

  FEdtVersion.Text := Entry.VersionOverride;

end;

procedure TMainForm.CboProjectSelect( Sender: TObject );
begin

  if FEdtProject.ItemIndex < 0 then Exit;

  AutoPopulateDefaults;
  RestoreProjectSettings( FEdtProject.Text );

end;

// ---------------------------------------------------------------------------
//  Defaults and detection
// ---------------------------------------------------------------------------

procedure TMainForm.AutoPopulateDefaults;
begin

  if FEdtProject.Text = '' then Exit;

  var ProjectDir := ExtractFilePath( FEdtProject.Text );
  var DefaultManifest := TPath.Combine( ProjectDir, 'components.json' );

  if ( not FileExists( DefaultManifest ) ) then
  begin
    CreateDefaultManifest( DefaultManifest );
    LogMessage( llInfo, Format( 'Created default components.json in %s', [ ProjectDir ] ) );
  end;

  if FEdtManifest.Text = '' then
    FEdtManifest.Text := DefaultManifest;

  FEdtOutputDir.Text := ExcludeTrailingPathDelimiter( ProjectDir );

end;

procedure TMainForm.CreateDefaultManifest( const APath: string );
begin

  var Json :=
    '{' + sLineBreak +
    '  "schema_version": "1.0",' + sLineBreak +
    '  "last_updated": "' + FormatDateTime( 'yyyy-mm-dd', Now ) + '",' + sLineBreak +
    '  "supplier": {' + sLineBreak +
    '    "name": "",' + sLineBreak +
    '    "url": ""' + sLineBreak +
    '  },' + sLineBreak +
    '  "components": []' + sLineBreak +
    '}' + sLineBreak;

  TFile.WriteAllText( APath, Json, TEncoding.UTF8 );

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
