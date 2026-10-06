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
  uTypes, uSettings, uOnlineCheck;

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

  /// <summary>
  ///   Background thread for the opt-in online check (network requests must not block the form).
  /// </summary>
  TSBOMOnlineThread = class( TThread )
  private
    FForm: TMainForm;
    FManifestPath: string;
    FFindings: TArray<TOnlineFinding>;
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
    FLblProject: TLabel;
    FEdtProject: TComboBox;
    FBtnProject: TButton;
    FLblManifest: TLabel;
    FEdtManifest: TEdit;
    FBtnManifest: TButton;
    FLblOutputDir: TLabel;
    FEdtOutputDir: TEdit;
    FBtnOutputDir: TButton;
    FLblDelphiPath: TLabel;
    FEdtDelphiPath: TEdit;
    FBtnDelphiPath: TButton;
    FLblVersion: TLabel;
    FEdtVersion: TEdit;
    FLblDXComply: TLabel;
    FEdtDXComply: TEdit;
    FBtnDXComply: TButton;
    FLblMapFile: TLabel;
    FEdtMapFile: TEdit;
    FBtnMapFile: TButton;
    FChkReports: TCheckBox;

    // Action buttons
    FBtnGenerate: TButton;
    FBtnValidate: TButton;
    FBtnViewSBOM: TButton;
    FBtnCheckOnline: TButton;

    // Results panel
    FPnlResults: TPanel;
    FPnlSummary: TPanel;
    FSplitter: TSplitter;
    FPnlDiscovery: TPanel;
    FMmoSummary: TMemo;
    FMmoDiscovery: TMemo;
    FBtnSaveRegen: TButton;
    FBtnEditLibraries: TButton;
    FBtnMarkOwnCode: TButton;

    // Log panel
    FMmoLog: TMemo;

    // Dialogs
    FDlgOpenProject: TOpenDialog;
    FDlgOpenManifest: TOpenDialog;

    FProcessing: Boolean;
    FLastResult: TSBOMResult;
    FDiscoveredLibraries: TArray<TDiscoveredLibrary>;
    FMRUManager: TMRUManager;
    FFieldsProject: string; // Project the per-project fields were last populated for
    FLibrariesEdited: Boolean; // Editor changes not yet saved to components.json

    procedure CreateControls;
    procedure CreateInputRow( var ATop: Integer; const ACaption: string;
      out ALabel: TLabel; out AEdit: TEdit; out AButton: TButton;
      AOnClick: TNotifyEvent );

    procedure LoadMRU;
    procedure SaveToMRU;
    procedure CboProjectSelect( Sender: TObject );
    procedure EdtProjectExit( Sender: TObject );

    procedure BtnProjectClick( Sender: TObject );
    procedure BtnManifestClick( Sender: TObject );
    procedure BtnOutputDirClick( Sender: TObject );
    procedure BtnMapFileClick( Sender: TObject );
    procedure BtnCheckOnlineClick( Sender: TObject );
    procedure ShowOnlineFindings( const AFindings: TArray<TOnlineFinding>; const AManifestPath: string );
    procedure BtnDelphiPathClick( Sender: TObject );
    procedure BtnDXComplyClick( Sender: TObject );
    procedure BtnGenerateClick( Sender: TObject );
    procedure BtnValidateClick( Sender: TObject );

    /// <summary>
    ///   Starts a generation run on a worker thread.
    /// </summary>
    /// <param name="AClearLog">False keeps messages logged just before (e.g. "Manifest saved").</param>
    procedure StartGenerate( AClearLog: Boolean );

    /// <summary>
    ///   Resets every per-project field (manifest, output directory, version override, DX.Comply file)
    ///   to the project's defaults, then applies the project's MRU entry, and clears the previous
    ///   project's results. Fields from one project must never carry over to another.
    /// </summary>
    procedure ApplyProjectSettings;
    procedure ClearResults;
    procedure UpdateActionButtons;
    procedure DisplayDiscoveredLibraries;
    procedure BtnSaveRegenClick( Sender: TObject );
    procedure BtnEditLibrariesClick( Sender: TObject );
    procedure BtnMarkOwnCodeClick( Sender: TObject );
    procedure BtnViewSBOMClick( Sender: TObject );
    function GetUnresolvedUnits: TArray<string>;
  public
    procedure SetProcessing( AValue: Boolean );
    procedure LogMessage( ALevel: TLogLevel; const AMessage: string );
    procedure DisplayResults( const AResult: TSBOMResult );
  end;

var
  MainForm          : TMainForm;

implementation

uses
  System.IOUtils, System.Generics.Collections, System.UITypes, Winapi.ActiveX,
{$IFDEF USE_SYNEDIT}
  SynEdit, SynHighlighterJSON,
{$ENDIF}
  uSBOMEngine, uManifestLoader, uLibraryEditor, uOnlineCheckForm;

{$R *.dfm}

// ---------------------------------------------------------------------------
//  TSBOMGenerateThread
// ---------------------------------------------------------------------------

constructor TSBOMGenerateThread.Create( AForm: TMainForm; const AOptions: TSBOMOptions );
begin

  inherited Create( True );
  FreeOnTerminate   := True;
  FForm             := AForm;
  FOptions          := AOptions;

end;

procedure TSBOMGenerateThread.SyncLog;
begin

  FForm.LogMessage( FLogLevel, FLogMsg );

end;

procedure TSBOMGenerateThread.SyncComplete;
begin

  // Always leave the form usable: a failure while displaying results must not strand it in
  // the processing state, where it can neither run again nor close
  try
    try
      FForm.DisplayResults( FResult );
    except
      Application.HandleException( FForm );
    end;
  finally
    FForm.SetProcessing( False );
  end;

end;

procedure TSBOMGenerateThread.DoLog( ALevel: TLogLevel; const AMsg: string );
begin

  FLogLevel         := ALevel;
  FLogMsg           := AMsg;
  Synchronize( SyncLog );

end;

procedure TSBOMGenerateThread.Execute;
begin

  // The .dproj is read with TXMLDocument (MSXML, a COM server): this thread needs its own apartment
  var ComInitialised := Succeeded( CoInitializeEx( nil, COINIT_APARTMENTTHREADED ) );
  try
    var Self_       := Self;
    var Engine      := TSBOMEngine.Create(
      procedure( ALevel: TLogLevel; AMsg: string )
      begin
        Self_.DoLog( ALevel, AMsg );
      end );
    try
      try
        FResult     := Engine.Execute( FOptions );
      except
        on E: Exception do
        begin
          FResult   := Default( TSBOMResult );
          FResult.Success := False;
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
  finally
    if ComInitialised then
      CoUninitialize;
  end;

end;

// ---------------------------------------------------------------------------
//  TSBOMValidateThread
// ---------------------------------------------------------------------------

constructor TSBOMValidateThread.Create( AForm: TMainForm; const AManifestPath: string );
begin

  inherited Create( True );
  FreeOnTerminate   := True;
  FForm             := AForm;
  FManifestPath     := AManifestPath;

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

  FLogLevel         := ALevel;
  FLogMsg           := AMsg;
  Synchronize( SyncLog );

end;

procedure TSBOMValidateThread.Execute;
begin

  var Self_         := Self;
  var Engine        := TSBOMEngine.Create(
    procedure( ALevel: TLogLevel; AMsg: string )
    begin
      Self_.DoLog( ALevel, AMsg );
    end );
  try
    try
      Engine.ValidateManifest( FManifestPath );
    except
      on E: Exception do
      begin
        FLogLevel   := llError;
        FLogMsg     := E.Message;
        Synchronize( SyncLog );
      end;
    end;

    Synchronize( SyncComplete );
  finally
    Engine.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  TSBOMOnlineThread
// ---------------------------------------------------------------------------

constructor TSBOMOnlineThread.Create( AForm: TMainForm; const AManifestPath: string );
begin

  inherited Create( True );
  FreeOnTerminate   := True;
  FForm             := AForm;
  FManifestPath     := AManifestPath;

end;

procedure TSBOMOnlineThread.SyncLog;
begin

  FForm.LogMessage( FLogLevel, FLogMsg );

end;

procedure TSBOMOnlineThread.SyncComplete;
begin

  // Always leave the form usable, whatever happens while showing the findings
  try
    try
      FForm.ShowOnlineFindings( FFindings, FManifestPath );
    except
      Application.HandleException( FForm );
    end;
  finally
    FForm.SetProcessing( False );
  end;

end;

procedure TSBOMOnlineThread.DoLog( ALevel: TLogLevel; const AMsg: string );
begin

  FLogLevel         := ALevel;
  FLogMsg           := AMsg;
  Synchronize( SyncLog );

end;

procedure TSBOMOnlineThread.Execute;
begin

  var Self_         := Self;
  var LogProc: TProc<TLogLevel, string> :=
    procedure( ALevel: TLogLevel; AMsg: string )
    begin
      Self_.DoLog( ALevel, AMsg );
    end;

  try
    var Loader      := TManifestLoader.Create( LogProc );
    try
      var Manifest  := Loader.Load( FManifestPath );

      var Checker   := TOnlineChecker.Create( LogProc );
      try
        FFindings   := Checker.Check( Manifest );
      finally
        Checker.Free;
      end;
    finally
      Loader.Free;
    end;
  except
    on E: Exception do
    begin
      FFindings     := nil;
      FLogLevel     := llError;
      FLogMsg       := 'Online check failed: ' + E.Message;
      Synchronize( SyncLog );
    end;
  end;

  Synchronize( SyncComplete );

end;

// ---------------------------------------------------------------------------
//  TMainForm
// ---------------------------------------------------------------------------

procedure TMainForm.FormCreate( Sender: TObject );
begin

  Caption           := 'DelphiSBOM - CycloneDX SBOM Generator';
  ShowHint          := True;
  FProcessing       := False;
  OnCloseQuery      := FormCloseQuery;

  FMRUManager       := TMRUManager.Create;

  CreateControls;
  LoadMRU;

end;

procedure TMainForm.FormCloseQuery( Sender: TObject; var CanClose: Boolean );
begin

  if FProcessing then
  begin
    CanClose        := False;
    ShowMessage( 'Please wait for the current operation to complete before closing.' );
  end;

end;

procedure TMainForm.FormDestroy( Sender: TObject );
begin

  FMRUManager.Free;

end;

procedure TMainForm.CreateControls;
begin

  var CurrentTop    := 12;

  // Project file row — TComboBox for MRU dropdown
  FLblProject       := TLabel.Create( Self );
  FLblProject.Parent := Self;
  FLblProject.Left  := 12;
  FLblProject.Top   := CurrentTop + 4;
  FLblProject.Width := 100;
  FLblProject.Caption := 'Project File:';

  FEdtProject       := TComboBox.Create( Self );
  FEdtProject.Parent := Self;
  FEdtProject.Left  := 120;
  FEdtProject.Top   := CurrentTop;
  FEdtProject.Width := ClientWidth - 120 - 90 - 24;
  FEdtProject.Anchors := [ akLeft, akTop, akRight ];
  FEdtProject.Style := csDropDown;
  FEdtProject.Hint  := 'Path to a .dpr, .dpk or .dproj file. Recent projects available in dropdown.';
  FEdtProject.OnSelect := CboProjectSelect;
  FEdtProject.OnExit := EdtProjectExit;

  FBtnProject       := TButton.Create( Self );
  FBtnProject.Parent := Self;
  FBtnProject.Left  := ClientWidth - 90 - 12;
  FBtnProject.Top   := CurrentTop;
  FBtnProject.Width := 90;
  FBtnProject.Caption := 'Browse...';
  FBtnProject.Hint  := 'Browse for a Delphi project file';
  FBtnProject.Anchors := [ akTop, akRight ];
  FBtnProject.OnClick := BtnProjectClick;

  Inc( CurrentTop, 30 );

  // Remaining input rows
  CreateInputRow( CurrentTop, 'Manifest:', FLblManifest, FEdtManifest, FBtnManifest, BtnManifestClick );
  FEdtManifest.Hint := 'Path to the components.json manifest. Created when you first save libraries or own-code units.';
  FBtnManifest.Hint := 'Browse for a components.json manifest file';

  CreateInputRow( CurrentTop, 'Output Dir:', FLblOutputDir, FEdtOutputDir, FBtnOutputDir, BtnOutputDirClick );
  FEdtOutputDir.Hint := 'Directory for the generated .cdx.json file. Defaults to the project directory.';
  FBtnOutputDir.Hint := 'Browse for an output directory';

  CreateInputRow( CurrentTop, 'Delphi Path:', FLblDelphiPath, FEdtDelphiPath, FBtnDelphiPath, BtnDelphiPathClick );
  FEdtDelphiPath.TextHint := 'blank = the project''s Delphi version, from the registry';
  FEdtDelphiPath.Hint := 'Delphi installation root directory. Leave blank to use the installation matching the project''s Delphi version.';
  FBtnDelphiPath.Hint := 'Browse for the Delphi installation directory';

  // Version override
  FLblVersion       := TLabel.Create( Self );
  FLblVersion.Parent := Self;
  FLblVersion.Left  := 12;
  FLblVersion.Top   := CurrentTop + 4;
  FLblVersion.Width := 100;
  FLblVersion.Caption := 'Version Override:';

  FEdtVersion       := TEdit.Create( Self );
  FEdtVersion.Parent := Self;
  FEdtVersion.Left  := 120;
  FEdtVersion.Top   := CurrentTop;
  FEdtVersion.Width := 200;
  FEdtVersion.TextHint := 'blank = read from .dproj';
  FEdtVersion.Hint  := 'Override the version from .dproj. Leave blank to use the project version.';

  FChkReports       := TCheckBox.Create( Self );
  FChkReports.Parent := Self;
  FChkReports.Left  := 340;
  FChkReports.Top   := CurrentTop + 2;
  FChkReports.Width := 260;
  FChkReports.Caption := 'Write HTML and Markdown reports';
  FChkReports.Hint  := 'Also write <Project>.sbom-report.html and .md beside the SBOM: components, licences, units and what is unclassified';

  Inc( CurrentTop, 30 );

  // DX.Comply evidence file (optional)
  CreateInputRow( CurrentTop, 'DX.Comply SBOM:', FLblDXComply, FEdtDXComply, FBtnDXComply, BtnDXComplyClick );
  FEdtDXComply.TextHint := 'optional — merges binary evidence into SBOM';
  FEdtDXComply.Hint := 'Path to a DX.Comply bom.json file. If provided, SHA-256 hashes are merged into the SBOM output.';
  FBtnDXComply.Hint := 'Browse for a DX.Comply bom.json file';

  // Linker MAP file (optional)
  CreateInputRow( CurrentTop, 'MAP File:', FLblMapFile, FEdtMapFile, FBtnMapFile, BtnMapFileClick );
  FEdtMapFile.TextHint := 'optional — the units the linker used, instead of the uses clause';
  FEdtMapFile.Hint  := 'A detailed .map file from a build of the project (Linking > Map file = Detailed). It lists every unit linked, ' +
    'including those used only indirectly, and leaves out {$IFDEF}-excluded ones.';
  FBtnMapFile.Hint  := 'Browse for a .map file';

  Inc( CurrentTop, 4 );

  // Action buttons
  FBtnGenerate      := TButton.Create( Self );
  FBtnGenerate.Parent := Self;
  FBtnGenerate.Left := 120;
  FBtnGenerate.Top  := CurrentTop;
  FBtnGenerate.Width := 130;
  FBtnGenerate.Height := 30;
  FBtnGenerate.Caption := 'Generate SBOM';
  FBtnGenerate.Hint := 'Parse the project, classify units, and generate a CycloneDX 1.5 JSON SBOM';
  FBtnGenerate.OnClick := BtnGenerateClick;

  FBtnValidate      := TButton.Create( Self );
  FBtnValidate.Parent := Self;
  FBtnValidate.Left := 260;
  FBtnValidate.Top  := CurrentTop;
  FBtnValidate.Width := 140;
  FBtnValidate.Height := 30;
  FBtnValidate.Caption := 'Validate Manifest';
  FBtnValidate.Hint := 'Check components.json for schema errors without generating an SBOM';
  FBtnValidate.OnClick := BtnValidateClick;

  FBtnViewSBOM      := TButton.Create( Self );
  FBtnViewSBOM.Parent := Self;
  FBtnViewSBOM.Left := 410;
  FBtnViewSBOM.Top  := CurrentTop;
  FBtnViewSBOM.Width := 120;
  FBtnViewSBOM.Height := 30;
  FBtnViewSBOM.Caption := 'View SBOM File';
  FBtnViewSBOM.Hint := 'View the last generated SBOM JSON file';
  FBtnViewSBOM.OnClick := BtnViewSBOMClick;
  FBtnViewSBOM.Enabled := False;

  FBtnCheckOnline   := TButton.Create( Self );
  FBtnCheckOnline.Parent := Self;
  FBtnCheckOnline.Left := 540;
  FBtnCheckOnline.Top := CurrentTop;
  FBtnCheckOnline.Width := 120;
  FBtnCheckOnline.Height := 30;
  FBtnCheckOnline.Caption := 'Check Online';
  FBtnCheckOnline.Hint := 'Compare components.json with each component''s GitHub repository (licence, latest release, archived). ' +
    'Connects to api.github.com; nothing is written unless you tick a suggestion.';
  FBtnCheckOnline.OnClick := BtnCheckOnlineClick;

  Inc( CurrentTop, 42 );

  // Bottom area — contains results panel, splitter, and log panel
  // Using a wrapper panel with aligned children so the splitter works
  var PnlBottom     := TPanel.Create( Self );
  PnlBottom.Parent  := Self;
  PnlBottom.Left    := 12;
  PnlBottom.Top     := CurrentTop;
  PnlBottom.Width   := ClientWidth - 24;
  PnlBottom.Height  := ClientHeight - CurrentTop - 12;
  PnlBottom.Anchors := [ akLeft, akTop, akRight, akBottom ];
  PnlBottom.BevelOuter := bvNone;
  PnlBottom.Caption := '';

  // Log panel (at the bottom, alBottom)
  var PnlLog        := TPanel.Create( Self );
  PnlLog.Parent     := PnlBottom;
  PnlLog.Align      := alBottom;
  PnlLog.Height     := 200;
  PnlLog.BevelOuter := bvNone;
  PnlLog.Caption    := '';

  var LblLog        := TLabel.Create( Self );
  LblLog.Parent     := PnlLog;
  LblLog.Align      := alTop;
  LblLog.Caption    := 'Log';
  LblLog.Font.Style := [ fsBold ];

  FMmoLog           := TMemo.Create( Self );
  FMmoLog.Parent    := PnlLog;
  FMmoLog.Align     := alClient;
  FMmoLog.ReadOnly  := True;
  FMmoLog.ScrollBars := ssBoth;
  FMmoLog.Font.Name := 'Consolas';
  FMmoLog.Font.Size := 9;

  // Horizontal splitter between results and log
  var SplitterH     := TSplitter.Create( Self );
  SplitterH.Parent  := PnlBottom;
  SplitterH.Align   := alBottom;
  SplitterH.Height  := 5;
  SplitterH.Top     := PnlLog.Top - 1;

  // Results panel (fills remaining space, alClient)
  FPnlResults       := TPanel.Create( Self );
  FPnlResults.Parent := PnlBottom;
  FPnlResults.Align := alClient;
  FPnlResults.BevelOuter := bvLowered;
  FPnlResults.Caption := '';

  FPnlSummary       := TPanel.Create( Self );
  FPnlSummary.Parent := FPnlResults;
  FPnlSummary.Align := alLeft;
  FPnlSummary.Width := 420;
  FPnlSummary.BevelOuter := bvNone;
  FPnlSummary.Caption := '';

  FMmoSummary       := TMemo.Create( Self );
  FMmoSummary.Parent := FPnlSummary;
  FMmoSummary.Align := alClient;
  FMmoSummary.ReadOnly := True;
  FMmoSummary.ScrollBars := ssVertical;
  FMmoSummary.Font.Name := 'Consolas';
  FMmoSummary.Font.Size := 9;

  FSplitter         := TSplitter.Create( Self );
  FSplitter.Parent  := FPnlResults;
  FSplitter.Left    := FPnlSummary.Width;
  FSplitter.Align   := alLeft;
  FSplitter.Width   := 5;

  FPnlDiscovery     := TPanel.Create( Self );
  FPnlDiscovery.Parent := FPnlResults;
  FPnlDiscovery.Align := alClient;
  FPnlDiscovery.BevelOuter := bvNone;
  FPnlDiscovery.Caption := '';

  var LblDiscovery  := TLabel.Create( Self );
  LblDiscovery.Parent := FPnlDiscovery;
  LblDiscovery.Align := alTop;
  LblDiscovery.Caption := '  Discovered Libraries / Unclassified Units';
  LblDiscovery.Font.Style := [ fsBold ];

  // Button grid at bottom of discovery area — 3 equal columns, auto-sized
  var GridButtons   := TGridPanel.Create( Self );
  GridButtons.Parent := FPnlDiscovery;
  GridButtons.Align := alBottom;
  GridButtons.Height := 30;
  GridButtons.BevelOuter := bvNone;
  GridButtons.Caption := '';
  GridButtons.ColumnCollection.BeginUpdate;
  try
    GridButtons.ColumnCollection.Clear;

    var Col1        := GridButtons.ColumnCollection.Add;
    Col1.SizeStyle  := ssPercent;
    Col1.Value      := 33.33;

    var Col2        := GridButtons.ColumnCollection.Add;
    Col2.SizeStyle  := ssPercent;
    Col2.Value      := 33.34;

    var Col3        := GridButtons.ColumnCollection.Add;
    Col3.SizeStyle  := ssPercent;
    Col3.Value      := 33.33;
  finally
    GridButtons.ColumnCollection.EndUpdate;
  end;
  GridButtons.RowCollection.BeginUpdate;
  try
    GridButtons.RowCollection.Clear;

    var Row1        := GridButtons.RowCollection.Add;
    Row1.SizeStyle  := ssPercent;
    Row1.Value      := 100;
  finally
    GridButtons.RowCollection.EndUpdate;
  end;

  FBtnSaveRegen     := TButton.Create( Self );
  FBtnSaveRegen.Parent := GridButtons;
  FBtnSaveRegen.Align := alClient;
  FBtnSaveRegen.Caption := 'Save && Regenerate';
  FBtnSaveRegen.Hint := 'Save discovered libraries to components.json and regenerate the SBOM';
  FBtnSaveRegen.OnClick := BtnSaveRegenClick;
  FBtnSaveRegen.Enabled := False;

  FBtnEditLibraries := TButton.Create( Self );
  FBtnEditLibraries.Parent := GridButtons;
  FBtnEditLibraries.Align := alClient;
  FBtnEditLibraries.Caption := 'Edit...';
  FBtnEditLibraries.Hint := 'Edit discovered library names, versions, vendors, and licences before saving';
  FBtnEditLibraries.OnClick := BtnEditLibrariesClick;
  FBtnEditLibraries.Enabled := False;

  FBtnMarkOwnCode   := TButton.Create( Self );
  FBtnMarkOwnCode.Parent := GridButtons;
  FBtnMarkOwnCode.Align := alClient;
  FBtnMarkOwnCode.Caption := 'Mark as Own Code';
  FBtnMarkOwnCode.Hint := 'Mark unresolved units as your own code in components.json';
  FBtnMarkOwnCode.OnClick := BtnMarkOwnCodeClick;
  FBtnMarkOwnCode.Enabled := False;

  FMmoDiscovery     := TMemo.Create( Self );
  FMmoDiscovery.Parent := FPnlDiscovery;
  FMmoDiscovery.Align := alClient;
  FMmoDiscovery.ReadOnly := True;
  FMmoDiscovery.ScrollBars := ssVertical;
  FMmoDiscovery.Font.Name := 'Consolas';
  FMmoDiscovery.Font.Size := 9;

  // Dialogs
  FDlgOpenProject   := TOpenDialog.Create( Self );
  FDlgOpenProject.Filter := 'Delphi Projects (*.dpr;*.dpk;*.dproj)|*.dpr;*.dpk;*.dproj|All Files (*.*)|*.*';
  FDlgOpenProject.Title := 'Select Delphi Project';

  FDlgOpenManifest  := TOpenDialog.Create( Self );
  FDlgOpenManifest.Filter := 'JSON Files (*.json)|*.json|All Files (*.*)|*.*';
  FDlgOpenManifest.Title := 'Select components.json';

end;

procedure TMainForm.CreateInputRow( var ATop: Integer; const ACaption: string;
  out ALabel: TLabel; out AEdit: TEdit; out AButton: TButton;
  AOnClick: TNotifyEvent );
begin

  ALabel            := TLabel.Create( Self );
  ALabel.Parent     := Self;
  ALabel.Left       := 12;
  ALabel.Top        := ATop + 4;
  ALabel.Width      := 100;
  ALabel.Caption    := ACaption;

  AEdit             := TEdit.Create( Self );
  AEdit.Parent      := Self;
  AEdit.Left        := 120;
  AEdit.Top         := ATop;
  AEdit.Width       := ClientWidth - 120 - 90 - 24;
  AEdit.Anchors     := [ akLeft, akTop, akRight ];

  AButton           := TButton.Create( Self );
  AButton.Parent    := Self;
  AButton.Left      := ClientWidth - 90 - 12;
  AButton.Top       := ATop;
  AButton.Width     := 90;
  AButton.Caption   := 'Browse...';
  AButton.Anchors   := [ akTop, akRight ];
  AButton.OnClick   := AOnClick;

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
    ApplyProjectSettings;
  end;

end;

procedure TMainForm.BtnManifestClick( Sender: TObject );
begin

  if FDlgOpenManifest.Execute then
    FEdtManifest.Text := FDlgOpenManifest.FileName;

end;

procedure TMainForm.BtnOutputDirClick( Sender: TObject );
begin

  var Dir: string   := FEdtOutputDir.Text;

  if Vcl.FileCtrl.SelectDirectory( 'Select Output Directory', '', Dir ) then
    FEdtOutputDir.Text := Dir;

end;

procedure TMainForm.BtnDelphiPathClick( Sender: TObject );
begin

  var Dir: string   := FEdtDelphiPath.Text;

  if Vcl.FileCtrl.SelectDirectory( 'Select Delphi Installation Directory', '', Dir ) then
    FEdtDelphiPath.Text := Dir;

end;

procedure TMainForm.BtnMapFileClick( Sender: TObject );
begin

  var Dlg           := TOpenDialog.Create( nil );
  try
    Dlg.Filter      := 'MAP Files (*.map)|*.map|All Files (*.*)|*.*';
    Dlg.Title       := 'Select a Detailed MAP File';

    if FEdtProject.Text <> '' then
      Dlg.InitialDir := ExtractFilePath( FEdtProject.Text );

    if Dlg.Execute then
      FEdtMapFile.Text := Dlg.FileName;
  finally
    Dlg.Free;
  end;

end;

procedure TMainForm.BtnDXComplyClick( Sender: TObject );
begin

  var Dlg           := TOpenDialog.Create( nil );
  try
    Dlg.Filter      := 'JSON Files (*.json)|*.json|All Files (*.*)|*.*';
    Dlg.Title       := 'Select DX.Comply SBOM File';

    if Dlg.Execute then
      FEdtDXComply.Text := Dlg.FileName;
  finally
    Dlg.Free;
  end;

end;

// ---------------------------------------------------------------------------
//  Action button handlers
// ---------------------------------------------------------------------------

procedure TMainForm.BtnGenerateClick( Sender: TObject );
begin

  if FLibrariesEdited and
    ( MessageDlg( 'Your edits to the discovered libraries have not been saved to components.json.' + sLineBreak +
      'Generate anyway and discard them?', mtConfirmation, [ mbYes, mbNo ], 0 ) <> mrYes ) then
    Exit;

  StartGenerate( True );

end;

procedure TMainForm.StartGenerate( AClearLog: Boolean );
begin

  if FProcessing then Exit;

  if Trim( FEdtProject.Text ) = '' then
  begin
    ShowMessage( 'Please select a project file first.' );
    Exit;
  end;

  // A project path typed by hand: make sure its own settings are in the fields
  if ( not SameText( Trim( FEdtProject.Text ), FFieldsProject ) ) then
    ApplyProjectSettings;

  SetProcessing( True );

  if AClearLog then
    FMmoLog.Clear;

  FMmoSummary.Clear;
  FMmoDiscovery.Clear;
  FLibrariesEdited  := False;

  var Options       := Default( TSBOMOptions );
  Options.ProjectFile := Trim( FEdtProject.Text );
  Options.ManifestFile := Trim( FEdtManifest.Text );
  Options.OutputDir := Trim( FEdtOutputDir.Text );
  Options.DelphiPath := Trim( FEdtDelphiPath.Text );
  Options.VersionOverride := Trim( FEdtVersion.Text );
  Options.DXComplyFile := Trim( FEdtDXComply.Text );
  Options.MapFile   := Trim( FEdtMapFile.Text );

  if FChkReports.Checked then
    Options.ReportFormats := [ rfMarkdown, rfHtml ];

  TSBOMGenerateThread.Create( Self, Options ).Start;

end;

procedure TMainForm.BtnValidateClick( Sender: TObject );
begin

  if FProcessing then Exit;

  var ManifestPath  := Trim( FEdtManifest.Text );

  if ManifestPath = '' then
  begin
    if Trim( FEdtProject.Text ) <> '' then
      ManifestPath  := TPath.Combine( ExtractFilePath( FEdtProject.Text ), 'components.json' );
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

procedure TMainForm.BtnCheckOnlineClick( Sender: TObject );
begin

  if FProcessing then Exit;

  // A project path typed by hand: make sure its own settings (the manifest path) are in the fields
  if ( Trim( FEdtProject.Text ) <> '' ) and ( not SameText( Trim( FEdtProject.Text ), FFieldsProject ) ) then
    ApplyProjectSettings;

  var ManifestPath  := Trim( FEdtManifest.Text );

  if ( ManifestPath = '' ) or ( not FileExists( ManifestPath ) ) then
  begin
    ShowMessage( 'There is no components.json to check yet. Generate the SBOM and save the libraries first.' );
    Exit;
  end;

  SetProcessing( True );
  FMmoLog.Clear;
  LogMessage( llInfo, 'Checking components.json against GitHub...' );

  TSBOMOnlineThread.Create( Self, ManifestPath ).Start;

end;

procedure TMainForm.ShowOnlineFindings( const AFindings: TArray<TOnlineFinding>; const AManifestPath: string );
begin

  for var F in AFindings do
    if F.Kind = ofkWarning then
      LogMessage( llWarning, Format( 'online: %s: %s', [ F.Component, F.Message ] ) )
    else
      LogMessage( llInfo, Format( 'online: %s: %s', [ F.Component, F.Message ] ) );

  if Length( AFindings ) = 0 then Exit;

  var Chosen: TArray<TOnlineFinding>;

  if ( not TOnlineCheckForm.Execute( AFindings, Chosen ) ) then Exit;

  // One write per component, with every field chosen for it
  var Loader        := TManifestLoader.Create(
    procedure( ALevel: TLogLevel; AMsg: string )
    begin
      LogMessage( ALevel, AMsg );
    end );
  try
    var Done        := TDictionary<string, Boolean>.Create;
    try
      for var F in Chosen do
      begin
        if Done.ContainsKey( F.Component ) then Continue;

        Done.Add( F.Component, True );
        var Fields: TArray<TPair<string, string>> := nil;

        for var G in Chosen do
          if G.Component = F.Component then
            Fields  := Fields + [ TPair<string, string>.Create( G.Field, G.Suggested ) ];

        try
          Loader.SetComponentFields( AManifestPath, F.Component, Fields );
        except
          on E: EManifestError do
            LogMessage( llError, E.Message );
          on E: EInOutError do
            LogMessage( llError, 'Could not save components.json: ' + E.Message );
        end;
      end;
    finally
      Done.Free;
    end;
  finally
    Loader.Free;
  end;

  LogMessage( llInfo, 'Generate the SBOM again to use the updated components.json' );

end;

// ---------------------------------------------------------------------------
//  UI helpers
// ---------------------------------------------------------------------------

procedure TMainForm.SetProcessing( AValue: Boolean );
begin

  FProcessing       := AValue;

  if AValue then
    Screen.Cursor   := crHourGlass
  else
    Screen.Cursor   := crDefault;

  FBtnGenerate.Enabled := not AValue;
  FBtnValidate.Enabled := not AValue;
  FBtnProject.Enabled := not AValue;
  FBtnManifest.Enabled := not AValue;
  FBtnOutputDir.Enabled := not AValue;
  FBtnDelphiPath.Enabled := not AValue;
  FEdtProject.Enabled := not AValue;
  FEdtManifest.Enabled := not AValue;
  FEdtOutputDir.Enabled := not AValue;
  FEdtDelphiPath.Enabled := not AValue;
  FEdtVersion.Enabled := not AValue;
  FEdtDXComply.Enabled := not AValue;
  FBtnDXComply.Enabled := not AValue;
  FEdtMapFile.Enabled := not AValue;
  FBtnMapFile.Enabled := not AValue;
  FBtnCheckOnline.Enabled := not AValue;
  FChkReports.Enabled := not AValue;

  // The result buttons write components.json or read the SBOM file — never while a run is using them
  UpdateActionButtons;

end;

procedure TMainForm.UpdateActionButtons;
begin

  var HasLibraries  := Length( FDiscoveredLibraries ) > 0;

  FBtnSaveRegen.Enabled := ( not FProcessing ) and HasLibraries;
  FBtnEditLibraries.Enabled := ( not FProcessing ) and HasLibraries;
  FBtnMarkOwnCode.Enabled := ( not FProcessing ) and ( Length( GetUnresolvedUnits ) > 0 );
  FBtnViewSBOM.Enabled := ( not FProcessing ) and FLastResult.Success and
    ( FLastResult.OutputFile <> '' ) and FileExists( FLastResult.OutputFile );

end;

procedure TMainForm.ClearResults;
begin

  FLastResult       := Default( TSBOMResult );
  FDiscoveredLibraries := nil;
  FLibrariesEdited  := False;
  FMmoSummary.Clear;
  FMmoDiscovery.Clear;
  UpdateActionButtons;

end;

procedure TMainForm.LogMessage( ALevel: TLogLevel; const AMessage: string );
begin

  FMmoLog.Lines.Add( FormatLogMessage( ALevel, AMessage ) );

end;

procedure TMainForm.DisplayResults( const AResult: TSBOMResult );
begin

  FMmoSummary.Clear;
  FMmoDiscovery.Clear;
  FLastResult       := AResult;
  FDiscoveredLibraries := nil;
  FLibrariesEdited  := False;

  if ( not AResult.Success ) then
  begin
    FMmoSummary.Lines.Add( 'SBOM generation failed.' );

    if AResult.ErrorMessage <> '' then
      FMmoSummary.Lines.Add( 'Error: ' + AResult.ErrorMessage );

    UpdateActionButtons;
    Exit;
  end;

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
  FMmoSummary.Lines.Add( 'Units from:  ' + AResult.UnitSource );

  if Length( AResult.ValidationErrors ) = 0 then
    FMmoSummary.Lines.Add( 'SBOM check:  passed' )
  else
    FMmoSummary.Lines.Add( Format( 'SBOM check:  %d problems - see the log', [ Length( AResult.ValidationErrors ) ] ) );

  for var F in AResult.ReportFiles do
    FMmoSummary.Lines.Add( 'Report:      ' + ExtractFileName( F ) );

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
      FMmoDiscovery.Lines.Add( 'Click "Edit..." to review them, then "Save & Regenerate" to add them to components.json.' );
      FMmoDiscovery.Lines.Add( '' );

      for var I := 0 to High( FDiscoveredLibraries ) do
      begin
        var Lib     := FDiscoveredLibraries[ I ];

        FMmoDiscovery.Lines.Add( Format( '-- %s --', [ Lib.Name ] ) );
        FMmoDiscovery.Lines.Add( Format( '  Directory: %s', [ Lib.Directory ] ) );

        if Lib.Version <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Version:   %s', [ Lib.Version ] ) );

        if Lib.Vendor <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Vendor:    %s', [ Lib.Vendor ] ) );

        if Lib.Licence <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Licence:   %s', [ Lib.Licence ] ) );

        if Lib.BinaryOnly then
          FMmoDiscovery.Lines.Add( '  Found as:  DCUs only - no source under this folder' );

        if Lib.SuggestedPrefix <> '' then
          FMmoDiscovery.Lines.Add( Format( '  Prefix:    %s', [ Lib.SuggestedPrefix ] ) );

        FMmoDiscovery.Lines.Add( Format( '  Units (%d):', [ Length( Lib.Units ) ] ) );

        for var U in Lib.Units do
          FMmoDiscovery.Lines.Add( '    ' + U );

        FMmoDiscovery.Lines.Add( '' );
      end;
    end;

    // Show remaining unclassified units (not found on disk)
    var UnfoundUnits := TList<string>.Create;
    try
      for var CU in FLastResult.ClassifiedUnits do
      begin
        if CU.Classification <> ucUnclassified then Continue;

        var Found   := False;

        for var Lib in FDiscoveredLibraries do
        begin
          for var U in Lib.Units do
            if SameText( U, CU.OriginalName ) then
            begin
              Found := True;
              Break;
            end;

          if Found then Break;
        end;

        if ( not Found ) then
          UnfoundUnits.Add( CU.OriginalName );
      end;

      if UnfoundUnits.Count > 0 then
      begin
        FMmoDiscovery.Lines.Add( 'UNRESOLVED UNITS' );
        FMmoDiscovery.Lines.Add( '================' );
        FMmoDiscovery.Lines.Add( 'No .pas or .dcu files found. Click "Mark as Own Code"' );
        FMmoDiscovery.Lines.Add( 'if these are your own project files:' );

        for var U in UnfoundUnits do
          FMmoDiscovery.Lines.Add( '  ' + U );
      end;
    finally
      UnfoundUnits.Free;
    end;

  finally
    FMmoDiscovery.Lines.EndUpdate;
  end;

  UpdateActionButtons;

end;

procedure TMainForm.BtnSaveRegenClick( Sender: TObject );
begin

  if ( Length( FDiscoveredLibraries ) = 0 ) or FProcessing then Exit;

  // The manifest the results came from — not whatever the field says now
  var ManifestPath  := FLastResult.ManifestFile;

  if ManifestPath = '' then
  begin
    ShowMessage( 'No manifest file specified.' );
    Exit;
  end;

  FMmoLog.Clear;

  // Save confirmed libraries to components.json
  var Loader        := TManifestLoader.Create(
    procedure( ALevel: TLogLevel; AMsg: string )
    begin
      LogMessage( ALevel, AMsg );
    end );
  try
    try
      Loader.SaveDiscoveredLibraries( ManifestPath, FDiscoveredLibraries );
    except
      on E: EManifestError do
      begin
        LogMessage( llError, E.Message );
        ShowMessage( E.Message );
        Exit;
      end;
    end;
  finally
    Loader.Free;
  end;

  FLibrariesEdited  := False;

  // Re-run generation, keeping the save messages in the log
  LogMessage( llInfo, 'Regenerating SBOM with updated manifest...' );
  StartGenerate( False );

end;

procedure TMainForm.BtnEditLibrariesClick( Sender: TObject );
begin

  if Length( FDiscoveredLibraries ) = 0 then Exit;

  if TLibraryEditorForm.Execute( FDiscoveredLibraries ) then
  begin
    // Refresh the discovery memo with edited values
    FLibrariesEdited := True;
    FMmoDiscovery.Clear;
    DisplayDiscoveredLibraries;
    LogMessage( llInfo, 'Library metadata updated from editor — click "Save & Regenerate" to write it to components.json' );
  end;

end;

procedure TMainForm.BtnViewSBOMClick( Sender: TObject );
begin

  if ( FLastResult.OutputFile = '' ) or ( not FileExists( FLastResult.OutputFile ) ) then
  begin
    ShowMessage( 'No SBOM file available.' );
    Exit;
  end;

  var ViewForm      := TForm.Create( Self );
  try
    ViewForm.Caption := 'SBOM - ' + ExtractFileName( FLastResult.OutputFile );
    ViewForm.Width  := 800;
    ViewForm.Height := 600;
    ViewForm.Position := poMainFormCenter;

{$IFDEF USE_SYNEDIT}
    var Editor      := TSynEdit.Create( ViewForm );
    Editor.Parent   := ViewForm;
    Editor.Align    := alClient;
    Editor.ReadOnly := True;
    Editor.Font.Name := 'Consolas';
    Editor.Font.Size := 10;
    Editor.Gutter.ShowLineNumbers := True;

    var Highlighter := TSynJSONSyn.Create( ViewForm );
    Editor.Highlighter := Highlighter;

    Editor.Lines.LoadFromFile( FLastResult.OutputFile, TEncoding.UTF8 );
{$ELSE}
    var Memo        := TMemo.Create( ViewForm );
    Memo.Parent     := ViewForm;
    Memo.Align      := alClient;
    Memo.ReadOnly   := True;
    Memo.ScrollBars := ssBoth;
    Memo.Font.Name  := 'Consolas';
    Memo.Font.Size  := 10;
    Memo.Lines.LoadFromFile( FLastResult.OutputFile, TEncoding.UTF8 );
{$ENDIF}

    var BtnClose    := TButton.Create( ViewForm );
    BtnClose.Parent := ViewForm;
    BtnClose.Align  := alBottom;
    BtnClose.Height := 35;
    BtnClose.Caption := 'Close';
    BtnClose.ModalResult := mrOK;

    ViewForm.ShowModal;
  finally
    ViewForm.Free;
  end;

end;

procedure TMainForm.BtnMarkOwnCodeClick( Sender: TObject );
begin

  var UnresolvedUnits := GetUnresolvedUnits;

  if ( Length( UnresolvedUnits ) = 0 ) or FProcessing then Exit;

  // The manifest the results came from — not whatever the field says now
  var ManifestPath  := FLastResult.ManifestFile;

  if ManifestPath = '' then
  begin
    ShowMessage( 'No manifest file specified.' );
    Exit;
  end;

  FMmoLog.Clear;

  var Loader        := TManifestLoader.Create(
    procedure( ALevel: TLogLevel; AMsg: string )
    begin
      LogMessage( ALevel, AMsg );
    end );
  try
    try
      Loader.SaveOwnCodeUnits( ManifestPath, UnresolvedUnits );
    except
      on E: EManifestError do
      begin
        LogMessage( llError, E.Message );
        ShowMessage( E.Message );
        Exit;
      end;
    end;
  finally
    Loader.Free;
  end;

  LogMessage( llInfo, 'Regenerating SBOM with own-code units marked...' );
  StartGenerate( False );

end;

function TMainForm.GetUnresolvedUnits: TArray<string>;
begin

  var Unfound       := TList<string>.Create;
  try
    for var CU in FLastResult.ClassifiedUnits do
    begin
      if CU.Classification <> ucUnclassified then Continue;

      var Found     := False;

      for var Lib in FDiscoveredLibraries do
      begin
        for var U in Lib.Units do
          if SameText( U, CU.OriginalName ) then
          begin
            Found   := True;
            Break;
          end;

        if Found then Break;
      end;

      if ( not Found ) then
        Unfound.Add( CU.OriginalName );
    end;

    Result          := Unfound.ToArray;
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

  var Entry         := Default( TMRUEntry );
  Entry.ProjectFile := Trim( FEdtProject.Text );
  Entry.ManifestFile := Trim( FEdtManifest.Text );
  Entry.OutputDir   := Trim( FEdtOutputDir.Text );
  Entry.VersionOverride := Trim( FEdtVersion.Text );
  Entry.DXComplyFile := Trim( FEdtDXComply.Text );
  Entry.MapFile     := Trim( FEdtMapFile.Text );
  Entry.WriteReports := FChkReports.Checked;

  if Entry.ProjectFile = '' then Exit;

  FMRUManager.AddOrPromote( Entry );

  try
    FMRUManager.Save;
  except
    on E: Exception do
      LogMessage( llWarning, 'Could not save MRU list: ' + E.Message );
  end;

  // Refresh dropdown items
  var CurrentText   := FEdtProject.Text;
  FEdtProject.Items.Clear;

  for var MRUEntry in FMRUManager.GetEntries do
    FEdtProject.Items.Add( MRUEntry.ProjectFile );

  FEdtProject.Text  := CurrentText;

end;

procedure TMainForm.CboProjectSelect( Sender: TObject );
begin

  if FEdtProject.ItemIndex < 0 then Exit;

  ApplyProjectSettings;

end;

procedure TMainForm.EdtProjectExit( Sender: TObject );
begin

  // A path typed or pasted by hand: switch the per-project fields once the user leaves the box
  if ( Trim( FEdtProject.Text ) <> '' ) and ( not SameText( Trim( FEdtProject.Text ), FFieldsProject ) ) then
    ApplyProjectSettings;

end;

// ---------------------------------------------------------------------------
//  Per-project defaults
// ---------------------------------------------------------------------------

procedure TMainForm.ApplyProjectSettings;
begin

  var ProjectFile   := Trim( FEdtProject.Text );
  FFieldsProject    := ProjectFile;

  // Results belong to the previous project
  ClearResults;

  // Defaults first, so nothing from the previous project survives. The manifest is not created
  // here: it is written only when the user saves libraries or own-code units.
  var ProjectDir    := ExcludeTrailingPathDelimiter( ExtractFilePath( ProjectFile ) );

  if ProjectDir <> '' then
  begin
    FEdtManifest.Text := TPath.Combine( ProjectDir, 'components.json' );
    FEdtOutputDir.Text := ProjectDir;
  end
  else
  begin
    FEdtManifest.Text := '';
    FEdtOutputDir.Text := '';
  end;

  FEdtVersion.Text  := '';
  FEdtDXComply.Text := '';
  FEdtMapFile.Text  := '';
  FChkReports.Checked := False;

  // Then the project's remembered settings
  var Entry         := FMRUManager.FindEntry( ProjectFile );

  if Entry.ProjectFile = '' then Exit;

  if Entry.ManifestFile <> '' then
    FEdtManifest.Text := Entry.ManifestFile;

  if Entry.OutputDir <> '' then
    FEdtOutputDir.Text := Entry.OutputDir;

  FEdtVersion.Text  := Entry.VersionOverride;
  FEdtDXComply.Text := Entry.DXComplyFile;
  FEdtMapFile.Text  := Entry.MapFile;
  FChkReports.Checked := Entry.WriteReports;

end;

end.

