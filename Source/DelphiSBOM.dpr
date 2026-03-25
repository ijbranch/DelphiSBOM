program DelphiSBOM;

uses
  Vcl.Forms,
  uMainForm in 'uMainForm.pas' {MainForm},
  uTypes in 'uTypes.pas',
  uProjectParser in 'uProjectParser.pas',
  uRTLScanner in 'uRTLScanner.pas',
  uManifestLoader in 'uManifestLoader.pas',
  uUnitClassifier in 'uUnitClassifier.pas',
  uSBOMBuilder in 'uSBOMBuilder.pas',
  uSBOMEngine in 'uSBOMEngine.pas',
  uLibraryDiscovery in 'uLibraryDiscovery.pas';

{$R *.res}

begin

  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'DelphiSBOM';
  Application.CreateForm( TMainForm, MainForm );
  Application.Run;

end.
