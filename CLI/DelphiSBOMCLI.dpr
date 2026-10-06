(*
  DelphiSBOM — CycloneDX 1.5 SBOM Generator for Delphi Applications
  Copyright (c) 2026 Ian
  MIT Licence — see LICENCE file

  DelphiSBOMCLI.dpr — Command-line SBOM generation for builds and CI (see Docs/CI-INTEGRATION.md)
*)
program DelphiSBOMCLI;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Winapi.Windows,
  uTypes in '..\Source\uTypes.pas',
  uTextFiles in '..\Source\uTextFiles.pas',
  uDelphiInstall in '..\Source\uDelphiInstall.pas',
  uProjectParser in '..\Source\uProjectParser.pas',
  uRTLScanner in '..\Source\uRTLScanner.pas',
  uManifestLoader in '..\Source\uManifestLoader.pas',
  uUnitClassifier in '..\Source\uUnitClassifier.pas',
  uLibraryDiscovery in '..\Source\uLibraryDiscovery.pas',
  uEvidenceMerger in '..\Source\uEvidenceMerger.pas',
  uMapFile in '..\Source\uMapFile.pas',
  uSBOMBuilder in '..\Source\uSBOMBuilder.pas',
  uSBOMValidator in '..\Source\uSBOMValidator.pas',
  uReportWriter in '..\Source\uReportWriter.pas',
  uSBOMEngine in '..\Source\uSBOMEngine.pas',
  uCommandLine in '..\Source\uCommandLine.pas';

begin

  // UTF-8 on the console and through redirection, so paths outside the ANSI code page survive
  SetConsoleOutputCP( CP_UTF8 );
  SetTextCodePage( Output, CP_UTF8 );
  SetTextCodePage( ErrOutput, CP_UTF8 );

  var Args: TArray<string>;
  SetLength( Args, ParamCount );

  for var I := 1 to ParamCount do
    Args[ I - 1 ] := ParamStr( I );

  try
    ExitCode := RunCommandLine( Args,
      procedure( ALine: string )
      begin
        WriteLn( Output, ALine );
      end,
      procedure( ALine: string )
      begin
        WriteLn( ErrOutput, ALine );
      end );
  except
    on E: Exception do
    begin
      WriteLn( ErrOutput, '[ERROR] ' + E.ClassName + ': ' + E.Message );
      ExitCode := ExitFileError;
    end;
  end;

end.
