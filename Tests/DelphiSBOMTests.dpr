program DelphiSBOMTests;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  uTypes in '..\Source\uTypes.pas',
  uTextFiles in '..\Source\uTextFiles.pas',
  uDelphiInstall in '..\Source\uDelphiInstall.pas',
  uProjectParser in '..\Source\uProjectParser.pas',
  uRTLScanner in '..\Source\uRTLScanner.pas',
  uManifestLoader in '..\Source\uManifestLoader.pas',
  uUnitClassifier in '..\Source\uUnitClassifier.pas',
  uLibraryDiscovery in '..\Source\uLibraryDiscovery.pas',
  uEvidenceMerger in '..\Source\uEvidenceMerger.pas',
  uSBOMBuilder in '..\Source\uSBOMBuilder.pas',
  uSBOMEngine in '..\Source\uSBOMEngine.pas',
  TestSupport in 'TestSupport.pas',
  TestTypes in 'TestTypes.pas',
  TestTextFiles in 'TestTextFiles.pas',
  TestProjectParser in 'TestProjectParser.pas',
  TestManifestLoader in 'TestManifestLoader.pas',
  TestUnitClassifier in 'TestUnitClassifier.pas',
  TestSBOMBuilder in 'TestSBOMBuilder.pas',
  TestEvidenceMerger in 'TestEvidenceMerger.pas',
  TestSBOMEngine in 'TestSBOMEngine.pas',
  TestDelphiInstall in 'TestDelphiInstall.pas',
  TestLibraryDiscovery in 'TestLibraryDiscovery.pas';

begin

  try
    // String assertions compare case-sensitively unless a test says otherwise: several tests are about casing
    Assert.IgnoreCaseDefault := False;

    TDUnitX.CheckCommandLine;

    var Runner := TDUnitX.CreateRunner;

    // Fixtures are discovered from their [TestFixture] attributes; no unit registers explicitly,
    // so a stock DUnitX (which does not de-duplicate) never runs a fixture twice
    Runner.UseRTTI := True;

    // A test that asserts nothing fails instead of passing silently
    Runner.FailsOnNoAsserts := True;

    Runner.AddLogger( TDUnitXConsoleLogger.Create( TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet ) );
    Runner.AddLogger( TDUnitXXMLNUnitFileLogger.Create( TDUnitX.Options.XMLOutputFile ) );

    var Results := Runner.Execute;

    if ( not Results.AllPassed ) then
      System.ExitCode := EXIT_ERRORS;

    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      Write( 'Done.. press <Enter> key to quit.' );
      Readln;
    end;
  except
    on E: Exception do
    begin
      Writeln( E.ClassName, ': ', E.Message );
      System.ExitCode := EXIT_ERRORS;
    end;
  end;

end.
