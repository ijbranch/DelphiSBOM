# GUI checks for DelphiSBOM, driven by window messages to named controls (no coordinates, no forced focus).
# Covers: project switching (H3), result-button states during a run (M10), no manifest on select (M13),
# MRU restore, library-editor Space toggle + close validation + discard prompt (L15), MRU UTF-8 round trip (M20),
# MAP-file unit list, reports checkbox and the summary's unit source and SBOM check lines.
#
# Usage (PowerShell 7, Windows):  pwsh -File Tests\GuiChecks.ps1 [-Exe <path to DelphiSBOM.exe>]
# Builds nothing: build Source\DelphiSBOM.dproj (Release, Win64) first. Your %APPDATA%\DelphiSBOM\DelphiSBOM.ini
# is backed up before the run and restored afterwards. Test projects are created under %TEMP% and removed.
# The library editor's grid cell is focused with a click posted in client coordinates that assume the editor's
# default column widths at 100% logical scale (the app is DPI-unaware).

param(
  [string]$Exe = ( Join-Path $PSScriptRoot '..\Source\Win64\Release\DelphiSBOM.exe' )
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "DelphiSBOM.exe not found at $Exe — build Source\DelphiSBOM.dproj (Release, Win64) first" }
$Scratch = Join-Path $env:TEMP ('DelphiSBOMGui-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$IniDir  = Join-Path $env:APPDATA 'DelphiSBOM'
$Ini     = Join-Path $IniDir 'DelphiSBOM.ini'
$IniBak  = Join-Path $Scratch 'DelphiSBOM.ini.bak'

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class W {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, int m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  public static string Cls(IntPtr h) { var s = new StringBuilder(256); GetClassName(h, s, 256); return s.ToString(); }
  public static string Text(IntPtr h) {
    int n = (int)SendMessage(h, 0x000E, IntPtr.Zero, IntPtr.Zero);            // WM_GETTEXTLENGTH
    var s = new StringBuilder(n + 1); SendMessage(h, 0x000D, (IntPtr)(n + 1), s); return s.ToString(); }
  public static List<IntPtr> Children(IntPtr p) { var r = new List<IntPtr>(); EnumChildWindows(p, (h, l) => { r.Add(h); return true; }, IntPtr.Zero); return r; }
  public static List<IntPtr> TopWindows(uint pid) { var r = new List<IntPtr>();
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == pid && IsWindowVisible(h)) r.Add(h); return true; }, IntPtr.Zero); return r; }
}
'@

$WM_SETTEXT = 0x000C; $WM_CLOSE = 0x0010; $WM_CHAR = 0x0102; $WM_KEYDOWN = 0x0100; $WM_KEYUP = 0x0101
$BM_CLICK = 0x00F5; $WM_COMMAND = 0x0111; $CB_SETCURSEL = 0x014E; $CB_GETCOUNT = 0x0146
$CB_GETLBTEXT = 0x0148; $CB_GETLBTEXTLEN = 0x0149; $CBN_SELCHANGE = 1

$Results = [System.Collections.Generic.List[object]]::new()
function Check([bool]$ok, [string]$name, [string]$detail = '') {
  $Results.Add([pscustomobject]@{ Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Check = $name; Detail = $detail })
}
function WaitFor([scriptblock]$cond, [int]$ms = 60000) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $ms) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 50 }
  return $false
}
function Top($rect) { $r = New-Object W+RECT; [void][W]::GetWindowRect($rect, [ref]$r); $r }

# ---- fixtures -----------------------------------------------------------------------------------------------
New-Item -ItemType Directory -Path $Scratch | Out-Null
$ProjA = Join-Path $Scratch 'Work\ProjA'; $LibDir = Join-Path $Scratch 'Work\ZzqLib'
$ProjB = Join-Path $Scratch ('Work\' + [string][char]0x041F + [char]0x0440 + [char]0x043E + [char]0x0435 + [char]0x043A + [char]0x0442 + '\ProjB')  # Cyrillic folder
foreach ($d in $ProjA, $LibDir, $ProjB) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText("$ProjA\ProjA.dpr", "program ProjA;`r`nuses`r`n  System.SysUtils, UnitA in 'UnitA.pas', ZzqLibMain, ZzqLibUtils, ZzqMissing;`r`nbegin end.", $utf8)
[IO.File]::WriteAllText("$ProjA\UnitA.pas", "unit UnitA; interface implementation end.", $utf8)
[IO.File]::WriteAllText("$ProjA\ProjA.dproj", '<Project><PropertyGroup><ProjectVersion>20.4</ProjectVersion></PropertyGroup><PropertyGroup><DCC_UnitSearchPath>..\ZzqLib</DCC_UnitSearchPath></PropertyGroup><ProjectExtensions><BorlandProject><Platforms><Platform value="Win64">True</Platform></Platforms></BorlandProject></ProjectExtensions></Project>', $utf8)
[IO.File]::WriteAllText("$LibDir\ZzqLibMain.pas", "// Copyright (c) 2024 Zzq Widgets`r`nunit ZzqLibMain; interface implementation end.", $utf8)
[IO.File]::WriteAllText("$LibDir\ZzqLibUtils.pas", "unit ZzqLibUtils; interface implementation end.", $utf8)
[IO.File]::WriteAllText("$LibDir\LICENSE", "MIT License`r`nPermission is hereby granted, free of charge, to any person obtaining a copy", $utf8)
[IO.File]::WriteAllText("$ProjB\ProjB.dpr", "program ProjB;`r`nuses`r`n  System.SysUtils;`r`nbegin end.", $utf8)
# A detailed map for project A: ZzqIndirect is linked but not in the uses clause, ZzqMissing is in it but not linked
[IO.File]::WriteAllText("$LibDir\ZzqIndirect.pas", "unit ZzqIndirect; interface implementation end.", $utf8)
$MapA = "$ProjA\ProjA.map"
[IO.File]::WriteAllText($MapA, "Detailed map of segments`r`n" + ((
  'System', 'System.SysUtils', 'UnitA', 'ZzqLibMain', 'ZzqLibUtils', 'ZzqIndirect', 'ProjA' | ForEach-Object {
    " 0001:00000000 00000010 C=CODE     S=.text    G=(none)   M=$_ ALIGN=4" }) -join "`r`n"), $utf8)
$Bom = Join-Path $Scratch 'bom.json'
[IO.File]::WriteAllText($Bom, '{ "bomFormat": "CycloneDX", "components": [] }', $utf8)

# ---- protect the user's real settings ----------------------------------------------------------------------
$HadIni = Test-Path $Ini
if ($HadIni) { Copy-Item $Ini $IniBak; Remove-Item $Ini }

$proc = $null
try {
  function Launch {
    $p = Start-Process -FilePath $Exe -PassThru
    if (-not (WaitFor { $script:main = [W]::TopWindows([uint32]$p.Id) | Where-Object { [W]::Text($_) -like 'DelphiSBOM*' } | Select-Object -First 1; $script:main } 15000)) { throw 'Main window did not appear' }
    $p
  }
  function MapControls {
    $kids = [W]::Children($script:main)
    $script:combo = $kids | Where-Object { [W]::Cls($_) -eq 'TComboBox' } | Select-Object -First 1
    $edits = $kids | Where-Object { [W]::Cls($_) -eq 'TEdit' } | Sort-Object { (Top $_).T }
    $script:edManifest, $script:edOutput, $script:edDelphi, $script:edVersion, $script:edDX, $script:edMap = $edits
    $script:chkReports = $kids | Where-Object { [W]::Cls($_) -eq 'TCheckBox' } | Select-Object -First 1
    $btn = @{}; foreach ($k in $kids | Where-Object { [W]::Cls($_) -eq 'TButton' }) { $btn[[W]::Text($k)] = $k }
    $script:btn = $btn
    $memos = $kids | Where-Object { [W]::Cls($_) -eq 'TMemo' } | Sort-Object { (Top $_).B }, { (Top $_).L }
    $script:mmLog = $memos[-1]                                            # lowest = log
    $upper = $memos[0..1] | Sort-Object { (Top $_).L }
    $script:mmSummary, $script:mmDiscovery = $upper
  }
  function SetText($h, [string]$t) { [void][W]::SendMessage($h, $WM_SETTEXT, [IntPtr]::Zero, $t) }
  function Click($h) { [void][W]::PostMessage($h, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) }
  function Generate {
    # Watch the result buttons while the run is in progress (M10)
    # Completion is read from the log (a fast run can start and finish between two polls)
    $script:seenEnabledDuringRun = $false; $script:sawRun = $false
    SetText $mmLog ''
    Click $btn['Generate SBOM']
    WaitRun
  }
  function WaitRun {
    $done = WaitFor {
      $busy = -not [W]::IsWindowEnabled($btn['Generate SBOM'])
      if ($busy) { $script:sawRun = $true
        foreach ($n in 'Save && Regenerate', 'Edit...', 'Mark as Own Code', 'View SBOM File') {
          if ([W]::IsWindowEnabled($btn[$n])) { $script:seenEnabledDuringRun = $true } } }
      (-not $busy) -and ([W]::Text($mmLog) -match 'SBOM generation complete|\[ERROR\]') } 180000
    if (-not $done) { throw 'Generation did not finish' }
  }
  # Any visible top-level window of the app that is not the main form or the library editor is a dialog
  function FindDialog { [W]::TopWindows([uint32]$proc.Id) | Where-Object { [W]::Cls($_) -in 'TMessageForm', '#32770' } | Select-Object -First 1 }
  # Press a dialog button: a VCL TMessageForm has real TButton children; a task dialog / MessageBox takes the command id
  function PressDialog($dlg, [int]$id, [string]$textRegex) {
    $b = [W]::Children($dlg) | Where-Object { [W]::Cls($_) -eq 'TButton' -and [W]::Text($_) -match $textRegex } | Select-Object -First 1
    if ($b) { [void][W]::PostMessage($b, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) }
    else { [void][W]::PostMessage($dlg, 0x0466, [IntPtr]$id, [IntPtr]::Zero)          # TDM_CLICK_BUTTON
           [void][W]::PostMessage($dlg, $WM_COMMAND, [IntPtr]$id, [IntPtr]::Zero) }
    Start-Sleep -Milliseconds 400 }
  $script:editor = [IntPtr]::Zero

  $proc = Launch
  MapControls
  Check ([W]::Text($edDelphi) -eq '') 'Delphi Path blank at start (project version decides)' ([W]::Text($edDelphi))

  # ---- Project A ------------------------------------------------------------------------------------------
  SetText $combo "$ProjA\ProjA.dpr"
  Generate
  Check $sawRun 'Run observed in progress' ''
  Check (-not $seenEnabledDuringRun) 'M10 result buttons disabled while a run is in progress'
  Check ((Get-Content -Raw (Join-Path $ProjA 'ProjA.cdx.json')) -match '"bomFormat"') 'Project A SBOM written'
  Check (-not (Test-Path "$ProjA\components.json")) 'M13 selecting/generating does not create components.json'
  Check ([W]::IsWindowEnabled($btn['Save && Regenerate']) -and [W]::IsWindowEnabled($btn['Edit...'])) 'Save/Edit enabled after discovery'
  Check ([W]::IsWindowEnabled($btn['Mark as Own Code'])) 'Mark as Own Code enabled (ZzqMissing unresolved)'
  Check ([W]::IsWindowEnabled($btn['View SBOM File'])) 'View SBOM enabled after success'
  Check ([W]::Text($mmDiscovery) -match 'ZzqLib' -and [W]::Text($mmDiscovery) -match 'Licence:\s+MIT') 'Sibling library discovered as third-party with MIT'
  Check ([W]::Text($mmDiscovery) -match 'Save & Regenerate' -and [W]::Text($mmDiscovery) -match '"Mark as Own Code"') 'L14 instructions name the real buttons'

  SetText $edVersion '9.9.9'
  SetText $edDX $Bom
  SetText $edMap $MapA
  Click $chkReports
  Start-Sleep -Milliseconds 200
  Generate   # saves A's settings to the MRU
  Check ([W]::Text($mmLog) -match 'MAP file ProjA\.map lists 6 linked units') 'MAP file supplies the unit list' (([W]::Text($mmLog) -split "`r`n" | Select-String 'MAP file') -join ' ')
  Check ([W]::Text($mmSummary) -match 'Units from:\s+MAP file ProjA\.map') 'Summary names the unit source'
  Check ([W]::Text($mmSummary) -match 'SBOM check:\s+passed') 'Summary shows the SBOM check result'
  Check ((Test-Path "$ProjA\ProjA.sbom-report.html") -and (Test-Path "$ProjA\ProjA.sbom-report.md")) 'Reports checkbox writes both reports'
  Check ([W]::Text($mmDiscovery) -match 'ZzqIndirect') 'Indirectly used unit from the MAP is discovered'

  # ---- Project B (Cyrillic path): A's fields must not carry over -------------------------------------------
  SetText $combo "$ProjB\ProjB.dpr"
  Generate
  Check ([W]::Text($edVersion) -eq '') 'H3 Version Override cleared on switching project' ([W]::Text($edVersion))
  Check ([W]::Text($edDX) -eq '') 'H3 DX.Comply cleared on switching project' ([W]::Text($edDX))
  Check ([W]::Text($edMap) -eq '') 'MAP file cleared on switching project' ([W]::Text($edMap))
  Check ([int][W]::SendMessage($chkReports, 0x00F0, [IntPtr]::Zero, [IntPtr]::Zero) -eq 0) 'Reports checkbox cleared on switching project'
  Check (-not (Test-Path "$ProjB\ProjB.sbom-report.html")) 'No report for project B'
  Check ([W]::Text($edManifest) -eq "$ProjB\components.json") 'H3 Manifest points at project B' ([W]::Text($edManifest))
  Check ([W]::Text($edOutput) -eq $ProjB) 'H3 Output Dir points at project B' ([W]::Text($edOutput))
  Check (Test-Path "$ProjB\ProjB.cdx.json") 'Project B SBOM written into the Cyrillic folder'
  Check (-not (Test-Path "$ProjA\components.json")) 'H3 project A manifest untouched by the B run'

  # ---- MRU: select project A from the dropdown, its settings come back ---------------------------------------
  $count = [int][W]::SendMessage($combo, $CB_GETCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
  $idxA = -1
  for ($i = 0; $i -lt $count; $i++) {
    $sb = New-Object Text.StringBuilder 1024; [void][W]::SendMessage($combo, $CB_GETLBTEXT, [IntPtr]$i, $sb)
    if ($sb.ToString() -eq "$ProjA\ProjA.dpr") { $idxA = $i } }
  Check ($idxA -ge 0) 'MRU lists project A' "count=$count"
  [void][W]::SendMessage($combo, $CB_SETCURSEL, [IntPtr]$idxA, [IntPtr]::Zero)
  $wparam = [IntPtr](($CBN_SELCHANGE -shl 16) -bor ([W]::GetDlgCtrlID($combo) -band 0xFFFF))
  [void][W]::SendMessage($main, $WM_COMMAND, $wparam, $combo)
  Check ([W]::Text($edVersion) -eq '9.9.9') 'MRU restores Version Override for A' ([W]::Text($edVersion))
  Check ([W]::Text($edDX) -eq $Bom) 'MRU restores DX.Comply for A' ([W]::Text($edDX))
  Check ([W]::Text($edMap) -eq $MapA) 'MRU restores the MAP file for A' ([W]::Text($edMap))
  Check ([int][W]::SendMessage($chkReports, 0x00F0, [IntPtr]::Zero, [IntPtr]::Zero) -eq 1) 'MRU restores the reports checkbox for A'
  Check (-not [W]::IsWindowEnabled($btn['Edit...'])) 'Switching project clears the previous results'

  Generate
  # ---- Library editor --------------------------------------------------------------------------------------
  Click $btn['Edit...']
  if (-not (WaitFor { $script:editor = [W]::TopWindows([uint32]$proc.Id) | Where-Object { [W]::Text($_) -eq 'Edit Discovered Libraries' } | Select-Object -First 1; $script:editor } 10000)) { throw 'Editor did not open' }
  $grid = [W]::Children($editor) | Where-Object { [W]::Cls($_) -eq 'TStringGrid' } | Select-Object -First 1
  $edBtns = @{}; foreach ($k in [W]::Children($editor) | Where-Object { [W]::Cls($_) -eq 'TButton' }) { $edBtns[[W]::Text($k)] = $k }
  function Key($vk) { [void][W]::SendMessage($grid, $WM_KEYDOWN, [IntPtr]$vk, [IntPtr]::Zero); [void][W]::SendMessage($grid, $WM_KEYUP, [IntPtr]$vk, [IntPtr]::Zero) }
  function Char($c) { [void][W]::SendMessage($grid, $WM_CHAR, [IntPtr][int][char]$c, [IntPtr]::Zero) }

  # The grid only shows its cell editor while it has focus: a click posted in the grid's own client
  # coordinates focuses it and selects row 1, Name column (Include 55 px wide, header row 22 px)
  function ClickNameCell {
    $lp = [IntPtr]((34 -shl 16) -bor 140)
    [void][W]::PostMessage($grid, 0x0201, [IntPtr]1, $lp)        # WM_LBUTTONDOWN
    [void][W]::PostMessage($grid, 0x0202, [IntPtr]0, $lp)        # WM_LBUTTONUP
    Start-Sleep -Milliseconds 300 }
  function SetCell([string]$text) {
    Char 'x'
    if (-not (WaitFor { $script:inplace = [W]::Children($grid) | Where-Object { [W]::Cls($_) -eq 'TInplaceEdit' -and [W]::IsWindowVisible($_) } | Select-Object -First 1; $script:inplace } 3000)) { throw 'Cell editor did not open' }
    SetText $script:inplace $text
    [void][W]::SendMessage($script:inplace, $WM_KEYDOWN, [IntPtr]0x0D, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 200 }

  # Blank the name of the (included) row
  ClickNameCell
  SetCell ''
  Click $edBtns['OK']
  $warn = $null
  $sawWarning = WaitFor { $script:warn = FindDialog; $script:warn } 5000
  Check $sawWarning 'L15 OK with an included, nameless row shows a warning' $(if ($warn) { "[$([W]::Cls($warn))] $([W]::Text($warn))" })
  if ($warn) { PressDialog $warn 1 '^&?OK$' }
  Check ([W]::IsWindowVisible($editor)) 'L15 editor stays open after the warning'

  # Restore a name, then Space on the Include column to exclude the library
  ClickNameCell
  SetCell 'ZzqLib'
  Key 0x25                       # VK_LEFT -> Include column
  Char ' '                       # Space toggles Include -> No
  Click $edBtns['OK']
  Check (WaitFor { -not [W]::IsWindowVisible($editor) } 5000) 'Editor closes on OK once every included row has a name'

  # ---- Generate with unsaved edits asks first; answering No keeps them --------------------------------------
  Click $btn['Generate SBOM']
  $script:editor = [IntPtr]::Zero
  $confirm = $null
  $asked = WaitFor { $script:confirm = FindDialog; $script:confirm } 5000
  Check $asked 'L15 Generate asks before discarding unsaved editor changes' $(if ($confirm) { "[$([W]::Cls($confirm))] $([W]::Text($confirm))" })
  if ($confirm) { PressDialog $confirm 7 '^&?No$' }
  Check ([W]::IsWindowEnabled($btn['Generate SBOM']) -and [W]::IsWindowEnabled($btn['Edit...'])) 'Answering No keeps the results (no run started)'

  # ---- Save & Regenerate writes the manifest, honouring Include = No ---------------------------------------
  SetText $mmLog ''
  Click $btn['Save && Regenerate']
  WaitRun
  $man = Get-Content -Raw "$ProjA\components.json" | ConvertFrom-Json
  Check ($man.schema_version -eq '1.0' -and $man.components.Count -eq 0) 'Save & Regenerate created the manifest; Include=No library not saved' "components=$($man.components.Count)"
  Check ([W]::Text($mmLog) -match 'Manifest saved') 'L13 save message kept in the log after the regenerate'
  Check ([IO.File]::ReadAllBytes("$ProjA\components.json")[0] -eq 0x7B) 'Manifest written without a BOM'

  # ---- MRU UTF-8 round trip --------------------------------------------------------------------------------
  [void][W]::PostMessage($main, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  [void](WaitFor { $proc.HasExited } 10000)
  $iniText = [IO.File]::ReadAllText($Ini, [Text.Encoding]::UTF8)
  Check ($iniText.Contains($ProjB)) 'M20 Cyrillic project path stored intact in the INI' ''
  $proc = Launch
  MapControls
  $count = [int][W]::SendMessage($combo, $CB_GETCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
  $items = for ($i = 0; $i -lt $count; $i++) { $sb = New-Object Text.StringBuilder 1024; [void][W]::SendMessage($combo, $CB_GETLBTEXT, [IntPtr]$i, $sb); $sb.ToString() }
  Check ($items -contains "$ProjB\ProjB.dpr") 'M20 Cyrillic project survives restart in the MRU list' ($items -join ' | ')
}
catch {
  Check $false 'Script error' $_.Exception.Message
}
finally {
  if ($proc -and -not $proc.HasExited) { [void][W]::PostMessage($main, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); if (-not (WaitFor { $proc.HasExited } 5000)) { Stop-Process -Id $proc.Id -Force } }
  if (Test-Path $Ini) { Remove-Item $Ini }
  if ($HadIni) { Copy-Item $IniBak $Ini }
  $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220
  "INI restored: $HadIni"
  Remove-Item -Recurse -Force $Scratch -ErrorAction SilentlyContinue
}

$failed = @($Results | Where-Object Result -eq 'FAIL').Count
"$($Results.Count - $failed) passed, $failed failed"
exit [int]($failed -gt 0)
