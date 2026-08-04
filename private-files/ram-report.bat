@echo off
REM ==================================================================
REM   WHAT RAM IS IN THIS PC?        siegestack.com/jesse
REM
REM   Read-only. It asks Windows what memory is already installed,
REM   prints it, and saves a text file to your Desktop.
REM
REM   It changes nothing, installs nothing, and sends nothing
REM   anywhere. No internet connection is used at all.
REM   The entire script is readable below - scroll down and look.
REM ==================================================================
setlocal EnableExtensions
set "SELF=%~f0"
where powershell >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Could not find PowerShell on this PC, which is very unusual.
  echo   Take a photo of this window and send it to your dad.
  echo.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $c = Get-Content -LiteralPath $env:SELF -Raw; Invoke-Expression $c.Substring($c.LastIndexOf('#=PSBODY=#') + 10) } catch { Write-Host ''; Write-Host ('  The script hit an error: ' + $_.Exception.Message) -ForegroundColor Red; Write-Host ''; Write-Host '  That is not your fault. Take a photo of this window and' -ForegroundColor Yellow; Write-Host '  send it to your dad, or use the copy-paste command on' -ForegroundColor Yellow; Write-Host '  siegestack.com/jesse instead.' -ForegroundColor Yellow; Write-Host '' }"
echo.
pause
exit /b
#=PSBODY=#

# ------------------------------------------------------------------
#  Everything below is read-only and needs no admin rights.
#  Goal: find out exactly what stick to buy for the empty slot.
# ------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$lines = New-Object System.Collections.Generic.List[string]
function Say($t = '') { Write-Host $t; $lines.Add([string]$t) }
function Hi($t = '')  { Write-Host $t -ForegroundColor Cyan; $lines.Add([string]$t) }

# SMBIOS memory type codes. Anything not on this list prints its raw
# number instead of guessing, because a wrong label is worse than none.
$types = @{
  18='DDR'; 19='DDR2'; 20='DDR2 FB-DIMM'; 21='DDR2'; 24='DDR3'; 25='FBD2'
  26='DDR4'; 27='LPDDR'; 28='LPDDR2'; 29='LPDDR3'; 30='LPDDR4'
  32='HBM'; 33='HBM2'; 34='DDR5'; 35='LPDDR5'; 36='HBM3'
}

# Prefer the modern CIM cmdlets, fall back to old WMI on older Windows.
function Get-Mem {
  try   { return @(Get-CimInstance -ClassName Win32_PhysicalMemory) }
  catch { return @(Get-WmiObject  -Class      Win32_PhysicalMemory) }
}
function Get-Arr {
  try   { return @(Get-CimInstance -ClassName Win32_PhysicalMemoryArray) }
  catch { try { return @(Get-WmiObject -Class Win32_PhysicalMemoryArray) } catch { return @() } }
}
function Get-Board {
  try   { return Get-CimInstance -ClassName Win32_BaseBoard }
  catch { try { return Get-WmiObject -Class Win32_BaseBoard } catch { return $null } }
}
function Get-Sys {
  try   { return Get-CimInstance -ClassName Win32_ComputerSystem }
  catch { try { return Get-WmiObject -Class Win32_ComputerSystem } catch { return $null } }
}

Say ''
Say '  =================================================='
Say '   WHAT RAM IS IN THIS PC?'
Say '  =================================================='
Say ''

$sys = $null; $board = $null
try { $sys = Get-Sys } catch { }
try { $board = Get-Board } catch { }
if ($sys)   { Say ("  PC          : {0} {1}" -f $sys.Manufacturer, $sys.Model) }
if ($board) { Say ("  Motherboard : {0} {1}" -f ([string]$board.Manufacturer).Trim(), ([string]$board.Product).Trim()) }
Say ("  Checked     : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))
Say ''

$mem = @()
$failed = $false
try {
  $mem = Get-Mem
} catch {
  $failed = $true
  Say '  Windows would not answer the memory question.'
  Say ("  Reason: {0}" -f $_.Exception.Message)
  Say ''
  Say '  Try right-clicking this file and choosing "Run as'
  Say '  administrator". If it still fails, see HELP at the bottom.'
}

if (-not $failed -and (-not $mem -or $mem.Count -eq 0)) {
  Say '  No memory modules were reported. That is almost always a'
  Say '  permissions problem, not a hardware problem. See HELP below.'
}

if ($mem -and $mem.Count -gt 0) {

  $totalBytes = 0
  foreach ($m in $mem) { $totalBytes += [double]$m.Capacity }
  $totalGB = [math]::Round($totalBytes / 1GB, 1)

  $slots = $null
  $arr = Get-Arr
  if ($arr -and $arr.Count -gt 0 -and $arr[0].MemoryDevices) { $slots = [int]$arr[0].MemoryDevices }

  # Resolve the type name for each module.
  $typeNames = @()
  foreach ($m in $mem) {
    $code = 0
    if ($m.SMBIOSMemoryType) { $code = [int]$m.SMBIOSMemoryType }
    elseif ($m.MemoryType)   { $code = [int]$m.MemoryType }
    if ($types.ContainsKey($code))  { $typeNames += $types[$code] }
    elseif ($code -gt 0)            { $typeNames += ("Unknown (code {0})" -f $code) }
    else                            { $typeNames += 'Not reported' }
  }

  # ---------- the part your dad actually needs ----------
  Say '  **************************************************'
  Say '   WHAT TO BUY FOR THE EMPTY SLOT'
  Say '  **************************************************'
  Say ''

  $ref = $mem[0]
  $refGB    = if ($ref.Capacity) { [math]::Round([double]$ref.Capacity / 1GB, 1) } else { '?' }
  $refType  = $typeNames[0]
  $refSpeed = if ($ref.Speed) { "$($ref.Speed) MT/s" } else { 'not reported' }
  $refPart  = if ($ref.PartNumber)   { ([string]$ref.PartNumber).Trim() }   else { 'not reported' }
  $refMake  = if ($ref.Manufacturer) { ([string]$ref.Manufacturer).Trim() } else { 'not reported' }

  Hi ("   Buy:  {0} GB   {1}   {2}" -f $refGB, $refType, $refSpeed)
  Hi ("   Exact part number to match:  {0}" -f $refPart)
  Hi ("   Brand:  {0}" -f $refMake)
  Say ''
  Say '   The safest buy is the SAME part number as above. DDR5 is'
  Say '   fussy about mixing - two sticks that were not sold as a'
  Say '   matched pair can refuse to run at full speed, or make the'
  Say '   PC fail to start until you turn XMP/EXPO off in the BIOS.'
  Say '   Same brand, same size, same speed, same part number.'
  Say ''

  if ($slots) {
    Say ("   TOTAL NOW : {0} GB in {1} of {2} slots" -f $totalGB, $mem.Count, $slots)
    if ($mem.Count -lt $slots) {
      $add = [math]::Round([double]$ref.Capacity / 1GB, 1)
      Say ("   AFTER     : about {0} GB if you fill one more slot" -f ($totalGB + $add))
    }
  } else {
    Say ("   TOTAL NOW : {0} GB in {1} module(s)" -f $totalGB, $mem.Count)
  }
  Say ''

  # ---------- slot map: which are full, which are empty ----------
  Say '  ---- slot map ----'
  Say ''
  $used = @()
  foreach ($m in $mem) { if ($m.DeviceLocator) { $used += ([string]$m.DeviceLocator).Trim() } }
  $i = 0
  foreach ($m in $mem) {
    $i++
    $gb = if ($m.Capacity) { [math]::Round([double]$m.Capacity / 1GB, 1) } else { '?' }
    Say ("   [FULL ] {0,-16} {1} GB  {2}  {3}" -f `
      $(if ($m.DeviceLocator) { ([string]$m.DeviceLocator).Trim() } else { "module $i" }), `
      $gb, $typeNames[$i - 1], $(if ($m.Speed) { "$($m.Speed) MT/s" } else { '' }))
  }
  if ($slots -and $mem.Count -lt $slots) {
    Say ("   [EMPTY] {0,-16} <-- this is the one to fill" -f ("x" + ($slots - $mem.Count) + " slot(s)"))
    Say ''
    Say '   Windows can see how many slots exist but not their labels'
    Say '   when they are empty. On most boards with two sticks you'
    Say '   want A2 and B2 (the 2nd and 4th slots from the CPU), not'
    Say '   A1 and B1. Check the motherboard manual - the model is'
    Say '   printed at the top of this report.'
  }
  Say ''

  Say '  ---- full detail for every installed stick ----'
  Say ''
  $i = 0
  foreach ($m in $mem) {
    $i++
    $gb = if ($m.Capacity) { [math]::Round([double]$m.Capacity / 1GB, 1) } else { '?' }
    Say ("   Module {0}" -f $i)
    Say ("     Slot        : {0}" -f $(if ($m.DeviceLocator) { ([string]$m.DeviceLocator).Trim() } else { 'not reported' }))
    if ($m.BankLabel) { Say ("     Bank        : {0}" -f ([string]$m.BankLabel).Trim()) }
    Say ("     Size        : {0} GB" -f $gb)
    Say ("     Type        : {0}" -f $typeNames[$i - 1])
    Say ("     Rated speed : {0}" -f $(if ($m.Speed) { "$($m.Speed) MT/s" } else { 'not reported' }))
    if ($m.ConfiguredClockSpeed) {
      Say ("     Running at  : {0} MT/s" -f $m.ConfiguredClockSpeed)
      if ($m.Speed -and [int]$m.ConfiguredClockSpeed -lt [int]$m.Speed) {
        Say '                   (slower than rated - XMP/EXPO is probably off in the BIOS)'
      }
    }
    Say ("     Made by     : {0}" -f $(if ($m.Manufacturer) { ([string]$m.Manufacturer).Trim() } else { 'not reported' }))
    Say ("     Part number : {0}" -f $(if ($m.PartNumber) { ([string]$m.PartNumber).Trim() } else { 'not reported' }))
    if ($m.SerialNumber) { Say ("     Serial      : {0}" -f ([string]$m.SerialNumber).Trim()) }
    Say ''
  }

  if ($refPart -eq 'not reported' -or $refMake -eq 'not reported') {
    Say '   Heads up: the brand or part number came back blank. Some'
    Say '   sticks just do not report it. If so, open the case and'
    Say '   read the sticker on the stick itself, or use the HELP'
    Say '   prompt below.'
    Say ''
  }
}

# ---------- help, always printed ----------
Say '  =================================================='
Say '   HELP - if any of this did not work'
Say '  =================================================='
Say ''
Say '   1. Right-click this file, choose "Run as administrator",'
Say '      and try once more.'
Say ''
Say '   2. Free tool that shows the same thing with a nicer window:'
Say '      CPU-Z, from cpuid.com. Open the "SPD" tab and click'
Say '      through each slot. That also shows empty slot names.'
Say ''
Say '   3. Still stuck? Copy the prompt below into ChatGPT, Claude,'
Say '      Copilot or Gemini, then paste whatever this window showed'
Say '      underneath it:'
Say ''
Say '   ------------------------------------------------------------'
Say '   I want to add one more stick of RAM to my desktop PC to fill'
Say '   an empty slot. Below is a report of the memory currently'
Say '   installed and my motherboard model. Please tell me: (1) the'
Say '   exact specification of the stick I should buy, (2) whether'
Say '   mixing it with what I already have is risky and why, (3) which'
Say '   physical slot it should go in for dual channel, and (4) what'
Say '   to check in the BIOS afterwards. Here is the report:'
Say '   ------------------------------------------------------------'
Say ''
Say '   4. Or just send the saved text file to your dad. He does this'
Say '      for a living.'
Say ''
Say '  =================================================='
Say ''
Say '   Love you, kiddo. See you soon.'
Say '                                        - Dad'
Say ''
Say '  =================================================='
Say ''

# Save a copy somewhere findable. Desktop first, then the folder the
# script was run from, then temp. A failed write must never kill the run.
$saved = $null
$targets = @()
try { $d = [Environment]::GetFolderPath('Desktop'); if ($d) { $targets += (Join-Path $d 'ram-report.txt') } } catch { }
try { if ($env:SELF) { $targets += (Join-Path (Split-Path -Parent $env:SELF) 'ram-report.txt') } } catch { }
try { $targets += (Join-Path $env:TEMP 'ram-report.txt') } catch { }

foreach ($t in $targets) {
  if ($saved) { break }
  try { ($lines -join [Environment]::NewLine) | Out-File -LiteralPath $t -Encoding utf8 -Force; $saved = $t } catch { }
}

Write-Host ''
if ($saved) {
  Write-Host '  ------------------------------------------------------------'
  Write-Host '   Saved a copy here - send this file to your dad:'
  Write-Host ("   {0}" -f $saved) -ForegroundColor Cyan
  Write-Host '  ------------------------------------------------------------'
} else {
  Write-Host '  Could not save a file, so take a screenshot of this window'
  Write-Host '  and send that instead. Everything needed is above.'
}
Write-Host ''
