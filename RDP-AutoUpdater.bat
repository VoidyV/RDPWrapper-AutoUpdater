@echo off
title RDP Wrapper Universal Installer and Auto-Updater
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
set "BAT_PATH=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c = Get-Content -LiteralPath $env:BAT_PATH -Raw; $parts = [regex]::Split($c, '(?m)^#__PS_START__\r?$'); Invoke-Expression $parts[1]"
pause
exit /b
#__PS_START__
$ErrorActionPreference = "Stop"
$dir = "C:\Program Files\RDP Wrapper"
$iniPath = "$dir\rdpwrap.ini"
$dllWrap = "$dir\rdpwrap.dll"
$dllPath = "C:\Windows\System32\termsrv.dll"

$needCore = -not ((Test-Path $dllWrap) -and ((Get-Item $dllWrap).Length -eq 116736) -and (Test-Path $iniPath))
$needConf = -not (Test-Path "$dir\RDPConf.exe")

if ($needCore -or $needConf) {
    Write-Host "[*] Downloading RDP Wrapper v1.6.2 package..." -ForegroundColor Cyan
    $tmp = "$dir\_setup"
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -Path $tmp -ItemType Directory -Force | Out-Null
    $zipUrl = "https://github.com/stascorp/rdpwrap/releases/download/v1.6.2/RDPWrap-v1.6.2.zip"
    $zipFile = "$tmp\rdp.zip"
    $extDir = "$tmp\extracted"
    curl.exe -s -L $zipUrl -o $zipFile
    if (-not (Test-Path $zipFile) -or ((Get-Item $zipFile).Length -lt 10000)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extDir)
    if ($needCore) {
        $winst = Get-ChildItem -Path $extDir -Filter "RDPWInst.exe" -Recurse | Select-Object -First 1
        if (-not $winst) {
            Write-Host "[-] RDPWInst.exe blocked by Windows Security (PUA)." -ForegroundColor Red
            Write-Host "[i] Allow the folder in Windows Security and run again." -ForegroundColor Yellow
            exit 1
        }
        Stop-Service -Name "UmRdpService" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
        if (Test-Path $dllWrap) { & $winst.FullName -u | Out-Null }
        & $winst.FullName -i | Out-Null
    }
    Get-ChildItem -Path $extDir -File -Recurse | Where-Object { $_.Name -notin @("rdpwrap.dll", "rdpwrap.ini") } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dir $_.Name) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Copy-Item $iniPath "$iniPath.bak" -Force

$verInfo = (Get-Item $dllPath).VersionInfo
$osVer = "$($verInfo.FileMajorPart).$($verInfo.FileMinorPart).$($verInfo.FileBuildPart).$($verInfo.FilePrivatePart)"
Write-Host "[*] Detected termsrv.dll version: $osVer" -ForegroundColor Cyan

$dll = [System.IO.File]::ReadAllBytes($dllPath)
$pe = [BitConverter]::ToInt32($dll, 0x3C)
$numSec = [BitConverter]::ToUInt16($dll, $pe + 6)
$optSize = [BitConverter]::ToUInt16($dll, $pe + 20)
$secStart = $pe + 24 + $optSize

$sections = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $sOff = $secStart + ($i * 40)
    $sections += [PSCustomObject]@{ Virt = [BitConverter]::ToUInt32($dll, $sOff + 12); Size = [BitConverter]::ToUInt32($dll, $sOff + 16); Raw = [BitConverter]::ToUInt32($dll, $sOff + 20) }
}

function Raw-To-Rva([uint32]$raw) { foreach ($s in $sections) { if ($raw -ge $s.Raw -and $raw -lt ($s.Raw + $s.Size)) { return ($raw - $s.Raw + $s.Virt) } }; return $raw }
function Rva-To-Raw([uint32]$rva) { foreach ($s in $sections) { if ($rva -ge $s.Virt -and $rva -lt ($s.Virt + $s.Size)) { return ($rva - $s.Virt + $s.Raw) } }; return $rva }

function Find-Sig([string]$sig) {
    $t = $sig -split " "; $len = $t.Length; $b = New-Object int[] $len
    for ($i = 0; $i -lt $len; $i++) { $b[$i] = if ($t[$i] -eq "??") { -1 } else { [Convert]::ToInt32($t[$i], 16) } }
    $lim = $dll.Length - $len
    for ($a = 0x400; $a -lt $lim; $a++) {
        if ($b[0] -ne -1 -and $dll[$a] -ne $b[0]) { continue }
        $ok = $true; for ($j = 1; $j -lt $len; $j++) { if ($b[$j] -ne -1 -and $dll[$a + $j] -ne $b[$j]) { $ok = $false; break } }
        if ($ok) { return $a }
    }
    return -1
}

$mLocal = Find-Sig "85 C0 78 ?? 83 7D ?? 00 74 ?? 83 3D ?? ?? ?? ?? 02 BB 05 00 07 80"
$localOff = if ($mLocal -ge 0) { ($mLocal + 8).ToString("X8") } else { $null }

$singleOff = $null
foreach ($sp in @(@("89 7D 28 44 8D 77 01 44 89 32 E8", 6), @("44 8D 77 01 44 89 32 E8", 3), @("44 8D 77 01 44 89 36 E8", 3), @("8D 47 01 89 06 E8", 2), @("8D 4F 01 89 0E E8", 2))) {
    $m = Find-Sig $sp[0]; if ($m -ge 0 -and $dll[$m + $sp[1]] -eq 0x01) { $singleOff = ($m + $sp[1]).ToString("X8"); break }
}

$defOff = $null; $defCode = $null
$mDef11 = Find-Sig "44 8B 87 3C 06 00 00 44 8B 8F 38 06 00 00 45 3B C1 75"
if ($mDef11 -ge 0) { $defOff = ($mDef11 + 17).ToString("X8"); $defCode = "jmpshort" } else {
    $mDef10 = Find-Sig "8B 87 3C 06 00 00 8B 8F 38 06 00 00 3B C1 0F 85"
    if ($mDef10 -ge 0) { $defOff = $mDef10.ToString("X8"); $defCode = "CDefPolicy_Query_eax_rdi" }
}

$mSL = Find-Sig "BB 57 00 07 80 E9 ?? 00 00 00 39 1D ?? ?? ?? 00 75 ?? E8 ?? ?? ?? 00"
if (-not $localOff -or -not $singleOff -or -not $defOff -or $mSL -lt 0) {
    Write-Host "[-] Signature mismatch for $osVer. Please open an issue on GitHub." -ForegroundColor Red; exit 1
}

$disp32 = [BitConverter]::ToInt32($dll, $mSL + 12)
$rel32 = [BitConverter]::ToInt32($dll, $mSL + 19)
$bInitRva = [uint32]((Raw-To-Rva ($mSL + 16)) + $disp32)
$slInitRva = [uint32]((Raw-To-Rva ($mSL + 23)) + $rel32)
$slInitOff = (Rva-To-Raw $slInitRva).ToString("X8")

$ini = [System.IO.File]::ReadAllText($iniPath)
$escVer = [regex]::Escape($osVer)
$ini = [regex]::Replace($ini, "(?s)\r?\n?\[$escVer(?:-SLInit)?\].*?(?=\r?\n\[|\z)", "")

$secLines = @(
    "[$osVer]",
    "LocalOnlyPatch.x64=1",
    "LocalOnlyOffset.x64=$localOff",
    "LocalOnlyCode.x64=jmpshort",
    "SingleUserPatch.x64=1",
    "SingleUserOffset.x64=$singleOff",
    "SingleUserCode.x64=Zero",
    "DefPolicyPatch.x64=1",
    "DefPolicyOffset.x64=$defOff",
    "DefPolicyCode.x64=$defCode",
    "SLInitHook.x64=1",
    "SLInitOffset.x64=$slInitOff",
    "SLInitFunc.x64=New_CSLQuery_Initialize",
    "",
    "[$osVer-SLInit]",
    "bInitialized.x64=$($bInitRva.ToString('X8'))",
    "bServerSku.x64=$((($bInitRva + 0x04)).ToString('X8'))",
    "lMaxUserSessions.x64=$((($bInitRva + 0x08)).ToString('X8'))",
    "bAppServerAllowed.x64=$((($bInitRva + 0x10)).ToString('X8'))",
    "bRemoteConnAllowed.x64=$((($bInitRva + 0x1C)).ToString('X8'))",
    "bMultimonAllowed.x64=$((($bInitRva + 0x20)).ToString('X8'))",
    "ulMaxDebugSessions.x64=$((($bInitRva + 0x28)).ToString('X8'))",
    "bFUSEnabled.x64=$((($bInitRva + 0x2C)).ToString('X8'))"
) -join "`r`n"

[System.IO.File]::WriteAllText($iniPath, ($ini.TrimEnd() + "`r`n`r`n" + $secLines + "`r`n"), [System.Text.Encoding]::ASCII)

$ErrorActionPreference = "Continue"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fSingleSessionPerUser" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxInstanceCount" -Value 999999 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
netsh advfirewall firewall set rule group="@FirewallAPI.dll,-28752" new enable=Yes >$null 2>&1

$deskRdp = Join-Path ([Environment]::GetFolderPath("Desktop")) "RDP Wrapper"
New-Item -Path $deskRdp -ItemType Directory -Force | Out-Null
Get-ChildItem -Path $dir -File | Where-Object { $_.Name -notin @("rdpwrap.dll", "rdpwrap.ini", "rdpwrap.ini.bak") } | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $deskRdp $_.Name) -Force -ErrorAction SilentlyContinue
}
if ($env:BAT_PATH -and (Test-Path $env:BAT_PATH)) {
    $destBat = Join-Path $deskRdp (Split-Path $env:BAT_PATH -Leaf)
    if ($env:BAT_PATH -ne $destBat) { Copy-Item -LiteralPath $env:BAT_PATH -Destination $destBat -Force -ErrorAction SilentlyContinue }
}

Stop-Service -Name "UmRdpService" -Force -ErrorAction SilentlyContinue
Restart-Service -Name "TermService" -Force
$svcDll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters" -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
$svcState = (Get-Service -Name "TermService" -ErrorAction SilentlyContinue).Status
$hasIniSec = (Get-Content -LiteralPath $iniPath -Raw) -match "\[$escVer\]"
Write-Host "`n[+] RDP Wrapper configured and TermService restarted! ($osVer)" -ForegroundColor Green
Write-Host "    Wrapper state : $(if ($svcDll -like '*rdpwrap.dll') { 'Installed' } else { 'Not installed' })" -ForegroundColor Green
Write-Host "    Service state : $svcState" -ForegroundColor Green
Write-Host "    Version patch : $(if ($hasIniSec) { '[fully supported]' } else { 'Missing' })" -ForegroundColor Green
Write-Host "    Offsets       : LocalOnly=$localOff | SingleUser=$singleOff \vert{} DefPolicy=$defOff ($defCode) \vert{} SLInit=$slInitOff" -ForegroundColor Gray
if (-not (Test-Path "$deskRdp\RDPConf.exe")) {
    Write-Host "[i] Note: RDPConf.exe was quarantined by Windows Defender (PUA), which is normal and does not affect RDP." -ForegroundColor Yellow
}