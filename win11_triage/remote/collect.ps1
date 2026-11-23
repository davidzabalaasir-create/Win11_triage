<#
  win11-triage · recolección remota (solo lectura) para Invoke-Command / WinRM.
  Devuelve un JSON con procesos, conexiones y puntos de persistencia del equipo remoto.
  No escribe nada en el equipo analizado ni instala herramientas.
#>
$ErrorActionPreference = 'SilentlyContinue'
$sigCache = @{}
$hashCache = @{}

function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 1) { return $c.Substring(1, $end - 1) } }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|hta|dll|scr))\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-Signer([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    if ($sigCache.ContainsKey($path)) { return $sigCache[$path] }
    $s = Get-AuthenticodeSignature -LiteralPath $path
    $cn = ''
    if ($s.SignerCertificate) { $cn = ($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '' }
    $value = if ($s.Status -eq 'Valid') { "(Verified) $cn" } elseif ($cn) { "(Not verified) $cn" } else { '' }
    $sigCache[$path] = $value
    return $value
}

function Get-Sha256([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    if (-not $hashCache.ContainsKey($path)) {
        $hashCache[$path] = ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash + '').ToLower()
    }
    return $hashCache[$path]
}

function New-Entry($name, $cmd, $category, $location) {
    $exe = Get-ExePath $cmd
    $created = ''
    if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $created = (Get-Item -LiteralPath $exe).CreationTimeUtc.ToString('s')
    }
    [ordered]@{
        name = [string]$name; path = $exe; cmdline = [string]$cmd; category = $category; location = $location
        signer = Get-Signer $exe; sha256 = Get-Sha256 $exe; created = $created
    }
}

$autoruns = New-Object System.Collections.ArrayList
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    $item = Get-ItemProperty -Path $key
    if (-not $item) { continue }
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        [void]$autoruns.Add((New-Entry $p.Name $p.Value 'Logon' $key))
    }
}
$startup = @([Environment]::GetFolderPath('CommonStartup'), [Environment]::GetFolderPath('Startup'))
foreach ($dir in $startup) {
    Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
        [void]$autoruns.Add((New-Entry $_.Name $_.FullName 'Logon' $dir))
    }
}
Get-CimInstance Win32_Service | ForEach-Object {
    [void]$autoruns.Add((New-Entry $_.Name $_.PathName 'Services' 'HKLM\System\CurrentControlSet\Services'))
}
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $task = $_
    foreach ($a in $task.Actions) {
        if ($a.Execute) {
            [void]$autoruns.Add((New-Entry ($task.TaskPath + $task.TaskName) (($a.Execute + ' ' + $a.Arguments).Trim()) 'Tasks' 'Task Scheduler'))
        }
    }
}
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object {
    [void]$autoruns.Add((New-Entry $_.Name $_.CommandLineTemplate 'WMI' 'root\subscription'))
}
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
Get-ChildItem -Path $ifeo | ForEach-Object {
    $dbg = (Get-ItemProperty -Path $_.PSPath).Debugger
    if ($dbg) { [void]$autoruns.Add((New-Entry $_.PSChildName $dbg 'Image Hijacks' $ifeo)) }
}

$procs = Get-CimInstance Win32_Process | ForEach-Object {
    $exe = [string]$_.ExecutablePath
    [ordered]@{
        pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = [string]$_.Name; exe = $exe
        cmdline = [string]$_.CommandLine
        created = if ($_.CreationDate) { $_.CreationDate.ToString('s') } else { '' }
        exe_missing = [bool]($exe -and -not (Test-Path -LiteralPath $exe))
    }
}
$names = @{}
foreach ($p in $procs) { $names[$p.pid] = $p.name }
$conns = Get-NetTCPConnection -State Established, SynSent | Where-Object {
    $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|::$)'
} | ForEach-Object {
    [ordered]@{
        protocol = 'TCP'; process = [string]$names[[int]$_.OwningProcess]; pid = [string]$_.OwningProcess
        state = ([string]$_.State).ToUpper(); local = "$($_.LocalAddress):$($_.LocalPort)"
        remote = "$($_.RemoteAddress):$($_.RemotePort)"
    }
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

[ordered]@{
    schema = 1; host = $env:COMPUTERNAME; user = $env:USERNAME; admin = $isAdmin
    collected = (Get-Date).ToUniversalTime().ToString('s')
    processes = @($procs); connections = @($conns); autoruns = @($autoruns)
} | ConvertTo-Json -Depth 4 -Compress
