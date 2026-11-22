// Reglas heurísticas genéricas de win11-triage. Suman peso a la puntuación; nunca deciden solas.
// Añade las tuyas en <config-dir>/yara/*.yar con meta: description, mitre y weight.

import "pe"

rule W11T_PS_EncodedOrHidden
{
    meta:
        description = "Script o acceso directo que lanza PowerShell codificado u oculto"
        mitre = "T1059.001"
        weight = 40
    strings:
        $ps  = "powershell" ascii wide nocase
        $enc = /\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $hid = /\s-w(indowstyle)?\s+h(idden)?\b/ ascii wide nocase
    condition:
        filesize < 5MB and $ps and ($enc or $hid)
}

rule W11T_Script_DownloadCradle
{
    meta:
        description = "Descarga + ejecución en memoria (cradle) en script"
        mitre = "T1105, T1059.001"
        weight = 40
    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "Net.WebClient" ascii wide nocase
        $d5 = "Start-BitsTransfer" ascii wide nocase
        $x1 = "IEX" ascii wide fullword
        $x2 = "Invoke-Expression" ascii wide nocase
        $x3 = "FromBase64String" ascii wide nocase
        $x4 = "Reflection.Assembly" ascii wide nocase
    condition:
        filesize < 2MB and 1 of ($d*) and 1 of ($x*)
}

rule W11T_LOLBin_ProxyExecution
{
    meta:
        description = "Uso de LOLBins para ejecutar o descargar contenido remoto"
        mitre = "T1218, T1140, T1197"
        weight = 45
    strings:
        $mshta = /mshta(\.exe)?["']?\s+["']?(https?|javascript|vbscript):/ ascii wide nocase
        $regsv = /regsvr32(\.exe)?["']?\s+.{0,60}\/i:\s*https?:/ ascii wide nocase
        $cert  = /certutil(\.exe)?["']?\s+.{0,30}-(urlcache|decode)/ ascii wide nocase
        $bits  = /bitsadmin(\.exe)?["']?\s+.{0,30}\/transfer/ ascii wide nocase
        $rdll  = /rundll32(\.exe)?["']?\s+.{0,60}javascript:/ ascii wide nocase
    condition:
        filesize < 5MB and any of them
}

rule W11T_Script_HeavyObfuscation
{
    meta:
        description = "VBS/JS con ofuscación por códigos de carácter y evaluación dinámica"
        mitre = "T1027"
        weight = 30
    strings:
        $chr  = "Chr(" ascii wide nocase
        $fcc  = "String.fromCharCode" ascii wide nocase
        $ev1  = "eval(" ascii wide nocase
        $ev2  = "Execute(" ascii wide nocase
        $ev3  = "ExecuteGlobal" ascii wide nocase
    condition:
        filesize < 2MB and (#chr > 50 or #fcc > 20) and any of ($ev*)
}

rule W11T_LNK_ShellLauncher
{
    meta:
        description = "Acceso directo (.lnk) que lanza un intérprete con argumentos"
        mitre = "T1204.002, T1547.009"
        weight = 35
    strings:
        $a = "powershell" ascii wide nocase
        $b = "cmd.exe" ascii wide nocase
        $c = "mshta" ascii wide nocase
        $d = "wscript" ascii wide nocase
        $h = "hidden" ascii wide nocase
        $e = "-enc" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and 1 of ($a, $b, $c, $d) and 1 of ($h, $e)
}

rule W11T_PE_PackedUPX
{
    meta:
        description = "PE empaquetado con UPX (muchas herramientas legítimas también lo usan)"
        mitre = "T1027.002"
        weight = 15
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.sections : ( s.name == "UPX0" or s.name == "UPX1" )
}

rule W11T_PE_ProcessInjectionImports
{
    meta:
        description = "Imports clásicos de inyección en procesos remotos"
        mitre = "T1055"
        weight = 30
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        ( pe.imports("kernel32.dll", "CreateRemoteThread") or
          pe.imports("kernel32.dll", "QueueUserAPC") or
          pe.imports("ntdll.dll", "NtCreateThreadEx") )
}
