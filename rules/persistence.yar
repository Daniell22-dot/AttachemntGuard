rule Suspicious_Logon_Persistence_Installer
{
    meta:
        description = "Flags executables that create logon scheduled-task persistence"
        severity = "high"
        author = "AttachmentGuard"
        date = "2026-10-27"

    strings:
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
        $logon = "/sc onlogon" ascii nocase
        $process_path = "Environment.ProcessPath" ascii nocase
        $task_name = "SENTINEL-Agent" ascii nocase
        $run_agent = "--run-agent" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of ($schtasks, $create, $logon, $process_path, $task_name, $run_agent)
}

rule Suspicious_Service_Install
{
    meta:
        description = "Flags service installation patterns"
        severity = "medium"

    strings:
        $sc_create = "sc create" ascii nocase
        $sc_config = "sc config" ascii nocase
        $binpath = "binpath" ascii nocase
        $services_exe = "\\services.exe" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Suspicious_PowerShell_Download_Exec
{
    meta:
        description = "Flags PowerShell download/execute patterns"
        severity = "high"

    strings:
        $iex = "IEX" ascii nocase
        $invoke_expression = "Invoke-Expression" ascii nocase
        $downloadstring = "DownloadString" ascii nocase
        $downloadfile = "DownloadFile" ascii nocase
        $webclient = "WebClient" ascii nocase
        $bitsadmin = "bitsadmin" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Suspicious_Script_Host
{
    meta:
        description = "Flags script interpreters with suspicious args"
        severity = "medium"

    strings:
        $wscript = "wscript.exe" ascii nocase
        $cscript = "cscript.exe" ascii nocase
        $mshta = "mshta.exe" ascii nocase
        $rundll32 = "rundll32.exe" ascii nocase
        $javascript = "javascript:" ascii nocase
        $vbscript = "vbscript:" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
