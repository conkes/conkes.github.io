# Enable-AllPrivileges.ps1
# Enables all privileges assigned to current token

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public struct LUID {
    public UInt32 LowPart;
    public Int32 HighPart;
}

public struct TOKEN_PRIVILEGES {
    public UInt32 PrivilegeCount;
    public LUID Luid;
    public UInt32 Attributes;
}

public struct LUID_AND_ATTRIBUTES {
    public LUID Luid;
    public UInt32 Attributes;
}

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, UInt32 TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref UInt32 cchName);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
}
"@

function Enable-AllPrivileges {
    Write-Host "[*] Enabling All Available Privileges..." -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan

    # Get current process token
    $processHandle = [Win32]::GetCurrentProcess()
    $tokenHandle = [IntPtr]::Zero

    if (-not [Win32]::OpenProcessToken($processHandle, 0x0028, [ref]$tokenHandle)) {
        Write-Host "[!] Failed to open process token" -ForegroundColor Red
        return
    }

    try {
        # Get token privileges
        $tokenInfoLength = 0
        $null = [Win32]::GetTokenInformation($tokenHandle, 3, [IntPtr]::Zero, 0, [ref]$tokenInfoLength)

        $tokenInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tokenInfoLength)

        try {
            if ([Win32]::GetTokenInformation($tokenHandle, 3, $tokenInfoPtr, $tokenInfoLength, [ref]$tokenInfoLength)) {

                # Read privilege count
                $privilegeCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($tokenInfoPtr)
                Write-Host "[+] Found $privilegeCount privileges" -ForegroundColor Green
                Write-Host ""

                $enabledCount = 0
                $alreadyEnabledCount = 0

                # Process each privilege
                for ($i = 0; $i -lt $privilegeCount; $i++) {
                    $offset = 4 + ($i * 12)  # Skip count (4 bytes) + i * sizeof(LUID_AND_ATTRIBUTES)

                    # Read LUID
                    $luidLow = [System.Runtime.InteropServices.Marshal]::ReadInt32($tokenInfoPtr, $offset)
                    $luidHigh = [System.Runtime.InteropServices.Marshal]::ReadInt32($tokenInfoPtr, $offset + 4)
                    $attributes = [System.Runtime.InteropServices.Marshal]::ReadInt32($tokenInfoPtr, $offset + 8)

                    $luid = New-Object LUID
                    $luid.LowPart = $luidLow
                    $luid.HighPart = $luidHigh

                    # Get privilege name
                    $nameLength = 256
                    $name = New-Object System.Text.StringBuilder($nameLength)

                    if ([Win32]::LookupPrivilegeName($null, [ref]$luid, $name, [ref]$nameLength)) {
                        $privilegeName = $name.ToString()

                        # Check if already enabled
                        $isEnabled = ($attributes -band 0x00000002) -ne 0  # SE_PRIVILEGE_ENABLED

                        if ($isEnabled) {
                            Write-Host "[=] $privilegeName" -ForegroundColor Yellow -NoNewline
                            Write-Host " (already enabled)" -ForegroundColor Gray
                            $alreadyEnabledCount++
                        } else {
                            # Try to enable privilege
                            $newLuid = New-Object LUID
                            if ([Win32]::LookupPrivilegeValue($null, $privilegeName, [ref]$newLuid)) {

                                $tokenPrivs = New-Object TOKEN_PRIVILEGES
                                $tokenPrivs.PrivilegeCount = 1
                                $tokenPrivs.Luid = $newLuid
                                $tokenPrivs.Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED

                                if ([Win32]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tokenPrivs, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
                                    Write-Host "[+] $privilegeName" -ForegroundColor Green -NoNewline
                                    Write-Host " (enabled)" -ForegroundColor Green
                                    $enabledCount++
                                } else {
                                    Write-Host "[-] $privilegeName" -ForegroundColor Red -NoNewline
                                    Write-Host " (failed to enable)" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "[-] $privilegeName" -ForegroundColor Red -NoNewline
                                Write-Host " (lookup failed)" -ForegroundColor Red
                            }
                        }
                    }
                }

                Write-Host ""
                Write-Host "=================================" -ForegroundColor Cyan
                Write-Host "[*] Summary:" -ForegroundColor Cyan
                Write-Host "    Total privileges: $privilegeCount" -ForegroundColor White
                Write-Host "    Already enabled: $alreadyEnabledCount" -ForegroundColor Yellow
                Write-Host "    Newly enabled: $enabledCount" -ForegroundColor Green
                Write-Host "    Failed: $($privilegeCount - $alreadyEnabledCount - $enabledCount)" -ForegroundColor Red

                if ($enabledCount -gt 0) {
                    Write-Host ""
                    Write-Host "[+] Successfully enabled $enabledCount privileges!" -ForegroundColor Green
                    Write-Host "[*] Try running your loader again now" -ForegroundColor Cyan
                }

            } else {
                Write-Host "[!] Failed to get token information" -ForegroundColor Red
            }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tokenInfoPtr)
        }
    } finally {
        [Win32]::CloseHandle($tokenHandle)
    }
}

function Show-CurrentPrivileges {
    Write-Host ""
    Write-Host "[*] Current privileges (via whoami /priv):" -ForegroundColor Cyan
    whoami /priv
}

# Main execution
Write-Host @"
 _____ _     _       _ _                  _____ _   _ ___   ____  _     _____ ____
| ____| |   | | ___ | | | __      __     | ____| \ | |/ _ \ | __ )| |   | ____|  _ \
|  _| | |   | |/ _ \| | | \ \ /\ / /_____|  _| |  \| | | | ||  _ \| |   |  _| | |_) |
| |___| |___| | (_) | | |  \ V  V /______| |___| |\  | |_| || |_) | |___| |___|  _ <
|_____|_____|_|\___/|_|_|   \_/\_/       |_____|_| \_|\___/ |____/|_____|_____|_| \_\

"@ -ForegroundColor Cyan

Write-Host "Privilege Escalation Tool - For Authorized Testing Only" -ForegroundColor Yellow
Write-Host ""

# Show current privileges first
Show-CurrentPrivileges

# Enable all privileges
Enable-AllPrivileges

Write-Host ""
Write-Host "[*] Done! You can now run your reflective loader with enhanced privileges." -ForegroundColor Green