@{
    'gather_info' = @'
$Computer_info = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

# Create hash of local security policies (exported in .ini format)
# Ref: Ingest .ini file: https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
$SPFile = [System.Environment]::GetEnvironmentVariable('TEMP','Machine') + "\secpol.cfg"
secedit /export /cfg $SPFile | Out-Null

$secpol = @{}  
switch -regex -file $SPFile
{
    "^\[(.+)\]$" # Section
    {
        $section = $matches[1]
        $secpol[$section] = @{}
    }
    "(.+?)\s*=\s*(.*)" # Key
    {
        if (!($section))
        {
            $section = "No-Section"
            $secpol[$section] = @{}
        }
        $name,$value = $matches[1..2]
        $secpol[$section][$name] = $value
    }
}
Remove-Item -Force $SPFile -Confirm:$false
'@
    'V-220697' = @'
try {
    if ($Computer_info.OsArchitecture -eq "64-bit") {
        if ($Computer_info.WindowsProductName -eq "Windows 10 Enterprise" -or $Computer_info.WindowsProductName -eq "Windows 11 Enterprise") {
            $V220697 = $true
        }
    }
} catch {
    $V220697 = $false
}
'@
    'V-220698' = @'
try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled) {
        $V220698 = $true
    } else {
        $V220698 = $false
} catch {
    $V220698 = $false
}
'@
    'V-220699' = @'
try {
    if (bcdedit | Select-String ".*bootmgfw.efi") {
        $V220699 = $true
    } else {
        $V220699 = $false
    }
} catch {
    $V220699 = $false
}
'@
    'V-220700' = @'
try {
    if (Confirm-SecureBootUEFI) {
        $V220700 = $true
    } else {
        $V220700 = $false
    }
} catch {
    $V220700 = $false
}
'@
# Needs manual check for ESS software
    'V-220701' = @'
$V220701 = $true
'@
    'V-220703' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseAdvancedStartup -ErrorAction Stop) -eq 1 -and
        ((1, 2) -contains (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMPIN -ErrorAction Stop)) -and
        ((1, 2) -contains (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMKeyPIN -ErrorAction Stop))) {
        $V220703 = $true
    } else {
        $V220703 = $false
    }
} catch {
    $V220703 = $false
}
'@
    'V-220704' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name MinimumPIN -ErrorAction Stop) -ge 6) {
        $V220704 = $true
    } else {
        $V220704 = $false
    }
} catch {
    $V220704 = $false
}
'@
    'V-220706' = @'
try {
    if ("19044", "19045", "22000", "22621" -contains $Computer_info.OsBuildNumber) {
        $V220706 = $true
    } else {
        $V220706 = $false
    }
} catch {
    $V220706 = $false
}
'@
    'V-220707' = @'
try {
    $V220707 = $false
    $apps = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
    foreach ($app in $apps) {
        if ($app.productState.ToString('X').Substring(1,2) -eq '10') {
            $V220707 = $true
        }
    }
} catch {
    $V220707 = $false
}
'@
    'V-220708' = @'
try {
    $volumes = Get-Volume
    # Get UniqueId for the EFI partition which is FAT32
    $efi_id = "\\?\Volume$(((Get-Partition).Where{$_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'}.Guid))\"
    $V220708 = $true
    foreach ($volume in $volumes) {
        if ($volume.UniqueId -ne $efi_id -and $volume.DriveType -eq "Fixed" -and $volume.FileSystemType -ne "NTFS") {
            $V220708 = $false
        }
    }
} catch {
    $V220708 = $false
}
'@
    'V-220711' = @'
try {
    $localUsers = Get-LocalUser | Select-Object Name, LastLogon, Enabled, SID
    $V220711 = $true
    # Check all local accounts except for DefaultAccount/Administrator/Guest
    foreach ($user in $localUsers) {
        if ( ("500", "501", "503") -contains $user.SID.ToString().Substring($user.SID.ToString().Length - 3, 3) -or
             $user.Enabled -eq $false) {
             # Skip these accounts
        } else {
            if ((Get-Date).AddDays(-35) -gt $user.LastLogon) {
                $V220711 = $false
            }
        }
    }
} catch {
    $V220711 = $false
}
'@
    'V-220712' = @'
try {
    $members = Get-LocalGroupMember -Group "Administrators"
    $V220712 = $true
    foreach ($member in $members) {
        if ($member.Name -match "\Domain Admins") {
            $V220712 = $false
        }
    }
} catch {
    $V220712 = $false
}
'@
    'V-220715' = @'
try {
    $localUsers = Get-LocalUser | Select-Object Name, Enabled
    $V220715 = $true
    # Check for any non-default accounts
    foreach ($user in $localUsers) {
        if ( ("Administrator", "Guest", "DefaultAccount", "defaultuser0", "WDAGUtilityAccount") -contains $user.Name -and
             $user.Enabled -eq $true) {
             # Skip these accounts
        } else {
            $V220715 = $false
        }
    }
} catch {
    $V220715 = $false
}
'@
    'V-220716' = @'
try {
    $localUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordExpires
    $V220716 = $true
    # Check all local accounts except for DefaultAccount/Administrator/Guest
    foreach ($user in $localUsers) {
        if ($user.Enabled -eq $true -and $user.PasswordExpires -eq '') {
             $V220716 = $false
        }
    }
} catch {
    $V220716 = $false
}
'@
    'V-220718' = @'
try {
    if (((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole").State) -eq "Disabled") {
        $V220718 = $true
    }
} catch {
    $V220718 = $false
}
'@
    'V-220719' = @'
try {
    if (Get-Service -Name snmp -or Test-Path -Path "C:\Windows\System32\snmp.exe") {
        $V220719 = $false
    } else {
        $V220719 = $true
    }
} catch {
    $V220719 = $false
}
'@
    'V-220720' = @'
try {
    if (Get-Service -Name simptcp) {
        $V220720 = $false
    } else {
        $V220720 = $true
    }
} catch {
    $V220720 = $false
}
'@
    'V-220726' = @'
try {
    $DEP = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property DataExecutionPrevention_SupportPolicy
    if ($DEP.DataExecutionPrevention_SupportPolicy -eq 1 -or $DEP.DataExecutionPrevention_SupportPolicy -eq 3) {
        $V220726 = $true
    } else {
        $V220726 = $false
    }
} catch {
    $V220726 = $false
}
'@
# TODO: Test that this is correct key
    'V-220747' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnablePlainTextPassword -ErrorAction Stop) -eq 0) {
        $V220747 = $true
    } else {
        $V220747 = $false
    }
} catch {
    $V220747 = $false
}
'@
# TODO: Additional checks needed besides reg checks
    'V-220811' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -ErrorAction Stop) -eq 1 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -ErrorAction Stop) -eq 1) {
        $V220811 = $true
    } else {
        $V220811 = $false
    }
} catch {
    $V220811 = $false
}
'@
    'V-220812' = @'
if (((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning) -eq 1) {
    $V220812 = $true
} else {
    $V220812 = $false
}
'@
    'V-220838' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -ErrorAction Stop) -eq 1) {
        $V220838 = $false
    } else {
        $V220838 = $true
    }
} catch {
    $V220838 = $true
}
'@
    'V-220918' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -ErrorAction Stop) -in 1..30) {
        $V220918 = $true
    } else {
        $V220918 = $false
    }
} catch {
    $V220918 = $false
}
'@
    'V-220923' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name CachedLogonsCount -ErrorAction Stop) -le 10) {
        $V220923 = $true
    } else {
        $V220923 = $false
    }
} catch {
    $V220923 = $false
}
'@
    'V-220928' = @'
try {
    if ($secpol.'System Access'.LSAAnonymousNameLookup -eq 0) {
        $V220928 = $true
    } else {
        $V220928 = $false
    }
} catch {
    $V220928 = $false
}
'@
# TODO: check that this fails if a user/group is granted this right
    'V-220958' = @'
try {
    if ($secpol.'Privilege Rights'.SeTcbPrivilege) {
        $V220958 = $false
    } else {
        $V220958 = $true
    }
} catch {
    $V220958 = $false
}
'@
# TODO: check that this fails if a user/group is granted this right
    'V-220963' = @'
try {
    if ($secpol.'Privilege Rights'.SeCreateTokenPrivilege) {
        $V220963 = $false
    } else {
        $V220963 = $true
    }
} catch {
    $V220963 = $false
}
'@
# TODO: check that this fails if more than just built in admin group is listed
    'V-220967' = @'
try {
    if ($secpol.'Privilege Rights'.SeDebugPrivilege -eq '*S-1-5-32-544') {
        $V220967 = $true
    } else {
        $V220967 = $false
    }
} catch {
    $V220967 = $false
}
'@
}
