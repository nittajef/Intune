@{
    'CAT1' = @(
        'ComputerInfo'
        'DeviceGuard'
        'SecurityPolicy'
    )
    'CAT2' = @(
        'AuditPolicy'
        'SecurityPolicy'
    )
    'CAT3' = @(
        'DeviceGuard'
    )

    'AuditPolicy' = @'
$AuditPolicy = @{}
auditpol /get /category:* /r | ConvertFrom-Csv | % { $AuditPolicy[$_.Subcategory] = $_.'Inclusion Setting' }
'@

    'ComputerInfo' = @'
$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture
'@

    'DeviceGuard' = @'
$DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
'@

    'SecurityPolicy' = @'
# Create hash of local security policies (exported in .ini format)
# Ref: Ingest .ini file: https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
$SPFile = [System.Environment]::GetEnvironmentVariable('TEMP','Machine') + "\secpol.cfg"
secedit /export /cfg $SPFile | Out-Null

$SecurityPolicy = @{}  
switch -regex -file $SPFile
{
    "^\[(.+)\]$" # Section
    {
        $section = $matches[1]
        $SecurityPolicy[$section] = @{}
    }
    "(.+?)\s*=\s*(.*)" # Key
    {
        if (!($section))
        {
            $section = "No-Section"
            $SecurityPolicy[$section] = @{}
        }
        $name,$value = $matches[1..2]
        $SecurityPolicy[$section][$name] = $value
    }
}
Remove-Item -Force $SPFile -Confirm:$false
'@

    'V-220697' = @'
try {
    if ($ComputerInfo.OsArchitecture -eq "64-bit") {
        if ($ComputerInfo.WindowsProductName -eq "Windows 10 Enterprise" -or $ComputerInfo.WindowsProductName -eq "Windows 11 Enterprise") {
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
    'V-220702' = @'
try {
    if (Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "Off" }) {
        $V220702 = $false
    } else {
        $V220702 = $true
    }
} catch {
    $V220702 = $false
}
'@
    'V-220703' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseAdvancedStartup -ErrorAction Stop) -eq 1 -and
        (((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMPIN -ErrorAction Stop) -in @(1,2)) -or
        ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMKeyPIN -ErrorAction Stop) -in @(1,2)))) {
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
    if ($MinimumPIN) {
        $pin = $MinimumPIN
    } else {
        $pin = 6
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name MinimumPIN -ErrorAction Stop) -ge $pin) {
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
    if ($SupportedBuilds) {
        $builds = $SupportedBuilds
    } else {
        $builds = @("19044", "19045", "22000", "22621")
    }
    if ($builds -contains $ComputerInfo.OsBuildNumber) {
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
             $Administrators -contains $user -or
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
        if ($member.Name -notin $Administrators) {
            $V220712 = $false
        }
    }
} catch {
    $V220712 = $false
}
'@
    'V-220713' = @'
try {
    $members = Get-LocalGroupMember -Group "Backup Operators"
    $V220713 = $true
    foreach ($member in $members) {
        if ($member.Name -notin $BackupOperators) {
            $V220713 = $false
        }
    }
} catch {
    $V220713 = $false
}
'@
    'V-220714' = @'
try {
    $members = Get-LocalGroupMember -Group "Hyper-V Administrators"
    $V220714 = $true
    foreach ($member in $members) {
        if ($member.Name -notin $HyperVAdministrators) {
            $V220714 = $false
        }
    }
} catch {
    $V220714 = $false
}
'@
    'V-220715' = @'
try {
    $localUsers = Get-LocalUser | Select-Object Name, Enabled
    $V220715 = $true
    # Check for any non-default accounts
    foreach ($user in $localUsers) {
        if ( (("Administrator", "Guest", "DefaultAccount", "defaultuser0", "WDAGUtilityAccount") -contains $user.Name -and
             $user.Enabled -eq $true) -or
             $Administrators -contains $user) {
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
    'V-220721' = @'
try {
    if (Test-Path -Path "C:\Windows\System32\telnet.exe") {
        $V220721 = $false
    } else {
        $V220721 = $true
    }
} catch {
    $V220721 = $false
}
'@
    'V-220722' = @'
try {
    if (Test-Path -Path "C:\Windows\System32\tftp.exe") {
        $V220722 = $false
    } else {
        $V220722 = $true
    }
} catch {
    $V220722 = $false
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
    'V-220728' = @'
try {
    $V220728 = $true
    if ((Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2* | Select-Object -ExpandProperty State) -contains "Enabled") {
        $V220728 = $false
    }
} catch {
    $V220728 = $false
}
'@
    'V-220729' = @'
try {
    $V220729 = $true
    if ((Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | Select-Object -ExpandProperty State) -contains "Enabled") {
        $V220729 = $false
    }
} catch {
    $V220729 = $false
}
'@
    'V-220732' = @'
try {
    $V220732
    $svc = Get-Service -Name "seclogon" | Select-Object Status,StartType
    if ($svc.StartType -ne "Disabled" -or $svc.Status -eq "Running") {
        $V220732 = $false
    }
} catch {
    $V220732 = $false
}
'@
    'V-220739' = @'
try {
    if ($LockoutDuration) {
        $lock = $LockoutDuration
    } else {
        $lock = 14
    }
    if ($lock -eq 0) {
        if ($SecurityPolicy.'System Access'.LockoutDuration -eq 0) {
            $V220739 = $true
        }
    } elseif ($SecurityPolicy.'System Access'.LockoutDuration -ne 1..$lock) {
            $V220739 = $true
    } else {
        $V220739 = $false
    }
} catch {
    $V220739 = $false
}
'@
    'V-220740' = @'
try {
    if ($LockoutThreshold) {
        $thresh = $LockoutThreshold
    } else {
        $thresh = 3
    }
    if ($SecurityPolicy.'System Access'.LockoutBadCount -eq 1..$thresh) {
        $V220740 = $true
    } else {
        $V220740 = $false
    }
} catch {
    $V220740 = $false
}
'@
    'V-220741' = @'
try {
    if ($ResetCounter) {
        $reset = $ResetCounter
    } else {
        $reset = 15
    }
    if ($SecurityPolicy.'System Access'.ResetLockoutCount -ge $reset) {
        $V220741 = $true
    } else {
        $V220741 = $false
    }
} catch {
    $V220741 = $false
}
'@
    'V-220742' = @'
try {
    if ($PWHistory) {
        $hist = $PWHistory
    } else {
        $hist = 24
    }
    if ($SecurityPolicy.'System Access'.PasswordHistorySize -ge $hist) {
        $V220742 = $true
    } else {
        $V220742 = $false
    }
} catch {
    $V220742 = $false
}
'@
    'V-220743' = @'
try {
    if ($MaxPwAge) {
        $age = $MaxPwAge
    } else {
        $age = 60
    }
    if ($SecurityPolicy.'System Access'.MaximumPasswordAge -eq 1..$age) {
        $V220743 = $true
    } else {
        $V220743 = $false
    }
} catch {
    $V220743 = $false
}
'@
    'V-220744' = @'
try {
    if ($MinPwAge) {
        $age = $MinPwAge
    } else {
        $age = 1
    }
    if ($SecurityPolicy.'System Access'.MinimumPasswordAge -le $age) {
        $V220744 = $true
    } else {
        $V220744 = $false
    }
} catch {
    $V220744 = $false
}
'@
    'V-220745' = @'
try {
    if ($MinPwLength) {
        $length = $MinPwLength
    } else {
        $length = 14
    }
    if ($SecurityPolicy.'System Access'.MinimumPasswordLength -ge $length) {
        $V220745 = $true
    } else {
        $V220745 = $false
    }
} catch {
    $V220745 = $false
}
'@
    'V-220746' = @'
try {
    if ($SecurityPolicy.'System Access'.PasswordComplexity -eq 1) {
        $V220746 = $true
    } else {
        $V220746 = $false
    }
} catch {
    $V220746 = $false
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
    'V-220748' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Credential Validation' -match "Failure") {
        $V220748 = $true
    } else {
        $V220748 = $false
    }
} catch {
    $V220748 = $false
}
'@
    'V-220749' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Credential Validation' -match "Success") {
        $V220749 = $true
    } else {
        $V220749 = $false
    }
} catch {
    $V220748 = $false
}
'@
    'V-220750' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security Group Management' -match "Success") {
        $V220750 = $true
    } else {
        $V220750 = $false
    }
} catch {
    $V220750 = $false
}
'@
    'V-220751' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'User Account Management' -match "Failure") {
        $V220751 = $true
    } else {
        $V220751 = $false
    }
} catch {
    $V220751 = $false
}
'@
    'V-220752' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'User Account Management' -match "Success") {
        $V220752 = $true
    } else {
        $V220752 = $false
    }
} catch {
    $V220752 = $false
}
'@
    'V-220753' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Plug and Play Events' -match "Success") {
        $V220753 = $true
    } else {
        $V220753 = $false
    }
} catch {
    $V220753 = $false
}
'@
    'V-220754' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Process Creation' -match "Success") {
        $V220754 = $true
    } else {
        $V220754 = $false
    }
} catch {
    $V220754 = $false
}
'@
    'V-220755' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Account Lockout' -match "Failure") {
        $V220755 = $true
    } else {
        $V220755 = $false
    }
} catch {
    $V220755 = $false
}
'@
    'V-220756' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Group Membership' -match "Success") {
        $V220756 = $true
    } else {
        $V220756 = $false
    }
} catch {
    $V220756 = $false
}
'@
    'V-220757' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logoff -match "Success") {
        $V220757 = $true
    } else {
        $V220757 = $false
    }
} catch {
    $V220757 = $false
}
'@
    'V-220758' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logon -match "Failure") {
        $V220758 = $true
    } else {
        $V220758 = $false
    }
} catch {
    $V220758 = $false
}
'@
    'V-220759' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logon -match "Success") {
        $V220759 = $true
    } else {
        $V220759 = $false
    }
} catch {
    $V220759 = $false
}
'@
    'V-220760' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Special Logon' -match "Success") {
        $V220760 = $true
    } else {
        $V220760 = $false
    }
} catch {
    $V220760 = $false
}
'@
    'V-220761' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'File Share' -match "Failure") {
        $V220761 = $true
    } else {
        $V220761 = $false
    }
} catch {
    $V220761 = $false
}
'@
    'V-220762' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'File Share' -match "Success") {
        $V220762 = $true
    } else {
        $V220762 = $false
    }
} catch {
    $V220762 = $false
}
'@
    'V-220763' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Object Access Events' -match "Success") {
        $V220763 = $true
    } else {
        $V220763 = $false
    }
} catch {
    $V220763 = $false
}
'@
    'V-220764' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Object Access Events' -match "Failure") {
        $V220764 = $true
    } else {
        $V220764 = $false
    }
} catch {
    $V220764 = $false
}
'@
    'V-220765' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Removable Storage' -match "Failure") {
        $V220765 = $true
    } else {
        $V220765 = $false
    }
} catch {
    $V220765 = $false
}
'@
    'V-220766' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Removable Storage' -match "Success") {
        $V220766 = $true
    } else {
        $V220766 = $false
    }
} catch {
    $V220766 = $false
}
'@
    'V-220767' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Audit Policy Change' -match "Success") {
        $V220767 = $true
    } else {
        $V220767 = $false
    }
} catch {
    $V220767 = $false
}
'@
    'V-220768' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Authentication Policy Change' -match "Success") {
        $V220768 = $true
    } else {
        $V220768 = $false
    }
} catch {
    $V220768 = $false
}
'@
    'V-220769' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Authorization Policy Change' -match "Success") {
        $V220769 = $true
    } else {
        $V220769 = $false
    }
} catch {
    $V220769 = $false
}
'@
    'V-220770' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Sensitive Privilege Use' -match "Failure") {
        $V220770 = $true
    } else {
        $V220770 = $false
    }
} catch {
    $V220770 = $false
}
'@
    'V-220771' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Sensitive Privilege Use' -match "Failure") {
        $V220771 = $true
    } else {
        $V220771 = $false
    }
} catch {
    $V220771 = $false
}
'@
    'V-220772' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'IPsec Driver' -match "Failure") {
        $V220772 = $true
    } else {
        $V220772 = $false
    }
} catch {
    $V220772 = $false
}
'@
    'V-220773' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other System Events' -match "Success") {
        $V220773 = $true
    } else {
        $V220773 = $false
    }
} catch {
    $V220773 = $false
}
'@
    'V-220774' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other System Events' -match "Failure") {
        $V220774 = $true
    } else {
        $V220774 = $false
    }
} catch {
    $V220774 = $false
}
'@
    'V-220775' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security State Change' -match "Success") {
        $V220775 = $true
    } else {
        $V220775 = $false
    }
} catch {
    $V220775 = $false
}
'@
    'V-220776' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security System Extension' -match "Success") {
        $V220776 = $true
    } else {
        $V220776 = $false
    }
} catch {
    $V220776 = $false
}
'@
    'V-220777' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'System Integrity' -match "Failure") {
        $V220777 = $true
    } else {
        $V220777 = $false
    }
} catch {
    $V220777 = $false
}
'@
    'V-220778' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'System Integrity' -match "Success") {
        $V220778 = $true
    } else {
        $V220778 = $false
    }
} catch {
    $V220778 = $false
}
'@
    'V-220779' = @'
try {
    if ($AppEventLogSize) {
        $size = $AppEventLogSize
    } else {
        $size = 32768
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -ErrorAction Stop) -ge $size) {
        $V220779 = $true
    } else {
        $V220779 = $false
    }
} catch {
    $V220779 = $false
}
'@
    'V-220780' = @'
try {
    if ($SecEventLogSize) {
        $size = $SecEventLogSize
    } else {
        $size = 1024000
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize -ErrorAction Stop) -eq 1024000) {
        $V220780 = $true
    } else {
        $V220780 = $false
    }
} catch {
    $V220780 = $false
}
'@
    'V-220781' = @'
try {
    if ($SysEventLogSize) {
        $size = $SysEventLogSize
    } else {
        $size = 32768
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize -ErrorAction Stop) -eq 1024000) {
        $V220781 = $true
    } else {
        $V220781 = $false
    }
} catch {
    $V220781 = $false
}
'@
    'V-220782' = @'
try {
    $acl = Get-Acl (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name File)
    
    $V220782 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220782 = $false
        }
    }
} catch {
    $V220782 = $false
}
'@
    'V-220783' = @'
try {
    $acl = Get-Acl (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name File)
    
    $V220783 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220783 = $false
        }
    }
} catch {
    $V220783 = $false
}
'@
    'V-220784' = @'
try {
    $acl = Get-Acl (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name File)
    
    $V220784 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220784 = $false
        }
    }
} catch {
    $V220784 = $false
}
'@
    'V-220786' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Policy Change Events' -match "Failure") {
        $V220786 = $true
    } else {
        $V220786 = $false
    }
} catch {
    $V220786 = $false
}
'@
    'V-220787' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Logon/Logoff Events' -match "Success") {
        $V220787 = $true
    } else {
        $V220787 = $false
    }
} catch {
    $V220787 = $false
}
'@
    'V-220788' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Logon/Logoff Events' -match "Failure") {
        $V220788 = $true
    } else {
        $V220788 = $false
    }
} catch {
    $V220788 = $false
}
'@
    'V-220789' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Detailed File Share' -match "Failure") {
        $V220789 = $true
    } else {
        $V220789 = $false
    }
} catch {
    $V220789 = $false
}
'@
    'V-220790' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'MPSSVC Rule-Level Policy Change' -match "Success") {
        $V220790 = $true
    } else {
        $V220790 = $false
    }
} catch {
    $V220790 = $false
}
'@
    'V-220791' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'MPSSVC Rule-Level Policy Change' -match "Failure") {
        $V220791 = $true
    } else {
        $V220791 = $false
    }
} catch {
    $V220791 = $false
}
'@
    'V-220793' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name Value -ErrorAction Stop) -eq "Deny") {
        $V220793 = $true
    } else {
        $V220793 = $false
    }
} catch {
    $V220793 = $false
}
'@
    'V-220801' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096) {
        $V220801 = $true
    } else {
        $V220801 = $false
    }
} catch {
    $V220801 = $false
}
'@
    'V-220805' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\" -Name EccCurves -ErrorAction Stop) -eq "NistP384 NistP256") {
        $V220805 = $true
    } else {
        $V220805 = $false
    }
} catch {
    $V220805 = $false
}
'@
    'V-220806' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 3) {
        $V220806 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 0) {
        $V220806 = $false
    } else {
        $V220806 = $false
    }
} catch {
    $V220806 = $true
}
'@
# TODO: Additional checks needed besides reg checks
    'V-220811' = @'
try {
    if ($DeviceGuard.RequiredSecurityProperties -contains 2 -and
        $DeviceGuard.VirtualizationBasedSecurityStatus -eq 2 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -ErrorAction Stop) -eq 1 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -ErrorAction Stop) -in @(1,3)) {
        $V220811 = $true
    } else {
        $V220811 = $false
    }
} catch {
    $V220811 = $false
}
'@
    'V-220812' = @'
if ($DeviceGuard.SecurityServicesRunning -contains 1) {
    $V220812 = $true
} else {
    $V220812 = $false
}
'@
    'V-220813' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -in @(1,3,8)) {
        $V220813 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -eq 7) {
        $V220813 = $false
    } else {
        $V220813 = $false
    }
} catch {
    $V220813 = $false
}
'@
    'V0220818' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -ErrorAction Stop) -eq 1) {
        $V220818 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -ErrorAction Stop) -eq 1) {
        $V220818 = $false
    } else {
        $V220818 = $false
    }
} catch {
    $V220818 = $true
}
'@
    'V-220833' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2) {
        if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name LimitEnhancedDiagnosticDataWindowsAnalytics -ErrorAction Stop) -eq 1) {
            $V220833 = $true
        } else {
            $V220833 = $false
        }
    } else {
        $V220833 = $true
    }
} catch {
    $V220833 = $false
}
'@
    'V-220834' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -in @(0,1)) {
        $V220834 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2 -and
              $V220833 -eq $true) {
        $V220834 = $true
    } else {
        $V220834 = $false
    }
} catch {
    $V220834 = $false
}
'@
    'V-220835' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" -Name DODownloadMode -ErrorAction Stop) -eq 3) {
        # Below for non-domain machines only
        #(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" -Name DODownloadMode -ErrorAction Stop) -eq 0) {
        $V220835 = $false
    } else {
        $V220835 = $true
    }
} catch {
    $V220835 = $false
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
    'V-220922' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeCaption -ErrorAction Stop) -ne "") {
        $V220922 = $true
    } else {
        $V220922 = $false
    }
} catch {
    $V220922 = $false
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
    if ($SecurityPolicy.'System Access'.LSAAnonymousNameLookup -eq 0) {
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
    if ($SecurityPolicy.'Privilege Rights'.SeTcbPrivilege) {
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
    if ($SecurityPolicy.'Privilege Rights'.SeCreateTokenPrivilege) {
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
    if ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege -eq '*S-1-5-32-544') {
        $V220967 = $true
    } else {
        $V220967 = $false
    }
} catch {
    $V220967 = $false
}
'@
    'V-252903' = @'
try {
    if ($DeviceGuard.SecurityServicesRunning -contains 2 -
       (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -ErrorAction Stop) -in @(1,2)) {
        $V252903 = $true
    } else {
        $V252903 = $false
    }
} catch {
    $V252903 = $false
}
'@
}
