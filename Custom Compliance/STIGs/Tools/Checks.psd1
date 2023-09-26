@{
    'CAT1' = @(
        'ComputerInfo'
        'DeviceGuard'
        'LTSB'
        'SecurityPolicy'
    )
    'CAT2' = @(
        'AuditPolicy'
        'ComputerInfo'
        'DomainSID'
        'LocalUsers'
        'LTSB'
        'SecurityPolicy'
    )
    'CAT3' = @(
        'ComputerInfo'
        'DeviceGuard'
        'LocalUsers'
        'LTSB'
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

    'DomainSID' = @'
# Determine the "Domain SID" that the machine is a member of
$id = new-object System.Security.Principal.NTAccount($env:COMPUTERNAME + "$")
$id.Translate([System.Security.Principal.SecurityIdentifier]).toString() -match "(^S-1-5-\d+-\d+-\d+-\d+-)\d+$" | Out-Null
$DomainSID = $Matches[1]
'@

    'LocalUsers' = @'
$LocalUsers = Get-LocalUser
'@

    'LTSB' = @'
$v1507 = "10240"
$v1607 = "14393"
$v1809 = "17763"
$v21H2 = "19044"
$LTSB = @($v1507, $v1607, $v1809, $v21H2)
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
        if ($ComputerInfo.WindowsProductName -eq "Windows 10 Enterprise") {
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
    }
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
    if ($MinimumBLPIN) {
        $pin = $MinimumBLPIN
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
        $builds += $LTSB
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
    $V220711 = $true
    # Check all local accounts except for DefaultAccount/Administrator/Guest
    foreach ($user in $LocalUsers) {
        if ( ("500", "501", "503") -contains $user.SID.ToString().Substring($user.SID.ToString().Length - 3, 3) -or
             $Administrators -contains $user.Name -or
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
    $V220715 = $true
    # Check for any non-default accounts
    foreach ($user in $LocalUsers) {
        if ( (("Administrator", "Guest", "DefaultAccount", "defaultuser0", "WDAGUtilityAccount") -contains $user.Name -and
             $user.Enabled -eq $true) -or
             $Administrators -contains $user.Name) {
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
    $V220716 = $true
    foreach ($user in $LocalUsers) {
        if ($user.Enabled -eq $true -and $user.PasswordExpires -eq '') {
             $V220716 = $false
        }
    }
} catch {
    $V220716 = $false
}
'@
    'V-220717' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name EveryoneIncludesAnonymous -ErrorAction Stop) -eq 0) {
        $V220717 = $true

        $acl = Get-Acl -Path "C:\"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "None") {
                # Okay as default permissions
            } elseif ($entry.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-536805376" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                # Okay as default permissions
            } elseif ($entry.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "AppendData" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                # Okay as default permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }

        $acl = Get-Acl -Path "\Program Files"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "None" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions  
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "Modify, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "CREATOR OWNER") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }
    
        $acl = Get-Acl -Path "\Windows"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "None" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions  
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "Modify, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "CREATOR OWNER") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }
    } else {
        $V220717 = $false
    }
} catch {
    $V220717 = $false
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
    'V-220723' = @'
try {
    $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | Select-Object -Expand DriveLetter
    $V220723 = $true
    foreach ($drive in $drives) {
        $drive = $drive + ":\"
        if (Get-Childitem -Path $drive -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '.+\.(pfx|p12)$' } | Select-Object -First 1) {
            $V220723 = $false
        }
    }
} catch {
    $V220723 = $false
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
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name File)
    
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
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name File)
    
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
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name File)
    
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
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220818 = $true
} catch {
    $V220818 = $false
}
'@
    'V-220825' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220825 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -ErrorAction Stop) -eq 1) {
        $V220825 = $true
    } else {
        $V220825 = $false
    }
} catch {
    $V220825 = $false
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
    'V-220836' = @'
try {
    if (($ComputerInfo.OsBuildNumber -eq $v1507) -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 2) {
        $V220836 = $true
    } elseif (($ComputerInfo.OsBuildNumber -eq $v1607) -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1) {
        $V220836 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1 -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name ShellSmartScreenLevel -ErrorAction Stop) -eq "Block") {
        $V220836 = $true
    } else {
        $V220836 = $false
    }
} catch {
    $V220836 = $false
}
'@
    'V-220837' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -ErrorAction Stop) -eq 0) {
        $V220837 = $true
    } else {
        $V220837 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220837 = $true
} catch {
    $V220837 = $false
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
    'V-220839' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -ErrorAction Stop) -eq 0) {
        $V220839 = $true
    } else {
        $V220839 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220839 = $true
} catch {
    $V220839 = $false
}
'@
    'V-220840' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220840 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverride -ErrorAction Stop) -eq 1) {
        $V220840 = $true
    } else {
        $V220840 = $false
    }
} catch {
    $V220840 = $false
}
'@
    'V-220841' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220841 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverrideAppRepUnknown -ErrorAction Stop) -eq 1) {
        $V220841 = $true
    } else {
        $V220841 = $false
    }
} catch {
    $V220841 = $false
}
'@
    'V-220842' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220842 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\" -Name PreventCertErrorOverrides -ErrorAction Stop) -eq 1) {
        $V220842 = $true
    } else {
        $V220842 = $false
    }
} catch {
    $V220842 = $false
}
'@
    'V-220843' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220843 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\" -Name FormSuggest Passwords -ErrorAction Stop) -eq "no") {
        $V220843 = $true
    } else {
        $V220843 = $false
    }
} catch {
    $V220843 = $false
}
'@
    'V-220844' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220844 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name EnabledV9 -ErrorAction Stop) -eq 1) {
        $V220844 = $true
    } else {
        $V220844 = $false
    }
} catch {
    $V220844 = $false
}
'@
    'V-220845' = @'
try {
    if ($ComputerInfo.OsBuildNumber -in @($v1507, $v1607)) {
        $V220845 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\" -Name AllowGameDVR -ErrorAction Stop) -eq 0) {
        $V220845 = $true
    } else {
        $V220845 = $false
    }
} catch {
    $V220845 = $false
}
'@
    'V-220847' = @'
try {
    if ($MinimumPIN) {
        $pin = $MinimumPIN
    } else {
        $pin = 6
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\" -Name MinimumPINLength -ErrorAction Stop) -ge $pin) {
        $V220847 = $true
    } else {
        $V220847 = $false
    }
} catch {
    $V220847 = $false
}
'@
    'V-220854' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -Name AllowBasicAuthInClear -ErrorAction Stop) -eq 0) {
        $V220854 = $true
    } else {
        $V220854 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220854 = $true
} catch {
    $V220854 = $false
}
'@
    'V-220858' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name SafeForScripting -ErrorAction Stop) -eq 0) {
        $V220858 = $true
    } else {
        $V220858 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220858 = $true
} catch {
    $V220858 = $false
}
'@
    'V-220869' = @'
try {
    if ($ComputerInfo.OsBuildNumber -ge "18362") {
        $V220869 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name LetAppsActivateWithVoice -ErrorAction Stop) -eq 2) {
        $V220869 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name LetAppsActivateWithVoiceAboveLock -ErrorAction Stop) -eq 2) {
        $V220869 = $true
    } else {
        $V220869 = $false
    }
} catch {
    $V220869 = $false
}
'@
    'V-220870' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name AllowDomainPINLogon -ErrorAction Stop) -eq 0) {
        $V220870 = $true
    } else {
        $V220870 = $false
    }
} catch {
    $V220870 = $false
}
'@
    'V-220871' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" -Name AllowWindowsInkWorkspace -ErrorAction Stop) -eq 1) {
        $V220871 = $true
    } else {
        $V220871 = $false
    }
} catch {
    $V220871 = $false
}
'@
    'V-220902' = @'
try {
    if ($ComputerInfo.OsBuildNumber -ge "17134") {
        $V220902 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name DeviceEnumerationPolicy -ErrorAction Stop) -eq 0) {
        $V220902 = $true
    } else {
        $V220902 = $false
    }
} catch {
    $V220902 = $false
}
'@
    'V-220903' = @'
try {
    if ($MachineRoots) {
        $installedRoots = $MachineRoots
    } else {
        $installedRoots = @(
            "D73CA91102A2204A36459ED32213B467D7CE97FB" # DoD Root CA 3
            "B8269F25DBD937ECAFD4C35A9838571723F2D026" # DoD Root CA 4
            "4ECB5CC3095670454DA1CBD410FC921F46B8564B" # DoD Root CA 5
        )
    }

    $LMroots = Get-ChildItem -Path Cert:Localmachine\root | Select-Object -Expand Thumbprint

    $V220903 = $true

    foreach ($root in $installedRoots) {
        if ($root -notin $LMroots) {
            $V220903 = $false
        }
    }
} catch {
    $V220903 = $false
}
'@
    'V-220904' = @'
try {
    # ECA Root CA 4
    if (Get-ChildItem -Path Cert:Localmachine\root | Where-Object Thumbprint -eq "73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582") {
        $V220904 = $true
    } else {
        $V220904 = $false
    }
} catch {
    $V220904 = $false
}
'@
    'V-220905' = @'
try {
    # DoD Root CA 3, issued by DoD Interoperability Root CA 2
    if (Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object Thumbprint -eq "49CBE933151872E17C8EAE7F0ABA97FB610F6477") {
        $V220905 = $true
    } else {
        $V220905 = $false
    }
} catch {
    $V220905 = $false
}
'@
    'V-220906' = @'
try {
    # DoD Root CA 3, issued by US DoD CCEB Interoperability Root CA 2
    if (Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object Thumbprint -eq "9B74964506C7ED9138070D08D5F8B969866560C8") {
        $V220906 = $true
    } else {
        $V220906 = $false
    }
} catch {
    $V220906 = $false
}
'@
    'V-220907' = @'
try {
    $V220907 = $true

    $acl = Get-Acl -Path "HKLM:\SECURITY\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -eq "NT AUTHORITY\SYSTEM" -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Administrators" -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadPermissions, ChangePermissions" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default special permissions
        } else {
            $V220907 = $false
        }
    }

    $acl = Get-Acl -Path "HKLM:\SOFTWARE\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("CREATOR OWNER", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -in @("BUILTIN\Users", "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default read permissions
        } elseif ($entry.IdentityReference.Value -eq @("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as MS added default read permissions
        } else {
            $V220907 = $false
        }
    }

    $acl = Get-Acl -Path "HKLM:\SYSTEM\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("CREATOR OWNER", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -in @("BUILTIN\Users", "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default read permissions
        } elseif ($entry.IdentityReference.Value -eq @("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as MS added default read permissions
        } else {
            $V220907 = $false
        }
    }
} catch {
    $V220907 = $false
}
'@
    'V-220908' = @'
try {
    $V220908 = $true
    foreach ($user in $LocalUsers) {
        if ($user.SID -like "*-500" -and $user.Enabled -eq $true) {
             $V220908 = $false
        }
    }
} catch {
    $V220908 = $false
}
'@
    'V-220909' = @'
try {
    $V220909 = $true
    foreach ($user in $LocalUsers) {
        if ($user.SID -like "*-501" -and $user.Enabled -eq $true) {
             $V220909 = $false
        }
    }
} catch {
    $V220909 = $false
}
'@
    'V-220911' = @'
try {
    if ((Get-LocalUser -Name "Administrator" -ErrorAction Stop | Select-Object SID).SID -like "*-500") {
        $V220911 = $false
    } else {
        $V220911 = $true
    }
} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    $V220911 = $true
} catch {
    $V220911 = $false
}
'@
    'V-220912' = @'
try {
    if ((Get-LocalUser -Name "Guest" -ErrorAction Stop | Select-Object SID).SID -like "*-501") {
        $V220912 = $false
    } else {
        $V220912 = $true
    }
} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    $V220912 = $true
} catch {
    $V220912 = $false
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
    'V-220920' = @'
try {
    if ($InactivityTimeout) {
        $sec = $InactivityTimeout
    } else {
        $sec = 900
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -ErrorAction Stop) -ne 1..$sec) {
        $V220920 = $true
    } else {
        $V220920 = $false
    }
} catch {
    $V220920 = $false
}
'@
    'V-220921' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeText -ErrorAction Stop) -ne "") {
        $V220921 = $true
    } else {
        $V220921 = $false
    }
} catch {
    $V220921 = $false
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
    'V-220924' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -ErrorAction Stop) -in @(1, 2)) {
        $V220924 = $true
    } else {
        $V220924 = $false
    }
} catch {
    $V220924 = $false
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
    'V-20933' = @'
try {
    if ($ComputerInfo.OsBuildNumber -eq $v1507) {
        $V220933 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictRemoteSAM -ErrorAction Stop) -eq "O:BAG:BAD:(A;;RC;;;BA)") {
        $V220933 = $true
    } else {
        $V220933 = $false
    }
} catch {
    $V220933 = $false
}
'@
    'V-220942' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" -Name Enabled -ErrorAction Stop) -eq 1 -or
        (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" -Name MDMEnabled -ErrorAction Stop) -eq 1) {
        $V220942 = $true
    } else {
        $V220942 = $false
    }
} catch {
    $V220942 = $false
}
'@
    'V-220945' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -ErrorAction Stop) -eq 2) {
        $V220945 = $true
    } else {
        $V220945 = $false
    }
} catch {
    $V220945 = $false
}
'@
    'V-220952' = @'
try {
    $localAdmins = Get-LocalGroupMember -Name "Administrators"
    $V220952 = $true
    foreach ($acct in $localAdmins) {
    if ($acct.PrincipalSource -eq "Local" -and ($LocalUsers | Where-Object { $_.SID -eq $acct.SID }).Enabled -eq $true) {
        if ((Get-Date).AddDays(-60) -gt ($LocalUsers | Where-Object { $_.SID -eq $acct.SID }).PasswordLastSet) {
            $V220952 = $false
        }
    }
}
} catch {
    $V220952 = $false
}
'@
    'V-220955' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name SaveZoneInformation -ErrorAction Stop) -eq 2) {
        $V220955 = $true
    } else {
        $V220955 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220955 = $true
} catch {
    $V220955 = $false
}
'@
    'V-220956' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeTrustedCredManAccessPrivilege -eq "") {
        $V220956 = $true
    } else {
        $V220956 = $false
    }
} catch {
    $V220956 = $false
}
'@
    'V-220957' = @'
try {
    $V220957 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeNetworkLogonRight).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-32-555")) {
            $V220957 = $false
        }
    }
} catch {
    $V220957 = $false
}
'@
    'V-220958' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeTcbPrivilege -eq "") {
        $V220958 = $true
    } else {
        $V220958 = $false
    }
} catch {
    $V220958 = $false
}
'@
    'V-220959' = @'
try {
    $V220959 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeInteractiveLogonRight).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-32-545")) {
            $V220959 = $false
        }
    }
} catch {
    $V220959 = $false
}
'@
    'V-220960' = @'
try {
    $V220960 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeBackupPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220960 = $false
        }
    }
} catch {
    $V220960 = $false
}
'@
# Check for this account? NT SERVICE\autotimesvc
    'V-220961' = @'
try {
    $V220961 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeBackupPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19")) {
            $V220961 = $false
        }
    }
} catch {
    $V220961 = $false
}
'@
    'V-220962' = @'
try {
    $V220962 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreatePagefilePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220962 = $false
        }
    }
} catch {
    $V220962 = $false
}
'@
    'V-220963' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeCreateTokenPrivilege -eq "") {
        $V220963 = $false
    } else {
        $V220963 = $true
    }
} catch {
    $V220963 = $false
}
'@
    'V-220964' = @'
try {
    $V220964 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreateGlobalPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")) {
            $V220964 = $false
        }
    }
} catch {
    $V220964 = $false
}
'@
    'V-220965' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeCreatePermanentPrivilege -eq "") {
        $V220965 = $true
    } else {
        $V220965 = $false
    }
} catch {
    $V220965 = $false
}
'@
    'V-220966' = @'
try {
    $V220966 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreateSymbolicLinkPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220966 = $false
        }
    }
} catch {
    $V220966 = $false
}
'@
    'V-220967' = @'
try {
    $V220967 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220967 = $false
        }
    }
} catch {
    $V220967 = $false
}
'@
    'V-220968' = @'
try {
    $V220968 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyNetworkLogonRight).Split(",")

    if ($rights -notcontains "*S-1-5-32-546" -or           # Guests group
        $rights -notcontains "*S-1-5-113" -or              # Local account (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220968 = $false
    }

} catch {
    $V220968 = $false
}
'@
    'V-220969' = @'
try {
    $V220969 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyBatchLogonRight).Split(",")

    if ($rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220969 = $false
    }

} catch {
    $V220969 = $false
}
'@
    'V-220970' = @'
try {
    $V220970 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyServiceLogonRight).Split(",")

    if ($rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220970 = $false
    }

} catch {
    $V220970 = $false
}
'@
    'V-220971' = @'
try {
    $V220971 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyInteractiveLogonRight).Split(",")

    if ($rights -notcontains "*S-1-5-32-546" -or           # Guests group
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220971 = $false
    }

} catch {
    $V220971 = $false
}
'@
    'V-220972' = @'
try {
    $V220972 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyInteractiveLogonRight).Split(",")
    
    if ($rights -contains "*S-1-1-0") {
        # If RDS is not used, adding "Everyone" group is okay
    } elseif ($rights -notcontains "*S-1-5-32-546" -or     # Guests group
        $rights -notcontains "*S-1-5-113" -or              # Local account
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220972 = $false
    }

} catch {
    $V220972 = $false
}
'@
    'V-220973' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeEnableDelegationPrivilege -eq "") {
        $V220973 = $true
    } else {
        $V220973 = $false
    }
} catch {
    $V220973 = $false
}
'@
    'V-220974' = @'
try {
    $V220974 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220974 = $false
        }
    }
} catch {
    $V220974 = $false
}
'@
    'V-220975' = @'
try {
    $V220975 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeImpersonatePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")) {
            $V220975 = $false
        }
    }
} catch {
    $V220975 = $false
}
'@
    'V-220976' = @'
try {
    $V220976 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeLoadDriverPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220976 = $false
        }
    }
} catch {
    $V220976 = $false
}
'@
    'V-220977' = @'
try {
    if ($SecurityPolicy.'Privilege Rights'.SeLockMemoryPrivilege -eq "") {
        $V220977 = $true
    } else {
        $V220977 = $false
    }
} catch {
    $V220977 = $false
}
'@
    'V-220978' = @'
try {
    $V220978 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeSecurityPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220978 = $false
        }
    }
} catch {
    $V220978 = $false
}
'@
    'V-220979' = @'
try {
    $V220979 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeSystemEnvironmentPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220979 = $false
        }
    }
} catch {
    $V220979 = $false
}
'@
    'V-220980' = @'
try {
    $V220980 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeManageVolumePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220980 = $false
        }
    }
} catch {
    $V220980 = $false
}
'@
    'V-220981' = @'
try {
    $V220981 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeProfileSingleProcessPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220981 = $false
        }
    }
} catch {
    $V220981 = $false
}
'@
    'V-220982' = @'
try {
    $V220982 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeRestorePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220982 = $false
        }
    }
} catch {
    $V220982 = $false
}
'@
    'V-220983' = @'
try {
    $V220983 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeTakeOwnershipPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220983 = $false
        }
    }
} catch {
    $V220983 = $false
}
'@
    'V-252903' = @'
try {
    if ($DeviceGuard.SecurityServicesRunning -contains 2 -and
       (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -ErrorAction Stop) -in @(1,2)) {
        $V252903 = $true
    } else {
        $V252903 = $false
    }
} catch {
    $V252903 = $false
}
'@
    'V-256894' = @'
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name NotifyDisableIEOptions -ErrorAction Stop) -eq 0) {
        $V256894 = $true
    } else {
        $V256894 = $false
    }
} catch {
    $V256894 = $false
}
'@
}
