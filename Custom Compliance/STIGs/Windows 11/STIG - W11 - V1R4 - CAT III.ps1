##
# Microsoft Windows 11 Security Technical Implementation Guide
# Version: 1, Release: 4 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
# Files created: 10/13/2023 1:53:09 PM
##


#
# Gather/set data used across multiple rule checks
#

$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

$DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

$LocalUsers = Get-LocalUser



##
# V-253268
# Unused accounts must be disabled or removed from the system after 35 days of inactivity.
#
##
# DISCUSSION: 
# Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be
# deleted if no longer necessary or, if still required, disable until needed.
#
# Satisfies: SRG-OS-000468-GPOS-00212, SRG-OS-000118-GPOS-00060
#
##
# CHECK: 
# Run "PowerShell".
# Copy the lines below to the PowerShell window and enter.
#
# "([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
#   $user = ([ADSI]$_.Path)
#   $lastLogin = $user.Properties.LastLogin.Value
#   $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
#   if ($lastLogin -eq $null) {
#    $lastLogin = 'Never'
#   }
#   Write-Host $user.Name $lastLogin $enabled 
# }"
#
# This will return a list of local accounts with the account name, last logon, and if the account is enabled
# (True/False).
# For example: User1 10/31/2015 5:49:56 AM True
#
# Review the list to determine the finding validity for each account reported.
#
# Exclude the following accounts:
# Built-in administrator account (Disabled, SID ending in 500)
# Built-in guest account (Disabled, SID ending in 501)
# Built-in DefaultAccount (Disabled, SID ending in 503)
# Local administrator account
#
# If any enabled accounts have not been logged on to within the past 35 days, this is a finding.
#
# Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.
#
##
# FIX: 
# Review local accounts and verify their necessity. Disable or delete any active accounts that have not been
# used in the last 35 days.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253268r828888_rule
# STIG ID: WN11-00-000065
# W10 ID: V-220711
# REFERENCE: 
##
try {
    $V253268 = $true
    # Check all local accounts except for DefaultAccount/Administrator/Guest
    foreach ($user in $LocalUsers) {
        if ( ("500", "501", "503") -contains $user.SID.ToString().Substring($user.SID.ToString().Length - 3, 3) -or
             $Administrators -contains $user.Name -or
             $user.Enabled -eq $false) {
             # Skip these accounts
        } else {
            if ((Get-Date).AddDays(-35) -gt $user.LastLogon) {
                $V253268 = $false
            }
        }
    }
} catch {
    $V253268 = $false
}

##
# V-253272
# Standard local user accounts must not exist on a system in a domain.
#
##
# DISCUSSION: 
# To minimize potential points of attack, local user accounts, other than built-in accounts and local
# administrator accounts, must not exist on a workstation in a domain. Users must log on to workstations in a
# domain with their domain accounts.
#
##
# CHECK: 
# Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Users.
#
# If local users other than the accounts listed below exist on a workstation in a domain, this is a finding. 
#
# For standalone or nondomain-joined systems, this is Not Applicable.
#
# Built-in Administrator account (Disabled)
# Built-in Guest account (Disabled)
# Built-in DefaultAccount (Disabled)
# Built-in defaultuser0 (Disabled)
# Built-in WDAGUtilityAccount (Disabled)
# Local administrator account(s)
#
# All of the built-in accounts may not exist on a system, depending on the Windows 11 version.
#
##
# FIX: 
# Limit local user accounts on domain-joined systems. Remove any unauthorized local accounts.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253272r890449_rule
# STIG ID: WN11-00-000085
# W10 ID: V-220715
# REFERENCE: 
##
try {
    $V253272 = $true
    # Check for any non-default accounts
    foreach ($user in $LocalUsers) {
        if ( (("Administrator", "Guest", "DefaultAccount", "defaultuser0", "WDAGUtilityAccount") -contains $user.Name -and
             $user.Enabled -eq $true) -or
             $Administrators -contains $user.Name) {
             # Skip these accounts
        } else {
            $V253272 = $false
        }
    }
} catch {
    $V253272 = $false
}

##
# V-253296
# The Windows 11 time service must synchronize with an appropriate DoD time source.
#
##
# DISCUSSION: 
# The Windows Time Service controls time synchronization settings. Time synchronization is essential for
# authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure,
# authorized time source. Domain-joined systems are automatically configured to synchronize with domain
# controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.
#
##
# CHECK: 
# Review the Windows time service configuration.
#
# Open an elevated "Command Prompt" (run as administrator).
#
# Enter "W32tm /query /configuration".
#
# Domain-joined systems (excluding the domain controller with the PDC emulator role):
#
# If the value for "Type" under "NTP Client" is not "NT5DS", this is a finding.
#
##
# FIX: 
# Configure the system to synchronize time with an appropriate DoD time source.
#
# Domain-joined systems use NT5DS to synchronize time from other systems in the domain by default.
#
# If the system needs to be configured to an NTP server, configure the system to point to an authorized time
# server by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows
# Time Service >> Time Providers >> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer"
# field to point to an appropriate DoD time server.
#
# The US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html.
# Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and
# lower-level servers will synchronize with an authorized time server in the hierarchy.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253296r877038_rule
# STIG ID: WN11-00-000260
# W10 ID: -
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\Currentcontrolset\Services\W32time\Parameters" -Name Type -ErrorAction Stop) -eq "NT5DS") {
        $V253296 = $true
    } else {
        $V253296 = $false
    }
} catch {
    $V253296 = $false
}

##
# V-253355
# The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding
# Open Shortest Path First (OSPF) generated routes.
#
##
# DISCUSSION: 
# Allowing ICMP redirect of routes can lead to traffic not being routed properly.  When disabled, this forces
# ICMP to be routed via shortest path first.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
#
# Value Name: EnableICMPRedirect
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" to "Disabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253355r829149_rule
# STIG ID: WN11-CC-000030
# W10 ID: V-220797
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name EnableICMPRedirect -ErrorAction Stop) -eq 0) {
        $V253355 = $true
    } else {
        $V253355 = $false
    }
} catch {
    $V253355 = $false
}


##
# V-253356
# The system must be configured to ignore NetBIOS name release requests except from WINS servers.
#
##
# DISCUSSION: 
# Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service
# (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the
# server's cache, causing a response delay in the normal operation of the servers WINS resolution capability.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
#
# Value Name: NoNameReleaseOnDemand
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers"
# to "Enabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253356r829152_rule
# STIG ID: WN11-CC-000035
# W10 ID: V-220798
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -ErrorAction Stop) -eq 1) {
        $V253356 = $true
    } else {
        $V253356 = $false
    }
} catch {
    $V253356 = $false
}


##
# V-253384
# The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.
#
##
# DISCUSSION: 
# Control of credentials and the system must be maintained within the enterprise. Enabling this setting allows
# enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: MSAOptional
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App
# Runtime >> "Allow Microsoft accounts to be optional" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253384r829236_rule
# STIG ID: WN11-CC-000170
# W10 ID: V-220825
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V253384 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -ErrorAction Stop) -eq 1) {
        $V253384 = $true
    } else {
        $V253384 = $false
    }
} catch {
    $V253384 = $false
}

##
# V-253385
# The Application Compatibility Program Inventory must be prevented from collecting data and sending the
# information to Microsoft.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature. Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system. This setting will prevent the Program Inventory
# from collecting data about a system and sending the information to Microsoft.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\AppCompat\
#
# Value Name: DisableInventory
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Application Compatibility >> "Turn off Inventory Collector" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253385r829239_rule
# STIG ID: WN11-CC-000175
# W10 ID: V-220826
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" -Name DisableInventory -ErrorAction Stop) -eq 1) {
        $V253385 = $true
    } else {
        $V253385 = $false
    }
} catch {
    $V253385 = $false
}


##
# V-253390
# Microsoft consumer experiences must be turned off.
#
##
# DISCUSSION: 
# Microsoft consumer experiences provides suggestions and notifications to users, which may include the
# installation of Windows Store apps. Organizations may control the execution of applications through other
# means such as allowlisting. Turning off Microsoft consumer experiences will help prevent the unwanted
# installation of suggested applications.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\
#
# Value Name: DisableWindowsConsumerFeatures
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Cloud Content >> "Turn off Microsoft consumer experiences" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253390r829254_rule
# STIG ID: WN11-CC-000197
# W10 ID: V-220831
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -ErrorAction Stop) -eq 1) {
        $V253390 = $true
    } else {
        $V253390 = $false
    }
} catch {
    $V253390 = $false
}


##
# V-253394
# Windows Update must not obtain updates from other PCs on the internet.
#
##
# DISCUSSION: 
# Windows 11 allows Windows Update to obtain updates from additional sources instead of Microsoft. In addition
# to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet.
# This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates
# from or sending to systems on the internet must be prevented.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
#
# Value Name: DODownloadMode
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0) - No peering (HTTP Only)
# 0x00000001 (1) - Peers on same NAT only (LAN)
# 0x00000002 (2) - Local Network / Private group peering (Group)
# 0x00000063 (99) - Simple download mode, no peering (Simple)
# 0x00000064 (100) - Bypass mode, Delivery Optimization not used (Bypass)
#
# A value of 0x00000003 (3), Internet, is a finding.
#
# Standalone systems (configured in Settings):
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\
#
# Value Name: DODownloadMode
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0) - Off
# 0x00000001 (1) - LAN
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Delivery Optimization >> "Download Mode" to "Enabled" with any option except "Internet" selected.
#
# Acceptable selections include:
# Bypass (100)
# Group (2)
# HTTP only (0)
# LAN (1)
# Simple (99)
#
# .
#
##
# SEVERITY: CAT III
# RULE ID: SV-253394r829266_rule
# STIG ID: WN11-CC-000206
# W10 ID: V-220835
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" -Name DODownloadMode -ErrorAction Stop) -eq 3) {
        # Below for non-domain machines only
        #(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" -Name DODownloadMode -ErrorAction Stop) -eq 0) {
        $V253394 = $false
    } else {
        $V253394 = $true
    }
} catch {
    $V253394 = $false
}

##
# V-253397
# File Explorer heap termination on corruption must be disabled.
#
##
# DISCUSSION: 
# Legacy plug-in applications may continue to function when a File Explorer session has become corrupt.
# Disabling this feature will prevent this.
#
##
# CHECK: 
# The default behavior is for File Explorer heap termination on corruption to be enabled.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
#
# Value Name: NoHeapTerminationOnCorruption
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0) (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for File Explorer heap termination on corruption to be enabled.
#
# To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows
# Components >> File Explorer >> "Turn off heap termination on corruption" to "Not Configured" or "Disabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253397r829275_rule
# STIG ID: WN11-CC-000220
# W10 ID: V-220838
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -ErrorAction Stop) -eq 1) {
        $V253397 = $false
    } else {
        $V253397 = $true
    }
} catch {
    $V253397 = $true
}

##
# V-253425
# Windows 11 must be configured to prevent users from receiving suggestions for third-party or additional
# applications.
#
##
# DISCUSSION: 
# Windows spotlight features may suggest apps and content from third-party software publishers in addition to
# Microsoft apps and content.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_CURRENT_USER
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CloudContent\
#
# Value Name: DisableThirdPartySuggestions
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for User Configuration >> Administrative Templates. >> Windows Components >> Cloud
# Content >> "Do not suggest third-party content in Windows spotlight" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253425r829359_rule
# STIG ID: WN11-CC-000390
# W10 ID: V-220872
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableThirdPartySuggestions -ErrorAction Stop) -eq 1) {
        $V253425 = $true
    } else {
        $V253425 = $false
    }
} catch {
    $V253425 = $false
}


##
# V-253441
# The computer account password must not be prevented from being reset.
#
##
# DISCUSSION: 
# Computer account passwords are changed automatically on a regular basis. Disabling automatic password changes
# can make the system more vulnerable to malicious access. Frequent password changes can be a significant
# safeguard for the system. A new password for the computer account will be generated every 30 days.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: DisablePasswordChange
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Disable machine account password changes" to "Disabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253441r829407_rule
# STIG ID: WN11-SO-000050
# W10 ID: V-220917
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name DisablePasswordChange -ErrorAction Stop) -eq 0) {
        $V253441 = $true
    } else {
        $V253441 = $false
    }
} catch {
    $V253441 = $false
}


##
# V-253442
# The maximum age for machine account passwords must be configured to 30 days or less.
#
##
# DISCUSSION: 
# Computer account passwords are changed automatically on a regular basis. This setting controls the maximum
# password age that a machine account may have. This setting must be set to no more than 30 days, ensuring the
# machine changes its password monthly.
#
##
# CHECK: 
# (remove)This is the default configuration for this setting (30 days).
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: MaximumPasswordAge
#
# Value Type: REG_DWORD
# Value: 0x0000001e (30) (or less, excluding 0)
#
##
# FIX: 
# This is the default configuration for this setting (30 days).
#
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Maximum machine account password age" to "30" or less
# (excluding 0 which is unacceptable).
#
##
# SEVERITY: CAT III
# RULE ID: SV-253442r829410_rule
# STIG ID: WN11-SO-000055
# W10 ID: V-220918
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -ErrorAction Stop) -in 1..30) {
        $V253442 = $true
    } else {
        $V253442 = $false
    }
} catch {
    $V253442 = $false
}

##
# V-253446
# The Windows message title for the legal notice must be configured.
#
##
# DISCUSSION: 
# Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from
# unauthorized access to system resources.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: LegalNoticeCaption
#
# Value Type: REG_SZ
# Value: See message title above
#
# "DoD Notice and Consent Banner", "US Department of Defense Warning Statement" or a site-defined equivalent,
# this is a finding.
#
# If a site-defined title is used, it can in no case contravene or modify the language of the banner text
# required in WN11-SO-000075.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Message title for users attempting to log on" to "DoD
# Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent.
#
# If a site-defined title is used, it can in no case contravene or modify the language of the banner text
# required in WN11-SO-000075.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253446r829422_rule
# STIG ID: WN11-SO-000080
# W10 ID: V-220922
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeCaption -ErrorAction Stop) -ne "") {
        $V253446 = $true
    } else {
        $V253446 = $false
    }
} catch {
    $V253446 = $false
}

##
# V-253447
# Caching of logon credentials must be limited.
#
##
# DISCUSSION: 
# The default Windows configuration caches the last logon credentials for users who log on interactively to a
# system. This feature is provided for system availability reasons, such as the user's machine being
# disconnected from the network or domain controllers being unavailable. Even though the credential cache is
# well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user
# account using a password-cracking program and gain access to the domain.
#
##
# CHECK: 
# This is the default configuration for this setting (10 logons to cache).
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE 
# Registry Path: \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
#
# Value Name: CachedLogonsCount
#
# Value Type: REG_SZ
# Value: 10 (or less)
#
# This setting only applies to domain-joined systems, however, it is configured by default on all systems.
#
##
# FIX: 
# This is the default configuration for this setting (10 logons to cache).
#
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Number of previous logons to cache (in case domain
# controller is not available)" to "10" logons or less.
#
# This setting only applies to domain-joined systems, however, it is configured by default on all systems.
#
##
# SEVERITY: CAT III
# RULE ID: SV-253447r829425_rule
# STIG ID: WN11-SO-000085
# W10 ID: V-220923
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name CachedLogonsCount -ErrorAction Stop) -le 10) {
        $V253447 = $true
    } else {
        $V253447 = $false
    }
} catch {
    $V253447 = $false
}

##
# V-253467
# The default permissions of global system objects must be increased.
#
##
# DISCUSSION: 
# Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and
# semaphores. Each type of object is created with a default DACL that specifies who can access the objects with
# what permissions. If this policy is enabled, the default DACL is stronger, allowing non-admin users to read
# shared objects, but not modify shared objects that they did not create.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\
#
# Value Name: ProtectionMode
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "System objects: Strengthen default permissions of internal system objects
# (e.g. Symbolic links)" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253467r829485_rule
# STIG ID: WN11-SO-000240
# W10 ID: V-220943
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name ProtectionMode -ErrorAction Stop) -eq 1) {
        $V253467 = $true
    } else {
        $V253467 = $false
    }
} catch {
    $V253467 = $false
}


##
# V-253477
# Toast notifications to the lock screen must be turned off.
#
##
# DISCUSSION: 
# Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized
# personnel. Turning off this feature will limit access to the information to a logged on user.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_CURRENT_USER
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\
#
# Value Name: NoToastApplicationNotificationOnLockScreen
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for User Configuration >> Administrative Templates >> Start Menu and Taskbar >>
# Notifications >> "Turn off toast notifications on the lock screen" to "Enabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-253477r829515_rule
# STIG ID: WN11-UC-000015
# W10 ID: V-220954
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name NoToastApplicationNotificationOnLockScreen -ErrorAction Stop) -eq 1) {
        $V253477 = $true
    } else {
        $V253477 = $false
    }
} catch {
    $V253477 = $false
}


$hash = [ordered]@{
    'V-253268 - Disable Inactive Accounts' = $V253268
    'V-253272 - No Local User Accounts' = $V253272
    'V-253296 - Audit Other Policy Change Events - Success Time Service Must Sync with Appropriate DoD Time Source' = $V253296
    'V-253355 - Prevent ICMP Redirect' = $V253355
    'V-253356 - Ignore NetBIOS Name Release Request' = $V253356
    'V-253384 - Configure MSA Optional for Modern Apps' = $V253384
    'V-253385 - Disable Application Compatibility Program Inventory' = $V253385
    'V-253390 - Disable Microsoft Consumer Experiences' = $V253390
    'V-253394 - Disable Windows Update from Internet PCs' = $V253394
    'V-253397 - Disable Turning Off Explorer Heap Termination on Corruption' = $V253397
    'V-253425 - Disable Windows Spotlight Suggestions' = $V253425
    'V-253441 - Configure Computer Account Password Must Not be Prevented From Reset' = $V253441
    'V-253442 - Configure Max Machine Account Password Age' = $V253442
    'V-253446 - Configure Legal Notice Dialog Box Title' = $V253446
    'V-253447 - Configure Cached Credentials Limit' = $V253447
    'V-253467 - Configure Increased Permissions of Global System Objects' = $V253467
    'V-253477 - Disable Toast Notifications on Lock Screen' = $V253477
}

return $hash | ConvertTo-Json -Compress
