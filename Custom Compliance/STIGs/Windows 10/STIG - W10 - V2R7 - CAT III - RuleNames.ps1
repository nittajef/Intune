##
# Microsoft Windows 10 Security Technical Implementation Guide
# Version: 2, Release: 7 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
# Files created: 10/5/2023 12:19:28 PM
##


#
# Gather/set data used across multiple rule checks
#

$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

$DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

$LocalUsers = Get-LocalUser

$v1507 = "10240"
$v1607 = "14393"
$v1809 = "17763"
$v21H2 = "19044"
$LTSB = @($v1507, $v1607, $v1809, $v21H2)



##
# V-220700
# Secure Boot must be enabled on Windows 10 systems.
#
##
# DISCUSSION: 
# Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is
# required to support additional security features in Windows 10, including Virtualization Based Security and
# Credential Guard. If Secure Boot is turned off, these security features will not function.
#
##
# CHECK: 
# Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a
# future date when broad support of Windows 10 hardware and firmware requirements are expected to be met.
# Devices that have UEFI firmware must have Secure Boot enabled. 
#
# For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon
# logoff, this is NA.
#
# Run "System Information".
#
# Under "System Summary", if "Secure Boot State" does not display "On", this is finding.
#
##
# FIX: 
# Enable Secure Boot in the system firmware.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220700r569187_rule
# STIG ID: WN10-00-000020
# REFERENCE: 
##
try {
    if (Confirm-SecureBootUEFI) {
        $V220700 = $true
    } else {
        $V220700 = $false
    }
} catch {
    $V220700 = $false
}

##
# V-220711
# Unused accounts must be disabled or removed from the system after 35 days of inactivity.
#
##
# DISCUSSION: 
# Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be
# deleted if no longer necessary or, if still required, disable until needed.
#
##
# CHECK: 
# Run "PowerShell".
# Copy the lines below to the PowerShell window and enter.
#
# "([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
#    $user = ([ADSI]$_.Path)
#    $lastLogin = $user.Properties.LastLogin.Value
#    $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
#    if ($lastLogin -eq $null) {
#       $lastLogin = 'Never'
#    }
#    Write-Host $user.Name $lastLogin $enabled 
# }"
#
# This will return a list of local accounts with the account name, last logon, and if the account is enabled
# (True/False).
# For example: User1  10/31/2015  5:49:56  AM  True
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
# Regularly review local accounts and verify their necessity.  Disable or delete any active accounts that have
# not been used in the last 35 days.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220711r569187_rule
# STIG ID: WN10-00-000065
# REFERENCE: 
##
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

##
# V-220715
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
# For standalone or nondomain-joined systems, this is Not Applicable.
#
# Run "Computer Management".
#
# Navigate to System Tools >> Local Users and Groups >> Users.
#
# If local users other than the accounts listed below exist on a workstation in a domain, this is a finding.
#
# Built-in Administrator account (Disabled)
# Built-in Guest account (Disabled)
# Built-in DefaultAccount (Disabled)
# Built-in defaultuser0 (Disabled)
# Built-in WDAGUtilityAccount (Disabled)
# Local administrator account(s)
#
# All of the built-in accounts may not exist on a system, depending on the Windows 10 version.
#
##
# FIX: 
# Limit local user accounts on domain-joined systems. Remove any unauthorized local accounts.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220715r890423_rule
# STIG ID: WN10-00-000085
# REFERENCE: 
##
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

##
# V-220797
# The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding
# Open Shortest Path First (OSPF) generated routes.
#
##
# DISCUSSION: 
# Allowing ICMP redirect of routes can lead to traffic not being routed properly.   When disabled, this forces
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
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220797r569187_rule
# STIG ID: WN10-CC-000030
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name EnableICMPRedirect -ErrorAction Stop) -eq 0) {
        $V220797 = $true
    } else {
        $V220797 = $false
    }
} catch {
    $V220797 = $false
}


##
# V-220798
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
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
#
# Value Name:  NoNameReleaseOnDemand
#
# Value Type:  REG_DWORD
# Value:  1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers"
# to "Enabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220798r851985_rule
# STIG ID: WN10-CC-000035
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -ErrorAction Stop) -eq 1) {
        $V220798 = $true
    } else {
        $V220798 = $false
    }
} catch {
    $V220798 = $false
}


##
# V-220811
# Virtualization Based Security must be enabled on Windows 10 with the platform security level configured to
# Secure Boot or Secure Boot with DMA Protection.
#
##
# DISCUSSION: 
# Virtualization Based Security (VBS) provides the platform for the additional security features, Credential
# Guard and Virtualization based protection of code integrity.  Secure Boot is the minimum security level with
# DMA protection providing additional memory protection.  DMA Protection requires a CPU that supports
# input/output memory management unit (IOMMU).
#
##
# CHECK: 
# Confirm Virtualization Based Security is enabled and running with Secure Boot or Secure Boot and DMA
# Protection.
#
# For those devices that support virtualization based security (VBS) features, including Credential Guard or
# protection of code integrity, this must be enabled. If the system meets the hardware and firmware dependencies
# for enabling VBS but it is not enabled, this is a CAT III finding.
#
# Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Run "PowerShell" with elevated privileges (run as administrator).
#
# Enter the following:
#
# "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
#
# If "RequiredSecurityProperties" does not include a value of "2" indicating "Secure Boot" (e.g., "{1, 2}"),
# this is a finding.
#
# If "Secure Boot and DMA Protection" is configured, "3" will also be displayed in the results (e.g., "{1, 2,
# 3}").
#
# If "VirtualizationBasedSecurityStatus" is not a value of "2" indicating "Running", this is a finding.
#
# Alternately:
#
# Run "System Information".
#
# Under "System Summary", verify the following:
#
# If "Device Guard Virtualization based security" does not display "Running", this is finding.
#
# If "Device Guard Required Security Properties" does not display "Base Virtualization Support, Secure Boot",
# this is finding.
#
# If "Secure Boot and DMA Protection" is configured, "DMA Protection" will also be displayed (e.g., "Base
# Virtualization Support, Secure Boot, DMA Protection").
#
# The policy settings referenced in the Fix section will configure the following registry values. However due to
# hardware requirements, the registry values alone do not ensure proper function.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\
#
# Value Name: EnableVirtualizationBasedSecurity
# Value Type: REG_DWORD
# Value: 1
#
# Value Name: RequirePlatformSecurityFeatures
# Value Type: REG_DWORD
# Value: 1 (Secure Boot only) or 3 (Secure Boot and DMA Protection)
#
# A Microsoft article on Credential Guard system requirement can be found at the following link:
#
# https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements
#
# NOTE:  The severity level for the requirement will be upgraded to CAT II starting January 2020.
#
##
# FIX: 
# Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >>
# "Turn On Virtualization Based Security" to "Enabled" with "Secure Boot" or "Secure Boot and DMA Protection"
# selected for "Select Platform Security Level:".
#
# A Microsoft article on Credential Guard system requirement can be found at the following link.
# https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements
#
##
# SEVERITY: CAT III
# RULE ID: SV-220811r569187_rule
# STIG ID: WN10-CC-000070
# REFERENCE: 
##
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

##
# V-220825
# The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.
#
##
# DISCUSSION: 
# Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows
# enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.
#
##
# CHECK: 
# Windows 10 LTSC\B versions do not support the Microsoft Store and modern apps; this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
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
# RULE ID: SV-220825r569187_rule
# STIG ID: WN10-CC-000170
# REFERENCE: 
##
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

##
# V-220826
# The Application Compatibility Program Inventory must be prevented from collecting data and sending the
# information to Microsoft.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting will prevent the Program
# Inventory from collecting data about a system and sending the information to Microsoft.
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
# RULE ID: SV-220826r569187_rule
# STIG ID: WN10-CC-000175
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" -Name DisableInventory -ErrorAction Stop) -eq 1) {
        $V220826 = $true
    } else {
        $V220826 = $false
    }
} catch {
    $V220826 = $false
}


##
# V-220831
# Microsoft consumer experiences must be turned off.
#
##
# DISCUSSION: 
# Microsoft consumer experiences provides suggestions and notifications to users, which may include the
# installation of Windows Store apps.  Organizations may control the execution of applications through other
# means such as whitelisting.  Turning off Microsoft consumer experiences will help prevent the unwanted
# installation of suggested applications.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.
#
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
# RULE ID: SV-220831r569187_rule
# STIG ID: WN10-CC-000197
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -ErrorAction Stop) -eq 1) {
        $V220831 = $true
    } else {
        $V220831 = $false
    }
} catch {
    $V220831 = $false
}


##
# V-220835
# Windows Update must not obtain updates from other PCs on the internet.
#
##
# DISCUSSION: 
# Windows 10 allows Windows Update to obtain updates from additional sources instead of Microsoft. In addition
# to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the internet.
# This is part of the Windows Update trusted process; however, to minimize outside exposure, obtaining updates
# from or sending to systems on the internet must be prevented.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
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
# v1507 LTSB:
# Domain joined systems:
# Verify the registry value above.
# If the value is not 0x00000000 (0) or 0x00000001 (1), this is a finding.
#
# Standalone or nondomain-joined systems (configured in Settings):
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
# v1507 (LTSB) does not include this group policy setting locally. For domain-joined systems, configure through
# domain group policy as "HTTP only (0)" or "Lan (1)". 
#
# For standalone or nondomain-joined systems, configure using Settings >> Update & Security >> Windows Update >>
# Advanced Options >> "Choose how updates are delivered" with either "Off" or "PCs on my local network"
# selected.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220835r857197_rule
# STIG ID: WN10-CC-000206
# REFERENCE: 
##
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

##
# V-220838
# Turning off File Explorer heap termination on corruption must be disabled.
#
##
# DISCUSSION: 
# Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. 
#  Disabling this feature will prevent this.
#
##
# CHECK: 
# The default behavior is for File Explorer heap termination on corruption to be enabled.
#
# If the registry Value Name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
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
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> File Explorer >> "Turn off heap termination on corruption" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT III
# RULE ID: SV-220838r851993_rule
# STIG ID: WN10-CC-000220
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -ErrorAction Stop) -eq 1) {
        $V220838 = $false
    } else {
        $V220838 = $true
    }
} catch {
    $V220838 = $true
}

##
# V-220872
# Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional
# applications. 
#
##
# DISCUSSION: 
# Windows spotlight features may suggest apps and content from third-party software publishers in addition to
# Microsoft apps and content. 
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
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
#
##
# FIX: 
# Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Cloud
# Content >> "Do not suggest third-party content in Windows spotlight" to "Enabled
#
##
# SEVERITY: CAT III
# RULE ID: SV-220872r569187_rule
# STIG ID: WN10-CC-000390
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableThirdPartySuggestions -ErrorAction Stop) -eq 1) {
        $V220872 = $true
    } else {
        $V220872 = $false
    }
} catch {
    $V220872 = $false
}


##
# V-220917
# The computer account password must not be prevented from being reset.
#
##
# DISCUSSION: 
# Computer account passwords are changed automatically on a regular basis.  Disabling automatic password changes
# can make the system more vulnerable to malicious access.  Frequent password changes can be a significant
# safeguard for your system.  A new password for the computer account will be generated every 30 days.
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
# RULE ID: SV-220917r569187_rule
# STIG ID: WN10-SO-000050
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name DisablePasswordChange -ErrorAction Stop) -eq 0) {
        $V220917 = $true
    } else {
        $V220917 = $false
    }
} catch {
    $V220917 = $false
}


##
# V-220918
# The maximum age for machine account passwords must be configured to 30 days or less.
#
##
# DISCUSSION: 
# Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum
# password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the
# machine changes its password monthly.
#
##
# CHECK: 
# This is the default configuration for this setting (30 days).
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: MaximumPasswordAge
#
# Value Type: REG_DWORD
# Value: 0x0000001e (30)  (or less, excluding 0)
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
# RULE ID: SV-220918r569187_rule
# STIG ID: WN10-SO-000055
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -ErrorAction Stop) -in 1..30) {
        $V220918 = $true
    } else {
        $V220918 = $false
    }
} catch {
    $V220918 = $false
}

##
# V-220922
# The Windows dialog box title for the legal banner must be configured.
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
# required in WN10-SO-000075.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Message title for users attempting to log on" to "DoD
# Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent.
#
# If a site-defined title is used, it can in no case contravene or modify the language of the banner text
# required in WN10-SO-000075.
#
##
# SEVERITY: CAT III
# RULE ID: SV-220922r569187_rule
# STIG ID: WN10-SO-000080
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeCaption -ErrorAction Stop) -ne "") {
        $V220922 = $true
    } else {
        $V220922 = $false
    }
} catch {
    $V220922 = $false
}

##
# V-220923
# Caching of logon credentials must be limited.
#
##
# DISCUSSION: 
# The default Windows configuration caches the last logon credentials for users who log on interactively to a
# system.  This feature is provided for system availability reasons, such as the user's machine being
# disconnected from the network or domain controllers being unavailable.  Even though the credential cache is
# well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user
# account using a password-cracking program and gain access to the domain.
#
##
# CHECK: 
# This is the default configuration for this setting (10 logons to cache).
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive:  HKEY_LOCAL_MACHINE 
# Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
#
# Value Name:  CachedLogonsCount
#
# Value Type:  REG_SZ
# Value:  10 (or less)
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
# RULE ID: SV-220923r569187_rule
# STIG ID: WN10-SO-000085
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name CachedLogonsCount -ErrorAction Stop) -le 10) {
        $V220923 = $true
    } else {
        $V220923 = $false
    }
} catch {
    $V220923 = $false
}

##
# V-220943
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
# RULE ID: SV-220943r569187_rule
# STIG ID: WN10-SO-000240
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name ProtectionMode -ErrorAction Stop) -eq 1) {
        $V220943 = $true
    } else {
        $V220943 = $false
    }
} catch {
    $V220943 = $false
}


##
# V-220954
# Toast notifications to the lock screen must be turned off.
#
##
# DISCUSSION: 
# Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized
# personnel.  Turning off this feature will limit access to the information to a logged on user.
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
# RULE ID: SV-220954r569187_rule
# STIG ID: WN10-UC-000015
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name NoToastApplicationNotificationOnLockScreen -ErrorAction Stop) -eq 1) {
        $V220954 = $true
    } else {
        $V220954 = $false
    }
} catch {
    $V220954 = $false
}


##
# V-252903
# Virtualization-based protection of code integrity must be enabled.
#
##
# DISCUSSION: 
# Virtualization-based protection of code integrity enforces kernel mode memory protections and protects Code
# Integrity validation paths. This isolates the processes from the rest of the operating system and can only be
# accessed by privileged system software.
#
##
# CHECK: 
# Confirm virtualization-based protection of code integrity.
#
# For devices that support the virtualization based security (VBS) feature for protection of code integrity,
# this must be enabled. If the system meets the hardware, firmware, and compatible device driver dependencies
# for enabling virtualization-based protection of code integrity but it is not enabled, this is a CAT II
# finding.
#
# Virtualization based security currently cannot be implemented in virtual desktop implementations (VDI) due to
# specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V
# feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Run "PowerShell" with elevated privileges (run as administrator).
# Enter the following:
# "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
#
# If "SecurityServicesRunning" does not include a value of "2" (e.g., "{1, 2}"), this is a finding.
#
# Alternately:
#
# Run "System Information".
#
# Under "System Summary", verify the following:
# If "Virtualization-based Security Services Running" does not list "Hypervisor enforced Code Integrity", this
# is finding.
#
# The policy settings referenced in the Fix section will configure the following registry value. However due to
# hardware requirements, the registry value alone does not ensure proper function.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\
#
# Value Name: HypervisorEnforcedCodeIntegrity
# Value Type: REG_DWORD
# Value: 0x00000001 (1) (Enabled with UEFI lock), or 0x00000002 (2) (Enabled without lock)
#
##
# FIX: 
# Virtualization-based security currently cannot be implemented in VDIs due to specific supporting requirements,
# including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual
# desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >>
# "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" or "Enabled without lock"
# selected for "Virtualization Based Protection of Code Integrity:".
#
# "Enabled with UEFI lock" is preferred as more secure; however, it cannot be turned off remotely through a
# group policy change if there is an issue.
#
# "Enabled without lock" will allow this to be turned off remotely while testing for issues.
#
##
# SEVERITY: CAT III
# RULE ID: SV-252903r822503_rule
# STIG ID: WN10-CC-000080
# REFERENCE: 
##
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

$hash = [ordered]@{
    'V-220700 - Use Secure Boot' = $V220700
    'V-220711 - Disable Inactive Accounts' = $V220711
    'V-220715 - No Local User Accounts' = $V220715
    'V-220797 - Prevent ICMP Redirect' = $V220797
    'V-220798 - Ignore NetBIOS Name Release Request' = $V220798
    'V-220811 - Enable Virtualization Based Security' = $V220811
    'V-220825 - Configure MSA Optional for Modern Apps' = $V220825
    'V-220826 - Disable Application Compatibility Program Inventory' = $V220826
    'V-220831 - Disable Microsoft Consumer Experiences' = $V220831
    'V-220835 - Disable Windows Update from Internet PCs' = $V220835
    'V-220838 - Disable Turning Off Explorer Heap Termination on Corruption' = $V220838
    'V-220872 - Disable Windows Spotlight Suggestions' = $V220872
    'V-220917 - Configure Computer Account Password Must Not be Prevented From Reset' = $V220917
    'V-220918 - Configure Max Machine Account Password Age' = $V220918
    'V-220922 - Configure Legal Notice Dialog Box Title' = $V220922
    'V-220923 - Configure Cached Credentials Limit' = $V220923
    'V-220943 - Configure Increased Permissions of Global System Objects' = $V220943
    'V-220954 - Disable Toast Notifications on Lock Screen' = $V220954
    'V-252903 - Enable Virtualization-based Protection of Code Integrity' = $V252903
}

return $hash | ConvertTo-Json -Compress
