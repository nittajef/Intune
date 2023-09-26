@{
    # Settings imported in to Convert-xccdf.ps1 policy generator
    input = @{
        STIG = "U_MS_Windows_10_STIG_V2R7_Manual-xccdf.xml"
        Checks = "STIG-W10-V2R7-Checks.psd1"
    }

    output = @{
        # JSON output to upload in to Intune Custom Compliance policy
        # Style:     discussion - Put STIG rule "Discussion" section in to Remediation Description
        #            fix - Put STIG rule "Fix" section in to Remediation Description
        #            debug - Description shows rule evaluation values in Company Portal, but need to adjust PS check returns to be useful
        # NoCheck:   include - Keep rules with no code checks in compliance policy (auto-pass & append rule name w/NoChk)
        #            exclude - Remove rules with no technical checks from compliance policy
        # Reference: include - Include rule references (not needed/used by Intune at the moment)
        #            exclude - Remove rule references (brings down JSON file size)
        #
        JSON = "cc_json.json"
        JSONStyle = "fix"
        JSONInfoURL = "https://contoso.com"
        JSONNoCheckRules = "include"
        JSONReference = "exclude"

        # PowerShell output to upload as script in Intune Custom Compliance
        # Style:   verbose - Add all of the STIG rule comments (Discussion, Check, Fix)
        #          mini - Add STIG rule title and additional metadata
        #          zen - Only include STIG rule title
        PS = "cc_ps.ps1"
        PSStyle = "verbose"
    }

    accounts = @{
        # List all accounts that should not be evaluated in STIG rule checks (one account per line)
        Administrators = @(
            #"root"
        )
        BackupOperators = @(
        )
        HyperVAdministrators = @(
        )
    }    

    severity = @{
        # Select which severity rules to generate policy for
        CAT1 = $false
        CAT2 = $true
        CAT3 = $false
    }

    # List all rules that are manual/process checks
    nocode = @(
        "V-220701" # ESS?
        "V-220705" # App allow-list
        "V-220710" # Share permissions
        "V-220725" # Firewall allows for mgmt
        "V-220733" # Remove orphaned SIDs
        "V-220734" # Disable Bluetooth - Not sure best way to check
        "V-220735" # Bluetooth turned off when not in use
        "V-220736" # Bluetooth connect alert
        "V-220737" # Admin account internet access
        "V-220738" # VDI 24 hour sessions
        "V-220946" # Use multifactor authentication
    )

    # Overrides - Settings here will override respective STIG rule values
    #             Rules with overrides will be indicated with trailing -OvR
    overrides = @{
        #'V-220704' = @{
        #    MinimumBLPIN = 6
        #}
        #'V-220706' = @{
        #    SupportedBuilds = @("19044", "19045")
        #}
        #'V-220706' = @{
        #    AllowAppCapabilitySIDs = $false # S-1-15-3-*
        #}
        #'V-220739' = @{
        #    LockoutDuration = 15
        #}
        #'V-220740' = @{
        #    LockoutThreshold = 3
        #}
        #'V-220741' = @{
        #    ResetCounter = 15
        #}
        #'V-220742' = @{
        #    PWHistory = 24
        #}
        #'V-220743' = @{
        #    MaxPwAge = 60
        #}
        #'V-220744' = @{
        #    MinPwAge = 1
        #}
        #'V-220745' = @{
        #    MinPwLength = 14
        #}
        #'V-220779' = @{
        #    AppEventLogSize = 32768
        #}
        #'V-220780' = @{
        #    SecEventLogSize = 1024000
        #}
        #'V-220781' = @{
        #    SysEventLogSize = 32768
        #}
        #'V-220847' = @{
        #    MinimumPIN = 6
        #}
        #'V-220903' = @{
        #    MachineRoots = @(
        #    )
        #}
        #'V-220920' = @{
        #    InactivityTimeout = 900
        #}
    }

    # Exemptions - Rules in this list will have checks return true and 
    #              exempted rules will be indidcated with trailing -EXM
    exemptions = @(
    )
}
