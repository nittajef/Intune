@{
    # Settings imported in to Convert-xccdf.ps1 policy generator
    input = @{
        STIG = "U_MS_Windows_10_STIG_V2R7_Manual-xccdf.xml"
        Checks = "STIG-W10-V2R7-Checks.psd1"
    }

    output = @{
        # JSON output to upload in to Intune Custom Compliance policy
        # Style:   discussion - Put STIG rule "Discussion" section in to Remediation Description
        #          fix - Put STIG rule "Fix" section in to Remediation Description
        #          debug - Description shows rule evaluation values in Company Portal, but need to adjust PS check returns to be useful
        # NoCheck: include - Keep rules with no code checks in compliance policy (auto-pass & append rule name w/NoChk)
        #          exclude - Remove rules with no technical checks from compliance policy
        #
        JSON = "cc_json.json"
        JSONStyle = "fix"
        JSONInfoURL = "https://contoso.com"
        JSONNoCheckRules = "include"

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
            "root"
        )
        BackupOperators = @(
        )
        HyperVAdministrators = @(
        )
    }    

    severity = @{
        # Select which severity rules to generate policy for
        CAT1 = $false
        CAT2 = $false
        CAT3 = $true
    }

    # List all rules that are manual/process checks
    nocode = @(
        "V-220705"
        "V-220733"
        "V-220735"
        "V-220737"
        "V-220738"
    )

    # Overrides - Settings here will override respective STIG rule values
    #             Rules with overrides will be indicated with trailing -OvR
    overrides = @{
        'V-220704' = @{
            MinimumPIN = 4
        }
        'V-220706' = @{
            SupportedBuilds = @("19044", "19045")
        }
        'V-220918' = @{
            MaxPwAge = 45
        }
    }

    # Exemptions - Rules in this list will have checks return true and 
    #              exempted rules will be indidcated with trailing -EXM
    exemptions = @(
    )
}
