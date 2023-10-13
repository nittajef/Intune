##
# Jeffrey Nitta - @nittajef
#
##

##
# Import script generation settings, additional rule data, and rule check content.
##
$OrgSettings = Import-PowerShellDataFile "Org-Settings-W10.psd1"
$RuleChecks = Import-PowerShellDataFile $OrgSettings.input.Checks
[xml]$stig = Get-Content -Path $OrgSettings.input.STIG -Encoding UTF8
$map = Import-Csv W10-W11-rule-map.csv

$PsOutput = @()        # Output string for the full PowerShell discovery script.
$JsonOutput = @()      # Output string for 
$W10,$W11 = $false     # Flags to tell script if it's a W10 or W11 STIG. W11 STIG needs to use rule map.
$SharedInfo = @()      # List of info needed for each severity (computer info, security policy, audit policy, etc)
$AccountInfo = @()     # List(s) of accounts that are allowed/exempted from rules
$EmptyRules = 0        # Count of rules that don't have definitions or aren't auto generated
$ReturnHash = '$hash = [ordered]@{' + "`r`n"  # Create the return hash of check values

## General setup, declare variables, etc

$PsHeader = @(
    "##"
    "# " + $stig.Benchmark.title
    "# Version: " + $stig.Benchmark.version + ", " + $stig.Benchmark.'plain-text'.'#text'[0]
    "#"
    "# PowerShell script and accompanying JSON file for Intune Custom Compliance"
    "# were generated with: https://github.com/nittajef/Intune/"
    "# Files created: " + (Get-Date).ToString()
    "##`r`n`r`n"
)

$PsOutput += $PsHeader

# Look at internal xccdf title to determine target Windows version (10/11)
switch -regex ($stig.Benchmark.title) {
    ".+Windows 10.+" {
        $W10 = $true
    }
    ".+Windows 11.+" {
        $W11 = $true
    }
}

function Format-Text ($input_txt) {
    # Replace non-Latin characters that Intune doesn't like
    $input_txt = $input_txt -replace ('“|”', '"')
    $input_txt = $input_txt -replace ('…', '...')
    $input_txt = $input_txt -replace ('™', '')
    $input_txt = $input_txt -replace ('–', '-')

    foreach ($sub_txt in $input_txt) {
        if ($sub_txt -eq "`n") {
            # Add the blank lines back in for spacing
            $formatted_text += "#`r`n"
        } else {
            $sub_txt = [regex]::Matches($sub_txt,'(?<=\s|^)(.{1,110})(?=\s|$)')
            foreach ($snip in $sub_txt) {
                $formatted_text += "# " + $snip.Groups[1].Value + "`r`n"
            }
        }
        $formatted_text += "#`r`n"
    }

    # Remove last extra blank line
    $formatted_text = $formatted_text.TrimEnd("`r`n")

    $formatted_text
}


# Add any shared info needed by multiple rules
foreach ($list in $OrgSettings.accounts.Keys) {
    if ($OrgSettings.accounts[$list].Length -gt 0) {
        $AccountInfo += "$" + $list + " = @(`"" + ($OrgSettings.accounts[$list] -join '", "') + "`")`r`n"
    }
}

if ($OrgSettings.severity.CAT1) {
    $SharedInfo += $RuleChecks.CAT1
}
if ($OrgSettings.severity.CAT2) {
    $SharedInfo += $RuleChecks.CAT2
}
if ($OrgSettings.severity.CAT3) {
    $SharedInfo += $RuleChecks.CAT3
}
if ($SharedInfo) {
    $PsOutput += "#`r`n# Gather/set data used across multiple rule checks`r`n#`r`n"
    foreach ($data in $SharedInfo) {
        if ($W11 -and $data -eq "LTSB") {
            continue  # Don't load LTSB info since W11 doesn't have LTSB/LTSC versions, yet
        }
        $PsOutput += $RuleChecks.$data + "`r`n"
    }
    $PsOutput += "`r`n"
}
if ($AccountInfo) {
    $PsOutput += "#`r`n# List of accounts used across multiple rule checks`r`n#"
    $PsOutput += $AccountInfo
    $PsOutput += "`r`n"
}

## Main rules loop, step through each rule in the STIG and generate the PS and JSON content for the two output files

### Variables used only within the loop
$ruleId = ""         # shared  - The STIG rule ID
$ruleVarName = ""    # ps only - STIG rule ID without the dash, since PS doesn't like dashes in variable names
$settingName = ""    # shared  - CC JSON setting name (output hash from the PS discovery script must have matching entries)
$mapSettingName = "" # shared  - The W10 equivalent STIG rule ID to a W11 rule ID, only set if processing W11 STIG


foreach ($rule in $stig.Benchmark.Group.Rule) {

    # Only process rule if it's included in OrgSettings file
    if (($OrgSettings.severity.CAT1 -and $rule.severity -eq "high") -or
        ($OrgSettings.severity.CAT2 -and $rule.severity -eq "medium") -or
        ($OrgSettings.severity.CAT3 -and $rule.severity -eq "low")) {
    } else {
        continue
    }

    $ruleId = $rule.id.Substring(1,8)    # Pull out Rule ID like "V-220706"
    $ruleVarName = $ruleId -replace "-"  # Remove the dash
    $settingName = $ruleId               # Start value of CC JSON setting name to Rule ID

    # If processing a W11 STIG, look at W10-W11 rule map and find matching W10 rule, if it exists
    if ($W11) {
        $mapSettingName = $map.GetEnumerator() | Where-Object { $_.'W11-V1-R4' -eq $ruleName } | Select-Object -ExpandProperty 'W10-V2-R7'
    } else {
        $mapSettingName = ""
    }

    # Check if the rule has a special status, and append suffix, or skip if appropriate
    if ($OrgSettings.nocode -contains $ruleId -or $OrgSettings.nocode -contains $mapSettingName) {
        if ($OrgSettings.output.JSONNoCheckRules -eq "exclude") {
            continue
        } else {
            $settingName = $settingName + "-NoChk"
        }
    } elseif ($OrgSettings.exemptions -contains $ruleId -or $OrgSettings.exemptions -contains $mapSettingName) {
        $settingName = $settingName + "-EXM"
    } elseif ($OrgSettings.overrides.ContainsKey($ruleId) -or $OrgSettings.overrides.ContainsKey($mapSettingName)) {
        $settingName = $settingName + "-OvR"
    }

    # If short names options is enabled, lookup rule short name from map file and append to JSON setting name/matching PS hash key
    if ($OrgSettings.output.JSONShortName) {
        if ($W11) {
            # fill this out
        } else {
            $short_name = $map.GetEnumerator() | Where-Object { $_.'W10-V2-R7' -eq $ruleId } | Select-Object -ExpandProperty 'short_name'
            $settingName = $settingName + " - " + $short_name
        }
    }

    ##
    # JSON generation
    ##

    # Fill out reference section of entry, which is not used by Intune CC
    $cciId = @()
    $legacyId = @() 
    $reference = [ordered]@{}
    $reference.Add('Severity', $rule.severity)
    $reference.Add('Rule_ID', $rule.id)
    $reference.Add('STIG_ID', $rule.version)

    foreach ($ident in $rule.ident) {
        if ($ident.system -eq 'http://cyber.mil/cci') {
            $cciId += $ident.'#text'
        } elseif ($ident.system -eq 'http://cyber.mil/legacy') {
            $legacyId += $ident.'#text'
        }
    }
    if ($cciId.Count -gt 0) { $reference.Add('CCI', $cciId -join ',') }
    if ($legacyId.Count -gt 0) { $reference.Add('Legacy_IDs', $legacyId -join ',') }

    # Fill out "Description" field of CC JSON "RemediationStrings", this info shows up on the client system
    $description = switch ($OrgSettings.output.JSONStyle) {
                       "description" { [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value }
                       "fix"    { $rule.fixtext.'#text' }
                       "debug"   { "Rule check return value: {ActualValue}" } # Need to adjust PS check returns to make this useful
                   }

    # Create JSON text for current rule
    $setting = [ordered]@{
                    SettingName = $settingName
                    Operator = "IsEquals"
                    DataType = "Boolean"
                    Operand = $true
                    MoreInfoUrl = $OrgSettings.output.JSONInfoURL
                    RemediationStrings = @(([ordered]@{
                        Language = "en_US"
                        Title = $ruleId + " - " + $rule.title
                        Description = $description
                    }))
               }

    # Only include the (non-functional) reference text if wanted
    if ($OrgSettings.output.JSONReference -eq "include") {
        $setting.Add("Reference", $reference)
    }

    # Add rule/setting to JSON output
    $JsonOutput += $setting


    ##
    # PowerShell discovery generation
    ##


}

$ReturnHash += "}`r`n`r`n"
$ReturnHash += 'return $hash | ConvertTo-Json -Compress'
$PsOutput += $ReturnHash

## Output PS and JSON files
@{"Rules" = $JsonOutput} | ConvertTo-Json -Depth 4 | Out-File $OrgSettings.output.JSON
$PsOutput | Out-File -FilePath $OrgSettings.output.PS
Write-Host("There are $EmptyRules unfinished rule checks")







# Iterate through all rules in the STIG document
foreach ($rule in $stig.Benchmark.Group.Rule) {

    $ruleId = $rule.id.Substring(1,8)
    $ruleIdSuffix = ""
    $ruleVarName = $ruleId -replace "-"
    $mapRuleId = ""


    #
    # Create rule comments (title, description, check, fix, ids)
    #
    # Split description/check/fix fields by blank lines to preserve spacing
    $formatted_title = Format-Text($rule.title)
    # Match text in VulnDiscussion section, but remove the VulnDiscussion tags
    $desc_txt = [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value
    $formatted_description = Format-Text($desc_txt -split "(?:\r?\n){2,}")
    $formatted_check = Format-Text($rule.check.'check-content' -split "(?:\r?\n){2,}")
    $formatted_fix = Format-Text($rule.fixtext.'#text' -split "(?:\r?\n){2,}")
    # Convert severity to CAT I/II/III
    $severity = switch ($rule.severity) {
                    "low" {"CAT III"}
                    "medium" {"CAT II"}
                    "high" {"CAT I"}
                }

    # If there are registry tests in rule, generate checks
    # $registryChecks holds a collection of individual registry checks, some rules have multiple
    $registryChecks = [System.Collections.ArrayList]@()
    $registryCheck = @()
    foreach ($line in $rule.check.'check-content'.Split("`n")) {
        if ($line.Contains("Registry Hive")) {
            $hive = switch -regex ($line) {
                'Registry Hive:\s+HKEY_LOCAL_MACHINE' { "HKLM:" }
                'Registry Hive:\s+HKEY_CURRENT_USER' { "HKCU:" }
                default { $null }
            }
        } elseif ($line.Contains("Registry Path:")) {
            $regPath = $line -replace 'Registry Path:\s+', "".Trim()
        } elseif ($line.Contains("Value Name:")) {
            $regName = $line -replace 'Value Name:\s+', "".Trim()
        } elseif ($line.Contains("Value:")) {
            # Match these: Value: 0x00000001 (1) (Enabled with UEFI lock)
            #              Value: 1
            if ($line.TrimEnd() -match '0x.{8}\s+\((\d+)\)') {
                $regValue = $Matches[1]
            } elseif ($line.TrimEnd() -match "(?m)Value:\s+(\d+)$") {
                $regValue = $Matches[1]
            }
            $registryCheck = $hive, $regPath, $regName, $regValue
            $registryChecks.Add($registryCheck) | Out-Null
        }
    }

    # Create check rule logic template
    $override = @{}
    $check_template = ""
    
    #
    # Create PowerShell logic check for the rule, looking in this order
    # 1. Rule in "exemptions" list
    # 2. Rule in "nocheck" list
    # 3. Rule in "overrides" list
    # 4. Rule in "checks" PSDataFile
    # 5. Rule has generated registry checks
    # 6. Empty rule template created
    #
    if ($OrgSettings.exemptions -contains $ruleId -or $OrgSettings.exemptions -contains $mapRuleId) {
        $ruleIdSuffix = "-EXM"
        $check_template = @(
            "$" + $ruleVarName + ' = $true'
        ) -join "`r`n"
    } elseif ($OrgSettings.nocode -contains $ruleId -or $OrgSettings.nocode -contains $mapRuleId) {
        $ruleIdSuffix = "-NoChk"
        $check_template = @(
            "$" + $ruleVarName + ' = $true'
        ) -join "`r`n"
    } elseif ($OrgSettings.overrides.ContainsKey($ruleId) -or $OrgSettings.overrides.ContainsKey($mapRuleId)) {
        if ($mapRuleId) {
            $override = $OrgSettings.overrides.$mapRuleId
        } else {
            $override = $OrgSettings.overrides.$ruleId
        }
        foreach ($setting in $override.Keys) {
            if ($override.$setting -is [array]) {
                $value = "@("
                foreach ($val in $override.$setting) {
                    $value += "`"$val`","
                }
                $value = $value.TrimEnd(",")
                $value += ")"
            } elseif ($override.$setting -is [int]) {
                $value = $override.$setting
            } else {
                $value = '"' + $override.$setting + '"'
            }
            $check_template += "`$${setting} = $value`r`n"
        }
        $check_template += $RuleChecks.$ruleId
        $ruleIdSuffix = "-OvR"
    } elseif ($RuleChecks.$ruleId -or $RuleChecks.$mapRuleId) {
        if ($mapRuleId -and $mapRuleId -ne "-") {
            $check_template = $RuleChecks.$mapRuleId -replace $mapRuleId.Substring(2,6), $ruleId.Substring(2,6)
        } else {
            $check_template = $RuleChecks.$ruleId
        }
    } elseif ($registryChecks) {
        # Template for the PowerShell registry check for the rule
        $psRegChecks = "    if ("
        foreach ($check in $registryChecks) {
            $psRegChecks += "(Get-ItemPropertyValue -Path `""+ $check[0] + $check[1] + "`" -Name " + $check[2] + " -ErrorAction Stop) -eq " + $check[3] + " -and`r`n        "
        }
        # Replace last entries "-and" and close the "if" conditional
        $psRegChecks = $psRegChecks.TrimEnd(" -and`r`n")
        $psRegChecks += ") {"

        $check_template = @(
            "try {"
                $psRegChecks
            "        $" + $ruleVarName + ' = $true'
            "    } else {"
            "        $" + $ruleVarName + ' = $false'
            "    }"
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n"
        ) -join "`r`n"
    } else {
        $check_template = @(
            "try {"
            "    "
            "    $" + $ruleVarName + ' = $true'
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n`r`n"
        ) -join "`r`n"
        $EmptyRules++
        $ruleId
    }

    # Output full check/logic test text for each rule
    $check = "##`r`n"
    $check += "# " + $ruleId + "`r`n"
    $check += $formatted_title + "`r`n"
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# DISCUSSION: `r`n"
        $check += $formatted_description + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# CHECK: `r`n"
        $check += $formatted_check + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# FIX: `r`n"
        $check += $formatted_fix + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -ne 'zen') {
        $check += "##`r`n"
        $check += "# SEVERITY: " + $severity + "`r`n"
        $check += "# RULE ID: " + $rule.id + "`r`n"
        $check += "# STIG ID: " + $rule.version + "`r`n"
        $check += "# REFERENCE: `r`n"
    }
    $check += "##`r`n"
    $check += $check_template + "`r`n"

    $PsOutput += $check

    if ($OrgSettings.output.JSONShortName) {
        if ($W11) {
            
        } else { 
            $short_name = $map.GetEnumerator() | Where-Object { $_.'W10-V2-R7' -eq $ruleId } | Select-Object -ExpandProperty 'short_name'
            $ret_hash += "    '" + $ruleId + $ruleIdSuffix + " - " + $short_name + "' = $" + $ruleVarName + "`r`n"
        }
    } else {
        $ret_hash += "    '" + $ruleId + $ruleIdSuffix + "' = $" + $ruleVarName + "`r`n"
    }
}

