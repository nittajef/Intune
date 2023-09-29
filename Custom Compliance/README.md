# Intune Custom Compliance (WIP)

Custom Compliance PowerShell & JSON files for Windows STIGs are located in the STIGs subfolders.

The Tools folder contains PowerShell scripts to help generate Intune compatible files for Custom Compliance via the STIG xccdf files.

<h4>All generated policy files are a work in progress and are not guaranteed to definitively confirm that a system is compliant with a particular STIG.</h4> That being said, the checks for CAT I and CAT III are complete. Improvements/bug reports for any of the checks are welcome. There are 2 uncompleted CAT II checks, V-220709, and V-220724.

<h1>Generator files</h1>

<h4>Convert-xccdf.ps1</h4> The main script, which will ingest the STIG file and generate matching PS and JSON files.

<h4>Org-Settings.psd1</h4> Needed to specify some file paths as well as other configuration options such as which CAT severity rules to output, as well as to specify rules that should be exempted or overrriden. For instance, you may not actually work with the DOD and not need the DOD Certificate Roots to be installed on your clients. If so, add the rules V-220903-V220906 to the "exemptions" array (one per line) in the Org-Settings file and they will be skipped.

<h4>Checks.psd1</h4> Where all of the custom PowerShell code to do the checks is stored. Most simple registry based checks are generated automatically, but any others need to be completed and stored in the Checks.psd1 file manually.

<h1>Output files</h1>

<h2>Pre-generated policy files</h2>
Policy files as close to the STIG standard for Windows 10 can be found here: https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs/Windows%2010
<br>
They are generated with the settings set in the Org-Settings-W10.psd1 file in the same directory. Rule sets are separated by CAT severity, and the CAT II severity is broken up further because there is a limit of 100 rules per Custom Compliance Policy. 


<h2>Policy file components</h2>
<h3>PowerShell discovery script</h3>
https://learn.microsoft.com/en-us/mem/intune/protect/compliance-custom-script
<br><br>
This will be uploaded in the "Scripts" section under "Compliance policies":
<br>
<img width="201" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/e58879e3-713f-4750-aaf5-0a305aa9162f">
<br>
It contains all of the logic checks to determine if the machine meets each STIG rule. Because Custom Compliance doesn't allow for flexible matching in the JSON file, all multi-part or ranged results are evaluated within the discovery script and return a boolean true/false for whether the rule is met or not.

If you are trying to upload a discovery script and nothing seems to happen when you click the "Review + Save" button, it may because of non-Latin characters in the text. You can verify by viewing the browser's console for errors on the page.


<h3>JSON file</h3>
https://learn.microsoft.com/en-us/mem/intune/protect/compliance-custom-json
<br><br>
This file is uploaded in the Compliance policy (after uploading your script):
<br>
<img width="325" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/5619850c-ec35-460d-9012-ad8c8cbabb3a">
<br>
The JSON is created using only boolean checks for now, for consistency, since each Intune policy setting can only compare one return value per rule. There is a loss in being able to see the raw values returned to Intune this way, and maybe STIG rules will be broken in to multiple sub-settings in the future (V-252903A, V-252903B, etc).
<br><br>
Here are some limits I've come across that are of interest and may or may not be documented:

- Script size of 1MB (documented)
- Rule limit of 100 (undocumented?)
- Script character limit of 102400 (undocumented?)


<h2>Intune Policy</h2>
Once the two policies files are generated, you can create a new Custom Compliance policy and see results similar to the screenshots below.

If you'd like to just see how your clients stack up against the STIG rules, you can change the delay to mark devices as non-compliant to 365 (which is the max) so that you can still see which tests pass/fail, without affecting the devices compliance status.
<br>
<img width="231" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/314d250f-308a-4bea-b48b-252308e8d0ff">
<br>

Device policy view:

<img width="491" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/45710655-5432-4b58-b182-86fbb637e104">

Per setting view from the policy configuration:

<img width="489" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/423a7153-5b04-421c-9a1e-f50df7aee02e">


<h2>Change Log</h2>

2023-09-28

- Added rule mapping for Windows 10 to Windows 11 ID names
- First pass at generating rules for Windows 11, CAT I and CAT III are posted

2023-09-26

- Fixed CAT III checks V-220977, V-220973, V-220965, V-220956, and CAT I check V-220958, which were checking for empty set of privilege assignment by empty string "", but needed to check against $null value.
- Fixed CAT II check V-220749, wrong value was being set when registry key didn't exist
- Modified unfinished CAT II checks V-220709 and V-220724 to return $true for now so they don't return $null and error out the PS script in Intune

2023-09-25

- Added flag to exclude "Reference" data in output JSON (to reduce file size with current 100KB limit)
- Completed CAT II checks: 
  - V-220903 - Override added to verify other/non-DOD roots
  - V-220904
  - V-220905
  - V-220906
  - V-220717 (extra verification welcome)
  - V-220723 - searches only local drives with drive letters (extra verification welcome)
  - V-220957
- Fixed CAT I checks:
  - V-220958 - check was switched from CAT II check V-220957
