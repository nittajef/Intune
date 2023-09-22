# Intune Custom Compliance

Custom Compliance PowerShell & JSON files for Windows STIGs are located in the subfolders.

The Tools folder contains PowerShell scripts to help generate Intune compatible files for Custom Compliance via the STIG xccdf filess.

<h1>Generator files</h1>

<h4>Convert-xccdf.ps1</h4> The main script, which will ingest the STIG file and generate matching PS and JSON files.

<h4>Org-Settings.psd1</h4> Needed to specify some file paths as well as other configuration options such as which CAT severity rules to output, as well as to specify rules that should be skipped or overrriden.

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
