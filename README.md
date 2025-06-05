# zscan-plugin-ado

## zScan Integration Script for Azure DevOps

This script can be used to upload mobile applications to Zimperium (zScan) to be scanned for vulnerabilities. Using this script simplifies integrating mobile application security testing into CI/CD process and enables detection and remediation of vulnerabilities earlier in the application SDLC.

For more information on zScan, please see [Continuous Mobile Application Security Scanning](https://www.zimperium.com/zscan/).

## Prerequisites

1. [Powershell v2 Task](https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/powershell-v2?view=azure-pipelines)
2. Zimperium [MAPS](https://www.zimperium.com/mobile-app-protection/) license that includes zScan functionality.
3. A valid application binary (.ipa, .apk, etc.), either built by the current pipeline or otherwise accessible by the script.
4. API credentials with permissions to upload binaries. In your console, head over to the Authorizations tab in the Account Management section and generate a new API key. At a minimum, the following permissions are required:

- Common Section: Teams - Manage
- zScan Section: zScan Apps - Manage, zScan Assessments - View, zScan Builds - Upload

The script has been verified to run on [Linux/Ubuntu](https://aka.ms/ubuntu-22.04-readme)-, [MacOS](https://aka.ms/macOS-14-readme)-, and [Windows](https://aka.ms/windows-2022-readme)-based Microsoft-hosted agents.  Other agents may also work; a working Powershell or Powershell Core installation is required.

## Parameters

We recommend using Azure DevOps [variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables) to provide parameters to the script, especially sensitive ones like **client_id** and **secret**.  if you decide to use [Secret Variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables), please note that they need to be explicitly bound to the environment available to the script via the `env:` section - see the sample pipeline snippet below.

### Mandatory

These parameters are mandatory, _unless_ a default value is available as described below.

- **server_url**: console base URL, e.g., `https://ziap.zimperium.com/`.
- **client_id** and **secret**: API credentials that can be obtained from the console (see the [Prerequisites](#prerequisites) section above).
- **input_file**: the path to the binary or binaries relative to the current workspace. Wildcards are supported, but the script will accept at most 5 files to avoid accidentally uploading too many files. If the pattern matches more than 5 files, you will need to narrow it down. **Note**: Depending on the environment, the script may not be able to access files outside of the current directory or its subdirectories.
- **team_name**: name of the team to which this application belongs.  This is required only if submitting the application for the first time; values are ignored if the application already exists in the console and assigned to a team.  If not supplied, the application will be assigned to the 'Default' team
- **report_format**: the format of the scan report, either 'json' or 'sarif' (default).  For more information on the SARIF format, please see [OASIS Open](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

### Optional

These parameters are optional, but may be used to supply additional information about the build and/or control the plugin's output.

- **report_location**: destination folder for the vulnerability report. If not provided, the report is stored in the current workspace. Report location and name are important for [Pipeline Artifact](https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/publish-pipeline-artifact-v1) collection.
- **report_file_name**: filename of the report. If not provided, the filename will be patterned as follows: zscan-results-AssessmentID.report_format, e.g., _zscan-results-123456789.sarif_. If multiple files match the provided pattern, filename of the uploaded file will be appended to the _report_file_name_ to avoid overwriting reports; the extension will be preserved.
- **wait_for_report**: if set to "true" (default), the script will wait for the assessment report to be complete. Otherwise, the script will exit after uploading the binary to zScan.  The assessment report can be obtained through the console. Report filename and location parameters are ignored. No artifact will be produced.
- **polling_interval**: wait time for polling the server in seconds. 30 seconds is the default and the minimum acceptable value.
- **branch_name**: source code branch that the build is based on.
- **build_number**: application build number.
- **environment**: target environment, e.g., uat, dev, prod.

**Note:** The script supports enhanced diagnostic output if the `-Debug` parameter is supplied. You can use this output to troubleshoot problems with the script. Be advised that **debug output may include sensitive information**, such as authorization tokens. Use at your own risk.

## Usage

The script is meant to be executed by the Azure DevOps [PowerShell v2 Task](https://learn.microsoft.com/en-us/azure/devops/pipelines/tasks/reference/powershell-v2).  However, it can be used in any environment with PowerShell installed, e.g., from a command-line prompt or another CI/CD environment.

The script can be downloaded from our public repository just before the execution or made available on the agent through other means.  Please refer to Microsoft documentation for more information on configuring [self-hosted agents](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents#self-hosted-agents).

Here's a _sample_ zScan pipeline snippet that downloads the script and uploads an (already-built) Android application to zScan:

```yaml
- task: PowerShell@2
  inputs:
    targetType: 'inline'
    script:  |
      # Define the URL of the PowerShell script
      $scriptUrl = "https://github.com/Zimperium/zscan-plugin-ado/releases/download/v1.1.0/zScan.ps1"

      # Define the local path where the script will be saved
      $scriptPath = "$(Build.SourcesDirectory)\zScan.ps1"

      # Download the script
      Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath

      # Execute the script
      & $scriptPath -server_url 'https://ziap.zimperium.com' -input_file '$(Build.SourcesDirectory)/app/build/outputs/apk/debug/*.apk' -client_id ${env:ZSCAN_CLIENT_ID} -secret ${env:ZSCAN_CLIENT_SECRET} -branch_name $(Build.SourceBranchName) -build_number $(Build.BuildNumber)

      Write-Output "Report: ${env:ZSCAN_REPORT_FILE}"
  env:
    ZSCAN_CLIENT_SECRET: $(ZSCAN_CLIENT_SECRET)
```

The above example assumes that the clint id and client secret variables are correctly configured (the latter using a secret variable), and the input file filename is correct.
You can adjust the script URL to point to the tag/release of your choice.

## License

This script is licensed under the MIT License. By using this plugin, you agree to the following terms:

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Enhancements

Submitting improvements to the plugin is welcomed and all pull requests will be approved by Zimperium after review.
