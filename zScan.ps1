param(
    [string]$server_url = "https://zc202.zimperium.com",
    [string]$client_id = $env:ZSCAN_CLIENT_ID,
    [string]$secret = $env:ZSCAN_CLIENT_SECRET,
    [string]$team_name = "Default",
    [Parameter(Mandatory)][string]$input_file,
    [string]$report_format = "sarif",
    [string]$report_location = '.',
    [string]$report_file_name,
    [bool]$wait_for_report = $true,
    [int]$wait_interval = 30,
    [string]$branch_name,
    [string]$build_number,
    [string]$environment
)

# Exit on error
$ErrorActionPreference = "Stop"

# Debug?
Write-Debug "Debug mode enabled."
Write-Debug (Get-Location).Path
if ($PSDebugContext -and $PSDebugContext.DebugMode -eq 1) { Write-Output (Get-ChildItem) }

# internal constants
[string]$login_url = "/api/auth/v1/api_keys/login"
[string]$upload_url = "/api/zdev-upload/public/v1/uploads/build"
[string]$status_url = "/api/zdev-app/public/v1/assessments/status?buildId="
[string]$teams_url = "/api/auth/public/v1/teams"
[string]$complete_upload_url = "/api/zdev-app/public/v1/apps"
[string]$download_assessment_url = "/api/zdev-app/public/v1/assessments"

[string]$AssessmentID = ""
[string]$ScanStatus = "Submitted"
[string]$ciToolId = "ADO"
[string]$ciToolName = "Azure DevOps"

# Input Validation
# Input file must be specified
if (-not $input_file) {
    Write-Error "Error: Please provide the path to the APK/IPA file as a command-line argument."
    exit 1
}

# Input file must exist
if (-not (Test-Path -Path $input_file)) {
    Write-Error "Error: File $input_file does not exist."
    exit 1
}

# Credentials must be specified
if (-not $client_id -or -not $secret) {
    Write-Error "Error: Please provide client id and secret via environment variables or as command-line parameters. Refer to the documentation for details."
    exit 1
}

# Output format must be one of [json, sarif]
if ($report_format -ne "json" -and $report_format -ne "sarif") {
    Write-Error "Error: Output format must be one of [json, sarif]."
    exit 1
}

# Minimum wait time is 30 seconds; we don't want to DDOS our own servers
if ($wait_interval -lt 30) {
    Write-Output "Warning: Wait interval is less than 30 seconds. Setting it to 30 seconds."
    $wait_interval = 30
}

# Remove trailing spaces and slashes
$server_url = $server_url.TrimEnd(' ', '/')
Write-Output "Using zConsole at $server_url"

# Execute the curl command with the server URL
$response = Invoke-RestMethod -Uri "$server_url$login_url" -Method Post -ContentType "application/json" -Body (@{ clientId = $client_id; secret = $secret } | ConvertTo-Json)
$secret = $null

# Check if the curl command was successful
if ($response) {
    $access_token = $response.accessToken

    # Check if access token is found
    if ($access_token) {
        if ($PSDebugContext -and $PSDebugContext.DebugMode -eq 1) {
            Write-Output "Extracted access token: $access_token"
        } else {
            Write-Output "Extracted access token: $($access_token.Substring(0, 10))..."
        }

        # convert to secure string as required by Invoke-RestMethod
        $access_token = ConvertTo-SecureString $access_token -AsPlainText -Force
    } else {
        Write-Error "Error: access token not found in response."
        exit 3
    }
} else {
    Write-Error "Error: unable to obtain access token."
    exit 3
}

$response = Invoke-RestMethod -Uri "$server_url$upload_url" -Method Post -Authentication Bearer -Token $access_token -ContentType "multipart/form-data" -Form @{ buildFile = Get-Item $input_file; buildNumber = $build_number; environment = $environment; branchName = $branch_name; ciToolId = $ciToolId; ciToolName = $ciToolName }

# Check for successful response
if ($response) {
    # Extract buildId and buildUploadedAt
    $zdevAppId = $response.zdevAppId
    $buildId = $response.buildId
    $buildUploadedAt = $response.buildUploadedAt
    $appBuildVersion = $response.zdevUploadResponse.appBuildVersion
    $uploadedBy = $response.uploadMetadata.uploadedBy
    $bundleIdentifier = $response.zdevUploadResponse.bundleIdentifier
    $appVersion = $response.zdevUploadResponse.appVersion

    # Check if variables were extracted successfully
    if (-not $buildId -or -not $buildUploadedAt -or -not $appBuildVersion -or -not $bundleIdentifier -or -not $appVersion) {
        Write-Error "Error: Failed to extract application attributes from response."
    } else {
        Write-Output "Successfully uploaded binary: $input_file"
        Write-Output "buildId: $buildId"
        Write-Output "buildUploadedAt: $buildUploadedAt"
        Write-Output "buildNumber (appBuildVersion): $appBuildVersion"
        Write-Debug "uploadedBy: $uploadedBy" # This prints Client_ID, which we don't want to expose unless debugging
        Write-Output "bundleIdentifier: $bundleIdentifier"
        Write-Output "appVersion: $appVersion"
    }
} else {
    Write-Error "Error: Failed to upload APK file."
    exit 1
}

# Assign to a team if this is a new application - teamId is null
$teamId = $response.teamId
if ($null -eq $teamId) {
    Write-Output "Assigning the application to team $team_name."

    # Fetch the list of teams using the access token
    $teams_response = Invoke-RestMethod -Uri "$server_url$teams_url" -Method Get -Authentication Bearer -Token $access_token

    if ($teams_response) {
        $teamId = $teams_response.content | Where-Object { $_.name -eq $team_name } | Select-Object -ExpandProperty id

        if (-not $teamId) {
            Write-Error "Error: Failed to extract teamId for the team named '$team_name'. Please ensure you have granted the Authorization token the 'view teams' permission under the 'Common' category, within the console's Authorization settings."
            exit 1
        } else {
            Write-Output "Successfully extracted teamId: '$teamId' for Team named: '$team_name'."

            # Perform the second API call to complete the upload
            $second_response = Invoke-RestMethod -Uri "$server_url$complete_upload_url/$zdevAppId/upload" -Method Put -Authentication Bearer -Token $access_token -ContentType "application/json" -Body (@{ teamId = $teamId; buildNumber = $appBuildVersion } | ConvertTo-Json)

            if (-not $second_response) {
                Write-Error "Error: Failed to perform assign the application to the specified team. Although the scan will complete, the results will not be visible in the console UI. Use -Debug to troubleshoot."
            }
        }
    } else {
        Write-Error "Error: Failed to extract the list of teams from your console. Although the scan will complete, the results will not be visible in the console UI. Please ensure you have granted the Authorization token the 'view teams' permission under the 'Common' category, within the console's Authorization settings."
    }
}

# If no need to wait for report, we're done
if (-not $wait_for_report) {
    Write-Output "ZSCAN_WAIT_FOR_REPORT is not set. We're done!"
    exit 0
}

# Wait for the upload to complete processing
Start-Sleep -Seconds 10

# Check the Status in a loop - wait for Interval
while ($true) {
    # Check the Status
    $response = Invoke-RestMethod -Uri "$server_url$status_url$buildId" -Method Get -Authentication Bearer -Token $access_token -ContentType "application/json"

    if ($response) {
        $ScanStatus = $response.zdevMetadata.analysis

        if ($ScanStatus -eq "Done") {
            $AssessmentID = $response.id
            Write-Output "Scan $AssessmentID is Done."
            break
        } else {
            Write-Output "Scan is not completed. Status: $ScanStatus."
        }
    } else {
        Write-Error "Error Checking the Status of Scan."
    }
    # Sleep for the interval
    Start-Sleep -Seconds $wait_interval
}

# Retrieve the report
# Figure out report's fully qualified file name
[string]$full_report_file_name = ""
if (-not $report_file_name) {
    $full_report_file_name = Join-Path $report_location "zscan-results-$AssessmentID-$report_format.json"
} else {
    $full_report_file_name = Join-Path $report_location $report_file_name
}

# Download the report
Invoke-RestMethod -Uri "$server_url$download_assessment_url/$AssessmentID/$report_format" -Authentication Bearer -Token $access_token -OutFile $full_report_file_name

# Print confirmation message
Write-Output "Response saved to: $full_report_file_name"
$env:ZSCAN_REPORT_FILE = $full_report_file_name

Write-Debug (Get-ChildItem)