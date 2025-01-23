#!/usr/bin/env pwsh

# Exit on error
$ErrorActionPreference = "Stop"

# Debug?
if ($env:ZSCAN_DEBUG) {
    $DebugPreference = "Continue"
    Write-Output "Debug mode enabled."
    Write-Output Get-Location
    Write-Output Get-ChildItem -Force
}

# Define mandatory parameters
[string]$server_url = ($env:ZSCAN_SERVER_URL) ? $env:ZSCAN_SERVER_URL : "https://zc202.zimperium.com"
[string]$client_id = $env:ZSCAN_CLIENT_ID
[string]$secret = $env:ZSCAN_CLIENT_SECRET
[string]$team_name = ($env:ZSCAN_TEAM_NAME) ? $env:ZSCAN_TEAM_NAME : "Default"
[string]$input_file = ($env:ZSCAN_INPUT_FILE) ? $env:ZSCAN_INPUT_FILE : $args[0]
[string]$report_format = ($env:ZSCAN_REPORT_FORMAT) ? $env:ZSCAN_REPORT_FORMAT : "sarif"

# Optional parameters
[string]$report_location = ($env:ZSCAN_REPORT_LOCATION) ? $env:ZSCAN_REPORT_LOCATION : "."
[string]$report_file_name = $env:ZSCAN_REPORT_FILE_NAME
[bool]$wait_for_report = ($env:ZSCAN_WAIT_FOR_REPORT) ? $env:ZSCAN_WAIT_FOR_REPORT : $true
[int]$wait_interval = ($env:ZSCAN_POLLING_INTERVAL) ? $env:ZSCAN_POLLING_INTERVAL : 30
[string]$branch_name = $env:ZSCAN_BRANCH
[string]$build_number = $env:ZSCAN_BUILD_NUMBER
[string]$environment = $env:ZSCAN_ENVIRONMENT

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
    Write-Error "Error: Please provide the path to the APK/IPA file in the plugin settings or as a command-line argument."
    exit 1
}

# Input file must exist
if (-not (Test-Path -Path $input_file)) {
    Write-Error "Error: File $input_file does not exist."
    exit 1
}

# Credentials must be specified
if (-not $client_id -or -not $secret) {
    Write-Error "Error: Please provide client id and secret via environment variables. Refer to the documentation for details."
    exit 1
}

# Output format must be one of [json, sarif]
if ($report_format -ne "json" -and $report_format -ne "sarif") {
    Write-Error "Error: Output format must be one of [json, sarif]."
    exit 1
}

# Minimum wait time is 30 seconds; we don't want to DDOS our own servers
if ($wait_interval -lt 30) {
    $wait_interval = 30
}

# Remove trailing spaces and slashes
$server_url = $server_url.TrimEnd(' ')
$server_url = $server_url.TrimEnd('/')

Write-Output "Using zConsole at $server_url"

# Execute the curl command with the server URL
$response = Invoke-RestMethod -Uri "$server_url$login_url" -Method Post -ContentType "application/json" -Body (@{ clientId = $client_id; secret = $secret } | ConvertTo-Json)
$secret = $null

# Check if the curl command was successful
if ($response) {
    $access_token = $response.accessToken

    # Check if access token is found
    if ($access_token) {
        if ($env:ZSCAN_DEBUG) {
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
        if ($env:ZSCAN_DEBUG) { Write-Output "uploadedBy: $uploadedBy" }
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
                Write-Error "Error: Failed to perform assign the application to the specified team. Although the scan will complete, the results will not be visible in the console UI. Set Debug to 1 to troubleshoot."
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
try {
    Invoke-RestMethod -Uri "$server_url$download_assessment_url/$AssessmentID/$report_format" -Authentication Bearer -Token $access_token -OutFile $full_report_file_name
} catch {
    Write-Error "Error downloading the report."
    exit 1
}

# Print confirmation message
Write-Output "Response saved to: $full_report_file_name"
$env:ZSCAN_REPORT_FILE = $full_report_file_name

if ($env:ZSCAN_DEBUG) {
    Get-ChildItem -Force
}