param(
    [string]$server_url = "https://zc202.zimperium.com", # zConsole URL
    [string]$client_id = $env:ZSCAN_CLIENT_ID, # Client ID from zConsole - Authorizations Tab
    [string]$secret = $env:ZSCAN_CLIENT_SECRET, # Secret from zConsole - Authorizations Tab
    [string]$team_name = "Default", # Team name to assign the application to
    [Parameter(Mandatory)][string]$input_file, # Path to the APK/IPA file
    [string]$report_format = "sarif", # Output format [json, sarif]
    [string]$report_location = '.', # Location (folder) to save the report
    [string]$report_file_name, # File name to save the report
    [bool]$wait_for_report = $true, # Wait for and download the report; exit after upload if false
    [int]$polling_interval = 30, # Interval to wait for report (in seconds)
    [string]$branch_name, # Branch name (optional)
    [string]$build_number, # Build number (optional)
    [string]$environment # Environment (optional)
)

# Exit on error
$ErrorActionPreference = "Stop"

# Debug?
Write-Debug "Debug mode enabled."
Write-Debug $PWD

# internal constants
[string]$login_url = "/api/auth/v1/api_keys/login"
[string]$refresh_token_url = "/api/auth/v1/api_keys/access"
[string]$upload_url = "/api/zdev-upload/public/v1/uploads/build"
[string]$status_url = "/api/zdev-app/public/v1/assessments/status?buildId="
[string]$teams_url = "/api/auth/public/v1/teams"
[string]$complete_upload_url = "/api/zdev-app/public/v1/apps"
[string]$download_assessment_url = "/api/zdev-app/public/v1/assessments"

[int]$processing_delay = 15 # seconds; periodic delays to allow the server to process the previous request
[int]$http_retry_count = 3 # number of times to retry HTTP requests]
[int]$max_files = 5 # Maximum number of files to process if wildcard matches multiple
[string]$ciToolId = "ADO"
[string]$ciToolName = "Azure DevOps"

# internal variables
[string]$AssessmentID = ""
[string]$ScanStatus = "Submitted"

# Input Validation
# Input file must be specified
if (-not $input_file) {
    Write-Error "Please provide the path to the APK/IPA file(s) as a command-line argument."
    exit 1
}

# Credentials must be specified
if (-not $client_id -or -not $secret) {
    Write-Error "Please provide client id and secret via environment variables or as command-line parameters. Refer to the documentation for details."
    exit 1
}

# Output format must be one of [json, sarif]
if ($report_format -ne "json" -and $report_format -ne "sarif") {
    Write-Error "Output format must be one of [json, sarif]."
    exit 1
}

# Minimum wait time is 30 seconds; we don't want to DDOS our own servers
if ($polling_interval -lt 30) {
    Write-Information "Wait interval is less than 30 seconds. Setting it to 30 seconds."
    $polling_interval = 30
}

# Remove trailing spaces and slashes
$server_url = $server_url.TrimEnd(' ', '/')
Write-Output "Using zConsole at $server_url"

# Resolve input files using the pattern
Write-Debug "Attempting to resolve input file(s) from pattern: $input_file"
$resolved_files = Get-ChildItem -Path $input_file -File -ErrorAction SilentlyContinue
if (-not $resolved_files) {
    Write-Error "No files found matching input: $input_file"
    exit 1
}

# Check if the number of matched files exceeds max_files
if ($resolved_files.Count -gt $max_files) {
    Write-Error "Found $($resolved_files.Count) files matching '$input_file'. This exceeds the maximum of $max_files allowed. Please provide a more specific pattern and try again."
    exit 1
}

# If we're here, the number of files is acceptable (<= max_files)
$files_to_process = $resolved_files 

Write-Output "The following $($files_to_process.Count) file(s) will be processed:"
$files_to_process | ForEach-Object { Write-Output "- $($_.FullName)" }

# Login to obtain bearer token
$response = Invoke-RestMethod -Uri "$server_url$login_url" -Method Post `
    -MaximumRetryCount $http_retry_count `
    -ContentType "application/json" `
    -Body (@{ clientId = $client_id; secret = $secret } | ConvertTo-Json)
    
$secret = $null
Write-Debug "Login Response: $response"

# Check if the login was successful
if ($response) {
    $access_token = $response.accessToken
    $refresh_token = $response.refreshToken

    # Check if access token is found
    if ($access_token) {
        Write-Output "Successfully obtained access token."

        # convert to secure string as required by Invoke-RestMethod
        $access_token = ConvertTo-SecureString $access_token -AsPlainText -Force
    } else {
        Write-Error "Access token not found in response."
        exit 3
    }
} else {
    Write-Error "Unable to obtain access token."
    exit 3
}

$global_exit_code = 0
$all_report_files = [System.Collections.Generic.List[string]]::new()
$processed_file_count = 0

foreach ($current_file_info in $files_to_process) {
    $current_input_file = $current_file_info.FullName
    $processed_file_count++
    Write-Output "--- Processing file $processed_file_count of $($files_to_process.Count): $current_input_file ---"

    # Reset per-file state variables
    $AssessmentID = ""
    $ScanStatus = "Submitted"
    $zdevAppId = $null # Ensure it's reset for each file
    $buildId = $null   # Ensure it's reset for each file

    $upload_response = Invoke-RestMethod -Uri "$server_url$upload_url" -Method Post `
        -Authentication Bearer -Token $access_token `
        -StatusCodeVariable http_status_upload `
        -ContentType "multipart/form-data" -Form @{ buildFile = Get-Item -Path $current_input_file; buildNumber = $build_number; environment = $environment; branchName = $branch_name; ciToolId = $ciToolId; ciToolName = $ciToolName }
    
    Write-Debug "Upload Status for $current_input_file : $http_status_upload `n Response: $upload_response"

    # Check for successful response
    if ($upload_response) {
        # Extract buildId and buildUploadedAt
        $zdevAppId = $upload_response.zdevAppId
        $buildId = $upload_response.buildId
        $buildUploadedAt = $upload_response.buildUploadedAt
        $appBuildVersion = $upload_response.zdevUploadResponse.appBuildVersion
        $uploadedBy = $upload_response.uploadMetadata.uploadedBy
        $bundleIdentifier = $upload_response.zdevUploadResponse.bundleIdentifier
        $appVersion = $upload_response.zdevUploadResponse.appVersion

        # Check if variables were extracted successfully
        if (-not $buildId -or -not $buildUploadedAt -or -not $appBuildVersion -or -not $bundleIdentifier -or -not $appVersion) {
            Write-Error "Failed to extract application attributes from response for '${current_input_file}'. Skipping this file."
            $global_exit_code = 1
            continue
        } else {
            Write-Output "Successfully uploaded binary: $current_input_file"
            Write-Output "buildId: $buildId"
            Write-Output "buildUploadedAt: $buildUploadedAt"
            Write-Output "buildNumber (appBuildVersion): $appBuildVersion"
            Write-Debug "uploadedBy: $uploadedBy"
            Write-Output "bundleIdentifier: $bundleIdentifier"
            Write-Output "appVersion: $appVersion"
        }
    } else {
        Write-Error "Failed to upload file: '${current_input_file}'. HTTP Status: $http_status_upload. Skipping this file."
        $global_exit_code = 1
        continue
    }

    # Assign to a team if this is a new application - teamId is null
    $teamId = $upload_response.teamId # From current file's upload response
    if ($null -eq $teamId) {
        Write-Output "Application from '${current_input_file}' appears to be new. Assigning it to team '${team_name}'."

        # Fetch the list of teams using the access token
        $teams_response = Invoke-RestMethod -Uri "$server_url$teams_url" -Method Get `
            -Authentication Bearer -Token $access_token `
            -StatusCodeVariable http_status_teams `
            -ErrorAction SilentlyContinue
        Write-Debug "Team List Status: $http_status_teams `n Response: $teams_response"

        if ($teams_response) {
            $teamId = $teams_response.content | Where-Object { $_.name -eq $team_name } | Select-Object -ExpandProperty id

            if (-not $teamId) {
                Write-Error "For file '${current_input_file}': Failed to extract teamId for the team named '${team_name}'. Please ensure you have granted the Authorization token the 'view teams' permission. Skipping this file."
                $global_exit_code = 1
                continue
            } else {
                Write-Output "Successfully extracted teamId: '${teamId}' for Team named: '${team_name}' for app from '${current_input_file}'."

                # Wait for the server to process the upload
                Start-Sleep -Seconds $processing_delay

                # Perform the second API call to complete the upload
                $second_response_body = Invoke-RestMethod -Uri "$server_url$complete_upload_url/$zdevAppId/upload" -Method Put `
                    -Authentication Bearer -Token $access_token `
                    -ContentType "application/json" `
                    -SkipHttpErrorCheck `
                    -StatusCodeVariable http_status_assign `
                    -Body (@{ teamId = $teamId; buildNumber = $appBuildVersion } | ConvertTo-Json)
                Write-Debug "Complete Upload Status for $current_input_file : $http_status_assign `n Response: $second_response_body"

                if (([int]$http_status_assign) -ge 400) {
                    Write-Warning "Failed to assign the application from '${current_input_file}' to the specified team. HTTP Status: $http_status_assign. Response: $($second_response_body | ConvertTo-Json -Depth 5). Although the scan will complete, the results will not be visible in the console UI for this app."
                }
            }
        } else {
            Write-Warning "For file '${current_input_file}': Failed to extract the list of teams from your console (HTTP Status: $http_status_teams). Although the scan will complete, the results will not be visible in the console UI for this app. Please ensure the 'view teams' permission is granted."
        }
    }

    # If no need to wait for report, we're done with this file
    if (-not $wait_for_report) {
        Write-Output "'wait_for_report' is false. Upload of '${current_input_file}' submitted. Moving to next file if any."
        continue # To the next file in $files_to_process
    }

    # Wait for the upload to complete processing
    Start-Sleep -Seconds $processing_delay

    # Check the Status in a loop - wait for Interval
    while ($true) {
        # Check the Status
        $status_check_response = Invoke-RestMethod -Uri "$server_url$status_url$buildId" -Method Get `
            -Authentication Bearer -Token $access_token `
            -SkipHttpErrorCheck `
            -StatusCodeVariable http_status_scan_status `
            -ContentType "application/json"

        Write-Debug "Status Response for $current_input_file (Build ID: $buildId): $http_status_scan_status"
        if ($status_check_response) {
            $ScanStatus = $status_check_response.zdevMetadata.analysis

            if ($ScanStatus -eq "Done") {
                $AssessmentID = $status_check_response.id
                Write-Output "Scan $AssessmentID for file '${current_input_file}' is Done."
                break
            } else {
                Write-Output "Scan for '${current_input_file}' is not completed. Status: $ScanStatus. Waiting for $polling_interval seconds."
            }
        } else {
            Write-Debug "Status Response for $current_input_file : $status_check_response"
            Write-Error "Error Checking the Status of Scan for '${current_input_file}' (Build ID: $buildId). HTTP Status: $http_status_scan_status. Check debug logs. Will retry."
            # This error is within the retry loop for status, so it will sleep and retry as per original logic
        }

        # Sleep for the interval
        Start-Sleep -Seconds $polling_interval
    }

    # Sleep to give the server some time to prepare the report
    Start-Sleep -Seconds $processing_delay

    # Refresh the access token, since it might have expired during the long wait
    $old_access_token = $access_token
    $response = Invoke-RestMethod -Uri "$server_url$refresh_token_url" -Method Post `
        -ContentType "application/json" -Body (@{ refreshToken = $refresh_token } | ConvertTo-Json)

    Write-Debug "Login Response: $response"

    # Check if the call was successful
    if ($response) {
        $access_token = $response.accessToken

        # Check if access token is found
        if ($access_token) {
            $refresh_token = $response.refreshToken
            Write-Output "Successfully obtained access token."

            # convert to secure string as required by Invoke-RestMethod
            $access_token = ConvertTo-SecureString $access_token -AsPlainText -Force
        } else {
            Write-Error "Access token not found in response. Restoring the old access token."
            # Restore the old access token
            $access_token = $old_access_token
        }
    } else {
        Write-Error "Unable to obtain access token. Restoring the old access token."
        # Restore the old access token
        $access_token = $old_access_token
    }

    # Retrieve the report
    # Figure out report's fully qualified file name
    [string]$full_report_file_name_current_file = ""
    if (-not $report_file_name) {
        $base_name_for_report = [System.IO.Path]::GetFileNameWithoutExtension($current_input_file)
        $full_report_file_name_current_file = Join-Path $report_location "zscan-results-$base_name_for_report-$AssessmentID.$report_format"
    } else {
        if ($files_to_process.Count -gt 1) {
            $input_file_base_for_report_name = [System.IO.Path]::GetFileNameWithoutExtension($current_input_file)
            $report_file_base_original = [System.IO.Path]::GetFileNameWithoutExtension($report_file_name)
            $report_file_ext_original = [System.IO.Path]::GetExtension($report_file_name) # includes the dot
            $full_report_file_name_current_file = Join-Path $report_location "${report_file_base_original}_${input_file_base_for_report_name}${report_file_ext_original}"
            Write-Warning "Multiple files are processed with 'report_file_name' specified. Modifying report name for '${current_input_file}' to '${full_report_file_name_current_file}'."
        } else {
            # Single file processed (either by pattern or direct name), use the provided $report_file_name
            $full_report_file_name_current_file = Join-Path $report_location $report_file_name
        }
    }

    # Download the report
    Invoke-RestMethod -Uri "$server_url$download_assessment_url/$AssessmentID/$report_format" -Method Get `
        -Authentication Bearer -Token $access_token `
        -StatusCodeVariable http_status_download `
        -OutFile $full_report_file_name_current_file

    Write-Debug "Download report status for $current_input_file : $http_status_download"

    if ($http_status_download -ge 200 -and $http_status_download -lt 300) {
        Write-Output "Report for '${current_input_file}' saved to: $full_report_file_name_current_file"
        $all_report_files.Add($full_report_file_name_current_file)
    } else {
        Write-Error "Failed to download report for '${current_input_file}'. HTTP Status: $http_status_download. Report URL might have been: $server_url$download_assessment_url/$AssessmentID/$report_format"
        $global_exit_code = 1
        # Continue to next file, this one failed at report download
    }
    
} # End foreach ($current_file_info in $files_to_process)

# After the loop
if ($all_report_files.Count -gt 0) {
    Write-Output "" #NewLine for readability
    Write-Output "All reports generated:"
    $all_report_files | ForEach-Object { Write-Output "- $_" }
    $env:ZSCAN_REPORT_FILE = $all_report_files -join ','
    Write-Output "Environment variable ZSCAN_REPORT_FILE set to: $($env:ZSCAN_REPORT_FILE)"
} else {
    if ($wait_for_report -and $files_to_process.Count -gt 0) { # Only if we expected reports for processed files
        Write-Warning "No reports were successfully generated."
    } elseif ($files_to_process.Count -eq 0) {
        # This case should be caught earlier, but as a safeguard
        Write-Output "No files were processed."
    }
}

Write-Output "Script finished."
# Exit with success or error based on individual file processing
exit $global_exit_code