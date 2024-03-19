<#
.SYNOPSIS
    Essential Eight Compliance Review
.DESCRIPTION
    This PowerShell script checks various security compliance measures on a Windows system,
    including application whitelisting, secure admin access, Windows updates, Microsoft Office macro settings,
    protection-based software, unnecessary services, multi-factor authentication, and daily backup checks.
.AUTHOR
    Simon
.VERSION
    1.1 (19th May 2024)
#>

# 1. Function to perform Application Whitelisting Compliance check
function Check-AppWhitelistingCompliance {
    try {
        # List of common application whitelisting solutions
        $whitelistingApps = "AppLocker", "Carbon Black Protection", "Symantec Endpoint Protection", "McAfee Application Control", "Ivanti Application Control", "CrowdStrike Falcon"

        $compliantApps = @()

        foreach ($app in $whitelistingApps) {
            $appInstalled = Get-Service -Name $app -ErrorAction SilentlyContinue
            if ($appInstalled -ne $null -and $appInstalled.Status -eq 'Running') {
                $compliantApps += $app
            }
        }

        # Output message when no whitelisting app is found
        if ($compliantApps.Count -eq 0) {
            return "Non-compliant: No whitelist app found."
        }

        # Return true if at least one whitelisting app is compliant, otherwise false
        return "Compliant: Whitelist app(s) found: $($compliantApps -join ', ')"
    }
    catch {
        return "Error checking application whitelisting compliance: $_"
    }
}

# 2. Function to perform Secure Admin Access check
function Check-SecureAdminAccess {
    try {
        # Check if Local Administrator account is renamed
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction Stop
        $adminRenamed = $adminAccount.Name -ne "Administrator"

        # Check if the current user is an administrator
        $isAdmin = $null -ne (whoami /groups /fo csv | ConvertFrom-Csv | Where-Object { $_.SID -eq "S-1-5-32-544" })

        # Display compliance status
        $status = "Compliant"
        if (-not $adminRenamed) {
            $status = "Non-compliant: Local Administrator account is not renamed."
        }
        if ($isAdmin) {
            $status += " Non-compliant: Current user has unnecessary administrative privileges."
        }

        return $status
    } catch {
        return "Error checking secure admin access: $_"
    }
}

# 3. Function to perform Last Windows Update check
function Check-LastWindowsUpdate {
    try {
        # Retrieve the LastSearchSuccessDate for Microsoft Windows updates
        $lastSearchSuccessDate = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate

        # Attempt to parse the date using various methods
        $parsedDate = $null

        # Method 1: Try parsing using [DateTime]::ParseExact
        try {
            $parsedDate = [DateTime]::ParseExact($lastSearchSuccessDate, @("yyyyMMdd", "yyyy-MM-dd"), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None)
        } catch {
            # Ignore any parsing errors
        }

        # Method 2: Try parsing using [DateTime]::Parse
        if ($parsedDate -eq $null) {
            try {
                $parsedDate = [DateTime]::Parse($lastSearchSuccessDate, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                # Ignore any parsing errors
            }
        }

        if ($parsedDate -ne $null) {
            # Calculate the difference in days between the LastSearchSuccessDate and the current date
            $daysDifference = (Get-Date) - $parsedDate

            # Check if the LastSearchSuccessDate is within the last 7 days
            if ($daysDifference.Days -le 7) {
                return "Compliant: Microsoft Windows updates were checked within the last 7 days."
            } else {
                return "Non-compliant: Microsoft Windows updates were not checked within the last 7 days."
            }
        } else {
            return "Error parsing last Microsoft Windows update date: Date format unrecognized."
        }
    } catch {
        return "Error checking last Microsoft Windows update: $_"
    }
}

# 4. Function to perform Microsoft Office Macro Settings check
function Check-MacroSettings {
    try {
        # Check if Microsoft Office folders exist
        $officeFolder1Exists = Test-Path "C:\Program Files\Microsoft Office"
        $officeFolder2Exists = Test-Path "C:\Program Files\Microsoft Office\root"
        $officeFoldersExist = $officeFolder1Exists -or $officeFolder2Exists

        if ($officeFoldersExist) {
            # Check the actual macro settings for Microsoft Office
            $macroKeyPath = "HKCU:\Software\Microsoft\Office\Outlook\Security"

            # Check if the key exists
            if (Test-Path $macroKeyPath) {
                # Check if macro settings are configured
                $macroConfigured = (Get-ItemProperty -LiteralPath $macroKeyPath).Level -eq "2"

                if ($macroConfigured) {
                    return "Compliant: Microsoft Office macro settings are configured."
                } else {
                    return "Non-compliant: Microsoft Office macro settings are not configured on this system."
                }
            } else {
                return "Non-compliant: Microsoft Office macro settings registry key does not exist on this system."
            }
        } else {
            return "Non-compliant: Microsoft Office is not installed on this system."
        }
    } catch {
        return "Error checking Microsoft Office macro settings: $_"
    }
}

# 5. Function to perform Protection-Based Software check
function Check-ProtectionBasedSoftware {
    try {
        # Define common protection-based software
        $protectionSoftware = "CrowdStrike", "Norton", "Bitdefender", "Windows Defender", "Trend Micro", "AVG", "Avira", "Symantec", "Malwarebytes", "Panda Security", "Webroot", "F-Secure", "Comodo"

        foreach ($software in $protectionSoftware) {
            $softwareInstalled = Get-ItemProperty -Path "HKLM:\SOFTWARE\$software" -ErrorAction SilentlyContinue
            if ($softwareInstalled -ne $null) {
                return "Compliant: $software protection-based software is installed."
            }
        }

        return "Non-compliant: No common protection-based software detected on this system."
    } catch {
        return "Error checking protection-based software: $_"
    }
}

# 6. Function to perform Identify Unnecessary Services check
function Check-IdentifyUnnecessaryServices {
    try {
        # Define unnecessary services to be identified
        $servicesToIdentify = "XblAuthManager", "XboxNetApiSvc", "XblGameSave", "XboxGipSvc"

        $identifiedServices = @()

        foreach ($service in $servicesToIdentify) {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue

            if ($serviceStatus -ne $null -and $serviceStatus.Status -eq 'Running') {
                $identifiedServices += $service
            }
        }

        if ($identifiedServices.Count -gt 0) {
            $identifiedServicesString = $identifiedServices -join ", "
            return "Non-compliant: Identified unnecessary services - $identifiedServicesString"
        } else {
            return "Compliant: No unnecessary services found running on this system."
        }
    } catch {
        return "Error identifying unnecessary services: $_"
    }
}

# 7. Function to perform Multi-Factor Authentication check
function Check-MultiFactorAuthentication {
    try {
        # Check for the existence of registry keys related to Azure Authenticator app
        $azureAuthenticatorKeysExist = Test-Path "HKCU:\Software\Microsoft\IdentityStore\AAD.PKeyAuth\Ring1"

        # Check for the existence of Okta registry keys (replace with actual registry keys used by Okta)
        $oktaKeysExist = Test-Path "HKCU:\Software\Okta"

        if ($azureAuthenticatorKeysExist) {
            return "Compliant: Multi-Factor Authentication is implemented using Azure Authenticator."
        } elseif ($oktaKeysExist
        ) {
            return "Compliant: Multi-Factor Authentication is implemented using Okta."
        } else {
            return "Non-compliant: Multi-Factor Authentication is not implemented for user accounts."
        }
    } catch {
        return "Error checking Multi-Factor Authentication: $_"
    }
}

# 8. Function to perform Daily Backup Checks
function Check-DailyBackupChecks {
    try {
        # Check if OneDrive is installed in the regular Program Files directory
        $oneDrivePath = "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
        $oneDriveInstalled = Test-Path $oneDrivePath

        # Check if OneDrive is installed in the Program Files (x86) directory
        if (-not $oneDriveInstalled) {
            $oneDrivePath = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
            $oneDriveInstalled = Test-Path $oneDrivePath
        }

        if ($oneDriveInstalled) {
            # Check if OneDrive process is running
            $oneDriveProcess = Get-Process -Name "OneDrive*" -ErrorAction SilentlyContinue

            if ($oneDriveProcess) {
                return "Compliant: OneDrive is installed and the service is running for backup and synchronization."
            } else {
                return "Non-compliant: OneDrive is installed, but the service is not running on this system."
            }
        } else {
            return "Non-compliant: OneDrive is not installed on this system."
        }
    } catch {
        return "Error checking OneDrive installation and service status: $_"
    }
}

# Generate HTML report
$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Essential Eight Compliance Review</title>
    <style>
        body { font-family: Arial, sans-serif; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .compliant { color: green; }
        .non-compliant { color: red; }
    </style>
</head>
<body>
    <h1>Essential Eight Compliance Review</h1>
    <table>
        <tr>
            <th>Category</th>
            <th>Status</th>
            <th>Error</th>
        </tr>
        <tr>
            <td>Application Whitelisting Compliance</td>
            <td class="$(Check-AppWhitelistingCompliance)">$(Check-AppWhitelistingCompliance)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Secure Admin Access</td>
            <td class="$(Check-SecureAdminAccess)">$(Check-SecureAdminAccess)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Last Windows Update</td>
            <td class="$(Check-LastWindowsUpdate)">$(Check-LastWindowsUpdate)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Microsoft Office Macro Settings</td>
            <td class="$(Check-MacroSettings)">$(Check-MacroSettings)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Protection-Based Software</td>
            <td class="$(Check-ProtectionBasedSoftware)">$(Check-ProtectionBasedSoftware)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Identify Unnecessary Services</td>
            <td class="$(Check-IdentifyUnnecessaryServices)">$(Check-IdentifyUnnecessaryServices)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Multi-Factor Authentication</td>
            <td class="$(Check-MultiFactorAuthentication)">$(Check-MultiFactorAuthentication)</td>
            <td>None</td>
        </tr>
        <tr>
            <td>Daily Backup Checks</td>
            <td class="$(Check-DailyBackupChecks)">$(Check-DailyBackupChecks)</td>
            <td>None</td>
        </tr>
    </table>
</body>
</html>
"@

# Define the path for the temporary HTML report
$tempHtmlFilePath = "$env:TEMP\Essential Eight Compliance Review.html"

# Output HTML report to the temporary file
$htmlReport | Out-File -FilePath $tempHtmlFilePath -Encoding UTF8

# Open the HTML report using the default web browser
Start-Process $tempHtmlFilePath

