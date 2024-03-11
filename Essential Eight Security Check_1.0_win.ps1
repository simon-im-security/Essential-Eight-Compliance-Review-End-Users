# Windows 11 Essential Eight Security Script for Enterprise Endpoints

# 1. Application Whitelisting Compliance
# Checking the installation and running status of various application whitelisting solutions commonly used in enterprise environments.
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
            Write-Host "Non-compliant: No whitelist app found."
        }

        # Return true if at least one whitelisting app is compliant, otherwise false
        return $compliantApps.Count -gt 0
    }
    catch {
        Write-Host "Error checking application whitelisting compliance: $_"
        return $false
    }
}

# 2. Secure Admin Access
# Ensuring secure admin access by renaming the local Administrator account and restricting unnecessary privileges.
function Check-SecureAdminAccess {
    try {
        # Check if Local Administrator account is renamed
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction Stop
        $adminRenamed = $adminAccount.Name -ne "Administrator"

        # Check if the current user is an administrator
        $isAdmin = $null -ne (whoami /groups /fo csv | ConvertFrom-Csv | Where-Object { $_.SID -eq "S-1-5-32-544" })

        # Display compliance status
        if ($adminRenamed) {
            Write-Host "Compliant: Local Administrator account is renamed."
        } else {
            Write-Host "Non-compliant: Local Administrator account is not renamed."
        }

        if ($isAdmin) {
            Write-Host "Non-compliant: Current user has unnecessary administrative privileges."
        } else {
            Write-Host "Compliant: Current user is a standard user."
        }

        # Return true if both conditions are met, otherwise false
        return ($adminRenamed -eq $true) -and ($isAdmin -eq $false)

    } catch {
        Write-Host "Error checking secure admin access: $_"
        return $false
    }
}

# 3. Patch Applications - Microsoft Windows Update Check
# Regularly checking for Microsoft Windows updates helps address vulnerabilities and reduce the risk of exploitation.
function Check-LastWindowsUpdate {
    try {
        # Retrieve the LastSearchSuccessDate for Microsoft Windows updates
        $lastSearchSuccessDate = (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate

        # Parse the date using a simple format
        $parsedDate = [DateTime]::Parse($lastSearchSuccessDate)

        # Calculate the difference in days between the LastSearchSuccessDate and the current date
        $daysDifference = (Get-Date) - $parsedDate

        # Check if the LastSearchSuccessDate is within the last 7 days
        if ($daysDifference.Days -le 7) {
            Write-Host "Compliant: Microsoft Windows updates were checked within the last 7 days."
            return $true
        } else {
            Write-Host "Non-compliant: Microsoft Windows updates were not checked within the last 7 days."
            return $false
        }
    } catch {
        Write-Host "Error checking last Microsoft Windows update: $_"
        return $false
    }
}

# 4. Configure Microsoft Office Macro Settings
# Configuring Microsoft Office macro settings helps mitigate the risk of malicious macros being executed.
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
                    Write-Host "Compliant: Microsoft Office macro settings are configured."
                    return $true
                } else {
                    Write-Host "Non-compliant: Microsoft Office macro settings are not configured on this system."
                    return $false
                }
            } else {
                Write-Host "Non-compliant: Microsoft Office macro settings registry key does not exist on this system."
                return $false
            }
        } else {
            Write-Host "Non-compliant: Microsoft Office is not installed on this system."
            return $false
        }
    } catch {
        Write-Host "Error checking Microsoft Office macro settings: $_"
        return $false
    }
}

# 5. Protection-Based Software Check
# Detecting and reporting common protection-based software enhances endpoint protection against malware.
function Check-ProtectionBasedSoftware {
    try {
        # Define common protection-based software
        $protectionSoftware = "CrowdStrike", "Norton", "Bitdefender", "Windows Defender", "Trend Micro", "AVG", "Avira", "Symantec", "Malwarebytes", "Panda Security", "Webroot", "F-Secure", "Comodo"

        foreach ($software in $protectionSoftware) {
            $softwareInstalled = Get-ItemProperty -Path "HKLM:\SOFTWARE\$software" -ErrorAction SilentlyContinue
            if ($softwareInstalled -ne $null) {
                Write-Host "Compliant: $software protection-based software is installed."
                return $true
            }
        }

        Write-Host "Non-compliant: No common protection-based software detected on this system."
        return $false
    } catch {
        Write-Host "Error checking protection-based software: $_"
        return $false
    }
}


# 6. Disable Unnecessary Services
# Disabling unnecessary services, such as Telnet and Xbox services, helps reduce the attack surface and potential vulnerabilities.
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
            Write-Host "Non-compliant: Identified unnecessary services - $identifiedServicesString"
            return $false  # Non-compliant
        } else {
            Write-Host "Compliant: No unnecessary services found running on this system."
            return $true  # Compliant
        }
    } catch {
        Write-Host "Error identifying unnecessary services: $_"
        return $false  # Non-compliant in case of an error
    }
}

# 7. Multi-Factor Authentication (MFA)
# Enabling MFA adds an additional layer of security, helping protect against unauthorized access.
function Check-MultiFactorAuthentication {
    try {
        # Check for the existence of registry keys related to Azure Authenticator app
        $azureAuthenticatorKeysExist = Test-Path "HKCU:\Software\Microsoft\IdentityStore\AAD.PKeyAuth\Ring1"

        # Check for the existence of Okta registry keys (replace with actual registry keys used by Okta)
        $oktaKeysExist = Test-Path "HKCU:\Software\Okta"

        if ($azureAuthenticatorKeysExist) {
            Write-Host "Compliant: Multi-Factor Authentication is implemented using Azure Authenticator."
            return $true
        } elseif ($oktaKeysExist) {
            Write-Host "Compliant: Multi-Factor Authentication is implemented using Okta."
            return $true
        } else {
            Write-Host "Non-compliant: Multi-Factor Authentication is not implemented for user accounts."
            return $false
        }
    } catch {
        Write-Host "Error checking Multi-Factor Authentication: $_"
        return $false
    }
}

# 8. Daily Backup Checks
# Regularly checking and validating backups helps ensure data integrity and availability in case of data loss or ransomware attacks.
function Check-DailyBackupChecks {
    try {
        # Check if OneDrive is installed
        $oneDrivePath = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
        $oneDriveInstalled = Test-Path $oneDrivePath

        if ($oneDriveInstalled) {
            # Check if OneDrive service is running
            $oneDriveService = Get-Service -Name "OneSyncSvc" -ErrorAction SilentlyContinue

            if ($oneDriveService -ne $null -and $oneDriveService.Status -eq 'Running') {
                Write-Host "Compliant: OneDrive is installed and the service is running for backup and synchronization."
                return $true
            } else {
                Write-Host "Non-compliant: OneDrive is installed, but the service is not running on this system."
                return $false
            }
        } else {
            Write-Host "Non-compliant: OneDrive is not installed on this system."
            return $false
        }
    } catch {
        Write-Host "Error checking OneDrive installation and service status: $_"
        return $false
    }
}

# Execute each function and display results
Check-AppWhitelistingCompliance
Check-SecureAdminAccess
Check-LastWindowsUpdate
Check-MacroSettings
Check-ProtectionBasedSoftware
Check-IdentifyUnnecessaryServices
Check-MultiFactorAuthentication
Check-DailyBackupChecks
