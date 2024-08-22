<#
.SYNOPSIS
    Essential Eight Compliance Review for End Users
.DESCRIPTION
    This PowerShell script checks various security compliance measures on a Windows system,
    with a focus on areas relevant to end users. It includes checks for Windows updates, daily backups,
    Microsoft Office macros, and admin account usage. It prompts the user for reasons only in cases where their input is relevant.
    Additionally, organisations can configure which checks are active using variables at the top of the script.
.AUTHOR
    Simon
.VERSION
    3.4 (21st August 2024)
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ==========================
# Organisation-Specific Variables
# ==========================

# Toggle these checks on/off based on organisational needs
$CheckAdminAccount = $true   # Set to $false to disable the Admin Account Usage check
$CheckWindowsUpdates = $true   # Set to $false to disable the Last Windows Update check
$CheckUnnecessaryServices = $true  # Set to $false to disable the Unnecessary Services check (engineer-focused)
$CheckMFA = $true    # Set to $false to disable the Multi-Factor Authentication check (engineer-focused)
$CheckDailyBackup = $true  # Set to $false to disable the Daily Backup check
$CheckProtectionSoftware = $true  # Set to $false to disable the Protection-Based Software check (engineer-focused)
$CheckAppWhitelisting = $true  # Set to $false to disable the Application Whitelisting check (engineer-focused)
$CheckOfficeMacros = $true   # Set to $false to disable the Microsoft Office Macros check

# Define the output folder (default is a hidden location in the user's profile directory)
$OutputFolder = "$env:USERPROFILE\AppData\Local\.ComplianceReview"

# Organisation-specific variables
$ProtectionSoftware = "CrowdStrike", "Windows Defender", "bdservicehost", "Malwarebytes"
$ServicesToIdentify = "XblAuthManager", "XboxNetApiSvc", "XblGameSave", "XboxGipSvc"
$OneDrivePaths = "C:\Program Files\Microsoft OneDrive\OneDrive.exe", "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
$WhitelistingApps = "CrowdStrike Falcon", "bdservicehost", "Ivanti Application Control"

# ==========================
# Script Functions and Logic
# ==========================

# Function to check if the current user is part of the Administrators group
function Test-IsUserAdmin {
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $adminGroup = [ADSI]"WinNT://./Administrators,group"
    $members = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
    
    return $members -contains $userName.Split('\')[1]
}

# Function to display a user-friendly GUI with all prompts at once
function Show-GuiPrompt {
    param (
        [string]$Title,
        [string]$Introduction,
        [string[]]$Questions
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(600, 700)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $form.Topmost = $true
    $form.Font = New-Object System.Drawing.Font("Arial", 10)

    # Introduction label
    $introLabel = New-Object System.Windows.Forms.Label
    $introLabel.Text = $Introduction
    $introLabel.Size = New-Object System.Drawing.Size(550, 40)
    $introLabel.Location = New-Object System.Drawing.Point(20, 20)
    $introLabel.AutoSize = $true
    $introLabel.MaximumSize = New-Object System.Drawing.Size(550, 0)
    $introLabel.AutoEllipsis = $true
    $introLabel.UseMnemonic = $false
    $form.Controls.Add($introLabel)
    
    # Create labels and text boxes for each question
    $textBoxes = @{}
    $yPos = 80

    foreach ($question in $Questions) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $question
        $label.Size = New-Object System.Drawing.Size(550, 0)
        $label.Location = New-Object System.Drawing.Point(20, $yPos)
        $label.AutoSize = $true
        $label.MaximumSize = New-Object System.Drawing.Size(550, 0)
        $label.AutoEllipsis = $true
        $label.UseMnemonic = $false
        $form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Size = New-Object System.Drawing.Size(550, 20)
        $textBox.Location = New-Object System.Drawing.Point(20, ($yPos + $label.Height + 10))
        $form.Controls.Add($textBox)
        $textBoxes[$question] = $textBox

        $yPos += ($label.Height + 60)
    }

    # Create the Submit button
    $submitButton = New-Object System.Windows.Forms.Button
    $submitButton.Text = "Submit"
    $submitButton.Location = New-Object System.Drawing.Point(250, ($yPos + 20))
    $submitButton.Size = New-Object System.Drawing.Size(100, 30)
    $submitButton.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
    $submitButton.ForeColor = [System.Drawing.Color]::White
    $submitButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $submitButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($submitButton)

    # Capture user input when the Submit button is clicked
    $submitButton.Add_Click({
        $answers = @{}
        foreach ($question in $Questions) {
            $answers[$question] = $textBoxes[$question].Text
        }
        $form.Tag = $answers
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    # Show the form and return the results
    $result = $form.ShowDialog() | Out-Null

    if ($form.DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        return $form.Tag
    } else {
        return $null
    }
}

# Function to check unnecessary services using the confirmed logic
function Check-IdentifyUnnecessaryServices {
    if (-not $CheckUnnecessaryServices) { return "Skipped" }

    try {
        $identifiedServices = @()

        foreach ($service in $ServicesToIdentify) {
            $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue

            if ($serviceStatus -ne $null -and $serviceStatus.Status -eq 'Running') {
                $identifiedServices += $service
            }
        }

        if ($identifiedServices.Count -gt 0) {
            return "Non-compliant: Unnecessary services running - $($identifiedServices -join ', '). Disabling unnecessary services reduces the attack surface and improves system performance."
        } else {
            return "Compliant: No unnecessary services found running on this system."
        }
    } catch {
        return "Error identifying unnecessary services: $_"
    }
}

function Check-DailyBackupChecks {
    if (-not $CheckDailyBackup) { return "Skipped" }

    try {
        $oneDriveInstalled = $false
        foreach ($path in $OneDrivePaths) {
            if (Test-Path $path) {
                $oneDriveInstalled = $true
                break
            }
        }

        if ($oneDriveInstalled) {
            $oneDriveProcess = Get-Process -Name "OneDrive*" -ErrorAction SilentlyContinue

            if ($oneDriveProcess) {
                return "Compliant: OneDrive is installed and the service is running for backup and synchronisation."
            } else {
                return "Non-compliant: OneDrive is installed, but the service is not running. Regular backups are critical to ensure that data can be restored in case of data loss or ransomware attacks. Please provide a reason as to why this has not yet been applied."
            }
        } else {
            return "Non-compliant: OneDrive is not installed. Without an active backup solution, your data is at risk of being permanently lost in the event of a system failure. Please provide a reason as to why this has not yet been applied."
        }
    } catch {
        return "Error checking OneDrive installation and service status: $_"
    }
}

function Check-MultiFactorAuthentication {
    if (-not $CheckMFA) { return "Skipped" }

    try {
        $azureAuthenticatorKeysExist = Test-Path "HKCU:\Software\Microsoft\IdentityStore\AAD.PKeyAuth\Ring1"
        $oktaKeysExist = Test-Path "HKCU:\Software\Okta"

        if ($azureAuthenticatorKeysExist -or $oktaKeysExist) {
            return "Compliant: Multi-Factor Authentication is enabled."
        } else {
            return "Non-compliant: Multi-Factor Authentication not enabled. MFA adds an additional layer of security by requiring a second form of verification before granting access."
        }
    } catch {
        return "Error checking Multi-Factor Authentication: $_"
    }
}

function Check-ProtectionBasedSoftware {
    if (-not $CheckProtectionSoftware) { return "Skipped" }

    try {
        foreach ($software in $ProtectionSoftware) {
            $softwareInstalled = Get-Process -Name $software -ErrorAction SilentlyContinue
            if ($softwareInstalled -ne $null) {
                return "Compliant: $software protection-based software is running."
            }
        }

        return "Non-compliant: No common protection-based software detected running on this system. Protection software is necessary to defend against malware, viruses, and other security threats."
    } catch {
        return "Error checking protection-based software: $_"
    }
}

function Check-AppWhitelistingCompliance {
    if (-not $CheckAppWhitelisting) { return "Skipped" }

    try {
        $compliantApps = @()

        foreach ($app in $WhitelistingApps) {
            $appInstalled = Get-Service -Name $app -ErrorAction SilentlyContinue
            if ($appInstalled -ne $null -and $appInstalled.Status -eq 'Running') {
                $compliantApps += $app
            }
        }

        if ($compliantApps.Count -eq 0) {
            return "Non-compliant: No whitelist app found. Application whitelisting ensures that only approved software is allowed to run, reducing the risk of malware infections."
        }

        return "Compliant: Whitelist app(s) found: $($compliantApps -join ', ')"
    }
    catch {
        return "Error checking application whitelisting compliance: $_"
    }
}

function Check-OfficeMacros {
    if (-not $CheckOfficeMacros) { return "Skipped" }

    try {
        # Check if Microsoft Office is installed by verifying the presence of a common registry key
        $macroKeyPath = "HKCU:\Software\Microsoft\Office\16.0\Excel\Security"
        if (Test-Path $macroKeyPath) {
            $macroSettings = Get-ItemProperty -Path $macroKeyPath -Name "VBAWarnings" -ErrorAction SilentlyContinue
            if ($macroSettings -eq 2) {
                return "Compliant: Macros are disabled with notifications."
            } else {
                return "Non-compliant: Macros are not properly restricted. Restricting macros helps prevent the execution of malicious code. Please provide a reason as to why this has not yet been applied."
            }
        } else {
            return "Non-compliant: Microsoft Office macros setting is not found. Please verify that macros are restricted."
        }
    } catch {
        return "Error checking Microsoft Office macros: $_"
    }
}

# Ensure the output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

# Functions to check for compliance - Add the missing functions
function Check-LastWindowsUpdate {
    if (-not $CheckWindowsUpdates) { return "Skipped" }

    try {
        $lastUpdateTime = (Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn

        if ($lastUpdateTime -gt (Get-Date).AddDays(-30)) {
            return "Compliant: Windows updates have been installed within the last 30 days."
        } else {
            return "Non-compliant: Windows updates have not been installed within the last 30 days. Keeping your system updated is crucial to protect against security vulnerabilities. Please provide a reason as to why this has not yet been applied."
        }
    } catch {
        return "Error checking last Windows update: $_"
    }
}

# Collect and process results
$results = @{}

$results['Admin Account Usage'] = if ($CheckAdminAccount -and (Test-IsUserAdmin)) {
    "Non-compliant: The currently logged-in user's account is an administrator. It is recommended that the user's account be a standard account to minimise security risks. Please provide a reason as to why this account is still an admin."
} else {
    "Compliant: The currently logged-in user's account is not an administrator."
}

$results['Last Windows Update'] = Check-LastWindowsUpdate
$results['Unnecessary Services'] = Check-IdentifyUnnecessaryServices
$results['Daily Backup Checks'] = Check-DailyBackupChecks
$results['Multi-Factor Authentication'] = Check-MultiFactorAuthentication
$results['Protection-Based Software'] = Check-ProtectionBasedSoftware
$results['Application Whitelisting'] = Check-AppWhitelistingCompliance
$results['Microsoft Office Macros'] = Check-OfficeMacros

# Display the GUI with all questions relevant to end users
$endUserQuestions = @()
foreach ($key in $results.Keys) {
    if ($results[$key] -match "Non-compliant" -and $key -in @("Admin Account Usage", "Last Windows Update", "Daily Backup Checks", "Microsoft Office Macros")) {
        $endUserQuestions += "$($key): $($results[$key])"
    }
}

if ($endUserQuestions.Count -gt 0) {
    $introduction = "The Essential 8 Compliance Review checks your system for basic security measures. " +
                    "Your input is required to resolve non-compliant areas."
    $userResponses = Show-GuiPrompt -Title "Essential 8 Compliance Review" -Introduction $introduction -Questions $endUserQuestions

    if ($userResponses -ne $null) {
        foreach ($question in $endUserQuestions) {
            $outputFile = "$OutputFolder\ComplianceReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            "$question - Reason: $($userResponses[$question])" | Out-File -FilePath $outputFile -Append
            Write-Host "$question - Reason: $($userResponses[$question])"
        }
    } else {
        Write-Host "User closed the compliance review without submitting answers."
    }
} else {
    Write-Host "All checks passed or were skipped. No further action required."
}
