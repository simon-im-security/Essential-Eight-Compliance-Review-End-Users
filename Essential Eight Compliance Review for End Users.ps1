# Title: Essential Eight Compliance Review for End Users
# Description: 
# This PowerShell script checks various security compliance measures on a Windows system,
# with a focus on areas relevant to end users. It includes checks for Windows updates, daily backups,
# Microsoft Office macros, admin account usage, and more. It prompts the user for reasons only in cases where their input is relevant.
# Additionally, organisations can configure which checks are active using variables at the top of the script.
# Author: Simon I
# Version: 2024.08.23

# Load WPF Assemblies
Add-Type -AssemblyName PresentationCore, PresentationFramework

# ==========================
# Organisation-Specific Variables
# ==========================

# Toggle these checks on/off based on organisational needs
$CheckAdminAccount = $true
$CheckWindowsUpdates = $true
$CheckUnnecessaryServices = $true
$CheckMFA = $true
$CheckDailyBackup = $true
$CheckProtectionSoftware = $true
$CheckAppWhitelisting = $true
$CheckOfficeMacros = $true

# Define the output folder (default is a hidden location in the user's profile directory)
$OutputFolder = "$env:USERPROFILE\AppData\Local\.ComplianceReview"

# Organisation-specific variables
$BackupSoftwarePaths = "C:\Program Files\Microsoft OneDrive\OneDrive.exe", "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
$ProtectionSoftware = "CrowdStrike", "Windows Defender", "bdservicehost", "Malwarebytes"
$ServicesToIdentify = "XblAuthManager", "XboxNetApiSvc", "XblGameSave", "XboxGipSvc"
$WhitelistingApps = "CrowdStrike", "bdservicehost", "Ivanti Application Control"

# ==========================
# Script Functions and Logic
# ==========================

# Function to check if the current user is part of the Administrators group
function Test-IsUserAdmin {
    Write-Host "Checking if the user is an administrator..."
    
    # Get the current user's name
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    if (-not $userName) {
        Write-Host "Error: User name could not be retrieved."
        return $false
    }

    $userNameParts = $userName.Split('\')
    
    if ($userNameParts.Count -eq 0) {
        Write-Host "Error: Unable to parse the user name."
        return $false
    }

    $userNameShort = $userNameParts[-1]  # Get the last part of the split array (username)
    
    # Get the members of the Administrators group
    $adminGroup = [ADSI]"WinNT://./Administrators,group"
    $members = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { 
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) 
    }
    
    if (-not $members) {
        Write-Host "Error: No members found in the Administrators group."
        return $false
    }
    
    $isAdmin = $members -contains $userNameShort
    Write-Host "User is admin: $isAdmin"
    
    return $isAdmin
}

# Function to check Windows Update status
function Check-LastWindowsUpdate {
    if (-not $CheckWindowsUpdates) { 
        Write-Host "Skipping Windows Updates check."
        return "Skipped" 
    }

    try {
        # Retrieve the last installed update
        $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
        
        if ($lastUpdate) {
            $lastUpdateTime = $lastUpdate.InstalledOn
            Write-Host "Last Windows update installed on: $lastUpdateTime"

            # Check if the last update was installed within the last 30 days
            if ($lastUpdateTime -gt (Get-Date).AddDays(-30)) {
                return "Compliant: Windows updates have been installed within the last 30 days."
            } else {
                return "Non-compliant: Windows updates have not been installed within the last 30 days. Keeping your system updated is crucial to protect against security vulnerabilities. Please provide a reason as to why this has not yet been applied."
            }
        } else {
            Write-Host "No updates found."
            return "Non-compliant: No Windows updates have been installed. This could indicate a significant security risk. Please provide a reason as to why updates have not been applied."
        }
    } catch {
        Write-Host "Error checking last Windows update: $_"
        return "Error checking last Windows update: $_"
    }
}

# Function to check daily backup compliance
function Check-DailyBackupChecks {
    if (-not $CheckDailyBackup) { return "Skipped" }

    try {
        $backupSoftwareInstalled = $false
        $oneDriveProcessFound = $false

        foreach ($path in $BackupSoftwarePaths) {
            if (Test-Path $path) {
                $backupSoftwareInstalled = $true
                Write-Host "Found backup software at $path"
                break
            }
        }

        if ($backupSoftwareInstalled) {
            $backupSoftwareProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
            if ($backupSoftwareProcess) {
                $oneDriveProcessFound = $true
                Write-Host "OneDrive process found running."
                return "Compliant: OneDrive backup software is installed and the service is running for backup and synchronisation."
            } else {
                Write-Host "OneDrive process not found running."
                return "Non-compliant: OneDrive backup software is installed, but the service is not running. Regular backups are critical to ensure that data can be restored in case of data loss or ransomware attacks. Please provide a reason as to why this has not yet been applied."
            }
        } else {
            Write-Host "OneDrive backup software not installed."
            return "Compliant: OneDrive backup software is not installed, assuming no need for it."
        }
        
    } catch {
        Write-Host "Error checking OneDrive software installation and service status: $_"
        return "Error checking OneDrive software installation and service status: $_"
    }
}

# Function to check Microsoft Office macros
function Check-OfficeMacros {
    if (-not $CheckOfficeMacros) { 
        Write-Host "Skipping Office macros check."
        return "Skipped" 
    }

    try {
        $officeRegistryPaths = @(
            "HKCU:\Software\Microsoft\Office\16.0\Excel\Security",
            "HKCU:\Software\Microsoft\Office\15.0\Excel\Security",
            "HKCU:\Software\Microsoft\Office\14.0\Excel\Security"
        )
        
        $macroSettingsFound = $false

        foreach ($path in $officeRegistryPaths) {
            if (Test-Path $path) {
                $macroSettings = Get-ItemProperty -Path $path -Name "VBAWarnings" -ErrorAction SilentlyContinue
                if ($macroSettings.VBAWarnings -eq 2) {
                    return "Compliant: Macros are disabled with notifications."
                } else {
                    return "Non-compliant: Macros are not properly restricted. Restricting macros helps prevent the execution of malicious code. Please provide a reason as to why this has not yet been applied."
                }
                $macroSettingsFound = $true
            }
        }

        if (-not $macroSettingsFound) {
            Write-Host "Office macros settings not found, assuming no Office installation."
            return "Compliant: Microsoft Office macros settings not found, assuming no Office installation."
        }

    } catch {
        Write-Host "Error checking Microsoft Office macros: $_"
        return "Error checking Microsoft Office macros: $_"
    }
}

# Function to check for unnecessary services
function Check-IdentifyUnnecessaryServices {
    if (-not $CheckUnnecessaryServices) { 
        Write-Host "Skipping Unnecessary Services check."
        return "Skipped" 
    }

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
        Write-Host "Error identifying unnecessary services: $_"
        return "Error identifying unnecessary services: $_"
    }
}

# Title: Check Local GPOs for MFA-Related Policies
# Description: This script checks local GPOs for indicators of MFA-related policies, focusing on top 5 specific keywords.
# Author: Simon I
# Version: 2024.08.23

function Check-LocalGPOs {
    # Define path for the temporary GPO report
    $gpoReportPath = "$env:TEMP\GPOReport.html"

    # Generate a report of applied GPOs
    gpresult /H $gpoReportPath > $null 2>&1

    if (Test-Path $gpoReportPath) {
        # Define specific terms to search for in the GPO report
        $searchTerms = @(
            "Multi-Factor Authentication",
            "Two-Factor Authentication",
            "Smart Card",
            "Authentication Policy",
            "MFA"
        )

        $content = Get-Content $gpoReportPath -ErrorAction SilentlyContinue

        foreach ($term in $searchTerms) {
            if ($content -match $term) {
                Write-Output "$term found in local GPO settings."
            } else {
                Write-Output "$term not found in local GPO settings."
            }
        }

        # Delete the temporary report file immediately after processing
        Remove-Item $gpoReportPath -ErrorAction SilentlyContinue
    } else {
        Write-Output "Failed to generate local GPO report."
    }
}

function Check-AzureADJoinStatus {
    # Check Azure AD join status and display result on console
    $dsregStatus = & dsregcmd /status > $null 2>&1

    if ($dsregStatus -match "AzureADJoined\s*:\s*YES") {
        Write-Output "The machine is Azure AD Joined."
    } else {
        Write-Output "The machine is not Azure AD Joined."
    }
}

# Function to check Protection-Based Software
function Check-ProtectionBasedSoftware {
    if (-not $CheckProtectionSoftware) { 
        Write-Host "Skipping Protection-Based Software check."
        return "Skipped" 
    }

    try {
        foreach ($software in $ProtectionSoftware) {
            $softwareInstalled = Get-Process -Name $software -ErrorAction SilentlyContinue
            if ($softwareInstalled -ne $null) {
                return "Compliant: $software protection-based software is running."
            }
        }

        return "Non-compliant: No common protection-based software detected running on this system. Protection software is necessary to defend against malware, viruses, and other security threats."
    } catch {
        Write-Host "Error checking protection-based software: $_"
        return "Error checking protection-based software: $_"
    }
}

# Function to check Application Whitelisting compliance
function Check-AppWhitelistingCompliance {
    if (-not $CheckAppWhitelisting) { 
        Write-Host "Skipping Application Whitelisting check."
        return "Skipped" 
    }

    try {
        $compliantApps = @()

        foreach ($app in $WhitelistingApps) {
            $appInstalled = Get-Process -Name $app -ErrorAction SilentlyContinue
            if ($appInstalled -ne $null) {
                $compliantApps += $app
            }
        }

        if ($compliantApps.Count -eq 0) {
            return "Non-compliant: No whitelisted applications found running. Application whitelisting ensures that only approved software is allowed to run, reducing the risk of malware infections."
        }

        return "Compliant: Whitelisted application(s) found running: $($compliantApps -join ', ')"
    }
    catch {
        Write-Host "Error checking application whitelisting compliance: $_"
        return "Error checking application whitelisting compliance: $_"
    }
}

# Function to display a WPF-based GUI with all prompts at once
function Show-WpfPrompt {
    param (
        [string]$Title,
        [string]$Introduction,
        [string[]]$Questions
    )

    # XAML layout for the WPF window
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="$Title"
        Height="500" Width="600"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        WindowStyle="SingleBorderWindow"
        Background="#1E1E1E"
        FontFamily="Segoe UI"
        Foreground="White">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="$Introduction" FontSize="14" Margin="0,0,0,20" TextWrapping="Wrap"/>
        
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <StackPanel Name="QuestionsPanel" />
        </ScrollViewer>

        <Button Grid.Row="2" Content="Submit" Width="100" Height="30" HorizontalAlignment="Center" Margin="0,20,0,0" Name="SubmitButton"/>
    </Grid>
</Window>
"@

    # Parse the XAML and create the window
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    $Window = [Windows.Markup.XamlReader]::Load($reader)

    # Add questions and textboxes dynamically
    $QuestionsPanel = $Window.FindName("QuestionsPanel")
    $textBoxes = @{}

    foreach ($question in $Questions) {
        $label = New-Object Windows.Controls.TextBlock
        $label.Text = $question
        $label.Margin = "0,0,0,10"
        $label.TextWrapping = "Wrap"
        $QuestionsPanel.Children.Add($label)

        $textBox = New-Object Windows.Controls.TextBox
        $textBox.Width = 550
        $textBox.Margin = "0,0,0,20"
        $QuestionsPanel.Children.Add($textBox)
        $textBoxes[$question] = $textBox
    }

    # Handle the Submit button click event
    $SubmitButton = $Window.FindName("SubmitButton")
    $SubmitButton.Add_Click({
        $answers = @{}
        foreach ($question in $Questions) {
            $answers[$question] = $textBoxes[$question].Text
        }
        $Window.Tag = $answers
        $Window.DialogResult = $true
        $Window.Close()
    })

    # Show the window and return the results
    $result = $Window.ShowDialog()
    if ($result -eq $true) {
        Write-Host "User submitted answers."
        return $Window.Tag
    } else {
        Write-Host "User closed the window without submitting."
        return $null
    }
}

# Ensure the output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
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
$results['Multi-Factor Authentication'] = if ($CheckMFA) {
    $mfaGpoCheck = Check-LocalGPOs
    $azureAdCheck = Check-AzureADJoinStatus
    "$mfaGpoCheck $azureAdCheck"
} else {
    "Skipped"
}
$results['Protection-Based Software'] = Check-ProtectionBasedSoftware
$results['Application Whitelisting'] = Check-AppWhitelistingCompliance
$results['Microsoft Office Macros'] = Check-OfficeMacros

# Generate JSON output with proper formatting
$outputFile = "$OutputFolder\ComplianceReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$jsonReport = $results | ConvertTo-Json -Depth 3 | Out-File -FilePath $outputFile -Encoding utf8

Write-Host "Compliance review completed. Results saved to $outputFile."

# Display the GUI with all questions relevant to end users
$endUserQuestions = @()
foreach ($key in $results.Keys) {
    # Include all results related to Daily Backup Checks, regardless of compliance status
    if ($key -eq "Daily Backup Checks" -or $results[$key] -match "Non-compliant") {
        $endUserQuestions += "$($key): $($results[$key])"
    }
}

if ($endUserQuestions.Count -gt 0) {
    $introduction = "The Essential 8 Compliance Review checks your system for basic security measures. " +
                    "Your input is required to resolve non-compliant areas."
    $userResponses = Show-WpfPrompt -Title "Essential 8 Compliance Review" -Introduction $introduction -Questions $endUserQuestions

    if ($userResponses -ne $null) {
        foreach ($question in $endUserQuestions) {
            $jsonReport += $question, $userResponses[$question]
            Write-Host "$question - Reason: $($userResponses[$question])"
        }

        # Save the updated report with user responses
        $jsonReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $outputFile -Encoding utf8
        Write-Host "User responses saved to $outputFile."
    } else {
        Write-Host "User closed the compliance review without submitting answers."
    }
} else {
    Write-Host "All checks passed or were skipped. No further action required."
}
