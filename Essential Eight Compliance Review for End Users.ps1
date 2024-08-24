# Title: SOC Incident Reporter
# Description: A WPF-based tool designed for SOC teams to record and manage cybersecurity incidents. The tool guides analysts through "New Incident," "Continuing Incident," and "Closing Incident" options, with sections for Internal Use and External Use, and exports the information to a plain text file.
# Author: Simon .I
# Version: 2024.08.24

# Load required assemblies for WPF
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Define the path for saving the data
$savePath = "$([System.Environment]::GetFolderPath('LocalApplicationData'))\SOCIncidentReporter\soc_incident_reporter_data.xml"

# Ensure the directory exists
$saveDir = [System.IO.Path]::GetDirectoryName($savePath)
if (-not (Test-Path -Path $saveDir)) {
    New-Item -Path $saveDir -ItemType Directory | Out-Null
}

# Define the XAML for the WPF GUI
$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" 
        Title="SOC Incident Reporter" Height="1050" Width="500" WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <StackPanel>

            <!-- Incident Type Selection -->
            <TextBlock Text="Select Incident Type:" FontSize="16" Margin="0,0,0,10"/>
            <ComboBox x:Name="IncidentTypeComboBox" SelectedIndex="0" Margin="0,0,0,20">
                <ComboBoxItem Content="New Incident (for your first contact with the client)"/>
                <ComboBoxItem Content="Continuing Incident (for your ongoing contact)"/>
                <ComboBoxItem Content="Closing Incident (for final resolution and closing summary)"/>
            </ComboBox>

            <!-- Internal Use Section -->
            <TextBlock x:Name="InternalUseHeader" Text="Internal Use" FontSize="16" FontWeight="Bold" Margin="0,0,0,10" Visibility="Collapsed"/>
            <StackPanel x:Name="NewIncidentPanel" Visibility="Collapsed">
                <TextBlock Text="Incident Type:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="CyberIncidentTypeComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Phishing"/>
                    <ComboBoxItem Content="Malware"/>
                    <ComboBoxItem Content="Ransomware"/>
                    <ComboBoxItem Content="Unauthorised Access"/>
                    <ComboBoxItem Content="Data Breach"/>
                    <ComboBoxItem Content="DDoS Attack"/>
                    <ComboBoxItem Content="Insider Threat"/>
                    <ComboBoxItem Content="Account Identity"/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomIncidentTypeTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>

                <TextBlock Text="Threat Level Rating:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="ThreatLevelComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Low - Basic or unsophisticated threats, such as automated scans or low-impact phishing attempts"/>
                    <ComboBoxItem Content="Moderate - More targeted or moderately sophisticated attacks, such as spear-phishing or common malware"/>
                    <ComboBoxItem Content="High - Advanced threats involving sophisticated tactics, such as ransomware or targeted attacks against critical infrastructure"/>
                    <ComboBoxItem Content="Critical - Highly advanced and persistent threats, such as APT threats, nation-state actors, or large-scale attacks that could cause significant and prolonged damage"/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomThreatLevelTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>

                <TextBlock Text="Initial Findings:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="InitialFindingsTextBox" Height="60" Margin="0,0,0,10"/>

                <TextBlock Text="Internal Next Steps:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="InternalNextStepsTextBox" Height="60" Margin="0,0,0,10"/>
            </StackPanel>

            <!-- External Use Section -->
            <TextBlock x:Name="ExternalUseHeader" Text="External Use" FontSize="16" FontWeight="Bold" Margin="0,0,0,10" Visibility="Collapsed"/>
            <StackPanel x:Name="NewIncidentExternalPanel" Visibility="Collapsed">
                <TextBlock Text="Client's Full Name:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ClientNameTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Full Name | Position | Email | Phone:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="AnalystDetailsTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Select Client Response:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="ClientResponseComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Hi [Client Name]. I'm currently looking into your reported cyber security incident. Once I have more information, I'll reach out to you as soon as possible."/>
                    <ComboBoxItem Content="Hi [Client Name], I’d like to discuss your reported cyber security incident. When would be a good time for us to connect? When available, please provide me with your best contact time and preferred method."/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomClientResponseTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>
            </StackPanel>

            <!-- Continuing Incident Panels -->
            <StackPanel x:Name="ContinuingIncidentPanel" Visibility="Collapsed">
                <TextBlock Text="Further Findings:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="FurtherFindingsTextBox" Height="60" Margin="0,0,0,10"/>

                <TextBlock Text="Client Contact Summary:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="ClientContactSummaryComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Phone"/>
                    <ComboBoxItem Content="Email"/>
                    <ComboBoxItem Content="Video Conference"/>
                    <ComboBoxItem Content="Ticket"/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomClientContactSummaryTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>

                <TextBlock Text="Next Steps:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="NextStepsTextBox" Height="60" Margin="0,0,0,10"/>

                <TextBlock x:Name="ContinuingExternalUseHeader" Text="External Use" FontSize="16" FontWeight="Bold" Margin="0,0,0,10" Visibility="Collapsed"/>
                <TextBlock Text="Client's Full Name:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ContinuingClientNameTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Full Name | Position | Email | Phone:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ContinuingAnalystDetailsTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Select Client Response:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="ContinuingClientResponseComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Hi [Client Name], I wanted to provide you with a quick update. We are still actively investigating your incident and will keep you informed as we make progress."/>
                    <ComboBoxItem Content="Hi [Client Name], it looks like we may need further information. Could I reach out to you directly? Please you let me know your best contact time and preferred method?"/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomContinuingClientResponseTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>
            </StackPanel>

            <!-- Closing Incident Panels -->
            <StackPanel x:Name="ClosingIncidentPanel" Visibility="Collapsed">
                <TextBlock Text="Resolution Summary:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ResolutionSummaryTextBox" Height="60" Margin="0,0,0,10"/>

                <TextBlock x:Name="ClosingExternalUseHeader" Text="External Use" FontSize="16" FontWeight="Bold" Margin="0,0,0,10" Visibility="Collapsed"/>
                <TextBlock Text="Client's Full Name:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ClosingClientNameTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Full Name | Position | Email | Phone:" FontSize="14" Margin="0,0,0,5"/>
                <TextBox x:Name="ClosingAnalystDetailsTextBox" Height="25" Margin="0,0,0,10"/>

                <TextBlock Text="Select Client Response:" FontSize="14" Margin="0,0,0,5"/>
                <ComboBox x:Name="ClosingClientResponseComboBox" Margin="0,0,0,10">
                    <ComboBoxItem Content="Hi [Client Name], this cyber security incident has now been cancelled, with no further action required."/>
                    <ComboBoxItem Content="Hi [Client Name], this cyber security incident has been resolved successfully. Please contact us if you experience any further issues."/>
                    <ComboBoxItem Content="Custom Field"/>
                </ComboBox>
                <TextBox x:Name="CustomClosingClientResponseTextBox" Height="25" Margin="0,0,0,10" Visibility="Collapsed"/>
            </StackPanel>

            <!-- Buttons for Save Info, Reload, and Export Report -->
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="10,0,0,10">
                <Button x:Name="SaveInfoButton" Content="Save Info" Width="100" Margin="5"/>
                <Button x:Name="ReloadButton" Content="Reload" Width="100" Margin="5"/>
                <Button x:Name="ExportButton" Content="Export Report" Width="150" Margin="5" Visibility="Collapsed"/>
            </StackPanel>

            <!-- Footer -->
            <TextBlock Text="SOC Incident Reporter" FontSize="12" FontWeight="Bold" HorizontalAlignment="Center" Margin="10,0,0,0"/>
            <TextBlock Text="Author: Simon .I" FontSize="12" HorizontalAlignment="Center"/>
            <TextBlock Text="Version: 2024.08.24" FontSize="12" HorizontalAlignment="Center"/>
            <TextBlock Text="Get the newest version from https://github.com/simon-im-security" FontSize="12" HorizontalAlignment="Center"/>
        </StackPanel>
    </Grid>
</Window>
"@

# Load the XAML into a PowerShell object
[xml]$XAMLReader = $XAML
$reader = New-Object System.Xml.XmlNodeReader $XAMLReader
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Function to update the UI based on incident type selection
function Update-UI {
    $selection = $Window.FindName("IncidentTypeComboBox").SelectedItem.Content
    $Window.FindName("InternalUseHeader").Visibility = "Collapsed"
    $Window.FindName("ExternalUseHeader").Visibility = "Collapsed"
    $Window.FindName("ContinuingExternalUseHeader").Visibility = "Collapsed"
    $Window.FindName("ClosingExternalUseHeader").Visibility = "Collapsed"
    $Window.FindName("NewIncidentPanel").Visibility = "Collapsed"
    $Window.FindName("NewIncidentExternalPanel").Visibility = "Collapsed"
    $Window.FindName("ContinuingIncidentPanel").Visibility = "Collapsed"
    $Window.FindName("ClosingIncidentPanel").Visibility = "Collapsed"

    # Hide all custom fields by default
    $Window.FindName("CustomIncidentTypeTextBox").Visibility = "Collapsed"
    $Window.FindName("CustomClientResponseTextBox").Visibility = "Collapsed"
    $Window.FindName("CustomClientContactSummaryTextBox").Visibility = "Collapsed"
    $Window.FindName("CustomContinuingClientResponseTextBox").Visibility = "Collapsed"
    $Window.FindName("CustomClosingClientResponseTextBox").Visibility = "Collapsed"
    $Window.FindName("CustomThreatLevelTextBox").Visibility = "Collapsed"

    if ($selection -eq "New Incident (for your first contact with the client)") {
        $Window.FindName("InternalUseHeader").Visibility = "Visible"
        $Window.FindName("NewIncidentPanel").Visibility = "Visible"
        $Window.FindName("ExternalUseHeader").Visibility = "Visible"
        $Window.FindName("NewIncidentExternalPanel").Visibility = "Visible"
        $Window.FindName("ExportButton").Visibility = "Visible"
    } elseif ($selection -eq "Continuing Incident (for your ongoing contact)") {
        $Window.FindName("InternalUseHeader").Visibility = "Visible"
        $Window.FindName("ContinuingIncidentPanel").Visibility = "Visible"
        $Window.FindName("ContinuingExternalUseHeader").Visibility = "Visible"
        $Window.FindName("ExportButton").Visibility = "Visible"
    } elseif ($selection -eq "Closing Incident (for final resolution and closing summary)") {
        $Window.FindName("InternalUseHeader").Visibility = "Visible"
        $Window.FindName("ClosingIncidentPanel").Visibility = "Visible"
        $Window.FindName("ClosingExternalUseHeader").Visibility = "Visible"
        $Window.FindName("ExportButton").Visibility = "Visible"
    }
}

# Function to toggle visibility of custom fields based on selection
function Toggle-CustomFields {
    param(
        $ComboBoxName,
        $TextBoxName
    )
    $comboBox = $Window.FindName($ComboBoxName)
    $textBox = $Window.FindName($TextBoxName)

    if ($comboBox.SelectedItem.Content -eq "Custom Field") {
        $textBox.Visibility = "Visible"
    } else {
        $textBox.Visibility = "Collapsed"
    }
}

# Function to save the information to a hidden local file
function Save_Info {
    $data = @{
        IncidentType           = $Window.FindName("IncidentTypeComboBox").SelectedItem.Content
        CyberIncidentType      = $Window.FindName("CyberIncidentTypeComboBox").SelectedItem.Content
        CustomIncidentType     = $Window.FindName("CustomIncidentTypeTextBox").Text
        ThreatLevel            = $Window.FindName("ThreatLevelComboBox").SelectedItem.Content
        CustomThreatLevel      = $Window.FindName("CustomThreatLevelTextBox").Text
        InitialFindings        = $Window.FindName("InitialFindingsTextBox").Text
        InternalNextSteps      = $Window.FindName("InternalNextStepsTextBox").Text
        ClientName             = $Window.FindName("ClientNameTextBox").Text
        AnalystDetails         = $Window.FindName("AnalystDetailsTextBox").Text
        ClientResponse         = $Window.FindName("ClientResponseComboBox").SelectedItem.Content
        CustomClientResponse   = $Window.FindName("CustomClientResponseTextBox").Text
        FurtherFindings        = $Window.FindName("FurtherFindingsTextBox").Text
        ClientContactSummary   = $Window.FindName("ClientContactSummaryComboBox").SelectedItem.Content
        CustomContactSummary   = $Window.FindName("CustomClientContactSummaryTextBox").Text
        NextSteps              = $Window.FindName("NextStepsTextBox").Text
        ContinuingClientName   = $Window.FindName("ContinuingClientNameTextBox").Text
        ContinuingAnalystDetails = $Window.FindName("ContinuingAnalystDetailsTextBox").Text
        ContinuingClientResponse = $Window.FindName("ContinuingClientResponseComboBox").SelectedItem.Content
        CustomContinuingClientResponse = $Window.FindName("CustomContinuingClientResponseTextBox").Text
        ClosingClientName      = $Window.FindName("ClosingClientNameTextBox").Text
        ClosingAnalystDetails  = $Window.FindName("ClosingAnalystDetailsTextBox").Text
        ClosingClientResponse  = $Window.FindName("ClosingClientResponseComboBox").SelectedItem.Content
        CustomClosingClientResponse = $Window.FindName("CustomClosingClientResponseTextBox").Text
        ResolutionSummary      = $Window.FindName("ResolutionSummaryTextBox").Text
    }
    $data | Export-Clixml -Path $savePath
    [System.Windows.MessageBox]::Show("Information saved successfully.", "Save Info", "OK", "Information")
}

# Function to reload the saved information
function Reload_Info {
    if (Test-Path $savePath) {
        $data = Import-Clixml -Path $savePath

        $Window.FindName("IncidentTypeComboBox").SelectedItem = $Window.FindName("IncidentTypeComboBox").Items | Where-Object { $_.Content -eq $data.IncidentType }
        $Window.FindName("CyberIncidentTypeComboBox").SelectedItem = $Window.FindName("CyberIncidentTypeComboBox").Items | Where-Object { $_.Content -eq $data.CyberIncidentType }
        $Window.FindName("CustomIncidentTypeTextBox").Text = $data.CustomIncidentType
        $Window.FindName("ThreatLevelComboBox").SelectedItem = $Window.FindName("ThreatLevelComboBox").Items | Where-Object { $_.Content -eq $data.ThreatLevel }
        $Window.FindName("CustomThreatLevelTextBox").Text = $data.CustomThreatLevel
        $Window.FindName("InitialFindingsTextBox").Text = $data.InitialFindings
        $Window.FindName("InternalNextStepsTextBox").Text = $data.InternalNextSteps
        $Window.FindName("ClientNameTextBox").Text = $data.ClientName
        $Window.FindName("AnalystDetailsTextBox").Text = $data.AnalystDetails
        $Window.FindName("ClientResponseComboBox").SelectedItem = $Window.FindName("ClientResponseComboBox").Items | Where-Object { $_.Content -eq $data.ClientResponse }
        $Window.FindName("CustomClientResponseTextBox").Text = $data.CustomClientResponse
        $Window.FindName("FurtherFindingsTextBox").Text = $data.FurtherFindings
        $Window.FindName("ClientContactSummaryComboBox").SelectedItem = $Window.FindName("ClientContactSummaryComboBox").Items | Where-Object { $_.Content -eq $data.ClientContactSummary }
        $Window.FindName("CustomClientContactSummaryTextBox").Text = $data.CustomContactSummary
        $Window.FindName("NextStepsTextBox").Text = $data.NextSteps
        $Window.FindName("ContinuingClientNameTextBox").Text = $data.ContinuingClientName
        $Window.FindName("ContinuingAnalystDetailsTextBox").Text = $data.ContinuingAnalystDetails
        $Window.FindName("ContinuingClientResponseComboBox").SelectedItem = $Window.FindName("ContinuingClientResponseComboBox").Items | Where-Object { $_.Content -eq $data.ContinuingClientResponse }
        $Window.FindName("CustomContinuingClientResponseTextBox").Text = $data.CustomContinuingClientResponse
        $Window.FindName("ClosingClientNameTextBox").Text = $data.ClosingClientName
        $Window.FindName("ClosingAnalystDetailsTextBox").Text = $data.ClosingAnalystDetails
        $Window.FindName("ClosingClientResponseComboBox").SelectedItem = $Window.FindName("ClosingClientResponseComboBox").Items | Where-Object { $_.Content -eq $data.ClosingClientResponse }
        $Window.FindName("CustomClosingClientResponseTextBox").Text = $data.CustomClosingClientResponse
        $Window.FindName("ResolutionSummaryTextBox").Text = $data.ResolutionSummary

        [System.Windows.MessageBox]::Show("Information reloaded successfully.", "Reload Info", "OK", "Information")
    } else {
        [System.Windows.MessageBox]::Show("No saved information found.", "Reload Info", "OK", "Warning")
    }
}

# Event handler for exporting the report
function Export_Report {
    $selection = $Window.FindName("IncidentTypeComboBox").SelectedItem.Content
    $report = "Incident Report:`r`n`r`n"

    # Internal Use Section
    $report += "Internal Use:`r`n"
    if ($selection -eq "New Incident (for your first contact with the client)") {
        $incidentType = $Window.FindName("CyberIncidentTypeComboBox").SelectedItem.Content
        $customIncidentType = $Window.FindName("CustomIncidentTypeTextBox").Text
        if ($incidentType -eq "Custom Field") { $incidentType = $customIncidentType }

        $threatLevel = $Window.FindName("ThreatLevelComboBox").SelectedItem.Content
        $customThreatLevel = $Window.FindName("CustomThreatLevelTextBox").Text
        if ($threatLevel -eq "Custom Field") { $threatLevel = $customThreatLevel }

        $initialFindings = $Window.FindName("InitialFindingsTextBox").Text
        $internalNextSteps = $Window.FindName("InternalNextStepsTextBox").Text

        $report += "Incident Type: $incidentType`r`n"
        $report += "Threat Level: $threatLevel`r`n"
        $report += "Initial Findings: $initialFindings`r`n"
        $report += "Internal Next Steps: $internalNextSteps`r`n"
    } elseif ($selection -eq "Continuing Incident (for your ongoing contact)") {
        $furtherFindings = $Window.FindName("FurtherFindingsTextBox").Text
        $clientContactSummary = $Window.FindName("ClientContactSummaryComboBox").SelectedItem.Content
        $customClientContactSummary = $Window.FindName("CustomClientContactSummaryTextBox").Text
        if ($clientContactSummary -eq "Custom Field") { $clientContactSummary = $customClientContactSummary }
        $nextSteps = $Window.FindName("NextStepsTextBox").Text

        $report += "Further Findings: $furtherFindings`r`n"
        $report += "Client Contact Summary: $clientContactSummary`r`n"
        $report += "Next Steps: $nextSteps`r`n"
    } elseif ($selection -eq "Closing Incident (for final resolution and closing summary)") {
        $resolutionSummary = $Window.FindName("ResolutionSummaryTextBox").Text

        $report += "Resolution Summary: $resolutionSummary`r`n"
    }

    # External Use Section
    $report += "`r`nExternal Use:`r`n"
    if ($selection -eq "New Incident (for your first contact with the client)") {
        $clientName = $Window.FindName("ClientNameTextBox").Text
        $clientResponse = $Window.FindName("ClientResponseComboBox").SelectedItem.Content
        $customClientResponse = $Window.FindName("CustomClientResponseTextBox").Text
        if ($clientResponse -eq "Custom Field") { $clientResponse = $customClientResponse }

        $clientResponse = $clientResponse -replace "\[Client Name\]", ($clientName -split " " | Select-Object -First 1)
        $yourDetails = $Window.FindName("AnalystDetailsTextBox").Text
        $clientResponse = $clientResponse -replace "\[Your Name\]", ($yourDetails -split "\|" | Select-Object -First 1).Trim()

        $report += "$clientResponse`r`n"
        $report += "$yourDetails`r`n"
    } elseif ($selection -eq "Continuing Incident (for your ongoing contact)") {
        $clientName = $Window.FindName("ContinuingClientNameTextBox").Text
        $clientResponse = $Window.FindName("ContinuingClientResponseComboBox").SelectedItem.Content
        $customContinuingClientResponse = $Window.FindName("CustomContinuingClientResponseTextBox").Text
        if ($clientResponse -eq "Custom Field") { $clientResponse = $customContinuingClientResponse }

        $clientResponse = $clientResponse -replace "\[Client Name\]", ($clientName -split " " | Select-Object -First 1)
        $yourDetails = $Window.FindName("ContinuingAnalystDetailsTextBox").Text
        $clientResponse = $clientResponse -replace "\[Your Name\]", ($yourDetails -split "\|" | Select-Object -First 1).Trim()

        $report += "$clientResponse`r`n"
        $report += "$yourDetails`r`n"
    } elseif ($selection -eq "Closing Incident (for final resolution and closing summary)") {
        $clientName = $Window.FindName("ClosingClientNameTextBox").Text
        $clientResponse = $Window.FindName("ClosingClientResponseComboBox").SelectedItem.Content
        $customClosingClientResponse = $Window.FindName("CustomClosingClientResponseTextBox").Text
        if ($clientResponse -eq "Custom Field") { $clientResponse = $customClosingClientResponse }

        $clientResponse = $clientResponse -replace "\[Client Name\]", ($clientName -split " " | Select-Object -First 1)
        $yourDetails = $Window.FindName("ClosingAnalystDetailsTextBox").Text
        $clientResponse = $clientResponse -replace "\[Your Name\]", ($yourDetails -split "\|" | Select-Object -First 1).Trim()

        $report += "$clientResponse`r`n"
        $report += "$yourDetails`r`n"
    }

    # Save the report to a temporary location
    $tempPath = [System.IO.Path]::GetTempPath()
    $reportFilePath = "$tempPath\Incident_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $report | Out-File -FilePath $reportFilePath -Encoding UTF8

    # Prompt the user to view the file
    $result = [System.Windows.MessageBox]::Show("The report has been saved to a temporary location. Would you like to view it now?", "Report Saved", "YesNo", "Question")
    if ($result -eq "Yes") {
        Start-Process "notepad.exe" -ArgumentList $reportFilePath
    }
}

# Assign the event handlers
$IncidentTypeComboBox = $Window.FindName("IncidentTypeComboBox")
$IncidentTypeComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Update-UI
})

$CyberIncidentTypeComboBox = $Window.FindName("CyberIncidentTypeComboBox")
$CyberIncidentTypeComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "CyberIncidentTypeComboBox" -TextBoxName "CustomIncidentTypeTextBox"
})

$ThreatLevelComboBox = $Window.FindName("ThreatLevelComboBox")
$ThreatLevelComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "ThreatLevelComboBox" -TextBoxName "CustomThreatLevelTextBox"
})

$ClientResponseComboBox = $Window.FindName("ClientResponseComboBox")
$ClientResponseComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "ClientResponseComboBox" -TextBoxName "CustomClientResponseTextBox"
})

$ClientContactSummaryComboBox = $Window.FindName("ClientContactSummaryComboBox")
$ClientContactSummaryComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "ClientContactSummaryComboBox" -TextBoxName "CustomClientContactSummaryTextBox"
})

$ContinuingClientResponseComboBox = $Window.FindName("ContinuingClientResponseComboBox")
$ContinuingClientResponseComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "ContinuingClientResponseComboBox" -TextBoxName "CustomContinuingClientResponseTextBox"
})

$ClosingClientResponseComboBox = $Window.FindName("ClosingClientResponseComboBox")
$ClosingClientResponseComboBox.Add_SelectionChanged([System.Windows.Controls.SelectionChangedEventHandler]{
    Toggle-CustomFields -ComboBoxName "ClosingClientResponseComboBox" -TextBoxName "CustomClosingClientResponseTextBox"
})

$SaveInfoButton = $Window.FindName("SaveInfoButton")
$SaveInfoButton.Add_Click([System.Windows.RoutedEventHandler]{
    Save_Info
})

$ReloadButton = $Window.FindName("ReloadButton")
$ReloadButton.Add_Click([System.Windows.RoutedEventHandler]{
    Reload_Info
})

$ExportButton = $Window.FindName("ExportButton")
$ExportButton.Add_Click([System.Windows.RoutedEventHandler]{
    Export_Report
})

# Initialize the UI correctly when the window loads
Update-UI

# Show the WPF window
$Window.ShowDialog() | Out-Null
