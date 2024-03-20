# Essential Eight Compliance Review

## Description:
Essential Eight Compliance Review is a PowerShell script designed to check various security compliance measures on a Windows system.
It covers critical security areas such as application whitelisting, secure admin access, Windows updates, Microsoft Office macro settings, protection-based software, unnecessary services, multi-factor authentication, and daily backup checks.

## Features:
- Conducts comprehensive security compliance assessments.
- Generates a detailed HTML report highlighting compliance status for each security measure.
- Provides insights into potential security vulnerabilities and areas for improvement.

## Screenshot:
![Essential Eight Compliance Review](https://github.com/simon-im-security/Essential-Eight-Compliance-Review/blob/main/essential-eight-compliance-review-image.png)

## Usage:
To execute the script, follow these steps:

Open PowerShell and execute the below command. This command will temporarily bypass any execution policy restrictions for the current session, enabling the script to execute before reverting back to the original policy.
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; $url = "https://raw.githubusercontent.com/simon-im-security/Essential-Eight-Compliance-Review/main/Essential%20Eight%20Compliance%20Review.ps1"; $tempScriptPath = "$env:TEMP\EssentialEightComplianceReview.ps1"; Invoke-WebRequest -Uri $url -OutFile $tempScriptPath; & $tempScriptPath -ExecutionPolicy Bypass
