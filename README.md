# Essential Eight Compliance Review for End Users

## Introduction

Welcome to the **Essential Eight Compliance Review for End Users** project. This tool is designed to help organisations ensure that their Windows systems comply with the Essential Eight cybersecurity framework. This script focuses on areas relevant to end users, such as verifying that updates are installed, backups are functioning, and the logged-in user's account is correctly configured as a standard account.

## Key Features

- **Admin Account Usage Check**: Verifies that the logged-in user's account is a standard account, not an administrator, to minimise security risks.
- **Windows Update Verification**: Ensures that the latest Windows updates have been installed within the last 30 days.
- **Daily Backup Checks**: Confirms that backup services like OneDrive are installed and running to protect against data loss.
- **Microsoft Office Macros**: Checks that macros in Microsoft Office are appropriately restricted to prevent malicious code execution.
- **Unnecessary Services Check**: Identifies and flags any unnecessary services running on the system.
- **Protection-Based Software**: Ensures that essential security software, such as antivirus or endpoint protection, is running.
- **Application Whitelisting**: Verifies that only approved software is allowed to run, reducing the risk of malware infections.
- **Multi-Factor Authentication (MFA)**: Confirms that MFA is enabled to provide an additional layer of security.

## Advantages of the Script

### Automated Compliance Checks
- The script automates the process of checking key security compliance measures, saving time and reducing the risk of human error.
- By running this script regularly, organisations can ensure that their systems are consistently aligned with the Essential Eight Level 1 cybersecurity framework.

### Customisable to Organisational Needs
- The script includes toggles for each compliance check, allowing organisations to enable or disable specific checks based on their requirements.
- This flexibility ensures that the tool can be tailored to fit the unique security policies and procedures of different organisations.

### End User Engagement
- The script is designed to interact directly with end users, asking them to provide reasons for any non-compliant areas. This engagement helps raise awareness and reinforces the importance of adhering to security best practices.
- By involving end users in the compliance process, organisations can foster a culture of responsibility and vigilance among their staff.

### Educational Opportunities
- Each compliance check in the script includes an explanation of why the check is important. For example, if a user's account is still an administrator, the script informs them of the security risks associated with this configuration.
- This educational aspect helps users understand the impact of their actions on overall security, making them more likely to follow best practices in the future.

### Visual and Clear Reporting
- The script generates clear, user-friendly reports that can be shared with IT teams or used for training purposes. These reports highlight areas of concern and can be used as a basis for further education or remediation.
- The output includes detailed explanations of non-compliant items, making it easier for end users to comprehend and address issues.

### Improved Security Posture
- By regularly running this script, organisations can ensure that their end users' systems are secure and compliant with the Essential Eight Level 1 framework.
- The script helps identify potential vulnerabilities before they can be exploited, thus improving the overall security posture of the organisation.

## Usage Instructions

```powershell
# Request Temporary Bypass of Execution Policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Download and run the script directly from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/simon-im-security/Essential-Eight-Compliance-Review-End-Users/main/Essential%20Eight%20Compliance%20Review%20for%20End%20Users.ps1" -OutFile "$env:TEMP\EssentialEightComplianceReview.ps1"
& "$env:TEMP\EssentialEightComplianceReview.ps1"

```

## Sample Output

Below is an example of what you can expect from the script's output:

![Sample Output](https://raw.githubusercontent.com/simon-im-security/Essential-Eight-Compliance-Review-End-Users/main/image_output_sample.png)

---
