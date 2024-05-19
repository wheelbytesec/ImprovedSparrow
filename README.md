# Sparrow.ps1 Repository

Welcome to the **Sparrow.ps1** repository! This repository contains the **Sparrow.ps1** script, created by CISA's Cloud Forensics team to assist in detecting possible compromised accounts and applications within the Azure/M365 environment. The tool is designed for use by incident responders, providing a focused examination of user and application activity pertinent to identity and authentication-based attacks.

## Features

**Sparrow.ps1** performs the following tasks:

- **Module Management:** Checks and installs the required PowerShell modules on the analysis machine.
- **Unified Audit Log Analysis:** Searches the unified audit log in Azure/M365 for specific indicators of compromise (IoCs).
- **Domain Listing:** Lists Azure AD domains for the tenant.
- **Service Principal Examination:** Checks Azure service principals and their Microsoft Graph API permissions to identify potential malicious activity.
- **Data Export:** Outputs the results into multiple CSV files in a default directory.

## Enhancements and Improvements

The script has been enhanced with the following additional features and improvements:

1. **New Detection Techniques:**
   - **Suspicious Logins:** Detects logins from unusual locations or devices.
   - **Privileged Role Assignments:** Monitors assignments of privileged roles such as Global Administrator.
   - **Risky User Activity:** Identifies users flagged as risky by Azure AD Identity Protection.
   - **Conditional Access Policy Changes:** Monitors modifications to conditional access policies.
   - **Unusual Application Consents:** Detects consents granted to applications that are not commonly used.

2. **Logging and Error Handling:**
   - Added detailed logging and error handling for each operation.
   - Errors are captured in an error log array for easier troubleshooting.

3. **Enhanced Reporting:**
   - Generates a comprehensive HTML report using the `PSWriteHTML` module.
   - Includes summary tables, charts, and detailed logs in the report.

## Usage

To use the enhanced **Sparrow.ps1** script, simply run it in your PowerShell environment. The script will automatically check for required modules, perform the analysis, and generate a detailed report with the findings.
![3dgifmaker72299](https://github.com/wheelbytesec/ImprovedSparrow/assets/170215972/288bda06-0e34-4a00-8d28-70bff89e1f4f)



```powershell
# Example of running the enhanced Sparrow.ps1 script
.\Sparrow.ps1
