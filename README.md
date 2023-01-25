# Azure AD Conditional Access Policies
_Author: Chad Cox_
_Created: January 2023_
_Updated: January 2023_

* Below is a list of Conditional Access Policies that Microsoft recommends in an Azure AD Tenant.
* Each link contains information about each policies with ways to help evaluate policies.
* Use this method to shorten the amount of time it takes to deploy Conditional Access Policies in Azure AD



**Table of Content**
- [Requirements](#Requirements)
- [Introduction](#Introduction)
- [Always require MFA](#Always require MFA)

### Requirements
* The best way to do this is sending the Azure AD Sign In Logs to Azure Monitor (LogAnalytics).
  * Instructions on how to set up: [Integrate Azure AD logs with Azure Monitor logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)
* Azure AD Premium 1 License are required for:
  * Conditional Access Policies
  * Sign in Logs to be sent to Log Analytics
  * Ability to query Sign in logs via microsoft graph
### Introduction
### Always require MFA
### Always require MFA from untrusted networks
### Always require MFA or Trusted Device or Compliant Device
### Always require MFA or Trusted Device or Compliant Device from untrusted networks
### Require MFA for Microsoft Graph PowerShell and Explorer
### Require MFA for Microsoft Azure Management
### Block Legacy Authentication
### Require privileged user to MFA
### Block privileged user from legacy authentication
### Block the Directory Sync Account from non trusted locations
### Block Guest from Azure Management
### Require guest to MFA
### Require Compliant Device for Office 365
### No Persistent Browser and 1 Hour Session for Unmanaged Devices
### Block clients that do not support modern authentication
### Require privileged user to use compliant device
### Block when user risk is high
### Block when sign-in risk is high
### Require MFA when sign-in risk is low, medium, or high
### Block when privileged users user risk is low medium high
### Block when privileged user sign in risk is low medium high
### Block when Directory Sync Account sign in risk is low medium high
### Require guest to MFA for Low and Medium Sign-in Risk
### Workload Identities / Service Principals
### Block Service Principal from Non Trusted Networks
### Block Service Principal with High Medium Low Risk
