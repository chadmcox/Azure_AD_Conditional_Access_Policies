# Azure AD Conditional Access Policies
_Author: Chad Cox_  
_Created: January 2023_  
_Updated: January 2023_  

* Below is a list of Conditional Access Policies that Microsoft recommends in an Azure AD Tenant.
* Each link contains information about each policies with ways to help evaluate policies.
* Use this method to shorten the amount of time it takes to deploy Conditional Access Policies in Azure AD

**Table of Content**
* [Requirements](#Requirements)
* [Introduction](#Introduction)
* [Always require MFA]()
* [Always require MFA from untrusted networks]()
* [Always require MFA or Trusted Device or Compliant Device]()
* [Always require MFA or Trusted Device or Compliant Device from untrusted networks]()
* [Require MFA for Microsoft Graph PowerShell and Explorer]()
* [Require MFA for Microsoft Azure Management]()
* [Block Legacy Authentication]()
* [Require privileged user to MFA]()
* [Block privileged user from legacy authentication]()
* [Block the Directory Sync Account from non trusted locations]()
* [Block Guest from Azure Management]()
* [Require guest to MFA]()
* [Require Compliant Device for Office 365]()
* [No Persistent Browser and 1 Hour Session for Unmanaged Devices]()
* [Block clients that do not support modern authentication]()
* [Require privileged user to use compliant device]()
* [Block when user risk is high]()
* [Block when sign-in risk is high]()
* [Require MFA when sign-in risk is low, medium, or high]()
* [Block when privileged users user risk is low medium high]()
* [Block when privileged user sign in risk is low medium high]()
* [Block when Directory Sync Account sign in risk is low medium high]()
* [Require guest to MFA for Low and Medium Sign-in Risk]()
* [Workload Identities / Service Principals]()
* [Block Service Principal from Non Trusted Networks]()
* [Block Service Principal with High Medium Low Risk]()

### Goals
* Protect Privileged Credentials
* Require trusted devices
* Do not depend on trusted networks / locations
* Always require multifactor

### Requirements
* The best way to do this is sending the Azure AD Sign In Logs to Azure Monitor (LogAnalytics).
  * Instructions on how to set up: [Integrate Azure AD logs with Azure Monitor logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)
* Azure AD Premium 1 License are required for:
  * Conditional Access Policies
  * Sign in Logs to be sent to Log Analytics
  * Ability to query Sign in logs via microsoft graph

### Introduction
### Always require MFA
* Link to Microsoft Documentation: [Common Conditional Access policy: Require MFA for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa)  

**Conditional Access Policy Setup**
* Users
  * Include: All Users
  * Exclude: Breakglass, _Exclusion Group_, Directory Role (Directory Sync Accounts), Guest
* Cloud Apps or Actions
  * Select what this policy applies to: Cloud apps
  * Include: All Cloud Apps
  * Exclude: Windows Store
* Conditions
* Grant
  * Grant Access
  * Require Multi-Factor Authentication
  * Require all the selected controls  

_Note: this policy will more than likely break on premise sync accounts, make sure the Directory Sync Accounts Role is in the exclusion group._  

**Comment**  
This policy is a harder policy to implement.  This query will return a unique list of users and applications that are not hitting up against a conditional access policy and not providing multifactor authentication.  Things to look for in the KQL results are applications that might have problems like the Windows Store and accounts that need to be excluded such as faceless user objects or "service accounts".

**Log Analytics AAD SigninLogs Query (KQL)**
```
let excludeapps = pack_array("Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V2","Microsoft Intune Company Portal","Microsoft Mobile Application Management");
//get an array of guest accounts to exclude from the non interactive logs
let guests = SigninLogs
| where TimeGenerated > ago(14d) and UserType == "Guest" and ResultType == 0 
| where AppDisplayName  !in (excludeapps)
| distinct UserPrincipalName;
AADNonInteractiveUserSignInLogs 
| where TimeGenerated > ago(14d)
| where HomeTenantId == ResourceTenantId and UserPrincipalName !in (guests)
| union SigninLogs 
| where TimeGenerated > ago(14d) 
| where UserType <> "Guest" 
| where ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName  !in (excludeapps)
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, Category 
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement,Category
```
   
![Untitled](./media/alwaysrequiremfa.jpg)

### Always require MFA from untrusted networks
* Link to Microsoft Documentation: [Common Conditional Access policy: Require MFA for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa)  

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Always require MFA or Trusted Device or Compliant Device
* Link to Microsoft Documentation: [Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device)  

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Always require MFA or Trusted Device or Compliant Device from untrusted networks
* Link to Microsoft Documentation: [Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device)
* Link to Microsoft Documentation: [Named locations](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa#named-locations)  

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require MFA for Microsoft Graph PowerShell and Explorer
* Link to Microsoft Documentation: [Blocking PowerShell for EDU Tenants](https://learn.microsoft.com/en-us/schooldatasync/blocking-powershell-for-edu)  

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require MFA for Microsoft Azure Management

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block Legacy Authentication
* Link to Microsoft Documentation: [Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy)  
**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require privileged user to MFA

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block privileged user from legacy authentication

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block the Directory Sync Account from non trusted locations

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block Guest from Azure Management
* Link to Microsoft Documentation: [Common Conditional Access policy: Require MFA for Azure management](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-azure-management)  

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require guest to MFA

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require Compliant Device for Office 365

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### No Persistent Browser and 1 Hour Session for Unmanaged Devices

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block clients that do not support modern authentication

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require privileged user to use compliant device

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when user risk is high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when sign-in risk is high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require MFA when sign-in risk is low, medium, or high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when privileged users user risk is low medium high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when privileged user sign in risk is low medium high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when Directory Sync Account sign in risk is low medium high

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Require guest to MFA for Low and Medium Sign-in Risk

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Workload Identities / Service Principals

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block Service Principal from Non Trusted Networks

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block Service Principal with High Medium Low Risk

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

