# Azure AD Conditional Access Policies
_Author: Chad Cox_  
_Created: January 2023_  
_Updated: January 2023_  

**How to use this guide**
* Below is a list of Conditional Access Policies that Microsoft recommends in an Azure AD Tenant.
* Each link contains information about each policy with notes about how to evaluate the impact of the policy.
* Use this method to shorten the amount of time it takes to deploy Conditional Access Policies in Azure AD, by proactively leveraging existing signinlogs and filtering to show the users that could be impacted.

**Table of Content**
* [Requirements](#Requirements)
* [Introduction](#Introduction)
* [Applications not being protected by Conditional Access Policies]()
* [Conditional Access Policies](#Introduction)
  * [Always require MFA]()
    * [Always require MFA from untrusted networks]()
    * [Always require MFA or Trusted Device or Compliant Device]()
    * [Always require MFA or Trusted Device or Compliant Device from untrusted networks]()
    * [Require MFA for Microsoft Graph PowerShell and Explorer]()
    * [Require MFA for Microsoft Azure Management]()
    * [Require privileged user to MFA]()
  * [Block Legacy Authentication]()
    * [Block privileged user from legacy authentication]()
    * [Block clients that do not support modern authentication]()
  * [Block the Directory Sync Account from non trusted locations]()
  * [Block Guest from Azure Management]()
  * [Require guest to MFA]()
  * [Require Compliant Device for Office 365]()
  * [No Persistent Browser and 1 Hour Session for Unmanaged Devices]()
  * [Require privileged user to use compliant device]()
  * [Block when user risk is high]()
  * [Block when sign-in risk is high]()
  * [Require MFA when sign-in risk is low, medium, or high]()
  * [Block when privileged users user risk is low medium high]()
  * [Block when privileged user sign in risk is low medium high]()
  * [Block when Directory Sync Account sign in risk is low medium high]()
  * [Require guest to MFA for Low and Medium Sign-in Risk]()
  * [Block Service Principal from Non Trusted Networks]()
  * [Block Service Principal with High Medium Low Risk]()

### Goals
* Protect Privileged Credentials
* Require trusted devices
* Do not depend on trusted networks / locations
* Always require multifactor
* Minimize the use of filters

### Requirements
* The best way to do this is sending the Azure AD Sign In Logs to Azure Monitor (LogAnalytics).
  * Instructions on how to set up: [Integrate Azure AD logs with Azure Monitor logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)
* Azure AD Premium 1 License are required for:
  * Conditional Access Policies
  * Sign in Logs to be sent to Log Analytics
  * Ability to query Sign in logs via microsoft graph

### Introduction

### Applications not being protected by Conditional Access Policies

```
//https://github.com/reprise99/Sentinel-Queries/blob/main/Azure%20Active%20Directory/Identity-Top20AppswithnoCA.kql
//This query shows applications that are not protected by conditional access policies.
let apps=
    SigninLogs
    | where TimeGenerated > ago (30d)
    | project TimeGenerated, ConditionalAccessPolicies, AppDisplayName
//Exclude native Microsoft apps that you can't enforce policy on or that are covered natively in Office 365
    | where AppDisplayName !in ("Microsoft Office Web Apps Service", "Microsoft App Access Panel", "Office Online Core SSO", "Microsoft Authentication Broker", "Microsoft Account Controls V2", "Microsoft 365 Support Service","Office Online Maker SSO","My Apps","My Profile")
    | mv-expand ConditionalAccessPolicies
    | extend CAResult = tostring(ConditionalAccessPolicies.result)
    | summarize ResultSet=make_set(CAResult) by AppDisplayName
    | where ResultSet !has "success" or ResultSet !has "failure"
    | project AppDisplayName;
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where AppDisplayName in (apps)
| summarize Count=count()by AppDisplayName
| top 20 by Count

```

**Comment**  
The image below, shows the applications and the logon count of those apps that is not being protected by some sort of Conditional Access Policy. Ideally every application will have a mfa requirement or a trusted/compliant policy requirement.  

![Untitled](./media/applicaationsnotprotectedbyca.jpg)

### Always require MFA
* Link to Microsoft Documentation: [Common Conditional Access policy: Require MFA for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa)  
* This policy will require all users logging into any application to MFA.  

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

**Comment**  
This policy is a harder policy to implement.  This query will return a unique list of users and applications that are not hitting up against a conditional access policy and not providing multifactor authentication.  Things to look for in the KQL results are applications that might have problems like the Windows Store and accounts that need to be excluded such as faceless user objects or "service accounts".  

Expect to see most of the users in a org in this list.  The goal is to find the users and applications that need to be excluded because it would cause impact.

Looking at the image below.  I would make sure to exclude the breakglass account and the sync account as those are accounts that should not have this policy applied to it.  

![Untitled](./media/alwaysrequiremfa.jpg)

### Always require MFA from untrusted networks
* Link to Microsoft Documentation: [Common Conditional Access policy: Require MFA for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa)  
* This policy will require all users logging into any application to MFA when signing in from networks not flagged as trusted.  

**Conditional Access Policy Setup**
* Users
  * Include: All Users
  * Exclude: Breakglass, _Exclusion Group_, Directory Role (Directory Sync Accounts), Guest
* Cloud Apps or Actions
  * Select what this policy applies to: Cloud apps
  * Include: All Cloud Apps
  * Exclude: Windows Store
* Conditions
  * Locations
  * Include: Any Location
  * Exclude: All trusted locations
* Grant
  * Grant Access
  * Require Multi-Factor Authentication
  * Require all the selected controls 

**Log Analytics AAD SigninLogs Query (KQL)**
```
//this query will show users that login from untrusted networks and only provide singlefactor authentication
//list of exclusion applications that seem to always have mfa
let excludeapps = pack_array("Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V2","Microsoft Intune Company Portal","Microsoft Mobile Application Management");
//get an array of guest accounts to exclude from the non interactive logs
let guests = SigninLogs
| where TimeGenerated > ago(14d) and UserType == "Guest" and ResultType == 0 
| where AppDisplayName  !in (excludeapps)
| distinct UserPrincipalName;
AADNonInteractiveUserSignInLogs 
| where TimeGenerated > ago(14d)
| where HomeTenantId == ResourceTenantId and UserPrincipalName !in (guests)
| where NetworkLocationDetails !contains "trustedNamedLocation"
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation','')) 
| union SigninLogs 
| where TimeGenerated > ago(14d) 
| where UserType <> "Guest" 
| where NetworkLocationDetails !contains "trustedNamedLocation"
| where ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation','')) 
| where AppDisplayName  !in (excludeapps)
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement,TrustedLocation
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement,TrustedLocation
```

**Comment**  
This policy is not required if you were able to implement: Always require MFA  
Also this policy has a network based filter which means if someone was able to "trick" the ip they would bypass important protections.  
This query will return a unique list of users and applications that are not hitting up against a conditional access policy and not providing multifactor authentication.  Things to look for in the KQL results are applications that might have problems like the Windows Store and accounts that need to be excluded such as faceless user objects or "service accounts".  

The goal is to find the users and applications that need to be excluded because it would cause impact. Also note if users are in this list that never access outside of the org then there is a good chance the IP that user is coming from is not trusted.  

Looking at the image below.  I would make sure to exclude the breakglass account from the policy and I would research the sync account to figure out why its being used outside a trusted network.  

![Untitled](./media/alwaysrequiremfauntrustednetwork.jpg)

### Always require MFA or Trusted Device or Compliant Device
* Link to Microsoft Documentation: [Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device)  

**Log Analytics AAD SigninLogs Query (KQL)**
```
//https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device
//Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users
//list of exclusion applications that seem to always have mfa
let excludeapps = pack_array("Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V2","Microsoft Intune Company Portal","Microsoft Mobile Application Management");
//get an array of guest accounts to exclude from the non interactive logs
let guests = SigninLogs
| where TimeGenerated > ago(14d) and UserType == "Guest" and ResultType == 0 
| where AppDisplayName  !in (excludeapps)
| distinct UserPrincipalName;
//query the non interactive logs
let AADNon = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName  !in (excludeapps)
| where HomeTenantId == ResourceTenantId and UserPrincipalName !in (guests)
| extend trustType = tostring(parse_json(DeviceDetail).trustType) 
| extend isCompliant = tostring(parse_json(DeviceDetail).isCompliant) 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation',''))
| extend os = tostring(parse_json(DeviceDetail).operatingSystem) 
| where isCompliant <> 'true' and trustType <> "Hybrid Azure AD joined"  
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation, trustType,isCompliant,os, Category;
//query the interactive logs
let AAD = SigninLogs 
| where TimeGenerated > ago(14d) and UserType <> "Guest" and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName  !in (excludeapps) 
| extend trustType = tostring(DeviceDetail.trustType) 
| extend isCompliant = tostring(DeviceDetail.isCompliant) 
| extend os = tostring(DeviceDetail.operatingSystem) 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation',''))
| where isCompliant <> 'true' and trustType <> "Hybrid Azure AD joined"  
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation, trustType,isCompliant,os,Category;
//combine the results
AADNon
| union AAD
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation,trustType,isCompliant,os
```

### Always require MFA or Trusted Device or Compliant Device from untrusted networks
* Link to Microsoft Documentation: [Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device)
* Link to Microsoft Documentation: [Named locations](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa#named-locations)  

**Log Analytics AAD SigninLogs Query (KQL)**
```
let excludeapps = pack_array("Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V2","Microsoft Intune Company Portal","Microsoft Mobile Application Management");
//get an array of guest accounts to exclude from the non interactive logs
let guests = SigninLogs
| where TimeGenerated > ago(14d) and UserType == "Guest" and ResultType == 0 
| where AppDisplayName  !in (excludeapps)
| distinct UserPrincipalName;
//query the non interactive logs
let AADNon = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName  !in (excludeapps)
| where HomeTenantId == ResourceTenantId and NetworkLocationDetails !contains "trustedNamedLocation" and UserPrincipalName !in (guests)
| extend trustType = tostring(parse_json(DeviceDetail).trustType) 
| extend isCompliant = tostring(parse_json(DeviceDetail).isCompliant) 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation',''))
| extend os = tostring(parse_json(DeviceDetail).operatingSystem) 
| where isCompliant <> 'true' and trustType <> "Hybrid Azure AD joined"  
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation, trustType,isCompliant,os, Category;
//query the interactive logs
let AAD = SigninLogs 
| where TimeGenerated > ago(14d) and UserType <> "Guest" and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName  !in (excludeapps) 
| where NetworkLocationDetails !contains "trustedNamedLocation"
| extend trustType = tostring(DeviceDetail.trustType) 
| extend isCompliant = tostring(DeviceDetail.isCompliant) 
| extend os = tostring(DeviceDetail.operatingSystem) 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation',''))
| where isCompliant <> 'true' and trustType <> "Hybrid Azure AD joined"  
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation, trustType,isCompliant,os,Category;
//combine the results
AADNon
| union AAD
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, TrustedLocation,trustType,isCompliant,os
```

### Require MFA for Microsoft Graph PowerShell and Explorer
* Link to Microsoft Documentation: [Blocking PowerShell for EDU Tenants](https://learn.microsoft.com/en-us/schooldatasync/blocking-powershell-for-edu)  

**Log Analytics AAD SigninLogs Query (KQL)**
```
let includeapps = pack_array("Graph Explorer","Microsoft Graph PowerShell");
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication"
| where AppDisplayName in (includeapps) 
| union SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName in (includeapps)
| distinct AppDisplayName, UserPrincipalName, ConditionalAccessStatus, AuthenticationRequirement
```

### Require MFA for Microsoft Azure Management

**Log Analytics AAD SigninLogs Query (KQL)**
```
//https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-azure-management
//Common Conditional Access policy: Require MFA for Azure management
let includeapps = pack_array("Windows Azure Service Management API");
AADNonInteractiveUserSignInLogs
| union SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where  ResourceDisplayName in (includeapps)
| distinct AppDisplayName, UserPrincipalName, ConditionalAccessStatus, AuthenticationRequirement, ResourceDisplayName
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
// URL: https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-tutorial-require-mfa
SigninLogs 
| where TimeGenerated > ago(14d) and UserType == "Guest" 
| where ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AADTenantId <> HomeTenantId
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement,Category 
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, Category
```

### Require Compliant Device for Office 365

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### No Persistent Browser and 1 Hour Session for Unmanaged Devices

**Log Analytics AAD SigninLogs Query (KQL)**
```
SigninLogs 
| where TimeGenerated > ago(14d) and ResultType == 0 and UserType <> "Guest" 
| extend trustType = tostring(DeviceDetail.trustType) 
| extend isCompliant = tostring(DeviceDetail.isCompliant) 
| extend deviceName = tostring(DeviceDetail.displayName) 
| extend os = tostring(DeviceDetail.operatingSystem) 
| extend TrustedLocation = tostring(iff(NetworkLocationDetails contains 'trustedNamedLocation', 'trustedNamedLocation','')) 
| where isCompliant <> 'true' and trustType <> "Hybrid Azure AD joined" and ClientAppUsed == "Browser" 
| distinct UserPrincipalName, os, deviceName, trustType, isCompliant, TrustedLocation
```

### Block clients that do not support modern authentication

**Log Analytics AAD SigninLogs Query (KQL)**
```
AADNonInteractiveUserSignInLogs
| union SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| extend ClientAppUsed = iff(isempty(ClientAppUsed) == true, "Unknown", ClientAppUsed)  
| extend isLegacyAuth = case(ClientAppUsed contains "Browser", "No", ClientAppUsed contains "Mobile Apps and Desktop clients", "No", ClientAppUsed contains "Exchange ActiveSync", "Yes", ClientAppUsed contains "Exchange Online PowerShell","Yes", ClientAppUsed contains "Unknown", "Unknown", "Yes") 
| where isLegacyAuth == "Yes"
| distinct UserDisplayName, UserPrincipalName, AppDisplayName, ClientAppUsed, isLegacyAuth, UserAgent, Category
```

### Require privileged user to use compliant device

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block when user risk is high

**Log Analytics AAD SigninLogs Query (KQL)**
```
SigninLogs 
| where TimeGenerated > ago(14d) 
| where RiskState == "atRisk" and RiskLevelAggregated == "high"
| project AppDisplayName, UserPrincipalName, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskDetail,IsRisky, RiskEventTypes_V2, MfaDetail, ConditionalAccessStatus, AuthenticationRequirement, ResultType
```

### Block when sign-in risk is high

**Log Analytics AAD SigninLogs Query (KQL)**
```
SigninLogs 
| where TimeGenerated > ago(14d)
| where RiskLevelDuringSignIn in ("high") 
| project ResultType, ResultDescription,AppDisplayName, UserPrincipalName, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskDetail, RiskEventTypes_V2, ConditionalAccessStatus, AuthenticationRequirement
```

### Require MFA when sign-in risk is low, medium, or high

**Log Analytics AAD SigninLogs Query (KQL)**
```
SigninLogs 
| where TimeGenerated > ago(14d) and ResultType == 0 
| where RiskLevelDuringSignIn in ("high","medium","low") 
| project AppDisplayName, UserPrincipalName, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskDetail, RiskEventTypes_V2, ConditionalAccessStatus, AuthenticationRequirement
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
SigninLogs | where TimeGenerated > ago(14d) and UserType == "Guest" and ResultType == 0 
| where AADTenantId <> HomeTenantId
| where RiskLevelDuringSignIn in ("high","medium") 
| distinct AppDisplayName,UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement,Category,RiskLevelDuringSignIn,RiskDetail 
| summarize apps=make_list(AppDisplayName) by UserPrincipalName,ConditionalAccessStatus,AuthenticationRequirement, RiskLevelDuringSignIn,RiskDetail
```

### Block Service Principal from Non Trusted Networks

**Log Analytics AAD SigninLogs Query (KQL)**
```

```

### Block Service Principal with High Medium Low Risk

**Log Analytics AAD SigninLogs Query (KQL)**
```
//nothing has been written yet to look into these logs
//ServicePrincipalRiskEvents
//RiskyServicePrincipals
```

