# Conditional Access Policy: Always require MFA or Trusted Device or Compliant Device from untrusted networks
* Link to Microsoft Documentation: [Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device)
* Link to Microsoft Documentation: [Named locations](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa#named-locations)
* Policy Prereqs: Azure AD Premium 1 License.

## Conditional Access Policy Settings
* Users
  * Include: All Users
  * Exclude: Breakglass, _Exclusion Group_, Directory Role (Directory Sync Accounts), Guest
* Cloud Apps or Actions
  * Select what this policy applies to: Cloud apps
  * Include: All Cloud Apps
  * Exclude: None
* Conditions
* Grant
  * Grant Access
  * Require Require multifactor authentication, Require device to be marked as compliant, and Require hybrid Azure AD joined device
  * Require one of the selected controls
## Find Possible Impact
* Using Log analytics to query the sign in logs is the fastest and easiest way to determine impact.  Not everyone uses log analytics so I have provided PowerShell Scripts that can be used that query the graph api instead.
* Review the results from the Log Analytics KQL Query or PowerShell Script
* Look for accounts that could be impacted by the policy. Remediate or exclude the users that might be impacted from this policy.

### Log Analytics KQL
This query can be ran to look at possible impact of this Conditional Access Policy  
Requirement: [Integrate Azure AD logs with Azure Monitor logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)  
Instructions:
 * Open the Azure AD Portal
 * Navigate to Log Analytics
 * Copy and Paste the kql from below into the search window
 * Then run it.
```
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

### PowerShell Script
[Link to script]()
