# Conditional Access Policy: Title
* Link to Microsoft Documentation: [Blocking PowerShell for EDU Tenants](https://learn.microsoft.com/en-us/schooldatasync/blocking-powershell-for-edu)
* Policy Prereqs: Azure AD Premium 1 License.

## Conditional Access Policy Settings
* Users
  * Include: All Users
  * Exclude: Breakglass, _Exclusion Group_
* Cloud Apps or Actions
  * Select what this policy applies to: Cloud Apps
  * Include: Microsoft Graph PowerShell, Graph Explorer
* Conditions
* Grant
  * Grant Access
  * Require Multi-Factor Authentication
  * Require all the selected controls
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
let includeapps = pack_array("Graph Explorer","Microsoft Graph PowerShell");
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication"
| where AppDisplayName in (includeapps) 
| union SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication" 
| where AppDisplayName in (includeapps)
| distinct AppDisplayName, UserPrincipalName, ConditionalAccessStatus, AuthenticationRequirement
```

### PowerShell Script
[Link to script]()

