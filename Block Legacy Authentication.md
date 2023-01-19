# Conditional Access Policy: Title
* Link to Microsoft Documentation: [Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy)
* Policy Prereqs: Azure AD Premium 1 License.

## Conditional Access Policy Settings

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

AADNonInteractiveUserSignInLogs
| union SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| extend ClientAppUsed = iff(isempty(ClientAppUsed) == true, "Unknown", ClientAppUsed)  
| extend isLegacyAuth = case(ClientAppUsed contains "Browser", "No", ClientAppUsed contains "Mobile Apps and Desktop clients", "No", ClientAppUsed contains "Exchange ActiveSync", "Yes", ClientAppUsed contains "Exchange Online PowerShell","Yes", ClientAppUsed contains "Unknown", "Unknown", "Yes") 
| where isLegacyAuth == "Yes"
| distinct UserDisplayName, UserPrincipalName, AppDisplayName, ClientAppUsed, isLegacyAuth, UserAgent, Category

```

### PowerShell Script
[Link to script]()

