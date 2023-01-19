# Title
* Link to Microsoft Documentation: [Link to Microsoft Documentation]()
* Policy Prereqs:

## Conditional Access Policy Settings

## Find Possible Impact
* Review the results from the Log Analytics KQL Query or PowerShell Script
* Look for accounhs that could be impacted by the policy and consider remediating or excluding the account from receiving the policy.

### Log Analytics KQL
This query can be ran to look at possible impact of this Conditional Access Policy  
Requirement: [Integrate Azure AD logs with Azure Monitor logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics)
 * Open the Azure AD Portal
 * Navigate to Log Analytics
 * Copy and Paste the kql from below into the search window
 * Then run it.
```
//

```

### PowerShell Script
[Link to script]()
