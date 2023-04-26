## Recommended Conditional Access Policies
## Best Practices
 * Minimize the use of location based policies
 * Most companies do not have compliance around MacOS or Linux, In the event you do not focus those policies on Windows.  Something is better than nothing.
 * Group based policies are great for one off requirements. Most holes exist because groups are poorly maintain and do not include all the accounts. Base policies should be focus'd on all users.
 * 

## Persona's
 * **All Users** = All Users
 * **Internal Users** = All Users Exclude Guest
 * **Privileged Role Members** = Directory Roles (Application Administrator,Authentication Administrator,Cloud Application Administrator,Conditional Access Administrator,Exchange Administrator,Global Administrator,Helpdesk Administrator,Hybrid Identity Administrator,Password Administrator,Privileged Authentication Administrator,Privileged Role Administrator,Security Administrator,SharePoint Administrator,User Administrator)
 * **Directory Sync Account** = Directory Role (Directory Sync Account)
 * **Break Glass Account** = Emergency Account that needs to be excluded from all policies
 * **Accounts Excluded** = Usually Service accounts or vault accounts that present an issue because MFA cannot be used.
 * **Azure Subscription Owners** = These are actual owners of Azure Subscriptions.

## Apps
* If not specified All Cloud Apps is required for the conditional access policies.

## Base Protection
 * Require internal users to use trusted or compliant device for register security information
 * Require MFA for Microsoft Intune enrollment
 * Require MFA for device enrollment
 * Require MFA all guest
 * Require MFA for privileged role members
 * Require internal users to use compliant or trusted device for office 365
 * Require MFA for internal users from non trusted location
 * Require privileged role member to use compliant device
 * Require MFA for Azure Subscription Owners
 * Require MFA for all users when accessing Microsoft Intune
 * Require MFA for all users when accessing Microsoft Azure Management
 * Require MFA for all users when accessing Microsoft Graph PowerShell and Graph Explorer

## Identity Protection
 * Block all users when user risk is high
 * Block all users when sign-in risk is high
 * Require MFA for all users when sign-in risk is medium
 * Block privileged role members when sign-in risk is low, medium and high
 * Block privileged role members when user risk is low, medium and high
 * Block all users access to Microsoft Azure Management when sign-in risk is low, medium and high
 * Block all users access to Microsoft Graph PowerShell and Graph Explorer when sign-in risk is low, medium and high
 * Block directory sync account when sign in risk is low, medium and high
 * Block internal users from register security information when sign in risk is low, medium and high

## Data Protection
 * Restrict guest to less than 8 hour session limit
 * Restrict privileged role members to less than 8 hour session limit
 * Restrict internal users using nontrusted or noncompliant device to 1 hour session limit
 * Restrict internal users using nontrusted or noncompliant device to no persistent browser session
 * Block guest from using mobile apps and desktop apps

## Attack Surface Reduction
 * Block all users legacy authentication
 * Block privileged role members legacy authentication
 * Block privileged role members from unsupported platforms.
 * Block all users access from tor exit nodes
 * Block guest access from unexpected countries
 
---

### Block guest access to non-approved apps

| Users | Cloud Apps or Actions | Conditions | Grant | Session |
| --------------------- | --------------------- | --------------------- | --------------------- | --------------------- |
| Include: guest  <br /> Exclude: BreakGlass  | Include: All Cloud Apps  <br /> Excluded: Office 365, Other B2B approved apps |  | Block |  |

**Prereq:**  

**Comment:** This Conditional Access Policy is used to make sure guest (external B2B) are only allowed to access applications they need access to.  This examples blocks everything but Office 365 so that teams and sharepoint collaberation can continue to work.  **Guest should be blocked from things like Microsoft Azure Management, Microsoft Graph PowerShell, Microsoft Graph Explorer, VPNs, and HR Apps.**  

**Log Analytics Queries (KQL) against AAD Signin Logs**
 * [Find possible guest impact by blocking Graph Explorer and MS Graph PowerShell](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Log%20Analytics/Conditional%20Access%20Policy/Guest%20Scenerios/Find%20possible%20guest%20impact%20by%20blocking%20Graph%20Explorer%20and%20MS%20Graph%20PowerShell.kql)
 * [Find possible guest impact by blocking Microsoft Azure Management](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Log%20Analytics/Conditional%20Access%20Policy/Guest%20Scenerios/Find%20possible%20guest%20impact%20by%20blocking%20Microsoft%20Azure%20Management.kql)
 * [Get list of applications guest are successfully logging into](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Log%20Analytics/Conditional%20Access%20Policy/Guest%20Scenerios/Get%20list%20of%20applications%20guest%20are%20successfully%20logging%20into.kql)

---
### Block privileged role members from countries except US (other acceptable countries)

| Users | Cloud Apps or Actions | Conditions | Grant | Session |
| --------------------- | --------------------- | --------------------- | --------------------- | --------------------- |
| Include: Role - privileged roles  <br /> Exclude: BreakGlass  | Include: All Cloud Apps  | Include: All Networks  <br /> Exclude: Trusted Countries | Block |  |

**Prereq:** Countries Locations should be defined with countries privileged roles members are located.  

**Comment:** This Conditional Access Policy is to force the privileged roles to only allow signing in from countries where these users are located in.  The goal is to prevent a global admin account from logging in from a country for example Russia where there are more than likely no administrators located.

**Log Analytics Queries (KQL) against AAD Signin Logs**  
 * [Using PIM activates find countries privileged role members are logging in from](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Log%20Analytics/Conditional%20Access%20Policy/Privileged%20Role%20Members/Using%20PIM%20activates%20find%20countries%20privileged%20role%20members%20are%20logging%20in%20from.kql)

---

### Block directory sync account from non trusted location

| Users | Cloud Apps or Actions | Conditions | Grant | Session |
| --------------------- | --------------------- | --------------------- | --------------------- | --------------------- |
| Include: Role - directory sync account  <br /> Exclude: BreakGlass  | Include: All Cloud Apps  | Include: All Networks  <br /> Exclude: Trusted Networks | Block |  |

**Prereq:** Trusted Locations (IP Ranges) should be defined.  

**Comment:** This Conditional Access Policy is used to make sure if the credentials for the directory sync account are stolen that they cannot be accessed outside of the trusted network.  

**Log Analytics Queries (KQL) against AAD Signin Logs**  
* [Find possible Directory Sync Account impact if blocked from untrusted network](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Log%20Analytics/Conditional%20Access%20Policy/Privileged%20Role%20Members/Find%20possible%20Directory%20Sync%20Account%20impact%20if%20blocked%20from%20untrusted%20network.kql)

---

### Block accounts excluded from require MFA policies from non trusted location

| Users | Cloud Apps or Actions | Conditions | Grant | Session |
| --------------------- | --------------------- | --------------------- | --------------------- | --------------------- |
| Include: (Group of excluded users) <br /> Exclude: BreakGlass  | Include: All Cloud Apps  | Include: All Networks  <br /> Exclude: Trusted Networks | Block |  |

**Prereq:** Trusted Locations (IP Ranges) should be defined.  

**Comment:** This Conditional Access Policy is used to make sure accounts excluded from requiring MFA should be required to authenticate from trusted locations. Link below contains the script that can be used to scan all the conditional access policy exclusions and return a list of accounts that should be in this list.  Do not include the breakglass account.
 * [Link to PowerShell script](https://github.com/chadmcox/Azure_Active_Directory/blob/master/Conditional%20Access%20Policy/exportConditionalAccessExclusions.ps1)

## Compliance
 * Require TOU for Guest

## Notes

## References
