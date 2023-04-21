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

# Apps
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
 * Require MFA for Microsoft Intune

## Identity Protection
 * Block all users when user risk is high
 * Block all users when sign-in risk is high
 * Require MFA for all users when sign-in risk is medium
 * Block privileged role members when sign-in risk is low, medium and high
 * Block privileged role members when user risk is low, medium and high
 * Block all users access to Microsoft Azure Management when sign-in risk is low, medium and high
 * Block all users access to Microsoft Graph PowerShell and Graph Explorer when sign-in risk is low, medium and high
 * Block directory sync account when sign in risk is low, medium and high

## Data Protection
 * Restrict guest to less than 8 hour session limit
 * Restrict privileged role members to less than 8 hour session limit
 * Restrict internal users using nontrusted or noncompliant device to 1 hour session limit
 * Restrict internal users using nontrusted or noncompliant device to no persistent browser session
 * Block guest from using mobile apps and desktop apps

## App Protection
 * Require MFA to Microsoft Azure Management
 * Require MFA to Microsoft Graph PowerShell and Graph Explorer

## Attack Surface Reduction
 * Block all users legacy authentication
 * Block privileged role members legacy authentication
 * Block privileged role members from unsupported platforms.
 * Block all users access from tor exit nodes
 * Block guest access from country
 * Block privileged role members from countries except US (other acceptable countries)
 * Block directory sync account from non trusted location
 * Block accounts excluded from require MFA policies from non trusted location

## Compliance
 * Require TOU for Guest

## Notes

## References
