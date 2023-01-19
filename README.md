# Azure AD Conditional Access Policy Help
Tools to help implement Conditional Access Policies in Azure AD
## Require MFA or Block Access Policies 
### All Internal User Policies
 * [Always require MFA]()
 * [Always require MFA from untrusted networks]()
 * [Always require MFA or Trusted Device or Compliant Device]()
 * [Always require MFA or Trusted Device or Compliant Device from untrusted networks]()
 * [Require MFA for Microsoft Graph PowerShell and Explorer]()
 * [Require MFA for Microsoft Azure Management]()
 * [Block Legacy Authentication]()
### Privileged User Policies
 * [Require privileged user to MFA]()
 * [Block privileged user from legacy authentication]()
 * [Block the Directory Sync Account from non trusted locations]()
### External Guest (B2B) User Policies
* [Block Guest from Azure Management]()
* [Require guest to MFA]()
### Device Policies
 * [Require Compliant Device for Office 365]()
 * [No Persistent Browser and 1 Hour Session for Unmanaged Devices]()
 * [Block clients that do not support modern authentication]()
 * [Require privileged user to use compliant device]()
## Identity Protection Risk Policies
### All Internal User Risk Policies
 * [Block when user risk is high]()
 * [Block when sign-in risk is high]()
 * [Require MFA when sign-in risk is low, medium, or high]()
### Privileged User Risk Policies
* [Block when privileged users user risk is low medium high]()
* [Block when privileged user sign in risk is low medium high]()
* [Block when Directory Sync Account sign in risk is low medium high]()
### External Guest (B2B) User Risk Policies
 * [Require guest to MFA for Low and Medium Sign-in Risk]()
## Workload Identities / Service Principals
 * [Block Service Principal from Non Trusted Networks]()
 * [Block Service Principal with High Medium Low Risk]()
