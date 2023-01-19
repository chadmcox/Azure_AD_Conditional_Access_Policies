# Azure AD Conditional Access Policies
Tools to help implement Conditional Access Policies in Azure AD
## Require MFA or Block Access Policies 
### All Internal User Policies
 * [Always require MFA](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA.md)
 * [Always require MFA from untrusted networks](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20from%20untrusted%20networks.md)
 * [Always require MFA or Trusted Device or Compliant Device](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20or%20Trusted%20Device%20or%20Compliant%20Device.md)
 * [Always require MFA or Trusted Device or Compliant Device from untrusted networks](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20or%20Trusted%20Device%20or%20Compliant%20Device%20from%20untrusted%20networks.md)
 * [Require MFA for Microsoft Graph PowerShell and Explorer](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20MFA%20for%20Microsoft%20Graph%20PowerShell%20and%20Explorer.md)
 * [Require MFA for Microsoft Azure Management](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20MFA%20for%20Microsoft%20Azure%20Management.md)
 * [Block Legacy Authentication]()
### Privileged User Policies
 * [Require privileged user to MFA](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20Legacy%20Authentication.md)
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
