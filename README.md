# Azure AD Conditional Access Policies
* Below is a list of Conditional Access Policies that Microsoft recommends in an Azure AD Tenant.
* Each link contains information about each policies with ways to help evaluate policies.

## Require MFA or Block Access Policies 
### All Internal User Policies
 * [Always require MFA](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA.md)
 * [Always require MFA from untrusted networks](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20from%20untrusted%20networks.md)
 * [Always require MFA or Trusted Device or Compliant Device](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20or%20Trusted%20Device%20or%20Compliant%20Device.md)
 * [Always require MFA or Trusted Device or Compliant Device from untrusted networks](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Always%20require%20MFA%20or%20Trusted%20Device%20or%20Compliant%20Device%20from%20untrusted%20networks.md)
 * [Require MFA for Microsoft Graph PowerShell and Explorer](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20MFA%20for%20Microsoft%20Graph%20PowerShell%20and%20Explorer.md)
 * [Require MFA for Microsoft Azure Management](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20MFA%20for%20Microsoft%20Azure%20Management.md)
 * [Block Legacy Authentication](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20Legacy%20Authentication.md)
### Privileged User Policies
 * [Require privileged user to MFA](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20privileged%20user%20to%20MFA.md)
 * [Block privileged user from legacy authentication](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/edit/main/Block%20privileged%20user%20from%20legacy%20authentication.md)
 * [Block the Directory Sync Account from non trusted locations](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20the%20Directory%20Sync%20Account%20from%20non%20trusted%20locations.md)
### External Guest (B2B) User Policies
* [Block Guest from Azure Management](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20Guest%20from%20Azure%20Management.md)
* [Require guest to MFA](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20guest%20to%20MFA.md)
### Device Policies
 * [Require Compliant Device for Office 365](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20Compliant%20Device%20for%20Office%20365.md)
 * [No Persistent Browser and 1 Hour Session for Unmanaged Devices](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/No%20Persistent%20Browser%20and%201%20Hour%20Session%20for%20Unmanaged%20Devices.md)
 * [Block clients that do not support modern authentication](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20clients%20that%20do%20not%20support%20modern%20authentication.md)
 * [Require privileged user to use compliant device](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20privileged%20user%20to%20use%20compliant%20device.md)
## Identity Protection Risk Policies
### All Internal User Risk Policies
 * [Block when user risk is high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20when%20user%20risk%20is%20high.md)
 * [Block when sign-in risk is high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20when%20sign-in%20risk%20is%20high.md)
 * [Require MFA when sign-in risk is low, medium, or high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20MFA%20when%20sign-in%20risk%20is%20low%2C%20medium%2C%20or%20high.md)
### Privileged User Risk Policies
* [Block when privileged users user risk is low medium high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20when%20privileged%20users%20user%20risk%20is%20low%20medium%20high.md)
* [Block when privileged user sign in risk is low medium high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20when%20privileged%20user%20sign%20in%20risk%20is%20low%20medium%20high.md)
* [Block when Directory Sync Account sign in risk is low medium high](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20when%20Directory%20Sync%20Account%20sign%20in%20risk%20is%20low%20medium%20high.md)
### External Guest (B2B) User Risk Policies
 * [Require guest to MFA for Low and Medium Sign-in Risk](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Require%20guest%20to%20MFA%20for%20Low%20and%20Medium%20Sign-in%20Risk.md)
## Workload Identities / Service Principals
 * [Block Service Principal from Non Trusted Networks]()
 * [Block Service Principal with High Medium Low Risk](https://github.com/chadmcox/Azure_AD_Conditional_Access_Policies/blob/main/Block%20Service%20Principal%20with%20High%20Medium%20Low%20Risk.md)
