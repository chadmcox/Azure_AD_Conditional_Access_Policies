## Base Protection
 * Require trusted or compliant device for register security information
 * Require MFA for intune enrollment
 * Require MFA for device enrollment
 * Require MFA all guest
 * Require MFA to Microsoft Azure Management
 * Require MFA to Microsoft Graph PowerShell and Graph Explorer
 * Require MFA for privileged role members
 * Require internal users to use compliant or trusted device for office 365
 * Require MFA for internal users from non trusted location
 * Require privileged role member to use compliant device

## Identity Protection
 * Block all users when user risk is high
 * Block all users when sign-in risk is high
 * Require MFA for all users when sign-in risk is medium
 * Block privileged role members when sign-in risk is low, medium and high
 * Block privileged role members when user risk is low, medium and high
 * Block access to Microsoft Azure Management when sign-in risk is low, medium and high
 * Block access to Microsoft Graph PowerShell and Graph Explorer when sign-in risk is low, medium and high
 * Block directory sync account when sign in risk is low, medium and high

## Data Protection
 * Restrict guest to less than 8 hour session limit
 * Restrict privileged role members to less than 8 hour session limit
 * Restrict nontrusted or noncompliant device to 1 hour session limit
 * Restrict nontrusted or noncompliant device to no persistent browser session
 * Restrict guest to browser sessions

## App Protection

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
