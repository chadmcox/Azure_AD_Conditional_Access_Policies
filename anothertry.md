## Base Protection
 * Require trusted or compliant device for register security information
 * Require MFA for intune enrollment
 * Require MFA for device enrollment
 * Require MFA All Guest
 * Require MFA to Microsoft Azure Management
 * Require MFA to Microsoft Graph PowerShell and Graph Explorer
 * Require MFA for privileged role members

## Identity Protection
 * Block all users when user risk is high
 * Block all users when sign-in risk is high
 * Require MFA for All users when sign-in risk is medium
 * Block privileged role members when sign-in risk is low, medium and high
 * Block privileged role members when user risk is low, medium and high
 * Block access to Microsoft Azure Management when sign-in risk is low, medium and high
 * Block access to Microsoft Graph PowerShell and Graph Explorer when sign-in risk is low, medium and high

## Data Protection
 * Restrict guest to 2 hour session limit
 * Restrict privileged role members to 2 hour session limit
 * Restrict nontrusted or noncompliant device to 1 hour session limit
 * Restrict nontrusted or noncompliant device to no persistent browser session

## App Protection

## Attack Surface Reduction
 * Block all users legacy authentication
 * Block privileged role members legacy authentication
 * Block privileged role members from unsupported platforms.
 * Block all users access from tor exit nodes

## Compliance
 * Require TOU for Guest
