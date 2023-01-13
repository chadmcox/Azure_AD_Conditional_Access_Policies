# Conditional Access Policy Help
Tools to help implement Conditional Access Policies in Azure AD
## Identity Protection Risk Policies
| AIP | All Users | Guest | Privileged Users | Directory Sync | Workload Identity |
| --------------- | --------------- | --------------- | --------------- | --------------- | --------------- |
| User Risk (low) |  |  | Block - All Apps |  |  | 
| User Risk (medium) |  |  | Block - All Apps |  |  | 
| User Risk (high) | Block - All Apps |  | Block - All Apps |  |  | 
| Sign in Risk (low) | MFA - All Apps <BR /> Block Microsoft Azure Management <BR /> Block HR App / VPN | Block - All Apps | Block - All Apps | Block - All Apps |  | 
| Sign in Risk (medium) | MFA - All Apps <BR /> Block Microsoft Azure Management <BR /> Block HR App / VPN | Block - All Apps | Block - All Apps | Block - All Apps |  | 
| Sign in Risk (high) | Block - All Apps | Block - All Apps | Block - All Apps | Block - All Apps |  | 
| Service Principal Risk (low) |  |  |  |  | Block - All APPS | 
| Service Principal Risk (medium) |  |  |  |  | Block - All APPS | 
| Service Principal Risk (high) |  |  |  |  | Block All - APPS | 
