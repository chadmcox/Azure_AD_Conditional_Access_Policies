# Conditional Access Policy Help
Tools to help implement Conditional Access Policies in Azure AD
## Identity Protection Risk Policies
| AIP | All Users | Guest | Privileged Users | 
| --------------- | --------------- | --------------- | --------------- |
| User Risk (low) |  |  | Block - All Apps | 
| User Risk (medium) |  |  | Block - All Apps | 
| User Risk (high) | Block - All Apps |  | Block - All Apps | 
| Sign in Risk (low) | MFA - All Apps <BR /> Block Microsoft Azure Management <BR /> Block HR App / VPN | Block - All Apps | Block - All Apps | 
| Sign in Risk (medium) | MFA - All Apps <BR /> Block Microsoft Azure Management <BR /> Block HR App / VPN | Block - All Apps | Block - All Apps | 
| Sign in Risk (high) | Block - All Apps | Block - All Apps | Block - All Apps | 
