param($resultslocation = "$env:USERPROFILE\Downloads")

cd $resultslocation

Connect-MgGraph -Scopes "Policy.Read.All","Reports.Read.All","AuditLog.Read.All","Directory.Read.All","Directory.Read.All","User.Read.All","AuditLog.Read.All"
cd $resultslocation
function fromSigninLogs{
    [cmdletbinding()] 
    param($uri)
    
    do{$results = $null
        for($i=0; $i -le 3; $i++){
            try{
                $results = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
                break
            }catch{#if this fails it is going to try to authenticate again and rerun query
                if(($_.Exception.response.statuscode -eq "TooManyRequests") -or ($_.Exception.Response.StatusCode.value__ -eq 429)){
                    #if this hits up against to many request response throwing in the timer to wait the number of seconds recommended in the response.
                    write-host "Error: $($_.Exception.response.statuscode), trying again $i of 3"
                    Start-Sleep -Seconds $_.Exception.response.headers.RetryAfter.Delta.seconds
                }
            }
        }
        $results.value | where {$_.appDisplayName -notin "Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V"}
        $uri=$null;$uri = $Results.'@odata.nextlink'
    }until ($uri -eq $null)
}



#Require MFA when sign-in risk is low, medium, or high
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'low' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'low' and status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -Unique | export-csv ".\Require MFA when sign-in risk is low.csv" -notypeinformation

#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -Unique | export-csv ".\Require MFA when sign-in risk is medium.csv" -notypeinformation

#Block when sign-in risk is high
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'high' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'high' and status/errorCode eq 0 and userType eq 'member'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -Unique | export-csv ".\Block when sign-in risk is high.csv" -notypeinformation

#Block when user risk is high
#Get-MgAuditLogSignIn -filter "RiskLevelAggregated eq 'high' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=RiskLevelAggregated eq 'high' and status/errorCode eq 0 and userType eq 'member'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},RiskLevelAggregated, authenticationRequirement -Unique  | export-csv ".\Block when user risk is high.csv" -notypeinformation

#Always require MFA from untrusted networks
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication'"
fromSigninLogs -uri $uri | where {$_.networkLocationDetails.networktype -ne "trustedNamedLocation"} | where {$_.appDisplayName -notin "Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V"} | select `
    userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}}, authenticationRequirement, @{name='trustType';expression={$_.deviceDetail.trustType}}, `
    @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} -first 15000 | export-csv ".\Always require MFA from untrusted networks.csv" -notypeinformation

#Require guest to MFA for High and Medium Sign-in Risk
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'low' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0 and userType eq 'guest' and authenticationRequirement eq 'singleFactorAuthentication'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -Unique | export-csv ".\Require guest to MFA for Medium Sign-in Risk.csv" -notypeinformation

#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'high' and status/errorCode eq 0 and userType eq 'guest' and authenticationRequirement eq 'singleFactorAuthentication'"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -Unique | export-csv ".\Require guest to MFA for High Sign-in Risk.csv" -notypeinformation

#Block clients that do not support modern authentication
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Exchange ActiveSync' and status/errorCode eq 0"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'IMAP4' and status/errorCode eq 0"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Other clients' and status/errorCode eq 0"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Exchange Web Services' and status/errorCode eq 0" 
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
