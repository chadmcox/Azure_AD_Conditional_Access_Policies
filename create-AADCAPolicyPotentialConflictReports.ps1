param($resultslocation = "$env:USERPROFILE\Downloads",$howmanydaysback=7,[switch]$skipprivilegedusers,[switch]$skipguest,[switch]$skipallusers)

#this date is used to filter the graph queries to the number of days back from today 
$startdate=$(get-date (get-date).AddDays(-$howmanydaysback) -Format yyyy-MM-dd)
cd $resultslocation

Connect-MgGraph -Scopes "Policy.Read.All","Reports.Read.All","AuditLog.Read.All","Directory.Read.All","Directory.Read.All","User.Read.All","AuditLog.Read.All"
Select-MgProfile -Name "beta"
$context = get-mgcontext
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
        $results.value | where {$_.appDisplayName -notin "Windows Sign In","Microsoft Authentication Broker","Microsoft Account Controls V2"}
        $uri=$null;$uri = $Results.'@odata.nextlink'
    }until ($uri -eq $null)
}
#region role export functions
$critical_role_template_guids = @("62e90394-69f5-4237-9190-012177145e10", ` #Company Administrator / Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", ` #Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", ` #Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", ` #Application Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", ` #Privileged Authentication Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", ` #Cloud Application Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", ` #Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f", ` #Authentication Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", ` #Exchange Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", ` #Hybrid Identity Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d", ` #Password Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", ` #SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", ` #User Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8") #Helpdesk Administrator

function retrieveaadpimrolemembers{
    [cmdletbinding()] 
    param()
    Get-MgPrivilegedAccessRoleDefinition -PrivilegedAccessId AADRoles -Filter "resourceId eq '$($context.TenantId)'" | where {$_.id -in $critical_role_template_guids} | foreach{
        $role = $null; $role = $_
        write-host "Exporting $($role.DisplayName) $($role.id)"
        Get-MgPrivilegedAccessRoleAssignment -PrivilegedAccessId AADRoles -Filter "resourceId eq '$($context.TenantId)' and roleDefinitionId eq '$($role.id)'" | `
            select @{N="roleId";E={$role.Id}}, @{N="roleName";E={$role.DisplayName}}, SubjectId, AssignmentState, `
                @{N="Permanant";E={if($_.AssignmentState -eq "Active" -and $_.EndDateTime -eq $null){$true}else{$false}}}
    }
    
}
function retrieveaaddirrolemembers{
    [cmdletbinding()] 
    param()
    Get-MgDirectoryRole -all | where {$_.RoleTemplateId -in $critical_role_template_guids} | foreach{$role=$null;$role=$_
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.id -All | select @{N="roleId";E={$role.Id}}, `
        @{N="roleName";E={$role.DisplayName}}, @{N="SubjectId";E={$_.ID}}, AssignmentState,Permanant 
    }
}


function retrieveactualobject{
    [cmdletbinding()] 
    param($objectid,$members)
    Get-MgDirectoryObject -DirectoryObjectId $objectid | select -ExpandProperty AdditionalProperties | Convertto-Json | ConvertFrom-Json | select `
        "@odata.type", displayName,userprincipalname, @{N="roleId";E={$members.roleId}}, @{N="roleName";E={$members.roleName}}, `
            @{N="SubjectId";E={$objectid}}, @{N="AssignmentState";E={$members.AssignmentState}}, `
            @{N="IsMfaRegistered";E={(Get-MgReportAuthenticationMethodUserRegistrationDetail -UserRegistrationDetailsId $objectid).IsMfaRegistered}}, `
            @{N="Permanant";E={$members.Permanant}}
}
function expandgroup{
    [cmdletbinding()] 
    param($objectid,$members,$group)
    write-host "Exporting $($cleanmem.DisplayName) $($cleanmem.id)"
    $groupmems = Get-MgPrivilegedAccessRoleAssignment -PrivilegedAccessId aadGroups -Filter "resourceId eq '$objectid'" | foreach{$pag=$null;$pag=$_
        #originally this was taking the pim values from the group, now it is taking from the user.
        $members.Permanant = $(if($pag.AssignmentState -eq "Active" -and $pag.EndDateTime -eq $null){$true}else{$false})
        $members.AssignmentState = $pag.AssignmentState
        retrieveactualobject -objectid $_.subjectid -members $members | select *, @{N="nestedgroup";E={$group}}            
    }
    if(!($groupmems)){
        write-host "Exporting $($cleanmem.DisplayName) $($cleanmem.id)" -ForegroundColor Yellow
        Get-MgGroupMember -GroupId $cleanmem.SubjectId | foreach{
            retrieveactualobject -objectid $_.id -members $members | select *, @{N="nestedgroup";E={$group}}
        }
    }else{
        $groupmems
    }
}

function exportAADRoleMembers{
    [cmdletbinding()] 
    param()
    $hash_alreadyexpandedgroups = @{}
    retrieveaadpimrolemembers -PipelineVariable members | foreach{
        retrieveactualobject -objectid $members.subjectid -members $members -PipelineVariable cleanmem | foreach {
            $cleanmem | select *, nestedgroup
            if($_."@odata.type" -eq "#microsoft.graph.group" -and !($hash_alreadyexpandedgroups.containskey($cleanmem.SubjectId))){
                $hash_alreadyexpandedgroups.add($cleanmem.SubjectId,$true)
                expandgroup -objectid $cleanmem.SubjectId -member $members -group $cleanmem.displayName
            }
        }
    } | where {$_."@odata.type" -eq "#microsoft.graph.user"} | select displayName, userprincipalname, SubjectId 

    retrieveaaddirrolemembers  -PipelineVariable members | foreach{
        retrieveactualobject -objectid $members.subjectid -members $members -PipelineVariable cleanmem | foreach {
            $cleanmem | select *, nestedgroup
            if($_."@odata.type" -eq "#microsoft.graph.group" -and !($hash_alreadyexpandedgroups.containskey($cleanmem.SubjectId))){
                $hash_alreadyexpandedgroups.add($cleanmem.SubjectId,$true)
                expandgroup -objectid $cleanmem.SubjectId -member $members -group $cleanmem.displayName
            }
        }
    } | where {$_."@odata.type" -eq "#microsoft.graph.user"} | select displayName, userprincipalname, SubjectId 
}
#endregion
#region Privileged Role Members
#Require privileged user to MFA
#retrieve a unique list of role members
$rolemembers = exportAADRoleMembers | select * -unique
write-host "Found $($rolemembers.count) unique privileged users that will be evaluated."
function findRolemembersnotmfa{
    [cmdletbinding()] 
    param()
    
    foreach($rm in $rolemembers){
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=userId eq '$($rm.subjectid)' and status/errorCode eq 0 and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement | select * -first 100 | select * -Unique
    }
}
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Starting Privileged user search--------"
findRolemembersnotmfa | export-csv ".\Require privileged user to MFA.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require privileged user to MFA"

#Require privileged user to use compliant device
function findRolemembersnotcompliantdevice{
    [cmdletbinding()] 
    param()
    
    foreach($rm in $rolemembers){
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,@{name='trustType';expression={$_.deviceDetail.trustType}}, `
        @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} | where {$_.trustType -ne "Hybrid Azure AD joined" -and $_.isCompliant -ne $true} | select * -first 100 | select * -Unique
    }
}

findRolemembersnotcompliantdevice | export-csv ".\Require privileged user to use compliant device.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require privileged user to use compliant device"


#Block when privileged user sign in risk is low medium high
function findRolememberssigninrisk{
    [cmdletbinding()] 
    param()
    
    foreach($rm in $rolemembers){
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'low' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,riskLevelDuringSignIn | select * -first 100
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'medium' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,riskLevelDuringSignIn | select * -first 100
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'high' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,riskLevelDuringSignIn | select * -first 100
    }
}

findRolememberssigninrisk  | select * -Unique | export-csv ".\Block when privileged user sign in risk is low medium high.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block when privileged user sign in risk is low medium high"

#Block when privileged users user risk is low medium high
function findRolemembersrisklevel{
    [cmdletbinding()] 
    param()
    
    foreach($rm in $rolemembers){
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=RiskLevelAggregated eq 'low' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,RiskLevelAggregated | select * -first 100
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=RiskLevelAggregated eq 'medium' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,RiskLevelAggregated | select * -first 100
        $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=RiskLevelAggregated eq 'high' and userId eq '$($rm.subjectid)' and status/errorCode eq 0 and createdDateTime ge $startDate"
        fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement,RiskLevelAggregated | select * -first 100
    }
}

findRolemembersrisklevel  | select * -Unique | export-csv ".\Block when privileged users user risk is low medium high.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block when privileged users user risk is low medium high"
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Privileged users search--------"
#endregion
#region guest user
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Starting: Guest users search--------"
#Require guest to MFA for Low and Medium Sign-in Risk
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'low' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0 and userType eq 'guest' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn,userType,crossTenantAccessType,authenticationRequirement -first 5000 | `
        select * -Unique | export-csv ".\Require guest to MFA for Medium Sign-in Risk.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require guest to MFA for Low Medium Sign-in Risk"

#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'low' and status/errorCode eq 0 and userType eq 'guest' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn,userType,crossTenantAccessType,authenticationRequirement -first 5000 | `
        select * -Unique | export-csv ".\Require guest to MFA for Low Sign-in Risk.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require guest to MFA for Low Sign-in Risk"

#require guest to mfa
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'guest' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},userType,crossTenantAccessType,authenticationRequirement -first 5000 | `
        select * -Unique | export-csv ".\Require guest to MFA.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require guest to mfa"

#block guest from Azure Management
"Windows Azure Service Management API" | foreach{
    $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'guest' and resourceDisplayName eq '$($_)' and createdDateTime ge $startDate"
    fromSigninLogs -uri $uri | where {$_.AADTenantId -eq $_.ResourceTenantId} | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},userType,crossTenantAccessType,authenticationRequirement -first 5000
} | select * -Unique | export-csv ".\Block guest from Azure Management.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block guest from Azure Management"
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Guest users search--------"
#endregion
#region all users
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Starting: All users search--------"
#Require MFA when sign-in risk is low, medium, or high
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'low' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'low' and status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -first 15000 | `
        select * -Unique | export-csv ".\Require MFA when sign-in risk is low.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require MFA when sign-in risk is low, medium, or high"

#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'medium' and status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -first 15000 | `
        select * -Unique | export-csv ".\Require MFA when sign-in risk is medium.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require MFA when sign-in risk is low, medium, or high"

#Block when sign-in risk is high
#Get-MgAuditLogSignIn -filter "riskLevelDuringSignIn eq 'high' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=riskLevelDuringSignIn eq 'high' and status/errorCode eq 0 and userType eq 'member' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},riskLevelDuringSignIn, authenticationRequirement -first 15000 | `
        select * -Unique | export-csv ".\Block when sign-in risk is high.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block when sign-in risk is high"

#Block when user risk is high
#Get-MgAuditLogSignIn -filter "RiskLevelAggregated eq 'high' and status/errorCode eq 0" -All
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=RiskLevelAggregated eq 'high' and status/errorCode eq 0 and userType eq 'member' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},RiskLevelAggregated, authenticationRequirement -first 15000 | `
        select * -Unique  | export-csv ".\Block when user risk is high.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block when user risk is high"

#Block clients that do not support modern authentication
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Exchange ActiveSync' and status/errorCode eq 0 and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | `
        export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'IMAP4' and status/errorCode eq 0 and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | `
        export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Other clients' and status/errorCode eq 0 and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | `
        export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
$uri =  "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=ClientAppUsed eq 'Exchange Web Services' and status/errorCode eq 0 and createdDateTime ge $startDate" 
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},authenticationRequirement -Unique  | `
        export-csv ".\Block clients that do not support modern authentication.csv" -notypeinformation -Append
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Block clients that do not support modern authentication"

#Require MFA for Microsoft Azure Management
"Windows Azure Service Management API" | foreach{
    $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and resourceDisplayName eq '$($_)' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
    fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},userType,crossTenantAccessType,authenticationRequirement -first 5000
} | select * -Unique | export-csv ".\Require MFA for Microsoft Azure Management.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require MFA for Microsoft Azure Management"

#Require MFA for Microsoft Graph PowerShell and Explorer
"Graph Explorer","Microsoft Graph PowerShell" | foreach{
    $uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and appDisplayName eq '$($_)' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
    fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}},userType,authenticationRequirement -first 5000
} | select * -Unique | export-csv ".\Require MFA for Microsoft Graph PowerShell and Explorer.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Require MFA for Microsoft Graph PowerShell and Explorer"

#No Persistent Browser and 1 Hour Session for Unmanaged Devices
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and clientAppUsed eq 'Browser' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri  | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}}, authenticationRequirement, @{name='trustType';expression={$_.deviceDetail.trustType}}, `
    @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} | where {$_.trustType -ne "Hybrid Azure AD joined" -and $_.isCompliant -ne $true}  | `
        select * -first 15000 | export-csv ".\No Persistent Browser and 1 Hour Session for Unmanaged Devices.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: No Persistent Browser and 1 Hour Session for Unmanaged Devices"

#All Devices - Require Compliant Device for Office 365


#Always require MFA or Trusted Device or Compliant Device from untrusted networks
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | where {$_.networkLocationDetails.networktype -ne "trustedNamedLocation"} | select `
    userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}}, authenticationRequirement, @{name='trustType';expression={$_.deviceDetail.trustType}}, `
    @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} | where {$_.trustType -ne "Hybrid Azure AD joined" -and $_.isCompliant -ne $true}  | `
        select * -first 15000 | export-csv ".\Always require MFA or Trusted Device or Compliant Device from untrusted networks.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Always require MFA or Trusted Device or Compliant Device from untrusted networks"

#Always require MFA or Trusted Device or Compliant Device
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
    @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}}, authenticationRequirement, @{name='trustType';expression={$_.deviceDetail.trustType}}, `
    @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} | where {$_.trustType -ne "Hybrid Azure AD joined" -and $_.isCompliant -ne $true}  | `
        select * -first 15000 | export-csv ".\Always require MFA or Trusted Device or Compliant Device.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Always require MFA or Trusted Device or Compliant Device"

#Always require MFA from untrusted networks
$uri = "https://graph.microsoft.com/beta/auditLogs/signins?&`$filter=status/errorCode eq 0 and userType eq 'member' and authenticationRequirement eq 'singleFactorAuthentication' and createdDateTime ge $startDate"
fromSigninLogs -uri $uri | where {$_.networkLocationDetails.networktype -ne "trustedNamedLocation"} |  select userPrincipalName, appDisplayName, clientAppUsed, ipAddress, `
        @{name='trustedNetwork';expression={$_.networkLocationDetails.networktype}}, authenticationRequirement, @{name='trustType';expression={$_.deviceDetail.trustType}}, `
        @{name='isCompliant';expression={$_.deviceDetail.isCompliant}} -first 15000 | export-csv ".\Always require MFA from untrusted networks.csv" -notypeinformation
write-host "$(get-date -Format "yyyy.MM.dd HH:mm:ss") Finished: Always require MFA from untrusted networks"

#Always require MFA

#Block Service Principal from Non Trusted Networks
#Service Principal Risk Block All Cloud Apps


#endregion
