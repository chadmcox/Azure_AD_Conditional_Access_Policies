param($path="$env:USERPROFILE\downloads")
cd $path

function login-MSGraph{
    Get-MgEnvironment | select name | out-host
    $selection = Read-Host "Type the name of the azure environment that you would like to connect to:  (example Global)"
    if($selection -notin "Global","China","USGov","Germany","USGovDoD"){$selection = "Global"}
    $mg_env = Get-MgEnvironment | where {$_.name -eq $selection}

    $script:graphendpoint = $mg_env.GraphEndpoint

    Connect-MgGraph -Scopes "Policy.Read.All" -Environment $mg_env.name
}
function get-MSGraphRequest{
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
                        write-host "Error: $($_.Exception.response.statuscode), trying again $i of 3, waiting for $($_.Exception.response.headers.RetryAfter.Delta.seconds) seconds"
                        Start-Sleep -Seconds $_.Exception.response.headers.RetryAfter.Delta.seconds
                    }else{
                        write-host "Error: $($_.Exception.response.statuscode)" -ForegroundColor Yellow
                        "Error: $($_.Exception.Response.StatusCode.value__)"| Add-Content $errorlogfile
                        "Error: $($_.Exception.response.statuscode)"| Add-Content $errorlogfile
                        "Error: $($_.Exception.response.RequestMessage.RequestUri.OriginalString)"| Add-Content $errorlogfile
                        $script:script_errors_found += 1
                    }
                }
            }
            if($results){
            if($results | get-member | where name -eq "value"){
                $results.value
            }else{
                $results
            }}
            $uri=$null;$uri = $Results.'@odata.nextlink'
        }until ($uri -eq $null)
}

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


#login
login-MSGraph
#export all enabled conditional access policies
$uri = "$script:graphendpoint/beta/identity/conditionalAccess/policies"

$all_capolicies = get-MSGraphRequest -uri $uri
$all_enabled_capolicies = $all_capolicies # | where {$_.state -eq "enabled"}

function categorize-policy{
 [cmdletbinding()] 
        param()
#Base Protection
$Protection_Level = "Base Protection"
#Require internal users to use trusted or compliant device for register security information
$Policy = "Require internal users to use trusted or compliant device for register security information"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls -contains "compliantDevice"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0} | `
    where {($_.conditions.applications.includeUserActions -eq 'urn:user:registersecurityinfo')}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for Microsoft Intune enrollment
$Policy = "Require MFA for Microsoft Intune enrollment"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")}  | `
    where {$_.conditions.applications.includeApplications -eq 'd4ebce55-015a-49b5-a083-c84d1797ae8c'}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for device enrollment
$Policy = "Require MFA for device enrollment"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")}  | `
    where {($_.conditions.applications.includeUserActions -eq 'urn:user:registerdevice')}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for all guest
$Policy = "Require MFA for all guest"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -like "*otherExternalUser*" -or $_.conditions.users.includeUsers -eq "GuestsOrExternalUsers"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.GrantControls.builtincontrols -eq "MFA"} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Guest Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for privileged role members
$Policy = "Require MFA for privileged role members"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {($_.grantControls.builtInControls -like "*mfa*") -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {!($_.grantControls.builtInControls -contains "compliantDevice") -and !($_.grantControls.builtInControls -contains "domainJoinedDevice")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
#$priv_found = @()
#$priv_found = $found | where {$_.conditions.users.includeUsers -eq "All"}  | `
#    where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})} 
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
               
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require internal users to use compliant or trusted device for office 365
$Policy = "Require internal users to use compliant or trusted device for office 365"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -eq 'Office365')} | `
    where {$_.grantControls.builtInControls -contains "compliantDevice"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for internal users from non trusted location
$Policy = "Require MFA for internal users from non trusted location"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {!($_.grantControls.builtInControls -contains "compliantDevice")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -gt 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require privileged role member to use compliant device
$Policy = "Require privileged role member to use compliant device"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {!($_.grantControls.builtInControls -like "*mfa*")} | `
    where {($_.conditions.applications.includeApplications -eq 'All')} | `
    where {$_.grantControls.builtInControls -contains "compliantDevice"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
$priv_found = @()
#$priv_found = $found | where {$_.conditions.users.includeUsers -eq "All"}  | `
#    where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for Azure Subscription Owners
$Policy = "Require MFA for Azure Subscription Owners"
$found = $null;
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Require MFA for all users when accessing Microsoft Management Endpoints
$Policy = "Require MFA for all users when accessing Microsoft Management Endpoints"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -contains 'de8bc8b5-d9f9-48b1-a8ad-b748da725064' -and $_.conditions.applications.includeApplications -contains '14d82eec-204b-4c2f-b7e8-296a70dab67e') -and ($_.conditions.applications.includeApplications -contains '797f4846-ba00-4fd7-ba43-dac1f8f63013')} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {!($_.grantControls.builtInControls -contains "compliantDevice")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Identity Protection
$Protection_Level = "Identity Protection"

#Require MFA when sign-in risk is low or medium
$Policy = "Require MFA when sign-in risk is low or medium"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.signInRiskLevels -like "*high*"} | `
    where {$_.conditions.signInRiskLevels -like "*medium*"} | `
    where {$_.conditions.signInRiskLevels -like "*low*"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block all users when user risk is high
$Policy = "Block all users when user risk is high"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
        where {$_.conditions.applications.includeApplications -eq 'All'} | `
        where {$_.conditions.userRiskLevels -like "*high*"} | `
        where {$_.grantControls.builtInControls  -like "*Block*"} | `
        where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
    $Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
        @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block all users when sign-in risk is high
$Policy = "Block all users when sign-in risk is high"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.signInRiskLevels -like "*high*"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block privileged role members when sign-in risk is low, medium and high
$Policy = "Block privileged user if sign-in risk is low, medium or high"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.signInRiskLevels -contains "high" -and $_.conditions.signInRiskLevels -contains "medium" -and $_.conditions.signInRiskLevels -contains "low"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
$priv_found = @()
$priv_found = $found | where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block privileged role members when user risk is low, medium and high
$Policy = "Block privileged role members when user risk is low, medium and high"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.userRiskLevels -eq "high" -and $_.conditions.userRiskLevels -contains "medium" -and $_.conditions.userRiskLevels -contains "low"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
$priv_found = @()
$priv_found = $found | where {$_.conditions.users.includeUsers -eq "All"}  | `
    where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block all users access to Microsoft Azure Management, Microsoft Graph PowerShell (Microsoft Graph Command Line Tools) and Graph Explorer when sign-in risk is low, medium and high
$Policy = "Block all users access to Microsoft Azure Management, Microsoft Graph PowerShell (Microsoft Graph Command Line Tools) and Graph Explorer when sign-in risk is low, medium and high"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -contains 'de8bc8b5-d9f9-48b1-a8ad-b748da725064' -and $_.conditions.applications.includeApplications -contains '14d82eec-204b-4c2f-b7e8-296a70dab67e') -and ($_.conditions.applications.includeApplications -contains '797f4846-ba00-4fd7-ba43-dac1f8f63013')} | `
    where {$_.grantControls.builtInControls  -like "*Block*"}
    where {$_.conditions.signInRiskLevels -contains "high" -and $_.conditions.signInRiskLevels -contains "medium" -and $_.conditions.signInRiskLevels -contains "low"} | `
    where {!($_.grantControls.builtInControls -contains "compliantDevice")} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block directory sync account when sign in risk is low, medium and high
$Policy = "Block directory sync account when sign in risk is low, medium and high"
$role = "d29b2b05-8046-44ba-8758-1e26182fcf32"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$role -in $_.Conditions.users.includeRoles} | `
    where {$_.conditions.signInRiskLevels -contains "high" -and $_.conditions.signInRiskLevels -contains "medium" -and$_.conditions.signInRiskLevels -contains "low"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"}
$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block internal users from register security information when sign in risk is low, medium and high
$Policy = "Block internal users from register security information when sign in risk is low, medium and high"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
     where {$_.conditions.signInRiskLevels -contains "high" -and $_.conditions.signInRiskLevels -contains "medium" -and $_.conditions.signInRiskLevels -contains "low"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0} | `
    where {($_.conditions.applications.includeUserActions -eq 'urn:user:registersecurityinfo')}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}


#Data Protection
$Protection_Level = "Data Protection"
#Restrict guest to less than 8 hour session limit
$Policy = "Restrict guest to less than 8 hour session limit"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -like "*otherExternalUser*" -or $_.conditions.users.includeUsers -eq "GuestsOrExternalUsers"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {$_.sessionControls.signInFrequency.isEnabled -eq "True"} 
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Restrict privileged role members to less than 8 hour session limit
$Policy = "Restrict privileged role members to less than 8 hour session limit"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {$_.sessionControls.signInFrequency.isEnabled -eq "True"}
#is all user defined?
$priv_found = @()
$priv_found = $found | where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Restrict internal users using nontrusted or noncompliant device to 1 hour session limit
$Policy = "Restrict internal users using nontrusted or noncompliant device to 1 hour session limit"
$found = $null;$found = $all_enabled_capolicies | where {($_.conditions.applications.includeApplications -eq 'All')} | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.devices.deviceFilter.mode -eq "include"} | `
    where {$_.conditions.devices.deviceFilter.rule -eq 'device.isCompliant -ne True -or device.trustType -ne "ServerAD"'} | `
    where {$_.sessionControls.signInFrequency.isEnabled -eq "True"} 
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Restrict internal users using nontrusted or noncompliant device to no persistent browser session
$Policy = "Restrict internal users using nontrusted or noncompliant device to no persistent browser session"
$found = $null;$found = $all_enabled_capolicies | where {($_.conditions.applications.includeApplications -eq 'All')} | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.devices.deviceFilter.mode -eq "include"} | `
    where {$_.conditions.devices.deviceFilter.rule -eq 'device.isCompliant -ne True -or device.trustType -ne "ServerAD"'} | `
    where {$_.sessionControls.persistentBrowser.isEnabled -eq "True"} 
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block guest from using mobile apps and desktop apps
$Policy = "Block guest from using mobile apps and desktop apps"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -like "*otherExternalUser*" -or $_.conditions.users.includeUsers -eq "GuestsOrExternalUsers"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {$_.conditions.clientAppTypes -contains "mobileAppsAndDesktopClients"} 
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Attack Surface Reduction
$Protection_Level = "Attack Surface Reduction"
#Block all users legacy authentication
$Policy = "Block all users legacy authentication"
 $found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.clientAppTypes -eq "other"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block privileged role members legacy authentication
$Policy = "Block privileged role members legacy authentication"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.clientAppTypes -eq "other"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
$priv_found = @()
$priv_found = $found | where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block privileged role members from unsupported platforms.
$Policy = "Block privileged role members from unsupported platforms"
$found = $null;$found = $all_enabled_capolicies  | `
    where {($_.conditions.users.includeRoles -like "*") -or ($_.conditions.users.includeUsers -eq "All")} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.conditions.platforms.includePlatforms -contains "all"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
#is all user defined?
$priv_found = @()
$priv_found = $found | where {!($_.conditions.users.excludeRoles | foreach{$_ -in $critical_role_template_guids})}
#if all isnt found is each privileged role defined 
if(!($priv_found)){
    $priv_found = $found
    $critical_role_template_guids | foreach{
        if(!($found.conditions.users.includeRoles -contains $_)){
                
            $priv_found = $null
        }
    }
}
$found = $priv_found | where {$_.conditions.users.includeRoles -notcontains "d29b2b05-8046-44ba-8758-1e26182fcf32"}

$Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block all users access from tor exit nodes
$Policy = "Block all users access from tor exit nodes"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {($_.conditions.locations.includeLocations | measure-object).count -gt 0}
$Protection_Level | select @{n='Section';e={"Common Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block guest access from unexpected countries

#Block guest access to non-approved apps
$Policy = "Block guest access to non-approved apps"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -like "*otherExternalUser*" -or $_.conditions.users.includeUsers -eq "GuestsOrExternalUsers"} | `
    where {$_.grantControls.builtInControls  -like "*Block*"} | `
    where {!($_.conditions.signInRiskLevels -contains "high")}
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"Guest Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block privileged role members from countries except US (other acceptable countries)

#Block directory sync account from non trusted location
$Policy = "Block directory sync account from non trusted location"
$role = "d29b2b05-8046-44ba-8758-1e26182fcf32"
    $found = $null;$found = $all_enabled_capolicies  | `
        where {$role -in $_.Conditions.users.includeRoles} | `
        where {$_.Conditions.locations.IncludeLocations -eq "All"} | `
        where {$_.Conditions.locations.ExcludeLocations -eq "AllTrusted"} | `
        where {$_.grantControls.builtInControls  -like "*Block*"}
    $Protection_Level | select @{n='Section';e={"Privileged User Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
        @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

#Block accounts excluded from require MFA policies from non trusted location

#--------------------------------------------------------------------------
$Protection_Level = "Intune"
$Policy = "Require approved apps on mobile devices"
$found = $null;$found = $all_enabled_capolicies | `
    where {$_.grantControls.builtInControls -contains "approvedApplication"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -eq 'Office365')} | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.platforms.includePlatforms -contains "android" -or $_.conditions.platforms.includePlatforms -contains "iOS"}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Policy = "Require app protection on mobile devices"
$found = $null;$found = $all_enabled_capolicies | `
    where {$_.grantControls.builtInControls -contains "compliantApplication"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -eq 'Office365')} | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.platforms.includePlatforms -contains "android" -or $_.conditions.platforms.includePlatforms -contains "iOS"}
$Protection_Level | select @{n='Section';e={"Common Device Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Protection_Level = "SharePoint Online"
#SharePoint Policies
$Policy = "Block access to SharePoint Online from apps on unmanaged devices" 
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.clientAppTypes -eq "mobileAppsAndDesktopClients"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -eq 'Office365') -or $_.conditions.applications.includeApplications -like "*00000003-0000-0ff1-ce00-000000000000*"} | `
    where {$_.grantControls.builtInControls -contains "compliantDevice" -and $_.grantControls.builtInControls -contains "domainJoinedDevice"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"SharePoint Online Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Policy = "Use app-enforced Restrictions for browser access to Sharepoint Online"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.clientAppTypes -eq "browser"} | `
    where {($_.conditions.applications.includeApplications -eq 'All') -or ($_.conditions.applications.includeApplications -eq 'Office365') -or $_.conditions.applications.includeApplications -like "*00000003-0000-0ff1-ce00-000000000000*"} | `
    where {$_.sessionControls.applicationEnforcedRestrictions.isEnabled -eq "True"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -eq 0}
$Protection_Level | select @{n='Section';e={"SharePoint Online Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Protection_Level = "Defender for Cloud App"
$Policy = "Monitor traffic from Unmanaged Devices using monitor only app control"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.devices.deviceFilter.rule -eq 'device.isCompliant -ne True -or device.trustType -ne "ServerAD"' -or $_.conditions.devices.deviceFilter.rule -eq 'device.trustType -ne "ServerAD" -or device.isCompliant -ne True'} |
    where {$_.sessionControls.cloudAppSecurity.isEnabled -eq "True"} | `
    where {$_.sessionControls.cloudAppSecurity.cloudAppSecurityType -eq "monitorOnly"}
$Protection_Level | select @{n='Section';e={"Defender for Cloud App Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Policy = "Block download of files labeled with sensitive or classified from unmanaged devices using block downloads app control"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.devices.deviceFilter.rule -eq 'device.isCompliant -ne True -or device.trustType -ne "ServerAD"' -or $_.conditions.devices.deviceFilter.rule -eq 'device.trustType -ne "ServerAD" -or device.isCompliant -ne True'} |
    where {$_.sessionControls.cloudAppSecurity.isEnabled -eq "True"} | `
    where {$_.sessionControls.cloudAppSecurity.cloudAppSecurityType -eq "blockDownloads"}
$Protection_Level | select @{n='Section';e={"Defender for Cloud App Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Policy = "Block download of files labeled classified from all devices"
$found = $null;$found = $all_enabled_capolicies  | `
    where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.sessionControls.cloudAppSecurity.isEnabled -eq "True"} | `
    where {$_.sessionControls.cloudAppSecurity.cloudAppSecurityType -eq "mcasConfigured"}
$Protection_Level | select @{n='Section';e={"Defender for Cloud App Policies"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

$Protection_Level = "Better then nothing"
$Policy = "Always require MFA or Trusted Device or Compliant Device from untrusted networks"
$found = $null;$found = $all_enabled_capolicies | where {$_.conditions.users.includeUsers -eq "All"} | `
    where {$_.conditions.applications.includeApplications -eq 'All'} | `
    where {$_.grantControls.builtInControls -like "*mfa*" -or ($_.grantControls.authenticationStrength.requirementsSatisfied -eq "mfa") -or ($_.grantControls.grantcontrols.customAuthenticationFactors -ne $null)} | `
    where {!($_.conditions.signInRiskLevels -like "*")} | `
    where {!($_.conditions.userRiskLevels -like "*")} | `
    where {$_.grantControls.builtInControls -contains "compliantDevice" -or $_.grantControls.builtInControls -contains "domainJoinedDevice"} | `
    where {($_.conditions.locations.ExcludeLocations | measure-object).count -gt 0}
$Protection_Level | select @{n='Section';e={"Generic Identity Policy"}},@{n='Protection Level';e={$Protection_Level}}, @{n='Policy';e={$Policy}}, `
    @{n='Applied';e={if($found){$true}else{$false}}},@{n='Policy Found';e={($found.DisplayName -join(" | "))}}

}

$tenant = (get-mgdomain  | where isdefault -eq $true).id
categorize-policy | select 'Protection Level',Policy,Applied,'Policy Found' | sort 'protection level'  | export-csv ".\$($tenant)_securet_policies.csv" -NoTypeInformation
