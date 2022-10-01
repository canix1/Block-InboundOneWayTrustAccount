<#
.Synopsis
    Block-InboundOneWayTrustAccount.ps1
     
    AUTHOR: Robin Granberg (robin.granberg@protonmail.com)
    
    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.
    
.DESCRIPTION
    A tool that prevent an admin in a trusted domain to access your domain using the TDO user credentials

.EXAMPLE
    .\Block-InboundOneWayTrustAccount.ps1 -protect

   Protect the incoming trusts outside of your forest by preventing the TDO user account from perform authentication.

.EXAMPLE
    .\Block-InboundOneWayTrustAccount.ps1 -unprotect

    Reverse any previously added protection

.OUTPUTS
    

.LINK
    https://github.com/canix1/Block-InboundOneWayTrustAccount

.NOTES
    Version: 1.0
    5 September, 2022


#>
Param
(
    # Run protect operations in the current domain
    [Parameter(Mandatory=$false, 
                ParameterSetName='')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $protect,
    # Run unprotect operations in the current domain
    [Parameter(Mandatory=$false, 
                ParameterSetName='unprotect')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [switch] 
    $unprotect
)
clear-host
Write-host  "********************************************"
Write-host  "Author: robin.granberg@protonmail.com"
Write-host  "twitter: @ipcdollar1"
Write-host  "github: https://github.com/canix1/Block-InboundOneWayTrustAccount"
Write-host  "********************************************`n"

$VerbosePreference = "continue"

$AuhtPolicyName = "Block_INBOUND_TrustUsers_Logon"
$AuhtPolicySiloName = "Block_INBOUND_TrustUsers_Logon_Silo"
#Get the current domain name
$DomainDN = (get-addomain).DistinguishedName
#Get the configuration naming context
$configDN = (Get-ADDomain).SubordinateReferences | Where-Object{($_.Remove(16,($_.Length-16))) -eq "CN=Configuration"}

#Run the protect operation
if($protect -and (!($unprotect)))
{
    Write-Host "Protect Operation`n"

    #Get all Trust Accounts
    $TDOUsers = Get-ADUser -SearchBase "CN=Users,$DomainDN" -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)(!msDS-AssignedAuthNPolicy=*))" 

    #Get all TDO Users that are not in the same forest and is only INBOUND. 
    $InboundTDOUser = $TDOUsers |where-object{Get-ADObject -SearchBase "CN=System,$DomainDN" -LDAPFilter "(&(objectClass=trustedDomain)(!trustattributes:1.2.840.113556.1.4.803:=32)(trustDirection=1)(flatName=$($_.samaccountname.Remove($_.samaccountname.length-1,1))))" }  
    if($InboundTDOUser)
    {
        #Counter to prevent duplicate messages
        $i = 0
        Foreach($TDOUser in $InboundTDOUser)
        {
            Write-Host "Identified a one-way inbound trust account:" -NoNewline
            Write-host  "$($TDOUser.samaccountname)." -ForegroundColor red
            Write-Host "Do you want to block inbound authentication for this account?"
            $a = Read-Host "Do you want to continue? Press Y[Yes] or N[NO]:"    
            if($a -eq "Y")
            {
                #Do the following only once
                if($i -eq 0)
                {
                    #Verify if the Authentication Policy already exist
                    if(!(Get-ADAuthenticationPolicy -filter "Name -eq '$AuhtPolicyName'"))
                    {
                        #Create Authentication Policy
                        New-ADAuthenticationPolicy -Name $AuhtPolicyName -Description "Authentication policy to block trust user accounts to authenticate." -Enforce -ProtectedFromAccidentalDeletion $True

                        Write-Host "Authentication Policy $($AuhtPolicyName) created!`n" -ForegroundColor Green

                        #Add a silo to the polciy, the silo does not need to exist, if it exist it should be empty
                        Set-ADAuthenticationPolicy -Identity $AuhtPolicyName -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"$AuhtPolicySiloName`"))"
                    }
                    else
                    {
                        Write-Host ("Authentication Policy "+[char]34+"$($AuhtPolicyName)"+[char]34+" already exist! `n") -ForegroundColor Yellow
                    }

                    if(!(Get-ADAuthenticationPolicySilo -filter "Name -eq '$AuhtPolicySiloName'"))
                    {
                        #Create an Authentication Policy Silo, this should be empty.
                        New-ADAuthenticationPolicySilo -Name:$AuhtPolicySiloName -OtherAttributes:@{"description"="Empty silo for blocking authentication for inbound one-way trust accounts."} -ProtectedFromAccidentalDeletion:$true 

                        Write-Host "Authentication Policy Silo $($AuhtPolicySiloName) created!`n" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host ("Authentication Policy Silo "+[char]34+"$($AuhtPolicySiloName)"+[char]34+" already exist! `n") -ForegroundColor Yellow
                }

                }
                $i++
                $TDOUser | Set-ADUser -AuthenticationPolicy $AuhtPolicyName
                Write-Host ("Blocked $($TDOUser.samaccountname) from signing in using Authentication Policy "+[char]34+"$AuhtPolicyName"+[char]34) -ForegroundColor Green
            }
            else
            {
                Write-Host "Skipping $($TDOUser.samaccountname)" -ForegroundColor Yellow
            }
   
        }
    }
    else
    {
        Write-Host "No inbound trust account/unprotected inbound trust account found!" -ForegroundColor Yellow
    }
}


#Run the unprotect operation
if($unprotect -and (!($protect)))
{
    Write-Host "Unprotect Operation`n"

    #Get all Trust Accounts
    $TDOUsers = Get-ADUser -SearchBase "CN=Users,$DomainDN" -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)(msDS-AssignedAuthNPolicy=$("CN="+$AuhtPolicyName+",CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,"+$configDN)))" 

    #Get all TDO Users that are not in the same forest and is only INBOUND. 
    $InboundTDOUser = $TDOUsers |where-object{Get-ADObject -SearchBase "CN=System,$DomainDN" -LDAPFilter "(&(objectClass=trustedDomain)(!trustattributes:1.2.840.113556.1.4.803:=32)(trustDirection=1)(flatName=$($_.samaccountname.Remove($_.samaccountname.length-1,1))))" }  
    if($InboundTDOUser)
    {
        Foreach($TDOUser in $InboundTDOUser)
        {
            Write-Host "Identified a protected one-way inbound trust account:" -NoNewline
            Write-host  "$($TDOUser.samaccountname)." -ForegroundColor red
            Write-Host "Do you want to remove the blocking Authentication Policy for inbound authentcation?" 
            $a = Read-Host "Do you want to continue? Press Y[Yes] or N[NO]:"    
            if($a -eq "Y")
            {
                $TDOUser | Set-aduser -clear msDS-AssignedAuthNPolicy
                Write-Host ("Protection removed for $($TDOUser.samaccountname)") -ForegroundColor red
            }
            else
            {
                Write-Host "Skipping $($TDOUser.samaccountname)" -ForegroundColor Yellow
            }
    
        }
    }
    else
    {
        Write-Host "No protected one-way inbound trust account found" -ForegroundColor Yellow
    }

    #Verify if the Authentication Policy exist
    if(Get-ADAuthenticationPolicy -filter "Name -eq '$AuhtPolicyName' -and (msDS-AssignedAuthNPolicyBL -notlike '*' )")
    {
        Write-Host "`nDo you want to delete the empty Authentcation Policy:" -NoNewline
        Write-host  "$($AuhtPolicyName) ?" -ForegroundColor red
        $a = Read-Host "Do you want to continue? Press Y[Yes] or N[NO]:"    
        if($a -eq "Y")
        {
            #Remove ProtectedFromAccidentalDeletion
            Set-ADAuthenticationPolicy -Identity $AuhtPolicyName -ProtectedFromAccidentalDeletion $false

            #Delete the Authentication Policy
            Get-ADAuthenticationPolicy -Identity $AuhtPolicyName | Remove-ADAuthenticationPolicy -Confirm:$false
            Write-Host ("Authentication Policy $($AuhtPolicyName) deleted!") -ForegroundColor red
        }
    }
    if(!(Get-ADAuthenticationPolicy -filter "Name -eq '$AuhtPolicyName'"))
    {
        if((Get-ADAuthenticationPolicySilo -filter "Name -eq '$AuhtPolicySiloName'"))
        {
            Write-Host "`nDo you want to delete the Authentcation Policy Silo:" -NoNewline
            Write-host  "$($AuhtPolicySiloName) ?" -ForegroundColor red
            $a = Read-Host "Do you want to continue? Press Y[Yes] or N[NO]:"    
            if($a -eq "Y")
            {
                #Remove ProtectedFromAccidentalDeletion
                Set-ADAuthenticationPolicySilo -Identity $AuhtPolicySiloName -ProtectedFromAccidentalDeletion $false

                #Delete the Authentication Policy
                Get-ADAuthenticationPolicySilo -Identity $AuhtPolicySiloName | Remove-ADAuthenticationPolicySilo -Confirm:$false
                Write-Host ("Authentication Policy Silo $($AuhtPolicySiloName) deleted!") -ForegroundColor red
            }
        }
    }
}

if((!($protect) -and (!$unprotect)))
{
    Write-Verbose "Use -protect or -unprotect"
}
if($protect -and $unprotect)
{
    Write-Verbose "Cannot run both protect and unprotect operations at once"
}
