###############################################################################
#    Title:        DC Replication Fix
#    Revision:     1.5 (PUBLIC)
#    Author:       DrPrEsq ; https://github.com/potr/adfix
#    Date:         28 June 2017
#
#    Purpose:      To restore replication between DC and FSMO Master when replication is failing
#                  
#    
#    Dependancies: 1) Access to the desktop of the affected DC via a Domain Administrator Account
#                  2) A Copy of this script on the desktop of the affected DC
#                  3) Connectivity between the affected DSC and the FSMO Master
#    
#    How to Run:   Right Click on the script and choose 'Run With PowerShell'
#
#    Rev history:  CURRENT     - Removed all organization specific information and replaced it with dynamically constructed versions for public release
#                  1.4         - Broke out more code from FixAD into functions and made FixAD more efficient overall
#                  1.3         - Added write-progress, text coloring, and refined menus and outputs
#                  1.2         - refined control logic in replication portion to reduce code length; improved error handling for all sections
#                  1.1(BETA)   - added rudementary error handling throughout, verbose commenting of all functions implemented, added menues/headers, and rev history info
#                  1.0(ALPHA)  - Script functioning in linear procedural fashion; limited error handling
#
#     Disclaimer:  This script is provided for free without warranty or support; no rights reserved; please give author credit.
#
################################################################################

################################################################################
### Elevate Privilege ###
################################################################################

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }



###############################################################################
###     GLOBAL VARIABLES     ###
###############################################################################

$Global:CurVer = "1.5"
$Global:MenuContext = $null


################################################################################
###    Function Definitions    ###
################################################################################

###
### MENUCONTEXT - HELPER FUNCTION
### Function responsible for providing a context for interface
### This function runs when the script executes

Function MenuContext()
{
    Clear-Host
    if ($Global:MenuContext -eq "Main")
    {
        Write-Host
        Write-Host
        Write-Host "=========================================================" -ForegroundColor Yellow
        Write-Host "= DC Replication Fix Tool                           $Global:CurVer =" -ForegroundColor Yellow
        Write-Host "=                                                       =" -ForegroundColor Yellow
        Write-Host "=========================================================" -ForegroundColor Yellow
        Write-Host
    }
}

###
### EXITFUNC - HELPER FUNCTION
### Function responsible for providing the user a reason for terminating the script
### This function runs when errors are caught or the script completes successfully

Function ExitFunc
{
    [string]$ExitMsg = $args[0]
    [int]$ExitCode = $args[1]
    [string]$Section = $args[3]

    Clear-Host
    MenuContext

    if ($ExitCode -ne 0)
    {
        Write-Host
        Write-Host 'The Script encountered the following fatal error:'
        Write-Host 
        if($section.ToString() -ne ""){Write-Host "Replication failed for section: $Section"}
        Write-Host $ExitMsg
        Write-Host
        Write-Host 'Press Enter to exit the script.'
        Read-Host
        Clear Host
        Write-Host "                   :::::::::   :::::::: ::::::::::: ::::::::: "
        Write-Host "                 :+:    :+: :+:    :+:    :+:     :+:    :+:  "
        Write-Host "                +:+    +:+ +:+    +:+    +:+     +:+    +:+   "
        Write-Host "               +#++:++#+  +#+    +:+    +#+     +#++:++#:     "
        Write-Host "              +#+        +#+    +#+    +#+     +#+    +#+     "
        Write-Host "             #+#        #+#    #+#    #+#     #+#    #+#      "
        Write-Host "            ###         ########     ###     ###    ###       "
        Start-Sleep -s 3
        exit
    }
    else
    {
        Write-Host
        Write-Host 'The Script has completed successfully!'
        Write-Host 
        Write-Host 'The system will now restart.' -ForegroundColor Red
        Write-Host 
        Write-Host 'Continue to observe DC behavior to verify the fix was successful.'
        Write-Host
        Write-Host 'Press Enter to Continue'
    }
    
    Read-Host
    Clear Host
    Write-Host
    Write-Host "                   :::::::::   :::::::: ::::::::::: ::::::::: "
    Write-Host "                 :+:    :+: :+:    :+:    :+:     :+:    :+:  "
    Write-Host "                +:+    +:+ +:+    +:+    +:+     +:+    +:+   "
    Write-Host "               +#++:++#+  +#+    +:+    +#+     +#++:++#:     "
    Write-Host "              +#+        +#+    +#+    +#+     +#+    +#+     "
    Write-Host "             #+#        #+#    #+#    #+#     #+#    #+#      "
    Write-Host "            ###         ########     ###     ###    ###       "
    start-sleep 3
    shutdown -r -t 0
}

###
### Get-AdminCreds - HELPER FUNCTION
### Function responsible for prompting the user for domain admin credentials and verifying that the provided cred is a member of the domain admins group
### This function runs when called by FixAd

Function Get-AdminCreds()
{
    Import-Module ActiveDirectory
    Do{
    MenuContext
    Write-Host "Please enter your Domain Administrator Credentials"
    start-sleep -s 1
    
    #Prompt for Domain Administrator Credentials (tested)
    $Admincreds = Get-Credential
    $x+=1
    }
    Until((Get-ADGroupMember -Identity "Domain Admins" | where SAMAccountName -eq $Admincreds.GetNetworkCredential().username) -or ($x -eq 3))
    if($x -eq 3)
    {
        $LastExitMsg = "ERROR: " + $Admincreds.GetNetworkCredential().username + " is not a member of the Domain Admins Group"
        ExitFunc $LastExitMsg 1 ""
    }

    return $Admincreds

}

###
### Set-DNS - HELPER FUNCTION
### Function responsible for swapping 127.0.0.1 and the FsmoMasterIP back and forth between primary and alternate DNS
### This function runs when called by Get-FsmoMasterIP and FixAD

Function Set-DnsServers([int]$Switch, [string]$FsmoMasterIP, [int]$Progress)
{
    if($Progress){Write-Progress -Activity "Fixing DC Replication" -CurrentOperation "Replicating Active Directory" -Status "Percent Complete:" -PercentComplete ((3 / 5) * 100)}

    $adapteralias = (Get-NetAdapter | where {$_.status -eq "Up"}).Name
    
    if($Switch -eq 0)
    {
        Set-DnsClientServerAddress -InterfaceAlias $adapteralias -ServerAddresses("$FsmoMasterIP","127.0.0.1")
    }
    
    if($Switch -eq 1)
    {
        Set-DnsClientServerAddress -InterfaceAlias $adapteralias -ServerAddresses("127.0.0.1","$FsmoMasterIP")
    }

    return
}

###
### Get-FsmoMasterIP - HELPER FUNCTION
### Function responsible for prompting the user for the FSMO Master Ip address, verifying user input, and verfying the address is online
### This function runs when called by FixAd
    
Function Get-FsmoMasterIP()
{
    Do {
        MenuContext
        $FsmoMasterIP = Read-Host -prompt "Enter the IP address of the FSMO Master"
        $x+=1
       }
    Until(($FsmoMasterIP -match '\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b') -or ($x -eq 3))
    if($x -eq 3)
    {
        $LastExitMsg = "ERROR: $FsmoMasterIP is not a valid IPv4 Address"
        ExitFunc $LastExitMsg 1 ""
    }

    MenuContext
    #Verify that IP address is live or exit with error code (tested)
    If((Test-Connection $FsmoMasterIP -count 1 -Quiet) -eq $false)
    {
        $LastExitMsg = "ERROR: Could not contact $FsmoMasterIP. Are you sure that it's online?"
        ExitFunc $LastExitMsg 1 ""
    }

    MenuContext

    #Adjust LocalHost Primary and Secondary DNS (tested)
    Set-DnsServers 0
    
    return $FsmoMasterIP   
}

###
### Get-FsmoMaster - HELPER FUNCTION
### Function responsible for resolving the FSMO Master IP to FQDN
### This function runs when called by FixAd

Function Get-FsmoMaster([String]$FsmoMasterIP)
{
    #Resolve DNS Name of FsmoMaster or exit with error code (tested)
    Try{$FsmoMaster = ([System.Net.Dns]::GetHostByAddress($FsmoMasterIP)).HostName}
    Catch
    {
        $LastExitMsg =  "ERROR: Could Not resolve the provided IP Address $FsmoMasterIP"
        ExitFunc $LastExitMsg 1 ""
    }

    return $FsmoMaster
}

###
### Set-KDC - HELPER FUNCTION
### Function responsible for stopping, disabling, and enabling the KDC Service
### This function runs when called by FixAd

Function Set-KDC([int]$Switch, [int]$Progress)
{
    if($Progress -eq 0){Write-Progress -Activity "Fixing DC Replication" -CurrentOperation "Disabling/Stopping KDC Service" -Status "Percent Complete:" -PercentComplete ((0 / 5) * 100)}
    if($Progress -eq 1){Write-Progress -Activity "Fixing DC Replication" -CurrentOperation "Enabling KDC Service" -Status "Percent Complete:" -PercentComplete ((4 / 5) * 100)}
    if($Switch -eq 0)
    {
            (Set-Service kdc -StartupType Disabled) > $null
            net stop kdc 2> null
    }
    if($Switch -eq 1)
    {
        (Set-Service kdc -StartupType Automatic) > $null
    }
    return
}

###
### Get-NetdomPWD - HELPER FUNCTION
### Function responsible for reseting the shared secret between the DC and the FSMO Master
### This function runs when called by FixAd

Function Set-NetdomPWD($AdminCreds)
{
    Write-Progress -Activity "Fixing DC Replication" -CurrentOperation "Resetting NETDOM Password" -Status "Percent Complete:" -PercentComplete ((1 / 5) * 100)
    
    #prepare netdom credentials (tested)
    $tempuser = $env:USERDOMAIN + "\" + $Admincreds.GetNetworkCredential().username
    $temppass = $Admincreds.GetNetworkCredential().password

    #execute netdom password reset or exit with error code (tested)
    $LastExitMsg = netdom resetpwd /Server:"$FsmoMaster" /UserD:$tempuser /PasswordD:$temppass
    if($LASTEXITCODE -ne 0) {ExitFunc $LastExitMsg $LASTEXITCODE ""}

    #clear netdom credentials (tested)
    $tempuser = ""
    $temppass = ""

    return
}

###
### Do-Replication - HELPER FUNCTION
### Function responsible for point replicating portions of AD
### This function runs when called by FixAd


Function Do-Replication()
{
    Write-Progress -Activity "Fixing DC Replication" -CurrentOperation "Replicating Active Directory" -Status "Percent Complete:" -PercentComplete ((2 / 5) * 100)
    $domainArray = $env:USERDNSDOMAIN.split(".")
    [string]$domain = $null
    $l = $domainArray.Length
    For($i=0; $i -lt $l; $i++)
    {
        if($i -lt ($l-1))
        {
            $domain+= "DC=" + $domainArray[$i] + ","
        }
        else
        {
        $domain+= "DC=" + $domainArray[$i] + '"'
        }
    }

    $i = 0
    Foreach($setions in @('"CN=Schema,CN=Configuration,','"CN=Configuration,','','"DC=ForestDnsZones,','"DC=DomainDnsZones,'))
    {
        if($i -ne 2)
        {
            $tempwrite = $setions + $domain 
        }
        if($i -eq 2)
        {
            $tempwrite = '"' + $domain
        }
        $LastExitMsg = repadmin /replicate $temphostname $FsmoMaster $tempwrite /full
        if($LASTEXITCODE -ne 0) {ExitFunc$LastExitMsg $LASTEXITCODE $Section}
        Write-Progress -Activity "Replication" -CurrentOperation "Copying: $tempwrite" -status "Percent Complete:" -PercentComplete (($i /5) * 100)
        start-sleep -s 1
        $i+=1
    }
 
    Write-Progress -Activity "Replicating Active Directory" -Completed
    Start-Sleep -Seconds 1
    return
}


###
### FixAD - WORKER FUNCTION
### Function responsible faciliting the automated fix of AD replication
### This function runs when called by the main function

Function FixAD()
{
    
    ################################################################################
    ###    Preparation Section of FIX AD 
    ################################################################################

    ###
    ### This section is responsible for:
    ###      1) Prompting for and validation of user provided data
    ###      2) Constructing variables used in the replication section
    MenuContext
 
    #Prompt for Domain Administrator Credentials (tested) 
    $Admincreds = Get-AdminCreds
    
    #Prompt for IP of FSMO Master or exit with error code (tested)
    $FsmoMasterIP = Get-FsmoMasterIP
    MenuContext
    #Find FsmoMaster FQDN
    $FsmoMaster = Get-FsmoMaster $FsmoMasterIP
    
    #prepare the target system hostname
    $temphostname = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN

    ################################################################################
    ###    Maunual Replication Section of FIX AD 
    ################################################################################

    ###
    ### This section is responsible for:
    ###      1) Disabling/Stopping KDC
    ###      2) Resetting the shared secret between the DC and FSMO Master
    ###      3) Replicating AD
    ###      4) Enabling KDC
    ###      5) Writing the progress of the above activities to the screen
    
    $i = 0
    foreach($FUNCS in @((Set-KDC 0 0),(Set-NetdomPWD $Admincreds),(Do-Replication),(Set-DnsServers 1 "" 1),(Set-KDC 1 1)))
    {
        $LastExitMsg = $FUNCS
        if($LASTEXITCODE -ne 0) {ExitFunc$LastExitMsg $LASTEXITCODE}
    }
    
    Start-Sleep -Seconds 2
    Write-Progress -Activity "Fixing DC Replication" -Completed
    #Exit Successfully
    
    MenuContext
    Write-Host
    Write-Host "Replication Completed Successfully!"
    start-sleep 3
    ExitFunc 0
}

################################################################################
###    MAIN FUNCTION START   ###
################################################################################

###
### Main Function
### Function responsible displaying the main menu
### This function runs when the script is run

While($true)
{
    Clear-Host
    $Global:MenuContext = "Main"
    MenuContext
    Write-Host
    Write-Host
    Write-Host "Main Menu:"
    Write-Host 
    Write-Host "1) Apply the Fix"
    Write-Host
    Write-Host "0) Exit"
    Write-Host
    $Choice = Read-Host -Prompt "Enter Choice"
    
    Switch ($Choice)
    {
        1 {
            FixAD
          }
        0 { exit }
        default {"Try Again."}
    }
}
