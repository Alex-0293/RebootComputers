<#
    .SYNOPSIS 
        .AUTOR Alexk
        .DATE  06.05.2020
        .VER   1
    .DESCRIPTION
    Script to reboot remote computers.
    .PARAMETER
    .EXAMPLE
#>
Param (
    [ValidateSet("Workstation", "Server", "DC", "Custom")]
    [string] $ComputerType    
)


clear-host
$Global:ScriptName = $MyInvocation.MyCommand.Name
$InitScript = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"
if (. "$InitScript" -MyScriptRoot (split-path $PSCommandPath -Parent) -force) { exit 1}

# Error trap
trap {
    if ($Global:Logger) {
       Get-ErrorReporting $_
        . "$GlobalSettings\$SCRIPTSFolder\Finish.ps1" 
    }
    Else {
        Write-Host "There is error before logging initialized." -ForegroundColor Red
    }   
    exit 1
}
################################# Script start here #################################

Function Get-DomainComputers {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 06.05.2020
        .VER 1   
    .DESCRIPTION
     Get domain computers in OU.
    .EXAMPLE
    Get-DomainComputers -Computer "Host1" -Credentials $Credentials 
    #>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Remote computer name." )]
        [ValidateNotNullOrEmpty()]
        [string] $Computer,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Credentials." )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential] $Credentials,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Distinguish name." )]
        [ValidateNotNullOrEmpty()]
        [string] $DN
    )

    [array]$output = @() 
    
    $ScriptBlock = {`
        Import-Module ActiveDirectory
        [array]$output = @()  
        $ADComputers = get-AdComputer -SearchBase $Using:DN -Filter * -Properties *
          
        return $ADComputers
    } 
       
    $output = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credentials -TestComputer
    return $output 
}

$User        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Login
$Pass        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Pass
if ($User -and $Pass){
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList (Get-VarToString $User), $Pass

    switch ($ComputerType.ToUpper()) {
        "CUSTOM" { 
            if ($ComputerList){
                foreach ($Item in $ComputerList) {
                    Restart-Computer -ComputerName $Item -Credential $Credentials -Force
                    Add-ToLog -Message "Reboot [$Item]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                    if ($ComputerList.Count -gt 1) {
                        Start-Sleep $DelayAfterWSReboot
                    }
                } 
            }           
        }
        "WORKSTATION" { 
            if ($ADWSDN) {
                [array] $Computers = @()
                foreach ($DN in $ADWSDN){
                    $Computers += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description | Where-Object { $_.OperatingSystem -like "*windows*" }
                }
            }
            $Computers | Format-Table -AutoSize
            foreach ($Item in $Computers) {
                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                Add-ToLog -Message "Reboot [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                if ($Computers.Count -gt 1) {
                    Start-Sleep $DelayAfterWSReboot
                }
            }            
        }
        "SERVER" { 
            if ($ADServerDN) {
                [array] $Servers   = @()
                foreach ($DN in $ADServerDN) {
                    $Servers += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description | Where-Object { $_.OperatingSystem -like "*windows*" }
                }
            }
            $Servers | Format-Table -AutoSize
            foreach ($Item in $Servers) {
                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                Add-ToLog -Message "Reboot [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                if ($Servers.Count -gt 1) {
                    Start-Sleep $DelayAfterServerReboot
                }
            }
        }
        "DC" { 
            if ($ADDCDN) {
                [array] $DCs       = @()
                foreach ($DN in $ADDCDN) {
                    $DCs += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description | Where-Object { $_.OperatingSystem -like "*windows*" }
                }
            }

            $DCs | Format-Table -AutoSize
            foreach ($Item in $DCs) {
                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                Add-ToLog -Message "Reboot [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                if ($DCs.Count -gt 1) {
                    Start-Sleep $DelayAfterDCReboot
                }
            }
        }
        Default {}
    }     
}

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"