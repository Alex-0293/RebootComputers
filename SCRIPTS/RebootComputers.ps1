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
    [Parameter( Mandatory = $false, Position = 0, HelpMessage = "Initialize global settings." )]
    [bool] $InitGlobal = $true,
    [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initialize local settings." )]
    [bool] $InitLocal = $true,
    [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Select computers set to reboot." )]
    [ValidateSet("Workstation", "Server", "DC", "Custom")]
    [string] $ComputerType        
)


$Global:ScriptInvocation = $MyInvocation
$InitScript = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"
. "$InitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal
if ($LastExitCode) { exit 1 }

# Error trap
trap {
    if (get-module -FullyQualifiedName AlexkUtils) {
        Get-ErrorReporting $_        
        . "$GlobalSettings\$SCRIPTSFolder\Finish.ps1" 
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand.path)] There is error before logging initialized. Error: $_" -ForegroundColor Red
    }  
    $Global:GlobalSettingsSuccessfullyLoaded = $false
    exit 1
}
################################# Script start here #################################
#$ComputerType = "DC"
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

[array] $ComputersWithErrors  = @()
[array] $ComputersWithSuccess = @()

$User        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Login
$Pass        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_Pass
if ($User -and $Pass){
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList (Get-VarToString $User), $Pass

    switch ($ComputerType.ToUpper()) {
        "CUSTOM" { 
            if ($ComputerList){
                foreach ($Item in $ComputerList) {
                    $Delay = $DelayCustom
                    if (Test-Connection -ComputerName $Item -Quiet) {
                        $Item.DNSHostName
                        try {
                            Restart-Computer -ComputerName $Item -Credential $Credentials -Force
                            Add-ToLog -Message "Rebooting [$($Item)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                            $ComputersWithSuccess += $Item
                            if ($Computers.Count -gt 1) {
                                Start-Sleep $Delay
                            }
                        }
                        Catch {
                            $ComputersWithErrors += $Item
                            Add-ToLog -Message "Reboot [$($Item)] failed [$_]." -logFilePath $ScriptLogFilePath -display -status "Error" -level ($ParentLevel + 1)
                        }
                    }
                } 
            }           
        }
        "WORKSTATION" { 
            if ($ADWSDN) {
                [array] $Computers = @()
                foreach ($DN in $ADWSDN){                    
                    $Computers += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description, Enabled | Where-Object { ($_.OperatingSystem -like "*windows*") -and ($_.DNSHostName -NotLike "*$($env:COMPUTERNAME)*") -and ($_.Enabled -eq $true)} | Sort-Object DNSHostName
                }
            }
            $Computers | Format-Table -AutoSize            
            foreach ($Item in $Computers) {
                $Delay = $DelayAfterWSReboot
                if (Test-Connection -ComputerName $Item.DNSHostName -Quiet){
                    $Item.DNSHostName
                    try {
                         Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                         write-host $Global:DelayAfterServerReboot
                         Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                         $ComputersWithSuccess += $Item.DNSHostName
                         if ($Computers.Count -gt 1) {
                            Start-Sleep $Delay
                         }
                    }
                    Catch {
                         $ComputersWithErrors += $Item.DNSHostName
                         Add-ToLog -Message "Reboot [$($Item.DNSHostName)] failed [$_]." -logFilePath $ScriptLogFilePath -display -status "Error" -level ($ParentLevel + 1)
                    }
                }
            }            
        }
        "SERVER" { 
            if ($ADServerDN) {
                [array] $Servers   = @()
                foreach ($DN in $ADServerDN) {
                    $Servers += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description, Enabled | Where-Object { ($_.OperatingSystem -like "*windows*") -and ($_.DNSHostName -NotLike "*$($env:COMPUTERNAME)*") -and ($_.Enabled -eq $true) } | Sort-Object DNSHostName
                }
            }
            $Servers | Format-Table -AutoSize
            foreach ($Item in $Servers) {
                $Delay = $DelayAfterServerReboot
                if (Test-Connection -ComputerName $Item.DNSHostName -Quiet) {
                    $Item.DNSHostName
                    try {
                        Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                        Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                        $ComputersWithSuccess += $Item.DNSHostName
                        if ($Computers.Count -gt 1) {
                            Start-Sleep $Delay
                        }
                    }
                    Catch {
                        $ComputersWithErrors += $Item.DNSHostName
                        Add-ToLog -Message "Reboot [$($Item.DNSHostName)] failed [$_]." -logFilePath $ScriptLogFilePath -display -status "Error" -level ($ParentLevel + 1)
                    }
                }               
            }
        }
        "DC" { 
            if ($ADDCDN) {
                [array] $DCs       = @()
                foreach ($DN in $ADDCDN) {
                    $DCs += (Get-DomainComputers -Computer $Global:DC -Credentials $Credentials -DN $DN) | Select-Object ObjectClass, DNSHostName, OperatingSystem, Description, Enabled | Where-Object { ($_.OperatingSystem -like "*windows*") -and ($_.DNSHostName -NotLike "*$($env:COMPUTERNAME)*") -and ($_.Enabled -eq $true) } | Sort-Object DNSHostName
                }
            }

            $DCs | Format-Table -AutoSize
            foreach ($Item in $DCs) {
                $Delay = $DelayAfterDCReboot
                if (Test-Connection -ComputerName $Item.DNSHostName -Quiet) {
                    $Item.DNSHostName
                    try {
                        Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force
                        Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                        $ComputersWithSuccess += $Item.DNSHostName
                        if ($Computers.Count -gt 1) {
                            Start-Sleep $Delay
                        }
                    }
                    Catch {
                        $ComputersWithErrors += $Item.DNSHostName
                        Add-ToLog -Message "Reboot [$($Item.DNSHostName)] failed [$_]." -logFilePath $ScriptLogFilePath -display -status "Error" -level ($ParentLevel + 1)
                    }
                }
            }
        }
        Default {}
    }
    
    $ErrorCount   =  $ComputersWithErrors.Count
    $SuccessCount =  $ComputersWithSuccess.Count
    $TotalCount   =  $ErrorCount + $SuccessCount
    Add-ToLog -Message "Statistic [$SuccessCount/$TotalCount], host with errors [$($ComputersWithErrors -join ", ")]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
    
}

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"