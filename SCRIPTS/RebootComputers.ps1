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
    [string] $ComputerType,
    [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Reboot only if pending." )]
    [switch] $OnlyPendingReboot        
)


$Global:ScriptInvocation = $MyInvocation
if ($env:AlexKFrameworkInitScript){. "$env:AlexKFrameworkInitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal} Else {Write-host "Environmental variable [AlexKFrameworkInitScript] does not exist!" -ForegroundColor Red; exit 1}
if ($LastExitCode) { exit 1 }

# Error trap
trap {
    if (get-module -FullyQualifiedName AlexkUtils) {
        Get-ErrorReporting $_        
        . "$GlobalSettingsPath\$SCRIPTSFolder\Finish.ps1" 
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
        $res = Import-Module ActiveDirectory -PassThru
        
        if ( $Res ) {
            [array]$output = @()  
            $ADComputers = Get-AdComputer -SearchBase $Using:DN -Filter * -Properties *
            
            return $ADComputers
        }
        Else {
            throw "Error [$_] while loading module [ActiveDirectory]"
        }
    } 
       
    $output = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credentials -TestComputer
    return $output 
}

#$ComputerType = "WORKSTATION"
#$OnlyPendingReboot = $true

[array] $ComputersWithErrors  = @()
[array] $ComputersWithSuccess = @()

$User        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_LoginFilePath
$Pass        = Get-VarFromAESFile $Global:GlobalKey1 $Global:APP_SCRIPT_ADMIN_PassFilePath
if ($User -and $Pass){
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList (Get-VarToString $User), $Pass
    $Restarted = $False
    & ipconfig.exe /FlushDNS
    switch ($ComputerType.ToUpper()) {
        "CUSTOM" { 
            if ($ComputerList){
                foreach ($Item in $ComputerList) {
                    $Delay = $DelayCustom
                    if (Test-Connection -ComputerName $Item -Quiet) {
                        $Item
                        try {                           
                            if ($OnlyPendingReboot) {
                                $ScriptBlock = {
                                    function Test-PendingReboot {
                                        if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { 
                                            return $true 
                                        }
                                        if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { 
                                            return $true 
                                        }
                                        if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { 
                                            return $true 
                                        }

                                        try { 
                                            $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
                                            $status = $util.DetermineIfRebootPending()
                                            if ($status -and $status.RebootPending) {
                                                return $true
                                            }
                                        }
                                        catch {}

                                        return $false
                                    }
                                    return Test-PendingReboot
                                }
                                $PendingReboot = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Item -Credentials $Credentials 
                                if ($PendingReboot){
                                    Restart-Computer -ComputerName $Item -Credential $Credentials -Force  
                                    $Restarted = $true                                  
                                }
                            }
                            Else {
                                Restart-Computer -ComputerName $Item -Credential $Credentials -Force
                                $Restarted = $true                                  
                            }
                            if ($Restarted) {
                                Add-ToLog -Message "Rebooting [$($Item)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                                $ComputersWithSuccess += $Item
                                if ($Computers.Count -gt 1) {
                                    Start-Sleep $Delay
                                }
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
                        if ($OnlyPendingReboot) {
                            $ScriptBlock = {
                                function Test-PendingReboot {
                                    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }

                                    try { 
                                        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
                                        $status = $util.DetermineIfRebootPending()
                                        if ($status -and $status.RebootPending) {
                                            return $true
                                        }
                                    }
                                    catch {}

                                    return $false
                                }
                                return Test-PendingReboot
                            }
                            $PendingReboot = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Item.DNSHostName -Credentials $Credentials 
                            if ($PendingReboot){
                                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force 
                                $Restarted = $true                                      
                            }
                        }
                        Else {
                            Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force 
                            $Restarted = $true                                 
                        }
                        if ($Restarted) {
                            Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                            $ComputersWithSuccess += $Item.DNSHostName
                            if ($Computers.Count -gt 1) {
                                Start-Sleep $Delay
                            }
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
                        if ($OnlyPendingReboot) {
                            $ScriptBlock = {
                                function Test-PendingReboot {
                                    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }

                                    try { 
                                        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
                                        $status = $util.DetermineIfRebootPending()
                                        if ($status -and $status.RebootPending) {
                                            return $true
                                        }
                                    }
                                    catch {}

                                    return $false
                                }
                                return Test-PendingReboot
                            }
                            $PendingReboot = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Item.DNSHostName -Credentials $Credentials 
                            if ($PendingReboot) {
                                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force  
                                $Restarted = $true                                     
                            }
                        }
                        Else {
                            Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force   
                            $Restarted = $true                               
                        }
                        if ($Restarted) {
                            Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                            $ComputersWithSuccess += $Item.DNSHostName
                            if ($Computers.Count -gt 1) {
                                Start-Sleep $Delay
                            }
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
                        if ($OnlyPendingReboot) {
                            $ScriptBlock = {
                                function Test-PendingReboot {
                                    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }
                                    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { 
                                        return $true 
                                    }

                                    try { 
                                        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
                                        $status = $util.DetermineIfRebootPending()
                                        if ($status -and $status.RebootPending) {
                                            return $true
                                        }
                                    }
                                    catch {}

                                    return $false
                                }
                                return Test-PendingReboot
                            }
                            $PendingReboot = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Item.DNSHostName -Credentials $Credentials 
                            if ($PendingReboot) {
                                Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force  
                                $Restarted = $true                                     
                            }
                        }
                        Else {
                            Restart-Computer -ComputerName $Item.DNSHostName -Credential $Credentials -Force   
                            $Restarted = $true                               
                        }
                        if ($Restarted) {
                            Add-ToLog -Message "Rebooting [$($Item.DNSHostName)]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
                            $ComputersWithSuccess += $Item.DNSHostName
                            if ($Computers.Count -gt 1) {
                                Start-Sleep $Delay
                            }
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
    
    if ($restarted) {        
        $ErrorCount   =  $ComputersWithErrors.Count
        $SuccessCount =  $ComputersWithSuccess.Count
        $TotalCount   =  $ErrorCount + $SuccessCount
        Add-ToLog -Message "Restart [$ComputerType]. OnlyPendingReboot [$OnlyPendingReboot]. Statistic [$SuccessCount/$TotalCount], host with errors [$($ComputersWithErrors -join ", ")]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)        
        if ( $ErrorCount ) {
            $Global:StateObject.Data        = "Statistic [$SuccessCount/$TotalCount], host with errors [$($ComputersWithErrors -join ", ")]."
            $Global:StateObject.Action      = "Restart [$ComputerType] opr [$OnlyPendingReboot]"
            $Global:StateObject.State       = "Errors while restart computers [$($ComputersWithErrors -join ", ")]. Completed successful [$($ComputersWithSuccess -join ", ")]."
            $Global:StateObject.GlobalState = $False
            Set-State -StateObject $Global:StateObject -StateFilePath $Global:StateFilePath -AlertType "telegram" -SaveOnChange
        }
        Else {
            $Global:StateObject.Action      = "Restart [$ComputerType] opr [$OnlyPendingReboot]"
            $Global:StateObject.State       = "Completed restart computers [$($ComputersWithSuccess -join ", ")]."
            $Global:StateObject.GlobalState = $true
            Set-State -StateObject $Global:StateObject -StateFilePath $Global:StateFilePath -AlertType "telegram" -SaveOnChange
        }
    }
    Else {
        Add-ToLog -Message "Restart [$ComputerType]. OnlyPendingReboot [$OnlyPendingReboot]. Statistic [0], host with errors [0]." -logFilePath $ScriptLogFilePath -display -status "Info" -level ($ParentLevel + 1)
        $Global:StateObject.Action      = "Restart [$ComputerType] opr [$OnlyPendingReboot]"
        $Global:StateObject.State       = "Completed restart computers [0]."
        $Global:StateObject.GlobalState = $true
        Set-State -StateObject $Global:StateObject -StateFilePath $Global:StateFilePath -AlertType "telegram" -SaveOnChange
    }
}

################################# Script end here ###################################
. "$GlobalSettingsPath\$SCRIPTSFolder\Finish.ps1"