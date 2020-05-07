# Rename this file to Settings.ps1
######################### value replacement #####################
[array]  $Global:ComputerList           = @()         
[array]  $Global:ADServerDN             = @()         
[array]  $Global:ADDCDN                 = @()         
[array]  $Global:ADWSDN                 = @()         
[string] $Global:DC                     = ""         


######################### no replacement ########################
[int]    $Global:DelayAfterServerReboot = 5*3600  #Delay in seconds
[int]    $Global:DelayAfterDCReboot     = 15*3600 #Delay in seconds
[int]    $Global:DelayAfterWSReboot     = 0       #Delay in seconds


[bool]  $Global:LocalSettingsSuccessfullyLoaded  = $true
# Error trap
    trap {
        $Global:LocalSettingsSuccessfullyLoaded = $False
        exit 1
    }
