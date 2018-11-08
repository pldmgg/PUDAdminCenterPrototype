function GetModuleDependencies {
    [CmdletBinding(DefaultParameterSetName="LoadedFunction")]
    Param (
        [Parameter(
            Mandatory=$False,
            ParameterSetName="LoadedFunction"
        )]
        [string]$NameOfLoadedFunction,

        [Parameter(
            Mandatory=$False,
            ParameterSetName="ScriptFile"    
        )]
        [string]$PathToScriptFile,

        [Parameter(Mandatory=$False)]
        [string[]]$ExplicitlyNeededModules
    )

    if ($NameOfLoadedFunction) {
        $LoadedFunctions = Get-ChildItem Function:\
        if ($LoadedFunctions.Name -notcontains $NameOfLoadedFunction) {
            Write-Error "The function '$NameOfLoadedFunction' is not currently loaded! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FunctionOrScriptContent = Invoke-Expression $('${Function:' + $NameOfLoadedFunction + '}.Ast.Extent.Text')
    }
    if ($PathToScriptFile) {
        if (!$(Test-Path $PathToScriptFile)) {
            Write-Error "Unable to find path '$PathToScriptFile'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FunctionOrScriptContent = Get-Content $PathToScriptFile
    }
    <#
    $ExplicitlyDefinedFunctionsInThisFunction = [Management.Automation.Language.Parser]::ParseInput($FunctionOrScriptContent, [ref]$null, [ref]$null).EndBlock.Statements.FindAll(
        [Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},
        $false
    ).Name
    #>

    # All Potential PSModulePaths
    $AllWindowsPSModulePaths = @(
        "C:\Program Files\WindowsPowerShell\Modules"
        "$HOME\Documents\WindowsPowerShell\Modules"
        "$HOME\Documents\PowerShell\Modules"
        "C:\Program Files\PowerShell\Modules"
        "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules"
    )

    $AllModuleManifestFileItems = foreach ($ModPath in $AllWindowsPSModulePaths) {
        if (Test-Path $ModPath) {
            Get-ChildItem -Path $ModPath -Recurse -File -Filter "*.psd1"
        }
    }

    $ModInfoFromManifests = foreach ($ManFileItem in $AllModuleManifestFileItems) {
        try {
            $ModManifestData = Import-PowerShellDataFile $ManFileItem.FullName -ErrorAction Stop
        }
        catch {
            continue
        }

        $Functions = $ModManifestData.FunctionsToExport | Where-Object {
            ![System.String]::IsNullOrWhiteSpace($_) -and $_ -ne '*'
        }
        $Cmdlets = $ModManifestData.CmdletsToExport | Where-Object {
            ![System.String]::IsNullOrWhiteSpace($_) -and $_ -ne '*'
        }

        @{
            ModuleName          = $ManFileItem.BaseName
            ManifestFileItem    = $ManFileItem
            ModuleManifestData  = $ModManifestData
            ExportedCommands    = $Functions + $Cmdlets
        }
    }
    $ModInfoFromGetCommand = Get-Command -CommandType Cmdlet,Function,Workflow

    $CurrentlyLoadedModuleNames = $(Get-Module).Name

    [System.Collections.ArrayList]$AutoFunctionsInfo = @()

    foreach ($ModInfoObj in $ModInfoFromManifests) {
        if ($AutoFunctionsInfo.ManifestFileItem -notcontains $ModInfoObj.ManifestFileItem) {
            $PSObj = [pscustomobject]@{
                ModuleName          = $ModInfoObj.ModuleName
                ManifestFileItem    = $ModInfoObj.ManifestFileItem
                ExportedCommands    = $ModInfoObj.ExportedCommands
            }
            
            if ($NameOfLoadedFunction) {
                if ($PSObj.ModuleName -ne $NameOfLoadedFunction -and
                $CurrentlyLoadedModuleNames -notcontains $PSObj.ModuleName
                ) {
                    $null = $AutoFunctionsInfo.Add($PSObj)
                }
            }
            if ($PathToScriptFile) {
                $ScriptFileItem = Get-Item $PathToScriptFile
                if ($PSObj.ModuleName -ne $ScriptFileItem.BaseName -and
                $CurrentlyLoadedModuleNames -notcontains $PSObj.ModuleName
                ) {
                    $null = $AutoFunctionsInfo.Add($PSObj)
                }
            }
        }
    }
    foreach ($ModInfoObj in $ModInfoFromGetCommand) {
        $PSObj = [pscustomobject]@{
            ModuleName          = $ModInfoObj.ModuleName
            ExportedCommands    = $ModInfoObj.Name
        }

        if ($NameOfLoadedFunction) {
            if ($PSObj.ModuleName -ne $NameOfLoadedFunction -and
            $CurrentlyLoadedModuleNames -notcontains $PSObj.ModuleName
            ) {
                $null = $AutoFunctionsInfo.Add($PSObj)
            }
        }
        if ($PathToScriptFile) {
            $ScriptFileItem = Get-Item $PathToScriptFile
            if ($PSObj.ModuleName -ne $ScriptFileItem.BaseName -and
            $CurrentlyLoadedModuleNames -notcontains $PSObj.ModuleName
            ) {
                $null = $AutoFunctionsInfo.Add($PSObj)
            }
        }
    }
    
    $AutoFunctionsInfo = $AutoFunctionsInfo | Where-Object {
        ![string]::IsNullOrWhiteSpace($_) -and
        $_.ManifestFileItem -ne $null
    }

    $FunctionRegex = "([a-zA-Z]|[0-9])+-([a-zA-Z]|[0-9])+"
    $LinesWithFunctions = $($FunctionOrScriptContent -split "`n") -match $FunctionRegex | Where-Object {![bool]$($_ -match "[\s]+#")}
    $FinalFunctionList = $($LinesWithFunctions | Select-String -Pattern $FunctionRegex -AllMatches).Matches.Value | Sort-Object | Get-Unique
    
    [System.Collections.ArrayList]$NeededWinPSModules = @()
    [System.Collections.ArrayList]$NeededPSCoreModules = @()
    foreach ($ModObj in $AutoFunctionsInfo) {
        foreach ($Func in $FinalFunctionList) {
            if ($ModObj.ExportedCommands -contains $Func -or $ExplicitlyNeededModules -contains $ModObj.ModuleName) {
                if ($ModObj.ManifestFileItem.FullName -match "\\WindowsPowerShell\\") {
                    if ($NeededWinPSModules.ManifestFileItem.FullName -notcontains $ModObj.ManifestFileItem.FullName -and
                    $ModObj.ModuleName -notmatch "\.WinModule") {
                        $PSObj = [pscustomobject]@{
                            ModuleName          = $ModObj.ModuleName
                            ManifestFileItem    = $ModObj.ManifestFileItem
                        }
                        $null = $NeededWinPSModules.Add($PSObj)
                    }
                }
                elseif ($ModObj.ManifestFileItem.FullName -match "\\PowerShell\\") {
                    if ($NeededPSCoreModules.ManifestFileItem.FullName -notcontains $ModObj.ManifestFileItem.FullName -and
                    $ModObj.ModuleName -notmatch "\.WinModule") {
                        $PSObj = [pscustomobject]@{
                            ModuleName          = $ModObj.ModuleName
                            ManifestFileItem    = $ModObj.ManifestFileItem
                        }
                        $null = $NeededPSCoreModules.Add($PSObj)
                    }
                }
                elseif ($PSVersionTable.PSEdition -eq "Core") {
                    if ($NeededPSCoreModules.ModuleName -notcontains $ModObj.ModuleName -and
                    $ModObj.ModuleName -notmatch "\.WinModule") {
                        $PSObj = [pscustomobject]@{
                            ModuleName          = $ModObj.ModuleName
                            ManifestFileItem    = $null
                        }
                        $null = $NeededPSCoreModules.Add($PSObj)
                    }
                }
                else {
                    if ($NeededWinPSModules.ModuleName -notcontains $ModObj.ModuleName) {
                        $PSObj = [pscustomobject]@{
                            ModuleName          = $ModObj.ModuleName
                            ManifestFileItem    = $null
                        }
                        $null = $NeededWinPSModules.Add($PSObj)
                    }
                }
            }
        }
    }

    [System.Collections.ArrayList]$WinPSModuleDependencies = @()
    [System.Collections.ArrayList]$PSCoreModuleDependencies = @()
    $($NeededWinPSModules | Where-Object {![string]::IsNullOrWhiteSpace($_.ModuleName)}) | foreach {
        $null = $WinPSModuleDependencies.Add($_)
    }
    $($NeededPSCoreModules | Where-Object {![string]::IsNullOrWhiteSpace($_.ModuleName)}) | foreach {
        $null = $PSCoreModuleDependencies.Add($_)
    }

    [pscustomobject]@{
        WinPSModuleDependencies     = $WinPSModuleDependencies
        PSCoreModuleDependencies    = $PSCoreModuleDependencies
    }
}

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMiM107jw9Y/cfs9lQqnHygts
# X96gggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
# 9w0BAQsFADBAMRMwEQYKCZImiZPyLGQBGRYDbGFiMRUwEwYKCZImiZPyLGQBGRYF
# YWxwaGExEjAQBgNVBAMTCUFscGhhREMwMTAeFw0xODExMDYxNTQ2MjhaFw0yMDEx
# MDYxNTU2MjhaMEExEzARBgoJkiaJk/IsZAEZFgNsYWIxFTATBgoJkiaJk/IsZAEZ
# FgVhbHBoYTETMBEGA1UEAxMKQWxwaGFTdWJDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAJ0yJxQZZ7jXPnBuOefihL0ehpBF1zoZpcM30pWneQA/kk9w
# ByX9ISyKWTABstiIu8b2g6lKUjZBM8AOcLPSjl1ZMQkh+qaSQbJFVNeNYllGpjd1
# oOYvSPtr9iPpghVkAFWw9IdOgnd/4XDd4NqlddyR4Qb0g7v3+AMYrqhQCk2VzELp
# 215LEO9sy1EMy7+B29B6P43Rp7ljA9Wc4Hnl+onviFWcIxmIhd0yGdobSxOSDgv5
# SUBfwk+DW03Y9pmJJHCU9hXFFVsPnrfBEvicGrkYx0vA+/O+jh5otex4eR+Tt7eB
# 5VhrfdHKbEkZnBwrJOVz3rURZIu3BsDFSfwNd70CAwEAAaOCARkwggEVMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRWBfwwFO+72Ebloy7rHmHnxX3k5DAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTq79v4G/Vf91c0y+vSJBWEI/vmDTA8BgNVHR8E
# NTAzMDGgL6AthitodHRwOi8vcGtpLmFscGhhLmxhYi9jZXJ0ZGF0YS9BbHBoYURD
# MDEuY3JsMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAoYraHR0cDovL3BraS5h
# bHBoYS5sYWIvY2VydGRhdGEvQWxwaGFEQzAxLmNydDANBgkqhkiG9w0BAQsFAAOC
# AQEAoE9hHZ0Y5M5tC15cnxVNJa/ILfwRmwCxzPyOAUrdBu4jbSHF2vRsKIJAXFs4
# +mwXqXpLYSUbXF5tfB86OKs2f9L7soln3BXJHj3eEs27htf7RJK1JjPtO8rs3pdn
# h7TbDO3nyjkTcywJioScFZUTdIsQj7TBm3HIQ+/ZSdIWMHlQnYV2kW13XqUZnLhv
# PRjy1NMBG1BAxUrc4bMi1X+mVxoYb/tiB59jakd95wi7ICi2H/07dXoDpi+kAQA1
# ki1/U+cuDhuH7Q8hegt64MlmKD01rO5HODVujuIG1+M5ZkGDeLNKksPHcSJ/DBSn
# KjZca16Sn9No2kLq1q9gD8X/wzCCBh4wggUGoAMCAQICE3AAAAAHhXSIXehTWisA
# AAAAAAcwDQYJKoZIhvcNAQELBQAwQTETMBEGCgmSJomT8ixkARkWA2xhYjEVMBMG
# CgmSJomT8ixkARkWBWFscGhhMRMwEQYDVQQDEwpBbHBoYVN1YkNBMB4XDTE4MTEw
# NzAzMTQyMFoXDTE5MTEwNzAzMTQyMFowTzETMBEGCgmSJomT8ixkARkWA2xhYjEV
# MBMGCgmSJomT8ixkARkWBWFscGhhMQ4wDAYDVQQDEwVVc2VyczERMA8GA1UEAxMI
# YWxwaGFkZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMUGwGv3p0
# prkDmSUQphU6UvIFQ57NxJFUOSmMZ7SY/nYNDy0iTN26eD0S5J8AQE8B/IGLHUno
# tKFl2AUcQ31hpaSLE1YkThR3WZ4SFUaBMUgKKLc/RQKqE0iNbAfh53N/nnGs6jyu
# 47kyuFRwWE2tZee6b5hh0dbT7YZnahLO7cLWErU4ikWWjEA98TcMK1gaNa5ThBn1
# +4bo9wuxjRKIGpkUJBP/1gq8qeSJnfNelZ34lD0EEirj7/YTzL5YkHMSXTuFMozw
# Av4lXUW/qZ1pAT9rKBalQETxBv9SuC31hU/2EiB4EYYqVFLHglFRogLd7nFZhqa/
# 2O+WdW2LsW9lAgMBAAGjggL/MIIC+zAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE
# FMy71rz8tJOXdsGvBt6SIVSKUlrkMB8GA1UdIwQYMBaAFFYF/DAU77vYRuWjLuse
# YefFfeTkMIH3BgNVHR8Ege8wgewwgemggeaggeOGgbJsZGFwOi8vL0NOPUFscGhh
# U3ViQ0EsQ049QWxwaGFTdWJDQSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vy
# dmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1hbHBoYSxEQz1s
# YWI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
# TERpc3RyaWJ1dGlvblBvaW50hixodHRwOi8vcGtpLmFscGhhLmxhYi9jZXJ0ZGF0
# YS9BbHBoYVN1YkNBLmNybDCB9AYIKwYBBQUHAQEEgecwgeQwgacGCCsGAQUFBzAC
# hoGabGRhcDovLy9DTj1BbHBoYVN1YkNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
# MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWFscGhh
# LERDPWxhYj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
# dGlvbkF1dGhvcml0eTA4BggrBgEFBQcwAoYsaHR0cDovL3BraS5hbHBoYS5sYWIv
# Y2VydGRhdGEvQWxwaGFTdWJDQS5jcnQwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGC
# NxUIhLycPIHG3hyBiYk0hLvpfobokGRgg9+kPoHDslgCAWQCAQIwHwYDVR0lBBgw
# FgYKKwYBBAGCNwoDDAYIKwYBBQUHAwMwKQYJKwYBBAGCNxUKBBwwGjAMBgorBgEE
# AYI3CgMMMAoGCCsGAQUFBwMDMC0GA1UdEQQmMCSgIgYKKwYBBAGCNxQCA6AUDBJh
# bHBoYWRldkBhbHBoYS5sYWIwDQYJKoZIhvcNAQELBQADggEBAIhV0GPEvq5KwIs+
# DTqLsqHcojMyJhJwrZkEim2XAJfNQFkiDrZzism7lOyXYJol6Bjz1txhos7P194+
# VyBdEZ/Q+r94hrq6SFgC2gCAReDZiy50Au/hTv958QNX/O0OFdIGBxavLqBrWbwu
# yH+RtE9E4LICSPPd0dM/5XE0xtqDMjZcl3pVkqgHpv3O3zgtsTW+FWr4b9lq3rCO
# HxsBGU1w7Eh0LLK8MLqioecr/4B1rPTJkcASXWMU5bllQgQvUmlKW0GIfhC9aM4J
# 04MeJOU1mHLjDcxwWpDD670AFmGRg/mMPxMywvY0HLUszWikcXNYxF1ph+LhlLI9
# f9R1qqkxggH5MIIB9QIBATBYMEExEzARBgoJkiaJk/IsZAEZFgNsYWIxFTATBgoJ
# kiaJk/IsZAEZFgVhbHBoYTETMBEGA1UEAxMKQWxwaGFTdWJDQQITcAAAAAeFdIhd
# 6FNaKwAAAAAABzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUFDrHVn1dZA5WNLaTbLSpj04I8eIw
# DQYJKoZIhvcNAQEBBQAEggEAZKNMk+ODutyfV030100xEj4GdHzaNIG4iPCvaygt
# 1/ED2/S0r/AwpxDDckhJ9beZ8y0QyXc88fVeGG9jagZq/p3ZFmGy9RXZnF9fpXls
# tnog5Aivw1lqzNvbzRXsHKMt/uz6I0ZYcaPsoBwlBqzTkoB+N9IvclW+Q1s/MU2v
# pQxEwNHaPvPTbild4kyWVs2CIM5HPTJ1o0euftuKZAI7iaGi7W6aECZks2eQPiP2
# mcD5TJKFeUyQ+wMsxyuzYjcvbTZEoaqe+9mMPPED6g70gaiOpji95ai8LByE0ALA
# GvmsmOy1AwT1CUya2HF/d+mPoW9LAkxnMIYqUwuwHaKNSw==
# SIG # End signature block
