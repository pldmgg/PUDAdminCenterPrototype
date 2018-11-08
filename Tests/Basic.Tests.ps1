[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)

# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\WinAdminCenterPS\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "WinAdminCenterPS"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\WinAdminCenterPS\WinAdminCenterPS\WinAdminCenterPS.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\WinAdminCenterPS\WinAdminCenterPS"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\WinAdminCenterPS\BuildOutput"
#>

# Verbose output for non-master builds on appveyor
# Handy for troubleshooting.
# Splat @Verbose against commands as needed (here or in pester tests)
$Verbose = @{}
if($env:BHBranchName -notlike "master" -or $env:BHCommitMessage -match "!verbose") {
    $Verbose.add("Verbose",$True)
}

# Make sure the Module is not already loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}

Describe -Name "General Project Validation: $env:BHProjectName" -Tag 'Validation' -Fixture {
    $Scripts = Get-ChildItem $env:BHProjectPath -Include *.ps1,*.psm1,*.psd1 -Recurse

    # TestCases are splatted to the script so we need hashtables
    $TestCasesHashTable = $Scripts | foreach {@{file=$_}}         
    It "Script <file> should be valid powershell" -TestCases $TestCasesHashTable {
        param($file)

        $file.fullname | Should Exist

        $contents = Get-Content -Path $file.fullname -ErrorAction Stop
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
        $errors.Count | Should Be 0
    }

    $Net472Check = Get-ChildItem "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 461808 }
    if ($Net472Check) {
        It "Module '$env:BHProjectName' Should Load" -Test {
            {Import-Module $env:BHPSModuleManifest -Force} | Should Not Throw
        }
    }

    It "Module '$env:BHProjectName' Public and Not Private Functions Are Available" {
        $Module = Get-Module $env:BHProjectName
        $Module.Name -eq $env:BHProjectName | Should Be $True
        $Commands = $Module.ExportedCommands.Keys
        $Commands -contains 'AddWinRMTrustedHost' | Should Be $False
        $Commands -contains 'AddWinRMTrustLocalHost' | Should Be $False
        $Commands -contains 'EnableWinRMViaRPC' | Should Be $False
        $Commands -contains 'GetComputerObjectsInLDAP' | Should Be $False
        $Commands -contains 'GetDomainController' | Should Be $False
        $Commands -contains 'GetDomainName' | Should Be $False
        $Commands -contains 'GetElevation' | Should Be $False
        $Commands -contains 'GetGroupObjectsInLDAP' | Should Be $False
        $Commands -contains 'GetLDAPGroupAndUsers' | Should Be $False
        $Commands -contains 'GetLDAPUserAndGroups' | Should Be $False
        $Commands -contains 'GetModuleDependencies' | Should Be $False
        $Commands -contains 'GetNativePath' | Should Be $False
        $Commands -contains 'GetUserObjectsInLDAP' | Should Be $False
        $Commands -contains 'GetWorkingCredentials' | Should Be $False
        $Commands -contains 'InstallFeatureDism' | Should Be $False
        $Commands -contains 'InvokeModuleDependencies' | Should Be $False
        $Commands -contains 'InvokePSCompatibility' | Should Be $False
        $Commands -contains 'ManualPSGalleryModuleInstall' | Should Be $False
        $Commands -contains 'NewUniqueString' | Should Be $False
        $Commands -contains 'ResolveHost' | Should Be $False
        $Commands -contains 'TestIsValidIPAddress' | Should Be $False
        $Commands -contains 'TestLDAP' | Should Be $False
        $Commands -contains 'TestPort' | Should Be $False
        $Commands -contains 'TestSSH' | Should Be $False
        $Commands -contains 'UnzipFile' | Should Be $False
        
        $Commands -contains 'Get-CertificateOverview' | Should Be $True
        $Commands -contains 'Get-Certificates' | Should Be $True
        $Commands -contains 'Get-CimPnpEntity' | Should Be $True
        $Commands -contains 'Get-EnvironmentVariables' | Should Be $True
        $Commands -contains 'Get-EventLogSummary' | Should Be $True
        $Commands -contains 'Get-FirewallProfile' | Should Be $True
        $Commands -contains 'Get-FirewallRules' | Should Be $True
        $Commands -contains 'Get-IPRange' | Should Be $True
        $Commands -contains 'Get-LocalGroups' | Should Be $True
        $Commands -contains 'Get-LocalGroupUsers' | Should Be $True
        $Commands -contains 'Get-LocalUserBelongGroups' | Should Be $True
        $Commands -contains 'Get-LocalUsers' | Should Be $True
        $Commands -contains 'Get-Networks' | Should Be $True
        $Commands -contains 'Get-PendingUpdates' | Should Be $True
        $Commands -contains 'Get-Processes' | Should Be $True
        $Commands -contains 'Get-PUDAdminCenter' | Should Be $True
        $Commands -contains 'Get-RegistrySubKeys' | Should Be $True
        $Commands -contains 'Get-RegistryValues' | Should Be $True
        $Commands -contains 'Get-RemoteDesktop' | Should Be $True
        $Commands -contains 'Get-ScheduledTasks' | Should Be $True
        $Commands -contains 'Get-ServerInventory' | Should Be $True
        $Commands -contains 'Get-StorageDisk' | Should Be $True
        $Commands -contains 'Get-StorageFileShare' | Should Be $True
        $Commands -contains 'Get-StorageVolume' | Should Be $True
        $Commands -contains 'Get-WUAHistory' | Should Be $True
        $Commands -contains 'Install-DotNet472' | Should Be $True
        $Commands -contains 'New-EnvironmentVariable' | Should Be $True
        $Commands -contains 'New-Runspace' | Should Be $True
        $Commands -contains 'Remove-EnvironmentVariable' | Should Be $True
        $Commands -contains 'Set-ComputerIdentification' | Should Be $True
        $Commands -contains 'Set-EnvironmentVariable' | Should Be $True
        $Commands -contains 'Set-RemoteDesktop' | Should Be $True
        $Commands -contains 'Start-DiskPerf' | Should Be $True
        $Commands -contains 'Stop-DiskPerf' | Should Be $True
    }

    It "Module '$env:BHProjectName' Private Functions Are Available in Internal Scope" {
        $Module = Get-Module $env:BHProjectName
        [bool]$Module.Invoke({Get-Item function:AddWinRMTrustedHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:AddWinRMTrustLocalHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:EnableWinRMViaRPC}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetComputerObjectsInLDAP}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetDomainController}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetDomainName}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetElevation}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetGroupObjectsInLDAP}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetLDAPGroupAndUsers}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetLDAPUserAndGroups}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetModuleDependencies}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetNativePath}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetUserObjectsInLDAP}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetWorkingCredentials}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InstallFeatureDism}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InvokeModuleDependencies}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InvokePSCompatibility}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ManualPSGalleryModuleInstall}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:NewUniqueString}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ResolveHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:TestIsValidIPAddress}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:TestLDAP}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:TestPort}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:UnzipFile}) | Should Be $True
    }
}

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0K2uSO6ixiKRhE8maDET+TUc
# 0NGgggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
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
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUvhvjGIJzf2JAMPzsGyel+zNqKk0w
# DQYJKoZIhvcNAQEBBQAEggEARu2/I0WP1B0xMEN2HNONjeFxLV1rGfdg1J5O2dcQ
# czDl5FlVC+hLJ7Lb9Lv+ffuuGdRRURr5KuvshvQdB/U3w4clHltj7SpY9zl1RahN
# s0vgiAQctj4peUSSg6ztxF/ZpRkO8YcbDtd346Y3LRlOt3Y3PbcFun03/2ScNi1Y
# GGz+PksIevuiCLYhCnHjBbISl3mussJKHLC7M7tlFsu3DBsejDVMgBLXLkMatmWb
# oiSNGfhqrbshshhjXNaKYgfqEsR9OaRbD+ir0Iwg9QUX2cj+CHlttMX5P09jHnhh
# cE6x0RUbG7SiJvyXOZ5nAl/QakK+kUA8jj8Ane1NkvQGhA==
# SIG # End signature block
