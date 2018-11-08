[CmdletBinding(DefaultParameterSetName = 'task')]
Param (
    [Parameter(
        Mandatory = $False,
        ParameterSetName = 'task',
        Position = 0
    )]
    [string[]]$Task = 'Default',

    [Parameter(Mandatory = $False)]
    [string]$CertFileForSignature,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

    [Parameter(Mandatory = $False)]
    [pscredential]$AdminUserCreds,

    [Parameter(
        Mandatory = $False,
        ParameterSetName = 'help'
    )]
    [switch]$Help,

    [Parameter(Mandatory = $False)]
    [switch]$AppVeyorContext
)

# Workflow is build.ps1 -> psake.ps1 -> *Tests.ps1

##### BEGIN Prepare For Build #####

$ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$ElevationCheck) {
    Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
    $global:FunctionResult = "1"
    return
}

if ($AdminUserCreds) {
    # Make sure $AdminUserCreds.UserName format is <Domain>\<User> and <LocalHostName>\<User>
    if ($AdminUserCreds.UserName -notmatch "[\w]+\\[\w]+") {
        Write-Error "The UserName provided in the PSCredential -AdminUserCreds is not in the correct format! Please create the PSCredential with a UserName in the format <Domain>\<User> or <LocalHostName>\<User>. Halting!"
        $global:FunctionResult = "1"
        return
    }
}

if ($CertFileForSignature -and !$Cert) {
    if (!$(Test-Path $CertFileForSignature)) {
        Write-Error "Unable to find the Certificate specified to be used for Code Signing! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $Cert = Get-PfxCertificate $CertFileForSignature -ErrorAction Stop
        if (!$Cert) {throw "There was a prblem with the Get-PfcCertificate cmdlet! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
}

if ($Cert) {
    # Make sure the Cert is good for Code Signing
    if ($Cert.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") {
        $CNOfCert = $($($Cert.Subject -split ",")[0] -replace "CN=","").Trim()
        Write-Error "The provided Certificate $CNOfCert says that it should be sued for $($Cert.EnhancedKeyUsageList.FriendlyName -join ','), NOT 'Code Signing'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure our ProtoHelpers are signed before we do anything else, otherwise we won't be able to use them
    $HelperFilestoSign = Get-ChildItem $(Resolve-Path "$PSScriptRoot\*Help*\").Path -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and $_.Name -ne "Remove-Signature.ps1"
    }

    # Before we loop through and sign the Helper functions, we need to sign Remove-Signature.ps1
    $RemoveSignatureFilePath = $(Resolve-Path "$PSScriptRoot\*Help*\Remove-Signature.ps1").Path
    if (!$(Test-Path $RemoveSignatureFilePath)) {
        Write-Error "Unable to find the path $RemoveSignatureFilePath! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Because Set-Authenticode sometimes eats a trailing line when it is used, make sure Remove-Signature.ps1 doesn't break
    $SingatureLineRegex = '^# SIG # Begin signature block|^<!-- SIG # Begin signature block -->'
    $RemoveSignatureContent = Get-Content $RemoveSignatureFilePath
    [System.Collections.ArrayList]$UpdatedRemoveSignatureContent = @()
    foreach ($line in $RemoveSignatureContent) {
        if ($line -match $SingatureLineRegex) {
            $null = $UpdatedRemoveSignatureContent.Add("`n")
            break
        }
        else {
            $null = $UpdatedRemoveSignatureContent.Add($line)
        }
    }
    Set-Content -Path $RemoveSignatureFilePath -Value $UpdatedRemoveSignatureContent

    try {
        $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $RemoveSignatureFilePath -Cert $Cert
        if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -ne "Valid") {throw "There was a problem using the Set-AuthenticodeSignature cmdlet to sign the Remove-Signature.ps1 function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Dot Source the Remove-Signature function
    . $RemoveSignatureFilePath
    if (![bool]$(Get-Item Function:\Remove-Signature)) {
        Write-Error "Problem dot sourcing the Remove-Signature function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Loop through the Help Scripts/Functions and sign them so that we can use them immediately if necessary
    Remove-Signature -FilePath $HelperFilestoSign.FullName

    [System.Collections.ArrayList]$FilesFailedToSign = @()
    foreach ($FilePath in $HelperFilestoSign.FullName) {
        try {
            $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $FilePath -cert $Cert
            if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -ne "Valid") {throw}
        }
        catch {
            $null = $FilesFailedToSign.Add($FilePath)
        }
    }

    if ($FilesFailedToSign.Count -gt 0) {
        Write-Error "Halting because we failed to digitally sign the following files:`n$($FilesFailedToSign -join "`n")"
        $global:FunctionResult = "1"
        return
    }
}

if (!$(Get-Module -ListAvailable PSDepend)) {
    & $(Resolve-Path "$PSScriptRoot\*Help*\Install-PSDepend.ps1").Path
}
try {
    Import-Module PSDepend
    $null = Invoke-PSDepend -Path "$PSScriptRoot\build.requirements.psd1" -Install -Import -Force

    # Hack to fix AppVeyor Error When attempting to Publish to PSGallery
    # The specific error this fixes is a problem with the Publish-Module cmdlet from PowerShellGet. PSDeploy
    # calls Publish-Module without the -Force parameter which results in this error: https://github.com/PowerShell/PowerShellGet/issues/79
    # This is more a problem with PowerShellGet than PSDeploy.
    <#
    Remove-Module PSDeploy
    $PSDeployScriptToEdit = Get-Childitem -Path $(Get-Module -ListAvailable PSDeploy).ModuleBase -File -Recurse -Filter "PSGalleryModule.ps1"
    [System.Collections.ArrayList][array]$PSDeployScriptContent = Get-Content $PSDeployScriptToEdit.FullName
    $LineOfInterest = $($PSDeployScriptContent | Select-String -Pattern ".*?Verbose[\s]+= \`$VerbosePreference").Matches.Value
    $IndexOfLineOfInterest = $PSDeployScriptContent.IndexOf($LineOfInterest)
    $PSDeployScriptContent.Insert($($IndexOfLineOfInterest+1),"            Force      = `$True")
    Set-Content -Path $PSDeployScriptToEdit.FullName -Value $PSDeployScriptContent
    #>
    Import-Module PSDeploy
}
catch {
    Write-Error $_
    $global:FunctionResult = "1"
    return
}

Set-BuildEnvironment -Force -Path $PSScriptRoot -ErrorAction SilentlyContinue

# Now the following Environment Variables with similar values should be available to use...
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# Make sure everything is valid PowerShell before continuing...
$FilesToAnalyze = Get-ChildItem $PSScriptRoot -Recurse -File | Where-Object {
    $_.Extension -match '\.ps1|\.psm1|\.psd1'
}
[System.Collections.ArrayList]$InvalidPowerShell = @()
foreach ($FileItem in $FilesToAnalyze) {
    $contents = Get-Content -Path $FileItem.FullName -ErrorAction Stop
    $errors = $null
    $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
    if ($errors.Count -gt 0 -and $FileItem.Name -ne "$env:BHProjectName.psm1") {
        $null = $InvalidPowerShell.Add($FileItem)
    }
}
if ($InvalidPowerShell.Count -gt 0) {
    Write-Error "The following files are not valid PowerShell:`n$($InvalidPowerShell.FullName -join "`n")`nHalting!"
    $global:FunctionResult = "1"
    return
}

if ($Cert) {
    # NOTE: We don't want to include the Module's .psm1 or .psd1 yet because the psake.ps1 Compile Task hasn't finalized them yet...
    # NOTE: We don't want to sign build.ps1, Remove-Signature.ps1, or Helper functions because we just did that above...
    $HelperFilesToSignNameRegex = $HelperFilestoSign.Name | foreach {[regex]::Escape($_)}
    $RemoveSignatureFilePathRegex = [regex]::Escape($RemoveSignatureFilePath)
    [System.Collections.ArrayList][array]$FilesToSign = Get-ChildItem $env:BHProjectPath -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and
        $_.Name -notmatch "^$env:BHProjectName\.ps[d|m]1$" -and
        $_.Name -notmatch "^module\.requirements\.psd1" -and
        $_.Name -notmatch "^build\.requirements\.psd1" -and
        $_.Name -notmatch "^build\.ps1$" -and
        $_.Name -notmatch $($HelperFilesToSignNameRegex -join '|') -and
        $_.Name -notmatch $RemoveSignatureFilePathRegex -and
        $_.FullName -notmatch "\\Pages\\Dynamic|\\Pages\\Static"
    }
    #$null = $FilesToSign.Add($(Get-Item $env:BHModulePath\Install-PSDepend.ps1))

    Remove-Signature -FilePath $FilesToSign.FullName

    # Build the Get-PUDAdminCenter Public Function
    $PUDAppMainFunctionTemplateContent = Get-Content "$env:BHModulePath\Private\PUDAppMainFunctionTemplate.ps1"
    $DynamicPagesContent = foreach ($FileItem in @(Get-ChildItem -Path "$env:BHModulePath\Pages\Dynamic" -File)) {
        @(
            Get-Content $FileItem.FullName
            ""
        )
    }
    $StaticPagesContent = foreach ($FileItem in @(Get-ChildItem -Path "$env:BHModulePath\Pages\Static" -File)) {
        @(
            Get-Content $FileItem.FullName
            ""
        )
    }
    $GetPUDAdminCenterFunction = $PUDAppMainFunctionTemplateContent | foreach {
        if ($_ -eq "'Add Dynamic Pages Here'") {
            $DynamicPagesContent | foreach {'    ' + $_}
        }
        elseif ($_ -eq "'Add Static Pages Here'") {
            $StaticPagesContent | foreach {'    ' + $_}
        }
        else {
            $_
        }
    }
    Set-Content -Path $env:BHModulePath\Public\Get-PUDAdminCenter.ps1 -Value $GetPUDAdminCenterFunction

    [System.Collections.ArrayList]$FilesFailedToSign = @()
    foreach ($FilePath in $FilesToSign.FullName) {
        try {
            $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $FilePath -cert $Cert
            if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -eq "HasMisMatch") {throw}
        }
        catch {
            $null = $FilesFailedToSign.Add($FilePath)
        }
    }

    if ($FilesFailedToSign.Count -gt 0) {
        Write-Error "Halting because we failed to digitally sign the following files:`n$($FilesFailedToSign -join "`n")"
        $global:FunctionResult = "1"
        return
    }
}
else {
    # Build the Get-PUDAdminCenter Public Function
    $PUDAppMainFunctionTemplateContent = Get-Content "$env:BHModulePath\Private\PUDAppMainFunctionTemplate.ps1"
    $DynamicPagesContent = foreach ($FileItem in @(Get-ChildItem -Path "$env:BHModulePath\Pages\Dynamic" -File)) {
        @(
            Get-Content $FileItem.FullName
            ""
        )
    }
    $StaticPagesContent = foreach ($FileItem in @(Get-ChildItem -Path "$env:BHModulePath\Pages\Static" -File)) {
        @(
            Get-Content $FileItem.FullName
            ""
        )
    }
    $GetPUDAdminCenterFunction = $PUDAppMainFunctionTemplateContent | foreach {
        if ($_ -eq "'Add Dynamic Pages Here'") {
            $DynamicPagesContent | foreach {'    ' + $_}
        }
        elseif ($_ -eq "'Add Static Pages Here'") {
            $StaticPagesContent | foreach {'    ' + $_}
        }
        else {
            $_
        }
    }
    Set-Content -Path $env:BHModulePath\Public\Get-PUDAdminCenter.ps1 -Value $GetPUDAdminCenterFunction
}

if (!$(Get-Module -ListAvailable PSDepend)) {
    & $(Resolve-Path "$PSScriptRoot\*Help*\Install-PSDepend.ps1").Path
}
try {
    Import-Module PSDepend
    $null = Invoke-PSDepend -Path "$PSScriptRoot\build.requirements.psd1" -Install -Import -Force

    # Hack to fix AppVeyor Error When attempting to Publish to PSGallery
    # The specific error this fixes is a problem with the Publish-Module cmdlet from PowerShellGet. PSDeploy
    # calls Publish-Module without the -Force parameter which results in this error: https://github.com/PowerShell/PowerShellGet/issues/79
    # This is more a problem with PowerShellGet than PSDeploy.
    Remove-Module PSDeploy -ErrorAction SilentlyContinue
    $PSDeployScriptToEdit = Get-Childitem -Path $(Get-Module -ListAvailable PSDeploy).ModuleBase -File -Recurse -Filter "PSGalleryModule.ps1"
    [System.Collections.ArrayList][array]$PSDeployScriptContent = Get-Content $PSDeployScriptToEdit.FullName
    $LineOfInterest = $($PSDeployScriptContent | Select-String -Pattern ".*?Verbose[\s]+= \`$VerbosePreference").Matches.Value
    $IndexOfLineOfInterest = $PSDeployScriptContent.IndexOf($LineOfInterest)
    $PSDeployScriptContent.Insert($($IndexOfLineOfInterest+1),"            Force      = `$True")
    Set-Content -Path $PSDeployScriptToEdit.FullName -Value $PSDeployScriptContent
    Import-Module PSDeploy
}
catch {
    Write-Error $_
    $global:FunctionResult = "1"
    return
}

if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force -ErrorAction SilentlyContinue
}

##### BEGIN Tasks Unique to this Module's Build #####

Remove-Module MiniLab -Force -ErrorAction SilentlyContinue

##### END Tasks Unique to this Module's Build #####

$psakeFile = "$env:BHProjectPath\psake.ps1"
if (!$(Test-Path $psakeFile)) {
    Write-Error "Unable to find the path $psakeFile! Halting!"
    $global:FunctionResult = "1"
    return
}

if ($PSBoundParameters.ContainsKey('help')) {
    Get-PSakeScriptTasks -buildFile $psakeFile | Format-Table -Property Name, Description, Alias, DependsOn
    return
}

##### END Prepare For Build #####

##### BEGIN PSAKE Build #####

# Add any test resources that you want to push to psake.ps1 and/or *.Tests.ps1 files
$TestResources = @{}

$InvokePSakeParams = @{}
if ($Cert) {
    $InvokePSakeParams.Add("Cert",$Cert)
}
if ($TestResources.Count -gt 0) {
    $InvokePSakeParams.Add("TestResources",$TestResources)
}

if ($InvokePSakeParams.Count -gt 0) {
    Invoke-Psake $psakeFile -taskList $Task -nologo -parameters $InvokePSakeParams -ErrorVariable IPSErr
}
else {
    Invoke-Psake $psakeFile -taskList $Task -nologo -ErrorAction Stop
}

exit ( [int]( -not $psake.build_success ) )

##### END PSAKE Build #####

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSx/YCClSO/2RSLktusEyk/jP
# QG+gggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
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
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUafdd6BfwiEfM033w4IetZ+yBxSww
# DQYJKoZIhvcNAQEBBQAEggEARu5XEU52TVs8yhvR7LBfXLJHcArHw8WIJkYht0S5
# AGSMN3/720yyQw6Y3XJd0YwOjYCt45Qk8FMO5avD0FmKjS8FJujpgHl8eONGefEQ
# wz0HY9+9aQSZ0R3S6W99v7OCQWZw5kU4tkPftU+LHhiBOwLuPiqjAfXlDOWnaiWM
# 6nFiLt5jSmOqpMKpm/69uQ1+v+B6uj169pY/acEReTlEoTYLStdl90/relBnQH9W
# XboGlK1DDw8RPerceri6/X9Bve8Fa9/gcCgUohZ9L3/zKk54k7X7NJEYfU8MTKdw
# cowLwE6NSSb8SrrEHfkvXXf51vgkmXBZLgYNtiPIwTYNEw==
# SIG # End signature block
