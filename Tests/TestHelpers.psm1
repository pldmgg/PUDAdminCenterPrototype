<#
    .SYNOPSIS
        Tests if a module contains a class resource.

    .PARAMETER ModulePath
        The path to the module to test.
#>
function Test-ModuleContainsClassResource
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $ModulePath
    )

    $psm1Files = Get-Psm1FileList -FilePath $ModulePath

    foreach ($psm1File in $psm1Files)
    {
        if (Test-FileContainsClassResource -FilePath $psm1File.FullName)
        {
            return $true
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Retrieves all .psm1 files under the given file path.

    .PARAMETER FilePath
        The root file path to gather the .psm1 files from.
#>
function Get-Psm1FileList
{
    [OutputType([Object[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $FilePath
    )

    return Get-ChildItem -Path $FilePath -Filter '*.psm1' -File -Recurse
}

<#
    .SYNOPSIS
        Retrieves the parse errors for the given file.

    .PARAMETER FilePath
        The path to the file to get parse errors for.
#>
function Get-FileParseErrors
{
    [OutputType([System.Management.Automation.Language.ParseError[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $FilePath
    )

    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref] $null, [ref] $parseErrors)

    return $parseErrors
}

<#
    .SYNOPSIS
        Retrieves all text files under the given root file path.

    .PARAMETER Root
        The root file path under which to retrieve all text files.

    .NOTES
        Retrieves all files with the '.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1',
        '.json', '.xml', '.cmd', or '.mof' file extensions.
#>
function Get-TextFilesList
{
    [OutputType([System.IO.FileInfo[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Root
    )

    $textFileExtensions = @('.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1', '.json', '.xml', '.cmd', '.mof','.md','.js','.yml')

    return Get-ChildItem -Path $Root -File -Recurse | Where-Object { $textFileExtensions -contains $_.Extension }
}

function ConvertTo-SpaceIndentation
{
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [System.IO.FileInfo]$fileInfo
    )

    process 
    {
        $content = (Get-Content -Raw -Path $fileInfo.FullName) -replace "`t",' '
        [System.IO.File]::WriteAllText($fileInfo.FullName, $content)
    }
}

<#
    .SYNOPSIS
        Tests if a file is encoded in Unicode.

    .PARAMETER FileInfo
        The file to test.
#>
function Test-FileInUnicode {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [System.IO.FileInfo]$fileInfo
    )

    process {
        $path = $fileInfo.FullName
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $zeroBytes = @($bytes -eq 0)
        return [bool]$zeroBytes.Length

    }
}

<#
    .SYNOPSIS
        Downloads and installs a module from PowerShellGallery using
        Nuget.

    .PARAMETER ModuleName
        Name of the module to install

    .PARAMETER DestinationPath
        Path where module should be installed
#>
function Install-ModuleFromPowerShellGallery
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [String]
        $DestinationPath
    )

    $nugetPath = 'nuget.exe'

    # Can't assume nuget.exe is available - look for it in Path
    if ($null -eq (Get-Command -Name $nugetPath -ErrorAction 'SilentlyContinue'))
    {
        # Is it in temp folder?
        $tempNugetPath = Join-Path -Path $env:temp -ChildPath $nugetPath

        if (-not (Test-Path -Path $tempNugetPath))
        {
            # Nuget.exe can't be found - download it to temp folder
            $nugetDownloadURL = 'http://nuget.org/nuget.exe'

            Invoke-WebRequest -Uri $nugetDownloadURL -OutFile $tempNugetPath
            Write-Verbose -Message "nuget.exe downloaded at $tempNugetPath"

            $nugetPath = $tempNugetPath
        }
        else
        {
            Write-Verbose -Message "Using Nuget.exe found at $tempNugetPath"
        }
    }

    $moduleOutputDirectory = "$(Split-Path -Path $DestinationPath -Parent)\"

    $nugetSource = 'https://www.powershellgallery.com/api/v2'
    # Use Nuget.exe to install the module
    $null = & $nugetPath @( `
        'install', $ModuleName, `
        '-source', $nugetSource, `
        '-outputDirectory', $moduleOutputDirectory, `
        '-ExcludeVersion' `
        )

    if ($LASTEXITCODE -ne 0)
    {
        throw "Installation of module $ModuleName using Nuget failed with exit code $LASTEXITCODE."
    }

    Write-Verbose -Message "The module $ModuleName was installed using Nuget."
}

<#
    .SYNOPSIS
        Imports the PS Script Analyzer module.
        Installs the module from the PowerShell Gallery if it is not already installed.
#>
function Import-PSScriptAnalyzer
{
    [CmdletBinding()]
    param ()

    $psScriptAnalyzerModule = Get-Module -Name 'PSScriptAnalyzer' -ListAvailable

    if ($null -eq $psScriptAnalyzerModule)
    {
        Write-Verbose -Message 'Installing PSScriptAnalyzer from the PowerShell Gallery'
        $userProfilePSModulePathItem = Get-UserProfilePSModulePathItem
        $psScriptAnalyzerModulePath = Join-Path -Path $userProfilePSModulePathItem -ChildPath PSScriptAnalyzer
        Install-ModuleFromPowerShellGallery -ModuleName 'PSScriptAnalyzer' -DestinationPath $psScriptAnalyzerModulePath
    }

    $psScriptAnalyzerModule = Get-Module -Name 'PSScriptAnalyzer' -ListAvailable

    <#
        When using custom rules in PSSA the Get-Help cmdlet gets
        called by PSSA. This causes a warning to be thrown in AppVeyor.
        This warning does not cause a failure or error, but causes
        additional bloat to the analyzer output. To suppress this
        the registry key
        HKLM:\Software\Microsoft\PowerShell\DisablePromptToUpdateHelp
        should be set to 1 when running in AppVeyor.

        See this line from PSSA in GetExternalRule() method for more
        information:
        https://github.com/PowerShell/PSScriptAnalyzer/blob/development/Engine/ScriptAnalyzer.cs#L1120
    #>
    if ($env:APPVEYOR -eq $true)
    {
        Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell -Name DisablePromptToUpdateHelp -Value 1
    }

    Import-Module -Name $psScriptAnalyzerModule
}

<#
    .SYNOPSIS
        Retrieves the list of suppressed PSSA rules in the file at the given path.

    .PARAMETER FilePath
        The path to the file to retrieve the suppressed rules of.
#>
function Get-SuppressedPSSARuleNameList
{
    [OutputType([String[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $suppressedPSSARuleNames = [String[]]@()

    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$null, [ref]$null)

    # Overall file attributes
    $attributeAsts = $fileAst.FindAll({$args[0] -is [System.Management.Automation.Language.AttributeAst]}, $true)

    foreach ($attributeAst in $attributeAsts)
    {
        if ([System.Diagnostics.CodeAnalysis.SuppressMessageAttribute].FullName.ToLower().Contains($attributeAst.TypeName.FullName.ToLower()))
        {
            $suppressedPSSARuleNames += $attributeAst.PositionalArguments.Extent.Text
        }
    }

    return $suppressedPSSARuleNames
}

<#
    .SYNOPSIS
        Gets the current Pester Describe block name
#>
function Get-PesterDescribeName
{

    return Get-CommandNameParameterValue -Command 'Describe'
}

<#
    .SYNOPSIS
        Gets the opt-in status of the current pester Describe
        block. Writes a warning if the test is not opted-in.

    .PARAMETER OptIns
        An array of what is opted-in
#>
function Get-PesterDescribeOptInStatus
{
    param
    (
        [Parameter()]
        [System.String[]]
        $OptIns
    )

    $describeName = Get-PesterDescribeName
    $optIn = $OptIns -icontains $describeName
    if (-not $optIn)
    {
        $message = @"
Describe $describeName will not fail unless you opt-in.
To opt-in, create a '.MetaTestOptIn.json' at the root
of the repo in the following format:
[
     "$describeName"
]
"@
        Write-Warning -Message $message
    }

    return $optIn
}

<#
    .SYNOPSIS
        Gets the opt-in status of an option with the specified name. Writes
        a warning if the test is not opted-in.

    .PARAMETER OptIns
        An array of what is opted-in.

    .PARAMETER Name
        The name of the opt-in option to check the status of.
#>
function Get-OptInStatus
{
    param
    (
        [Parameter()]
        [System.String[]]
        $OptIns,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $optIn = $OptIns -icontains $Name
    if (-not $optIn)
    {
        $message = @"
$Name will not fail unless you opt-in.
To opt-in, create a '.MetaTestOptIn.json' at the root
of the repo in the following format:
[
     "$Name"
]
"@
        Write-Warning -Message $message
    }

    return $optIn
}

<#
    .SYNOPSIS
        Gets the value of the Name parameter for the specified command in the stack.

    .PARAMETER Command
        The name of the command to find the Name parameter for.
#>
function Get-CommandNameParameterValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Command
    )

    $commandStackItem = (Get-PSCallStack).Where{ $_.Command -eq $Command }
    $commandArgumentNameValues = $commandStackItem.Arguments.TrimStart('{',' ').TrimEnd('}',' ') -split '\s*,\s*'
    $nameParameterValue = ($commandArgumentNameValues.Where{ $_ -like 'name=*' } -split '=')[-1]
    return $nameParameterValue
}

<#
    .SYNOPSIS
        Returns first the item in $env:PSModulePath that matches the given Prefix ($env:PSModulePath is list of semicolon-separated items).
        If no items are found, it reports an error.
    .PARAMETER Prefix
        Path prefix to look for.
    .NOTES
        If there are multiple matching items, the function returns the first item that occurs in the module path; this matches the lookup
        behavior of PowerSHell, which looks at the items in the module path in order of occurrence.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        then
            Get-PSModulePathItem C:\Users
        will return
            C:\Users\foo\Documents\WindowsPowerShell\Modules
#>
function Get-PSModulePathItem
{
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $Prefix
    )

    $item = $env:PSModulePath.Split(';') |
        Where-Object -FilterScript { $_ -like "$Prefix*" } |
        Select-Object -First 1

    if (-not $item)
    {
        Write-Error -Message "Cannot find the requested item in the PowerShell module path.`n`$env:PSModulePath = $env:PSModulePath"
    }

    return $item
}

<#
    .SYNOPSIS
        Returns the first item in $env:PSModulePath that is a path under $env:USERPROFILE.
        If no items are found, it reports an error.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        and the current user is 'foo', then
            Get-UserProfilePSModulePathItem
        will return
            C:\Users\foo\Documents\WindowsPowerShell\Modules
#>
function Get-UserProfilePSModulePathItem {
    param()

    return Get-PSModulePathItem -Prefix $env:USERPROFILE
}

<#
    .SYNOPSIS
        Returns the first item in $env:PSModulePath that is a path under $env:USERPROFILE.
        If no items are found, it reports an error.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        then
            Get-PSHomePSModulePathItem
        will return
            C:\Windows\system32\WindowsPowerShell\v1.0\Modules
#>
function Get-PSHomePSModulePathItem {
    param()

    return Get-PSModulePathItem -Prefix $global:PSHOME
}

<#
    .SYNOPSIS
        Tests if a file contains Byte Order Mark (BOM).

    .PARAMETER FilePath
        The file path to evaluate.
#>
function Test-FileHasByteOrderMark
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath
    )

    # This reads the first three bytes of the first row.
    $firstThreeBytes = Get-Content -Path $FilePath -Encoding Byte -ReadCount 3 -TotalCount 3

    # Check for the correct byte order (239,187,191) which equal the Byte Order Mark (BOM).
    return ($firstThreeBytes[0] -eq 239 `
        -and $firstThreeBytes[1] -eq 187 `
        -and $firstThreeBytes[2] -eq 191)
}

<#
    .SYNOPSIS
        This returns a string containing the relative path from the module root.

    .PARAMETER FilePath
        The file path to remove the module root path from.

    .PARAMETER ModuleRootFilePath
        The root path to remove from the file path.
#>
function Get-RelativePathFromModuleRoot
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ModuleRootFilePath
    )

    <#
        Removing the module root path from the file path so that the path
        doesn't get so long in the Pester output.
    #>
    return ($FilePath -replace [Regex]::Escape($ModuleRootFilePath),'').Trim('\')
}

<#
    .SYNOPSIS
        Installs dependent modules in the user scope, if not already available
        and only if run on an AppVeyor build worker. If not run on a AppVeyor
        build worker, it will output a warning saying that the users must
        install the correct module to be able to run the test.

    .PARAMETER Module
        An array of hash tables containing one or more dependent modules that
        should be installed. The correct array is returned by the helper
        function Get-ResourceModulesInConfiguration.

        Hash table should be in this format. Where property Name is mandatory
        and property Version is optional.

        @{
            Name    = 'xStorage'
            [Version = '3.2.0.0']
        }
#>
function Install-DependentModule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable[]]
        $Module
    )

    # Check any additional modules required are installed
    foreach ($requiredModule in $Module)
    {
        $getModuleParameters = @{
            Name = $requiredModule.Name
            ListAvailable = $true
            ErrorAction = 'SilentlyContinue'
        }

        if ($requiredModule.ContainsKey('Version'))
        {
            $requiredModuleExist = `
                Get-Module @getModuleParameters |
                    Where-Object -FilterScript {
                        $_.Version -eq $requiredModule.Version
                    }
        }
        else
        {
            $requiredModuleExist = Get-Module @getModuleParameters
        }

        if (-not ($requiredModuleExist))
        {
            # The required module is missing from this machine
            if ($requiredModule.ContainsKey('Version'))
            {
                $requiredModuleName = ('{0} version {1}' -f $requiredModule.Name, $requiredModule.Version)
            }
            else
            {
                $requiredModuleName = ('{0}' -f $requiredModule.Name)
            }

            if ($env:APPVEYOR -eq $true)
            {
                <#
                    Tests are running in AppVeyor so just install the module.
                    If not installed by using Force then the error message
                    "User declined to install untrusted module (<module name>)."
                    is thrown
                #>
                $installModuleParameters = @{
                    Name  = $requiredModule.Name
                    Force = $true
                }

                if ($requiredModule.ContainsKey('Version'))
                {
                    $installModuleParameters['RequiredVersion'] = $requiredModule.Version
                }

                Write-Verbose -Message "Installing module $requiredModuleName required to compile a configuration." -Verbose
                try
                {
                    Install-Module @installModuleParameters -Scope CurrentUser
                }
                catch
                {
                    throw "An error occurred installing the required module $($requiredModuleName) : $_"
                }
            }
            else
            {
                # Warn the user that the test fill fail
                Write-Warning -Message ("To be able to compile a configuration the resource module $requiredModuleName " + `
                    'is required but it is not installed on this computer. ' + `
                    'The test that is dependent on this module will fail until the required module is installed. ' + `
                    'Please install it from the PowerShell Gallery to enable these tests to pass.')
            } # if
        } # if
    } # foreach
}

<#
    .SYNOPSIS
        The is a wrapper to set $env:PSModulePath both in current session and
        machine wide.
        This is needed to be able to mock the function in the unit tests.

    .PARAMETER Path
        A string with all the paths separated by semi-colons.

    .PARAMETER Machine
        If set the PSModulePath will be changed machine wide. If not set, only
        the current session will be changed.

    .EXAMPLE
        Set-PSModulePath -Path '<Path 1>;<Path 2>'

    .EXAMPLE
        Set-PSModulePath -Path '<Path 1>;<Path 2>' -Machine
#>
function Set-PSModulePath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter()]
        [Switch]
        $Machine
    )

    if ($Machine.IsPresent)
    {
        [System.Environment]::SetEnvironmentVariable('PSModulePath', $Path, [System.EnvironmentVariableTarget]::Machine)
    }
    else
    {
        $env:PSModulePath = $Path
    }
}

<#
    .SYNOPSIS
        Writes a message to the console in a standard format.

    .PARAMETER Message
        The message to write to the console.

    .PARAMETER ForegroundColor
        The text color to use when writing the message to the console. Defaults
        to 'Yellow'.
#>
function Write-Info
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [System.String]
        $Message,

        [Parameter()]
        [System.String]
        $ForegroundColor = 'Yellow'
    )

    Write-Host -ForegroundColor $ForegroundColor -Object "[Build Info] [UTC $([System.DateTime]::UtcNow)] $message"
}

<#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ModuleName
        The name of the module as it appears before '.strings.psd1' of the localized string file.
        For example:
            For module: DscResource.Container

    .PARAMETER ModuleRoot
        The module root path where to expect to find the culture folder.
#>
function Get-LocalizedData
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleRoot
    )

    $localizedStringFileLocation = Join-Path -Path $ModuleRoot -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US
        $localizedStringFileLocation = Join-Path -Path $ModuleRoot -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ModuleName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

<#
Export-ModuleMember -Function @(
    'Install-ModuleFromPowerShellGallery'
    'Test-ModuleContainsClassResource'
    'Get-Psm1FileList'
    'Get-FileParseErrors'
    'Get-TextFilesList'
    'Test-FileInUnicode'
    'Import-PSScriptAnalyzer'
    'Get-SuppressedPSSARuleNameList'
    'Get-PesterDescribeOptInStatus'
    'Get-OptInStatus'
    'Get-UserProfilePSModulePathItem'
    'Get-PSHomePSModulePathItem'
    'Test-FileHasByteOrderMark'
    'Get-RelativePathFromModuleRoot'
    'Get-ResourceModulesInConfiguration'
    'Install-DependentModule'
    'Set-PSModulePath'
    'Write-Info'
    'Get-LocalizedData'
)
#>

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7DoGJ43QnuJfMvvbjsWEuMUo
# mGegggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
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
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUVySGYIYmuWd6REqB+qKGvpnF0kQw
# DQYJKoZIhvcNAQEBBQAEggEAhWYwsNxI1Oau1P8ekCuuPK3o2EHDlN/HdaobXzz8
# rUGjqHzk5hf+EH1Bi90Se60OLD3F776NB7DF+GphC/Lxow9ZoO+MZ00kySTfO95q
# hYvn/GbC6ZEHnxKJYc+nka64RobVvyBoRxb0TI8qoO2rpKCPp4WjPNh6puB1NPfL
# ISoOapyku+8rnhf1xwx+ZDpSXW42QYul0iIut8FD96xZEqmLh5q6oFDy9gH4aWb0
# crIhbQNuF4+TybfeX2RYz++1cIXAe5P+Dq6wsAUWJ03Z9qcP7E7o112KTuhUicgx
# AdQr/kaPiD8ROBRSoJAPKifjb7Z33Hce2ysC7iAKi5l0xw==
# SIG # End signature block
