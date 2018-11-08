function UnzipFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$PathToZip,
        
        [Parameter(Mandatory=$true,Position=1)]
        [string]$TargetDir,

        [Parameter(Mandatory=$false,Position=2)]
        [string[]]$SpecificItem
    )

    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$AssembliesToCheckFor = @("System.Console","System","System.IO",
            "System.IO.Compression","System.IO.Compression.Filesystem","System.IO.Compression.ZipFile"
        )

        [System.Collections.ArrayList]$NeededAssemblies = @()

        foreach ($assembly in $AssembliesToCheckFor) {
            try {
                [System.Collections.ArrayList]$Failures = @()
                try {
                    $TestLoad = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
                    if (!$TestLoad) {
                        throw
                    }
                }
                catch {
                    $null = $Failures.Add("Failed LoadWithPartialName")
                }

                try {
                    $null = Invoke-Expression "[$assembly]"
                }
                catch {
                    $null = $Failures.Add("Failed TabComplete Check")
                }

                if ($Failures.Count -gt 1) {
                    $Failures
                    throw
                }
            }
            catch {
                Write-Host "Downloading $assembly..."
                $NewAssemblyDir = "$HOME\Downloads\$assembly"
                $NewAssemblyDllPath = "$NewAssemblyDir\$assembly.dll"
                if (!$(Test-Path $NewAssemblyDir)) {
                    New-Item -ItemType Directory -Path $NewAssemblyDir
                }
                if (Test-Path "$NewAssemblyDir\$assembly*.zip") {
                    Remove-Item "$NewAssemblyDir\$assembly*.zip" -Force
                }
                $OutFileBaseNamePrep = Invoke-WebRequest "https://www.nuget.org/api/v2/package/$assembly" -DisableKeepAlive -UseBasicParsing
                $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
                Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/$assembly" -OutFile "$NewAssemblyDir\$OutFileBaseName"
                $null = Expand-Archive -Path "$NewAssemblyDir\$OutFileBaseName" -DestinationPath $NewAssemblyDir -Force

                $PossibleDLLs = Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {$_.Name -eq "$assembly.dll" -and $_.Parent -notmatch "net[0-9]" -and $_.Parent -match "core|standard"}

                if ($PossibleDLLs.Count -gt 1) {
                    Write-Warning "More than one item within $NewAssemblyDir\$OutFileBaseName matches $assembly.dll"
                    Write-Host "Matches include the following:"
                    for ($i=0; $i -lt $PossibleDLLs.Count; $i++){
                        "$i) $($($PossibleDLLs[$i]).FullName)"
                    }
                    $Choice = Read-Host -Prompt "Please enter the number corresponding to the .dll you would like to load [0..$($($PossibleDLLs.Count)-1)]"
                    if ($(0..$($($PossibleDLLs.Count)-1)) -notcontains $Choice) {
                        Write-Error "The number indicated does is not a valid choice! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }

                    if ($PSVersionTable.Platform -eq "Win32NT") {
                        # Install to GAC
                        [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                        $publish = New-Object System.EnterpriseServices.Internal.Publish
                        $publish.GacInstall($PossibleDLLs[$Choice].FullName)
                    }

                    # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                    Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"

                    # Remove everything else that was extracted with Expand-Archive
                    Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                        $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                        $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                    } | Remove-Item -Recurse -Force
                    
                }
                if ($PossibleDLLs.Count -lt 1) {
                    Write-Error "No matching .dll files were found within $NewAssemblyDir\$OutFileBaseName ! Halting!"
                    continue
                }
                if ($PossibleDLLs.Count -eq 1) {
                    if ($PSVersionTable.Platform -eq "Win32NT") {
                        # Install to GAC
                        [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                        $publish = New-Object System.EnterpriseServices.Internal.Publish
                        $publish.GacInstall($PossibleDLLs.FullName)
                    }

                    # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                    Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"

                    # Remove everything else that was extracted with Expand-Archive
                    Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                        $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                        $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                    } | Remove-Item -Recurse -Force
                }
            }
            $AssemblyFullInfo = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
            if (!$AssemblyFullInfo) {
                $AssemblyFullInfo = [System.Reflection.Assembly]::LoadFile("$NewAssemblyDir\$assembly.dll")
            }
            if (!$AssemblyFullInfo) {
                Write-Error "The assembly $assembly could not be found or otherwise loaded! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $null = $NeededAssemblies.Add([pscustomobject]@{
                AssemblyName = "$assembly"
                Available = if ($AssemblyFullInfo){$true} else {$false}
                AssemblyInfo = $AssemblyFullInfo
                AssemblyLocation = $AssemblyFullInfo.Location
            })
        }

        if ($NeededAssemblies.Available -contains $false) {
            $AssembliesNotFound = $($NeededAssemblies | Where-Object {$_.Available -eq $false}).AssemblyName
            Write-Error "The following assemblies cannot be found:`n$AssembliesNotFound`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        $Assem = $NeededAssemblies.AssemblyInfo.FullName

        $Source = @"
        using System;
        using System.IO;
        using System.IO.Compression;

        namespace MyCore.Utils
        {
            public static class Zip
            {
                public static void ExtractAll(string sourcepath, string destpath)
                {
                    string zipPath = @sourcepath;
                    string extractPath = @destpath;

                    using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Update))
                    {
                        archive.ExtractToDirectory(extractPath);
                    }
                }

                public static void ExtractSpecific(string sourcepath, string destpath, string specificitem)
                {
                    string zipPath = @sourcepath;
                    string extractPath = @destpath;
                    string itemout = @specificitem.Replace(@"\","/");

                    //Console.WriteLine(itemout);

                    using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            //Console.WriteLine(entry.FullName);
                            //bool satisfied = new bool();
                            //satisfied = entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1;
                            //Console.WriteLine(satisfied);

                            if (entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1)
                            {
                                string finaloutputpath = extractPath + "\\" + entry.Name;
                                entry.ExtractToFile(finaloutputpath, true);
                            }
                        }
                    } 
                }
            }
        }
"@

        Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source

        if (!$SpecificItem) {
            [MyCore.Utils.Zip]::ExtractAll($PathToZip, $TargetDir)
        }
        else {
            [MyCore.Utils.Zip]::ExtractSpecific($PathToZip, $TargetDir, $SpecificItem)
        }
    }


    if ($PSVersionTable.PSEdition -eq "Desktop" -and $($($PSVersionTable.Platform -and $PSVersionTable.Platform -eq "Win32NT") -or !$PSVersionTable.Platform)) {
        if ($SpecificItem) {
            foreach ($item in $SpecificItem) {
                if ($SpecificItem -match "\\") {
                    $SpecificItem = $SpecificItem -replace "\\","\\"
                }
            }
        }

        ##### BEGIN Native Helper Functions #####
        function Get-ZipChildItems {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$false,Position=0)]
                [string]$ZipFile = $(Read-Host -Prompt "Please enter the full path to the zip file")
            )

            $shellapp = new-object -com shell.application
            $zipFileComObj = $shellapp.Namespace($ZipFile)
            $i = $zipFileComObj.Items()
            Get-ZipChildItems_Recurse $i
        }

        function Get-ZipChildItems_Recurse {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,Position=0)]
                $items
            )

            foreach($si in $items) {
                if($si.getfolder -ne $null) {
                    # Loop through subfolders 
                    Get-ZipChildItems_Recurse $si.getfolder.items()
                }
                # Spit out the object
                $si
            }
        }

        ##### END Native Helper Functions #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (!$(Test-Path $PathToZip)) {
            Write-Verbose "The path $PathToZip was not found! Halting!"
            Write-Error "The path $PathToZip was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-ChildItem $PathToZip).Extension -ne ".zip") {
            Write-Verbose "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            Write-Error "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ZipFileNameWExt = $(Get-ChildItem $PathToZip).Name

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        if (!$SpecificItem) {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $null = Expand-Archive -Path $PathToZip -DestinationPath $TargetDir -Force
            }
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                # Load System.IO.Compression.Filesystem 
                [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

                # Unzip file
                [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
            }
        }
        if ($SpecificItem) {
            $ZipSubItems = Get-ZipChildItems -ZipFile $PathToZip

            foreach ($searchitem in $SpecificItem) {
                [array]$potentialItems = foreach ($item in $ZipSubItems) {
                    if ($item.Path -match $searchitem) {
                        $item
                    }
                }

                $shell = new-object -com shell.application

                if ($potentialItems.Count -eq 1) {
                    $shell.Namespace($TargetDir).CopyHere($potentialItems[0], 0x14)
                }
                if ($potentialItems.Count -gt 1) {
                    Write-Warning "More than one item within $ZipFileNameWExt matches $searchitem."
                    Write-Host "Matches include the following:"
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        "$i) $($($potentialItems[$i]).Path)"
                    }
                    $Choice = Read-Host -Prompt "Please enter the number corresponding to the item you would like to extract [0..$($($potentialItems.Count)-1)]"
                    if ($(0..$($($potentialItems.Count)-1)) -notcontains $Choice) {
                        Write-Warning "The number indicated does is not a valid choice! Skipping $searchitem..."
                        continue
                    }
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        $shell.Namespace($TargetDir).CopyHere($potentialItems[$Choice], 0x14)
                    }
                }
                if ($potentialItems.Count -lt 1) {
                    Write-Warning "No items within $ZipFileNameWExt match $searchitem! Skipping..."
                    continue
                }
            }
        }
        ##### END Main Body #####
    }
}

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSReprAA0pw3FDnifPJFa/+RJ
# ECmgggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
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
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUK7GUvDyE33qKVM+yYitT/O5W9d0w
# DQYJKoZIhvcNAQEBBQAEggEAMR81raFWlw9Wqig1eDz4CQFNTzpD4tR/H9X8PnDl
# rTJw12cza87ACIRMBHwEnyRJLwLlDbb6BawyQ1CORKtZda2J4W9q74JlBkUnThR7
# JMOwnjhXJ8H3TdrljGu2o10EuXPtSKCWVxBUHkmW8Hu+VvR704pfR+ybYoIaq3Dq
# EBQpIK0Q50ZT2NphpR0Ve/tEXlTK91a4FcQjazJSsuQJx8P9d0YX7Uc+izZkpCym
# Rfuk/EOHjnydO02xThFcgmFLz15b5cxgUFFizJTbOEWCWlY6ALCjQ3kmaiisv+wg
# kfpUQ+NeNhLhZmOOQ/LeXtkSPez75+wHgViKUA7605rovQ==
# SIG # End signature block
