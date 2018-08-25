[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions


<#
    
    .SYNOPSIS
        Script that get the certificates overview (total, ex) in the system.
    
    .DESCRIPTION
        Script that get the certificates overview (total, ex) in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CertificateOverview {
     param (
            [Parameter(Mandatory = $true)]
            [ValidateSet(
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*",
                "Microsoft-Windows-CertificateServices-Deployment*",
                "Microsoft-Windows-CertificateServicesClient-CredentialRoaming*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-User*",
                "Microsoft-Windows-CAPI2*",
                "Microsoft-Windows-CertPoleEng*"
            )]
            [String]$channel,

            [Parameter(Mandatory = $false)]
            [String]$path = "Cert:\",

            [Parameter(Mandatory = $false)]
            [int]$nearlyExpiredThresholdInDays = 60
        )
    
    Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue
    
    # Notes: $channelList must be in this format:
    #"Microsoft-Windows-CertificateServicesClient-Lifecycle-System*,Microsoft-Windows-CertificateServices-Deployment*,
    #Microsoft-Windows-CertificateServicesClient-CredentialRoaming*,Microsoft-Windows-CertificateServicesClient-Lifecycle-User*,
    #Microsoft-Windows-CAPI2*,Microsoft-Windows-CertPoleEng*"
    
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    $certCounts = New-Object -TypeName psobject
    $certs = Get-ChildLeafRecurse -pspath $path
    
    $channelList = $channel.split(",")
    $totalCount = 0
    $x = Get-WinEvent -ListLog $channelList -Force -ErrorAction 'SilentlyContinue'
    for ($i = 0; $i -le $x.Count; $i++){
        $totalCount += $x[$i].RecordCount;
    }
    
    $certCounts | add-member -Name "allCount" -Value $certs.length -MemberType NoteProperty
    $certCounts | add-member -Name "expiredCount" -Value ($certs | Where-Object {$_.NotAfter -lt [DateTime]::Now }).length -MemberType NoteProperty
    $certCounts | add-member -Name "nearExpiredCount" -Value ($certs | Where-Object { ($_.NotAfter -gt [DateTime]::Now ) -and ($_.NotAfter -lt [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays) ) }).length -MemberType NoteProperty
    $certCounts | add-member -Name "eventCount" -Value $totalCount -MemberType NoteProperty
    
    $certCounts    
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificates in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificates in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-Certificates {
    param (
        [String]$path = "Cert:\",
        [int]$nearlyExpiredThresholdInDays = 60
    )
    
    <#############################################################################################
    
        Helper functions.
    
    #############################################################################################>
    
    <#
    .Synopsis
        Name: Get-ChildLeafRecurse
        Description: Recursively enumerates each scope and store in Cert:\ drive.
    
    .Parameters
        $pspath: The initial pspath to use for creating whole path to certificate store.
    
    .Returns
        The constructed ps-path object.
    #>
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    <#
    .Synopsis
        Name: Compute-PublicKey
        Description: Computes public key algorithm and public key parameters
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        A hashtable object of public key algorithm and public key parameters.
    #>
    function Compute-PublicKey
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $publicKeyInfo = @{}
    
        $publicKeyInfo["PublicKeyAlgorithm"] = ""
        $publicKeyInfo["PublicKeyParameters"] = ""
    
        if ($cert.PublicKey)
        {
            $publicKeyInfo["PublicKeyAlgorithm"] =  $cert.PublicKey.Oid.FriendlyName
            $publicKeyInfo["PublicKeyParameters"] = $cert.PublicKey.EncodedParameters.Format($true)
        }
    
        $publicKeyInfo
    }
    
    <#
    .Synopsis
        Name: Compute-SignatureAlgorithm
        Description: Computes signature algorithm out of original certificate object.
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        The signature algorithm friendly name.
    #>
    function Compute-SignatureAlgorithm
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $signatureAlgorithm = [System.String]::Empty
    
        if ($cert.SignatureAlgorithm)
        {
            $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
        }
    
        $signatureAlgorithm
    }
    
    <#
    .Synopsis
        Name: Compute-PrivateKeyStatus
        Description: Computes private key exportable status.
    .Parameters
        $hasPrivateKey: A flag indicating certificate has a private key or not.
        $canExportPrivateKey: A flag indicating whether certificate can export a private key.
    
    .Returns
        Enum values "Exported" or "NotExported"
    #>
    function Compute-PrivateKeyStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $hasPrivateKey,
    
            [Parameter(Mandatory = $true)]
            [bool]
            $canExportPrivateKey
        )
    
        if (-not ($hasPrivateKey))
        {
            $privateKeystatus = "None"
        }
        else
        {
            if ($canExportPrivateKey)
            {
                $privateKeystatus = "Exportable"
            }
            else
            {
                $privateKeystatus = "NotExportable"
            }
        }
    
        $privateKeystatus
    }
    
    <#
    .Synopsis
        Name: Compute-ExpirationStatus
        Description: Computes expiration status based on notAfter date.
    .Parameters
        $notAfter: A date object refering to certificate expiry date.
    
    .Returns
        Enum values "Expired", "NearlyExpired" and "Healthy"
    #>
    function Compute-ExpirationStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [DateTime]$notAfter
        )
    
        if ([DateTime]::Now -gt $notAfter)
        {
           $expirationStatus = "Expired"
        }
        else
        {
           $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);
    
           if ($nearlyExpired -ge $notAfter)
           {
              $expirationStatus = "NearlyExpired"
           }
           else
           {
              $expirationStatus = "Healthy"
           }
        }
    
        $expirationStatus
    }
    
    <#
    .Synopsis
        Name: Compute-ArchivedStatus
        Description: Computes archived status of certificate.
    .Parameters
        $archived: A flag to represent archived status.
    
    .Returns
        Enum values "Archived" and "NotArchived"
    #>
    function Compute-ArchivedStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $archived
        )
    
        if ($archived)
        {
            $archivedStatus = "Archived"
        }
        else
        {
            $archivedStatus = "NotArchived"
        }
    
        $archivedStatus
    }
    
    <#
    .Synopsis
        Name: Compute-IssuedTo
        Description: Computes issued to field out of the certificate subject.
    .Parameters
        $subject: Full subject string of the certificate.
    
    .Returns
        Issued To authority name.
    #>
    function Compute-IssuedTo
    {
        param (
            [String]
            $subject
        )
    
        $issuedTo = [String]::Empty
    
        $issuedToRegex = "CN=(?<issuedTo>[^,?]+)"
        $matched = $subject -match $issuedToRegex
    
        if ($matched -and $Matches)
        {
           $issuedTo = $Matches["issuedTo"]
        }
    
        $issuedTo
    }
    
    <#
    .Synopsis
        Name: Compute-IssuerName
        Description: Computes issuer name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The Issuer authority name.
    #>
    function Compute-IssuerName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $issuerName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    
        $issuerName
    }
    
    <#
    .Synopsis
        Name: Compute-CertificateName
        Description: Computes certificate name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The certificate name.
    #>
    function Compute-CertificateName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (!$certificateName) {
            $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        }
    
        $certificateName
    }
    
    <#
    .Synopsis
        Name: Compute-Store
        Description: Computes certificate store name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate store name.
    #>
    function Compute-Store
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Scope
        Description: Computes certificate scope/location name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate scope/location name.
    #>
    function Compute-Scope
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[1].Split(':')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Path
        Description: Computes certificate path. E.g. CurrentUser\My\<thumbprint>
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate path.
    #>
    function Compute-Path
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split(':')[2]
    }
    
    
    <#
    .Synopsis
        Name: EnhancedKeyUsage-List
        Description: Enhanced KeyUsage
    .Parameters
        $cert: The original cert object.
    
    .Returns
        Enhanced Key Usage.
    #>
    function EnhancedKeyUsage-List
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $usageString = ''
        foreach ( $usage in $cert.EnhancedKeyUsageList){
           $usageString = $usageString + $usage.FriendlyName + ' ' + $usage.ObjectId + "`n"
        }
    
        $usageString
    }
    
    <#
    .Synopsis
        Name: Compute-Template
        Description: Compute template infomation of a certificate
        $certObject: The original certificate object.
    
    .Returns
        The certificate template if there is one otherwise empty string
    #>
    function Compute-Template
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $template = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if ($template) {
            $name = $template.Format(1).split('(')[0]
            if ($name) {
                $name -replace "Template="
            }
            else {
                ''
            }
        }
        else {
            ''
        }
    }
    
    <#
    .Synopsis
        Name: Extract-CertInfo
        Description: Extracts certificate info by decoding different field and create a custom object.
    .Parameters
        $certObject: The original certificate object.
    
    .Returns
        The custom object for certificate.
    #>
    function Extract-CertInfo
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $certObject
        )
    
        $certInfo = @{}
    
        $certInfo["Archived"] = $(Compute-ArchivedStatus $certObject.Archived)
        $certInfo["CertificateName"] = $(Compute-CertificateName $certObject)
    
        $certInfo["EnhancedKeyUsage"] = $(EnhancedKeyUsage-List $certObject) #new
        $certInfo["FriendlyName"] = $certObject.FriendlyName
        $certInfo["IssuerName"] = $(Compute-IssuerName $certObject)
        $certInfo["IssuedTo"] = $(Compute-IssuedTo $certObject.Subject)
        $certInfo["Issuer"] = $certObject.Issuer #new
    
        $certInfo["NotAfter"] = $certObject.NotAfter
        $certInfo["NotBefore"] = $certObject.NotBefore
    
        $certInfo["Path"] = $(Compute-Path  $certObject.PsPath)
        $certInfo["PrivateKey"] =  $(Compute-PrivateKeyStatus -hasPrivateKey $certObject.CalculatedHasPrivateKey -canExportPrivateKey  $certObject.CanExportPrivateKey)
        $publicKeyInfo = $(Compute-PublicKey $certObject)
        $certInfo["PublicKey"] = $publicKeyInfo.PublicKeyAlgorithm
        $certInfo["PublicKeyParameters"] = $publicKeyInfo.PublicKeyParameters
    
        $certInfo["Scope"] = $(Compute-Scope  $certObject.PsPath)
        $certInfo["Store"] = $(Compute-Store  $certObject.PsPath)
        $certInfo["SerialNumber"] = $certObject.SerialNumber
        $certInfo["Subject"] = $certObject.Subject
        $certInfo["Status"] =  $(Compute-ExpirationStatus $certObject.NotAfter)
        $certInfo["SignatureAlgorithm"] = $(Compute-SignatureAlgorithm $certObject)
    
        $certInfo["Thumbprint"] = $certObject.Thumbprint
        $certInfo["Version"] = $certObject.Version
    
        $certInfo["Template"] = $(Compute-Template $certObject)
    
        $certInfo
    }
    
    
    <#############################################################################################
    
        Main script.
    
    #############################################################################################>
    
    
    $certificates =  @()
    
    Get-ChildLeafRecurse $path | foreach {
        $cert = $_
        $cert | Add-Member -Force -NotePropertyName "CalculatedHasPrivateKey" -NotePropertyValue $_.HasPrivateKey
        $exportable = $false
    
        if ($cert.HasPrivateKey)
        {
            [System.Security.Cryptography.CspParameters] $cspParams = new-object System.Security.Cryptography.CspParameters
            $contextField = $cert.GetType().GetField("m_safeCertContext", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
            $privateKeyMethod = $cert.GetType().GetMethod("GetPrivateKeyInfo", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
            if ($contextField -and $privateKeyMethod) {
            $contextValue = $contextField.GetValue($cert)
            $privateKeyInfoAvailable = $privateKeyMethod.Invoke($cert, @($ContextValue, $cspParams))
            if ($privateKeyInfoAvailable)
            {
                $PrivateKeyCount++
                $csp = new-object System.Security.Cryptography.CspKeyContainerInfo -ArgumentList @($cspParams)
                if ($csp.Exportable)
                {
                    $exportable = $true
                }
            }
            }
            else
            {
                    $exportable = $true
            }
        }
    
        $cert | Add-Member -Force -NotePropertyName "CanExportPrivateKey" -NotePropertyValue $exportable
    
        $certificates += Extract-CertInfo $cert
    
        }
    
    $certificates
    
}


<#
    
    .SYNOPSIS
        Get Plug and Play device instances by using CIM provider.
    
    .DESCRIPTION
        Get Plug and Play device instances by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpEntity {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity   
}


<#
    
    .SYNOPSIS
        Gets 'Machine' and 'User' environment variables.
    
    .DESCRIPTION
        Gets 'Machine' and 'User' environment variables.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EnvironmentVariables {
    Set-StrictMode -Version 5.0
    
    $data = @()
    
    $system = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
    $user = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
    
    foreach ($h in $system.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "Machine"}
        $data += $obj
    }
    
    foreach ($h in $user.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "User"}
        $data += $obj
    }
    
    $data
}


<#
    
    .SYNOPSIS
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EventLogSummary {
    Param(
        [string]$channel
    )
    
    $ErrorActionPreference = 'SilentlyContinue'
    
    Import-Module Microsoft.PowerShell.Diagnostics;
    
    $channelList = $channel.split(",")
    
    Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue
}


<#
    
    .SYNOPSIS
        Gets the local users.
    
    .DESCRIPTION
        Gets the local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalUsers {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                                Description,
                                                Enabled,
                                                FullName,
                                                LastLogon,
                                                Name,
                                                ObjectClass,
                                                PasswordChangeableDate,
                                                PasswordExpires,
                                                PasswordLastSet,
                                                PasswordRequired,
                                                @{Name="SID"; Expression={$_.SID.Value}},
                                                UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                    Description,
                                    Enabled,
                                    FullName,
                                    LastLogon,
                                    Name,
                                    ObjectClass,
                                    PasswordChangeableDate,
                                    PasswordExpires,
                                    PasswordLastSet,
                                    PasswordRequired,
                                    @{Name="SID"; Expression={$_.SID.Value}},
                                    UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }    
}


<#
    .SYNOPSIS
        This function starts a PowerShell Universal Dashboard (Web-based GUI) instance on the specified port on the
        localhost. The Dashboard features a Network Monitor tool that pings the specified Remote Hosts in your Domain
        every 5 seconds and reports the results to the site.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER Port
        This parameter is OPTIONAL, however, it has a default value of 80.

        This parameter takes an integer between 1 and 32768 that represents the port on the localhost that the site
        will run on.

    .PARAMETER RemoveExistingPUD
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, all running PowerShell Universal Dashboard instances will be removed
        prior to starting the Network Monitor Dashboard.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PUDAdminCenter
        
#>
function Get-PUDAdminCenter {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True
    )

    #region >> Prep

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Remove All Runspaces to Remote Hosts
    Get-PSSession | Remove-PSSession
    $RunspacesToDispose = @(
        Get-Runspace | Where-Object {$_.Type -eq "Remote"}
    )
    if ($RunspacesToDispose.Count -gt 0) {
        foreach ($RSpace in $RunspacesToDispose) {$_.Dispose()}
    }

    # Define all of this Module's functions (both Public and Private) as an array of strings so that we can easily load them in different contexts/scopes
    $Cache:ThisModuleFunctionsStringArray = $ThisModuleFunctionsStringArray =  $(Get-Module PUDAdminCenterPrototype).Invoke({$FunctionsForSBUse})

    # Create the $Pages ArrayList that will be used with 'New-UDDashboard -Pages'
    [System.Collections.ArrayList]$Pages = @()

    # Create a $Cache: and Current Scope variable (ArrayList) containing the names of all of **Dynamic** Pages -
    # i.e. Pages where the URL contains a variable/parameter that is referenced within the Page itself.
    # For example, in this PUDAdminCenter App, the Overview Page (and all other Dynamic Pages in this list) is
    # eventually created via...
    #     New-UDPage -Url "/Overview/:RemoteHost" -Endpoint {param($RemoteHost) ...}
    # ...meaning that if a user were to navigate to http://localhost/Overview/Server01, Overview Page Endpoint scriptblock
    # code that referenced the variable $RemoteHost would contain the string value 'Server01' (unless it is specifcally
    # overriden within the Overview Page Endpoint scriptblock, which is NOT recommended).
    $Cache:DynamicPages = $DynamicPages = @(
        "PSRemotingCreds"
        "ToolSelect"
        "Overview"
        "Certificates"
        "Devices"
        "Events"
        "Files"
        "Firewall"
        "Users And Groups"
        "Network"
        "Processes"
        "Registry"
        "Roles And Features"
        "Scheduled Tasks"
        "Services"
        "Storage"
        "Updates"
    )

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = $(Get-CimInstance Win32_ComputerSystem).Domain
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }    

    # Create Synchronized Hashtable so that we can pass variables between Pages regardless of scope.
    # This provides benefits above and beyond Universal Dashboard's $Cache: scope for two main reasons:
    #     1) It can be referenced anywhere (not just within an -Endpoint, which is what $Cache: scope is limited to)
    #     2) It allows us to more easily communicate with our own custom Runspace(s) that handle Live (Realtime) Data. For
    #     examples of this, see uses of the 'New-Runspace' function within each of the Dynamic Pages (excluding the
    #     PSRemotingCreds and ToolSelect Pages)
    Remove-Variable -Name PUDRSSyncHT -Scope Global -Force -ErrorAction SilentlyContinue
    $global:PUDRSSyncHT = [hashtable]::Synchronized(@{})

    # Populate $PUDRSSyncHT with information that you will need for your PUD Application. This will vary depending on
    # how your application works, but at the very least, you should:
    #     1) Add a Key that will contain information that will be displayed on your HomePage (for the PUDAdminCenter App,
    #     this is the Value contained within the 'RemoteHostList' Key)
    #     2) If you are planning on using Live (Realtime) Data, ensure you add one or more keys that will contain
    #     Live Data. (For the PUDAdminCenter App, this is the LiveDataRSInfo Key that exists within a hashtable
    #     dedicated to each specific Remote Host)
    # For this PUDAdminCenterPrototype Application, the structure of the $PUDRSSyncHT will look like...
    <#
        @{
            RemoteHostList   = $null
            <RemoteHostInfo> = @{
                NetworkInfo                 = $null
                <DynamicPage>               = @{
                    <StaticInfoKey>     = $null
                    LiveDataRSInfo      = $null
                    LiveDataTracker     = @{
                        Current     = $null
                        Previous    = $null
                    }
                }
            }
        }
    #>
    # In other words. each Key within the $PUDRSSyncHT Synchronized Hashtable (with the exception of the 'RemoteHostList' key)
    # will represent a Remote Host that we intend to manage. Each RemoteHost key value will be a hashtable containing the key
    # 'NetworkInfo', as well as keys that rperesent relevant Dynamic Pages ('Overview','Certificates',etc). Each Dynamic Page
    # key value will be a hashtable containing one or more keys with value(s) representing static info that is queried at the time
    # the page loads as well as the keys 'LiveDataRSInfo', and 'LiveDataTracker'. Some key values are initially set to $null because
    # actions taken either prior to starting the UDDashboard or actions taken within the PUDAdminCenter WebApp itself on different
    # pages will set/reset their values as appropriate.

    # Let's populate $PUDRSSyncHT.RemoteHostList with information that will be needed immediately upon navigating to the $HomePage.
    # For this reason, we're gathering the info before we start the UDDashboard. (Note that the below 'GetComputerObjectInLDAP' Private
    # function gets all Computers in Active Directory without using the ActiveDirectory PowerShell Module)
    [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
    }

    # Filter Out the Remote Hosts that we can't resolve
    [System.Collections.ArrayList]$InitialRemoteHostList = @()

    $null = Clear-DnsClientCache
    foreach ($HName in $InitialRemoteHostListPrep) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

            $null = $InitialRemoteHostList.Add($RemoteHostNetworkInfo)
        }
        catch {
            continue
        }
    }

    $PUDRSSyncHT.Add("RemoteHostList",$InitialRemoteHostList)

    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
    foreach ($RHost in $InitialRemoteHostList) {
        $Key = $RHost.HostName + "Info"
        $Value = @{
            NetworkInfo                 = $RHost
            CredHT                      = $null
            ServerInventoryStatic       = $null
            RelevantNetworkInterfaces   = $null
            LiveDataRSInfo              = $null
            LiveDataTracker             = @{Current = $null; Previous = $null}
        }
        foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
            $DynPageHT = @{
                LiveDataRSInfo      = $null
                LiveDataTracker     = @{Current = $null; Previous = $null}
            }
            $Value.Add($DynPage,$DynPageHT)
        }
        $PUDRSSyncHT.Add($Key,$Value)
    }

    #endregion >> Prep


    #region >> Dynamic Pages

    $CertificatesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:CertificatesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:CertificatesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetCertificatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Certificates" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetCertificateOverviewFunc
                Invoke-Expression $using:GetCertificatesFunc
                
                $CertificateSummary = Get-CertificateOverview -channel "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*"
                $AllCertificates = Get-Certificates
    
                [pscustomobject]@{
                    CertificateSummary          = $CertificateSummary
                    AllCertificates             = [pscustomobject]$AllCertificates
                }
            }
            $Session:CertSummaryStatic = $StaticInfo.CertificateSummary
            $Session:AllCertsStatic = $StaticInfo.AllCertificates
            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "CertSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("CertSummary",$Session:CertSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.CertSummary = $Session:CertSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "AllCerts") {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("AllCerts",$Session:AllCertsStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.AllCerts = $Session:AllCertsStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Certificates (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetCertificatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Certificates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetCertificateOverviewFunc,$GetCertificatesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Certificates$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Certificates$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllCerts = Get-Certificates}
                            }
    
                            # Operations that you want to run once every second go here
                            @{CertSummary = Get-CertificateOverview -channel "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Certificates$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo equal to
                # $RSSyncHash."Certificates$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo = $RSSyncHash."Certificates$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $AllCertsProperties = @("CertificateName","FriendlyName","Subject","Issuer","Path","Status","PrivateKey","PublicKey","NotBefore","NotAfter")
            $AllCertsUDTableSplatParams = @{
                Headers         = $AllCertsProperties
                Properties      = $AllCertsProperties
                PageSize        = 5
            }
            New-UDGrid @AllCertsUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllCertsGridData = $PUDRSSyncHT."$RemoteHost`Info".Certificates.AllCerts | Out-UDGridData
    
                $AllCertsGridData
            }
    
            # Live Data Element Example
            $CertSummaryProperties = @("allCount","expiredCount","nearExpiredCount","eventCount")
            $CertSummaryUDTableSplatParams = @{
                Headers         = $CertSummaryProperties
                AutoRefresh     = $True 
                RefreshInterval = 5
            }
            New-UDTable @CertSummaryUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $CertSummaryLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Count
                if ($CertSummaryLiveOutputCount -gt 0) {
                    $ArrayOfCertSummaryEntries = @(
                        $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous.CertSummary
                    ) | Where-Object {$_ -ne $null}
                    if ($ArrayOfCertSummaryEntries.Count -gt 0) {
                        $CertSummaryTableData = $ArrayOfCertSummaryEntries[-1] | Out-UDTableData -Property $CertSummaryProperties
                    }
                }
                if (!$CertSummaryTableData) {
                    $CertSummaryTableData = [pscustomobject]@{
                        allCount            = "Collecting Info"
                        expiredCount        = "Collecting Info"
                        nearExpiredcount    = "Collecting Info"
                        eventCount          = "Collecting Info"
                    } | Out-UDTableData -Property $CertSummaryProperties
                }
    
                $CertSummaryTableData
            }
    
            # Remove the Loading  Indicator
            $null = $Session:CertificatesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Certificates/:RemoteHost" -Endpoint $CertificatesPageContent
    $null = $Pages.Add($Page)
    
    $DevicesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:DevicesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:DevicesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetCimPnPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CimPnpEntity" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetCimPnPFunc
                
                $DevicesInfo = Get-CimPnpEntity
    
                [pscustomobject]@{
                    AllDevices  = $DevicesInfo
                }
            }
            $Session:AllDevicesStatic = $StaticInfo.AllDevices
            if ($PUDRSSyncHT."$RemoteHost`Info".Devices.Keys -notcontains "AllDevices") {
                $PUDRSSyncHT."$RemoteHost`Info".Devices.Add("AllDevices",$Session:AllDevicesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Devices.AllDevices = $Session:AllDevicesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Devices (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetCimPnPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CimPnpEntity" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetCimPnPFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Devices$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Devices$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllDevices = Get-CimPnpEntity}
                            }
    
                            # Operations that you want to run once every second go here
                            #@{AllDevices = Get-CimPnpEntity}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Devices$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo equal to
                # $RSSyncHash."Devices$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo = $RSSyncHash."Devices$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $AllDevicesProperties = @("Name","Status","InstallDate","PNPClass","PNPDeviceID","Service","Manufacturer","Present")
            $AllDevicesUDTableSplatParams = @{
                Headers         = $AllDevicesProperties
                Properties      = $AllDevicesProperties
                PageSize        = 5
            }
            New-UDGrid @AllDevicesUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllDevicesGridData = $PUDRSSyncHT."$RemoteHost`Info".Devices.AllDevices | Out-UDGridData
    
                $AllDevicesGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:DevicesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Devices/:RemoteHost" -Endpoint $DevicesPageContent
    $null = $Pages.Add($Page)
    
    #region >> Disconnected Page
    
    $DisconnectedPageContent = {
        param($RemoteHost)
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        $ConnectionStatusTableProperties = @("RemoteHost", "Status")
    
        New-UDRow -Columns {
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 4 -Content {
                New-UDTable -Headers $ConnectionStatusTableProperties -AutoRefresh -Endpoint {
                    [PSCustomObject]@{
                        RemoteHost      = $RemoteHost.ToUpper()
                        Status          = "Disconnected"
                    } | Out-UDTableData -Property @("RemoteHost", "Status")
                }
            }
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 2 -Content {
                New-UDLink -Text "|| Return Home ||" -Url "/Home"
            }
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 12 -Content {
                # Grid below UDTable
                $ResultProperties = @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink")
    
                $RHost = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
    
                $GridEndpoint = {
                    $GridData = @{}
                    $GridData.Add("HostName",$RHost.HostName.ToUpper())
                    $GridData.Add("FQDN",$RHost.FQDN)
                    $GridData.Add("IPAddress",$RHost.IPAddressList[0])
    
                    # Check Ping
                    try {
                        $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                            $RHost.IPAddressList[0],1000
                        ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                        $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                        $GridData.Add("PingStatus",$PingStatus)
                    }
                    catch {
                        $GridData.Add("PingStatus","Unavailable")
                    }
    
                    # Check WSMan Ports
                    try {
                        $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                        $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                        $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                        foreach ($WSManUrl in $WSManUrls) {
                            $Request = [System.Net.WebRequest]::Create($WSManUrl)
                            $Request.Timeout = 1000
                            try {
                                [System.Net.WebResponse]$Response = $Request.GetResponse()
                            }
                            catch {
                                if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $True
                                    }
                                    else {
                                        $WSMan5986Available = $True
                                    }
                                }
                                elseif ($_.Exception.Message -match "The operation has timed out") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                                else {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                            }
                        }
    
                        if ($WSMan5985Available -or $WSMan5986Available) {
                            $GridData.Add("WSMan","Available")
    
                            [System.Collections.ArrayList]$WSManPorts = @()
                            if ($WSMan5985Available) {
                                $null = $WSManPorts.Add("5985")
                            }
                            if ($WSMan5986Available) {
                                $null = $WSManPorts.Add("5986")
                            }
    
                            $WSManPortsString = $WSManPorts -join ', '
                            $GridData.Add("WSManPorts",$WSManPortsString)
                        }
                    }
                    catch {
                        $GridData.Add("WSMan","Unavailable")
                    }
    
                    # Check SSH
                    try {
                        $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                        if ($TestSSHResult.Open) {
                            $GridData.Add("SSH","Available")
                        }
                        else {
                            $GridData.Add("SSH","Unavailable")
                        }
                    }
                    catch {
                        $GridData.Add("SSH","Unavailable")
                    }
    
                    $GridData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                    if ($GridData.WSMan -eq "Available" -or $GridData.SSH -eq "Available") {
                        if ($PUDRSSyncHT."$($RHost.HostName)`Info".PSRemotingCreds -ne $null) {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                        }
                        else {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                        }
                    }
                    else {
                        $GridData.Add("ManageLink","Unavailable")
                    }
                    
                    [pscustomobject]$GridData | Out-UDGridData
                }
    
                $NewUdGridSplatParams = @{
                    Headers         = $ResultProperties 
                    NoPaging        = $True
                    Properties      = $ResultProperties
                    AutoRefresh     = $True
                    RefreshInterval = 5
                    Endpoint        = $GridEndpoint
                }
                New-UdGrid @NewUdGridSplatParams
            }
        }
    }
    $Page = New-UDPage -Url "/Disconnected/:RemoteHost" -Endpoint $DisconnectedPageContent
    $null = $Pages.Add($Page)
    # We need this page as a string for later on. For some reason, we can't use this same ScriptBlock directly on other Pages
    $DisconnectedPageContentString = $DisconnectedPageContent.ToString()
    
    #endregion >> Disconnected Page
    
    $EventsPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:EventsPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:EventsPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetEventLogSummaryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EventLogSummary" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetEventLogSummaryFunc
                
                $EventLogChannelSummaries = Get-EventLogSummary -channel *
    
                [pscustomobject]@{
                    EventLogChannelSummaries    = $EventLogChannelSummaries
                }
            }
            $Session:EventLogChannelSummariesStatic = $StaticInfo.EventLogChannelSummaries
            if ($PUDRSSyncHT."$RemoteHost`Info".Events.Keys -notcontains "EventLogChannelSummaries") {
                $PUDRSSyncHT."$RemoteHost`Info".Events.Add("EventLogChannelSummaries",$Session:EventLogChannelSummariesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Events.EventLogChannelSummaries = $Session:EventLogChannelSummariesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Events (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetEventLogSummaryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EventLogSummary" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetEventLogSummaryFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Events$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Events$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 100) {
                            $LiveOutput.RemoveRange(0,90)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{EventLogChannelSummaries = Get-EventLogSummary -channel *}
                            }
    
                            # Operations that you want to run once every second go here
                            @{EventLogChannelSummaries = Get-EventLogSummary -channel *}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Events$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo equal to
                # $RSSyncHash."Events$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo = $RSSyncHash."Events$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $EventLogChannelSummaryProperties = @("LogName","LogMode","MaximumSizeInBytes","RecordCount")
            $EventLogChannelSummaryUDTableSplatParams = @{
                Headers         = $EventLogChannelSummaryProperties
                Properties      = $EventLogChannelSummaryProperties
                PageSize        = 10
            }
            New-UDGrid @EventLogChannelSummaryUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $EventLogChannelSummaryGridData = $PUDRSSyncHT."$RemoteHost`Info".Events.EventLogChannelSummaries | Out-UDGridData
    
                $EventLogChannelSummaryGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:EventsPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Events/:RemoteHost" -Endpoint $EventsPageContent
    $null = $Pages.Add($Page)
    
    $FilesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:FilesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:FilesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            if (!$Session:RootDirChildItems) {
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $RootDirChildItems = Get-ChildItem -Path "$env:SystemDrive\"
                    $RootDirItem = Get-Item -Path "$env:SystemDrive\"
    
                    [pscustomobject]@{
                        RootDirItem             = $RootDirItem
                        RootDirChildItems      = $RootDirChildItems
                    }
                }
                $Session:RootDirChildItems = $StaticInfo.RootDirChildItems
                $Session:RootDirItem = $StaticInfo.RootDirItem
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.Keys -notcontains "RootDirChildItems") {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.Add("RootDirChildItems",$StaticInfo.RootDirChildItems)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $StaticInfo.RootDirChildItems
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.Keys -notcontains "RootDirItem") {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.Add("RootDirItem",$StaticInfo.RootDirItem)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $StaticInfo.RootDirItem
                }
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Files (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
    
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Files$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Files$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{RootFiles = Get-ChildItem -Path "$env:SystemDrive\" }
                            }
    
                            # Operations that you want to run once every second go here
                            @{RootFiles = Get-ChildItem -Path "$env:SystemDrive\"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Files$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo equal to
                # $RSSyncHash."Files$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo = $RSSyncHash."Files$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
    
            # Static Data Element Example
    
            New-UDCollapsible -Id $CollapsibleId -Items {
                New-UDCollapsibleItem -Title "File System" -Icon laptop -Active -Endpoint {
                    <#
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDTextbox -Label "Full Path to Directory to Explore" -Id "NewRootDirTB" -Placeholder "Directory to Explore"
                            New-UDButton -Text "Explore" -Id "Button" -OnClick {
                                $NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
                        
                                    [pscustomobject]@{
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                }
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    #>
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentRootDirTB" -Tag div -EndPoint {
                                #New-UDTextbox -Label "Current Directory" -Placeholder "Directory to Explore" -Value $Session:RootDirItem.FullName
                                New-UDHeading -Text "Current Directory: $($Session:RootDirItem.FullName)" -Size 5
                            }
                            New-UDElement -Id "NewRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $NewRootDirTextBox = Get-UDElement -Id "NewRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                    $RootDirItem = Get-Item -Path $args[0]
    
                                    [pscustomobject]@{
                                        RootDirItem            = $RootDirItem
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                Sync-UDElement -Id "NewRootDirTB"
                                Sync-UDElement -Id "CurrentRootDirTB"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $FullPathToExplore = $Session:RootDirItem.FullName | Split-Path -Parent
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                    $RootDirItem = Get-Item -Path $args[0]
    
                                    [pscustomobject]@{
                                        RootDirItem            = $RootDirItem
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                Sync-UDElement -Id "NewRootDirTB"
                                Sync-UDElement -Id "CurrentRootDirTB"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 12 -Endpoint {
                            $RootFilesProperties = @("Name","FullPath","DateModified","Type","Size","Explore")
                            $RootFilesUDGridSplatParams = @{
                                Id              = "RootDirChildItemsUDGrid"
                                Headers         = $RootFilesProperties
                                Properties      = $RootFilesProperties
                                PageSize        = 20
                            }
                            New-UDGrid @RootFilesUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $Session:RootDirChildItems | foreach {
                                    [pscustomobject]@{
                                        Name            = $_.Name
                                        FullPath        = $_.FullName
                                        DateModified    = Get-Date $_.LastWriteTime -Format MM/dd/yy_hh:mm:ss
                                        Type            = if ($_.PSIsContainer) {"Folder"} else {"File"}
                                        Size            = if ($_.PSIsContainer) {'-'} else {[Math]::Round($($_.Length / 1KB),2).toString() + 'KB'}
                                        Explore         = if (!$_.PSIsContainer) {'-'} else {
                                            New-UDButton -Text "Explore" -OnClick {
                                                #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                $FullPathToExplore = $_.FullName
                    
                                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                                    $RootDirItem = Get-Item -Path $args[0]
    
                                                    [pscustomobject]@{
                                                        RootDirItem            = $RootDirItem
                                                        RootDirChildItems      = $RootDirChildItems
                                                    }
                                                } -ArgumentList $FullPathToExplore
                                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                                Sync-UDElement -Id "NewRootDirTB"
                                                Sync-UDElement -Id "CurrentRootDirTB"
                                            }
                                        }
                                    }
                                } | Out-UDGridData
                            }
                        }
                    }
                }
            }
    
            <#
            New-UDInput -Title "Explore Path" -SubmitText "Explore" -Content {
                New-UDInputField -Name "FullPathToExplore" -Type textbox
            } -Endpoint {
                param($FullPathToExplore)
    
                #region >> Check Connection
    
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                #endregion >> Check Connection
    
                #region >> SubMain
    
                if (!$FullPathToExplore) {
                    New-UDInputAction -Toast "You must fill out the 'FullPathToExplore' field!" -Duration 10000
                    return
                }
    
                try {
                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
            
                        [pscustomobject]@{
                            RootDirChildItems      = $RootDirChildItems
                        }
                    }
                    $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
    
                    Sync-UDElement -Id "RootDirChildItemsUDGrid"
    
                    #Invoke-UDRedirect -Url "/Files/$RemoteHost"
                }
                catch {
                    New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                
                    #Invoke-UDRedirect -Url "/Overview/$RemoteHost"
                }
            }
            #>
    
            <#
            # Static Data Element Example
            New-UDCollapsible -Id $CollapsibleId -Items {
                New-UDCollapsibleItem -Title "File System" -Icon laptop -Active -Endpoint {
                    #region >> Main
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 12 -Endpoint {
                            $RootFilesProperties = @("Name","FullPath","DateModified","Type","Size")
                            $RootFilesUDGridSplatParams = @{
                                Id              = "RootDirChildItemsUDGrid"
                                Headers         = $RootFilesProperties
                                Properties      = $RootFilesProperties
                                PageSize        = 20
                            }
                            New-UDGrid @RootFilesUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $Session:RootDirChildItems | foreach {
                                    [pscustomobject]@{
                                        Name            = $_.Name
                                        FullPath        = $_.FullName
                                        DateModified    = Get-Date $_.LastWriteTime -Format MM/dd/yy_hh:mm:ss
                                        Type            = if ($_.PSIsContainer) {"Folder"} else {"File"}
                                        Size            = if ($_.PSIsContainer) {'-'} else {[Math]::Round($($_.Length / 1KB),2).toString() + 'KB'}
                                        #Inspect         = $Cache:InspectCell
                                    }
                                } | Out-UDGridData
                            }
                        }
                    }
                    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 4 -Endpoint {
                            New-UDInput -Title "Explore Path" -SubmitText "Explore" -Content {
                                New-UDInputField -Name "FullPathToExplore" -Type textbox
                            } -Endpoint {
                                param($FullPathToExplore)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> SubMain
    
                                if (!$FullPathToExplore) {
                                    New-UDInputAction -Toast "You must fill out the 'FullPathToExplore' field!" -Duration 10000
                                    return
                                }
    
                                try {
                                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
                            
                                        [pscustomobject]@{
                                            RootDirChildItems      = $RootDirChildItems
                                        }
                                    }
                                    $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
    
                                    Sync-UDElement -Id "RootDirChildItemsUDGrid"
    
                                    #Invoke-UDRedirect -Url "/Files/$RemoteHost"
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                
                                    #Invoke-UDRedirect -Url "/Overview/$RemoteHost"
                                }
    
                                #endregion >> SubMain
                            }
                        }
                    }
    
                    New-UDButton -Text "SyncFileGrid" -Id "Button" -OnClick {
                        Sync-UDElement -Id "RootDirChildItemsUDGrid"
                    }
    
                    #endregion >> Main
                }
            }
            #>
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:FilesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Files/:RemoteHost" -Endpoint $FilesPageContent
    $null = $Pages.Add($Page)
    
    #region >> Overview Page
    
    $OverviewPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:OverviewPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                if ($Session:OverviewPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                <#
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Disconnected"
                                }
                                #>
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                            }
                            
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Count -eq 0) {
                                if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            elseif (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            else {
                                $CredSSPStatus = "NotYetDetermined"
                            }
                            $TableData.Add("CredSSP",$CredSSPStatus)
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","CredSSP","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
            #$GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetServerInventoryFunc
                #Invoke-Expression $using:GetEnvVarsFunc
                
                $SrvInv = Get-ServerInventory
                #$EnvVars = Get-EnvironmentVariables
                $RelevantNetworkInterfacesPrep = [System.Net.NetworkInformation.Networkinterface]::GetAllNetworkInterfaces() | Where-Object {
                    $_.NetworkInterfaceType -eq "Ethernet" -or $_.NetworkInterfaceType -match "Wireless" -and $_.OperationalStatus -eq "Up"
                }
                $RelevantNetworkInterfaces = foreach ($NetInt in $RelevantNetworkInterfacesPrep) {
                    $IPv4Stats = $NetInt.GetIPv4Statistics()
                    [pscustomobject]@{
                        Name                = $NetInt.Name
                        Description         = $NetInt.Description
                        TotalSentBytes      = $IPv4Stats.BytesSent
                        TotalReceivedBytes  = $IPv4Stats.BytesReceived
                    }
                }
    
                [pscustomobject]@{
                    ServerInventoryStatic       = $SrvInv
                    RelevantNetworkInterfaces   = $RelevantNetworkInterfaces
                    #EnvironmentVariables        = [pscustomobject]$EnvVars
                }
            }
            $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
            $Session:RelevantNetworkInterfacesStatic = $StaticInfo.RelevantNetworkInterfaces
            #$Session:EnvironmentVariablesStatic = $StaticInfo.EnvironmentVariables
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "ServerInventoryStatic") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("ServerInventoryStatic",$Session:ServerInventoryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic = $Session:ServerInventoryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "RelevantNetworkInterfaces") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("RelevantNetworkInterfaces",$Session:RelevantNetworkInterfacesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces = $Session:RelevantNetworkInterfacesStatic
            }
            <#
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "EnvironmentVariablesStatic") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvironmentVariablesStatic",$Session:EnvironmentVariablesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvironmentVariablesStatic = $Session:EnvironmentVariablesStatic
            }
            #>
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Overview" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                <#
                if (!$Session:ServerInventoryStatic) {
                    # Gather Basic Info From $RemoteHost
                    $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                    $StaticInfoA = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        Invoke-Expression $using:GetServerInventoryFunc
    
                        $SrvInv = Get-ServerInventory
    
                        [pscustomobject]@{
                            ServerInventoryStatic       = $SrvInv
                        }
                    }
                    $Session:ServerInventoryStatic = $StaticInfoA.ServerInventoryStatic
                    if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "ServerInventoryStatic") {
                        $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("ServerInventoryStatic",$Session:ServerInventoryStatic)
                    }
                    else {
                        $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic = $Session:ServerInventoryStatic
                    }
                }
                #>
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetEnvVarsFunc,$GetServerInventoryFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Overview$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Overview$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go withing this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                # Server Inventory
                                @{ServerInventory = Get-ServerInventory}
                                #Start-Sleep -Seconds 3
                            
                                # Processes
                                #@{Processes = [System.Diagnostics.Process]::GetProcesses()}
                                #Start-Sleep -Seconds 3
                            }
    
                            # Operations that you want to run once every second go here
    
                            # Processes
                            @{ProcessesCount = $(Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue).CounterSamples.Count}
                            @{HandlesCount = $(Get-Counter "\Process(_total)\handle count").CounterSamples.CookedValue}
                            @{ThreadsCount = $(Get-Counter "\Process(_total)\thread count").CounterSamples.CookedValue}
    
                            # Environment Variables
                            #@{EnvVars = [pscustomobject]@{EnvVarsCollection = Get-EnvironmentVariables}}
    
                            # RAM Utilization
                            $OSInfo = Get-CimInstance Win32_OperatingSystem
                            $TotalMemoryInGB = [Math]::Round($($OSInfo.TotalVisibleMemorySize / 1MB),2)
                            @{RamTotalGB = $TotalMemoryInGB}
                            
                            $FreeMemoryInGB = [Math]::Round($($(Get-Counter -Counter "\Memory\available bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamFreeGB = $FreeMemoryInGB}
    
                            $RamPct = [Math]::Round($($(Get-Counter -Counter "\Memory\% committed bytes in use").CounterSamples.CookedValue),2)
                            @{RamPct = $RamPct}
                            
                            $RamCommittedGB = [Math]::Round($($(Get-Counter -Counter "\Memory\committed bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamCommittedGB = $RamCommittedGB}
    
                            $RamCachedGB = $RamCommitted + [Math]::Round($($(Get-Counter -Counter "\Memory\cache bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamCachedGB = $RamCachedGB}
    
                            $RamInUseGB = $TotalMemoryInGB - $FreeMemoryInGB
                            @{RamInUseGB = $RamInUseGB}
    
                            $RamPagedPoolMB = [Math]::Round($($(Get-Counter -Counter "\Memory\pool paged bytes").CounterSamples.CookedValue / 1MB),2)
                            @{RamPagedPoolMB = $RamPagedPoolMB}
    
                            $RamNonPagedPoolMB = [Math]::Round($($(Get-Counter -Counter "\Memory\pool nonpaged bytes").CounterSamples.CookedValue / 1MB),2)
                            @{RamNonPagedPoolMB = $RamNonPagedPoolMB}
    
                            # CPU
                            $CPUInfo = Get-CimInstance Win32_Processor
                            @{CPUPct = $CPUInfo.LoadPercentage}
                            @{ClockSpeed = [Math]::Round($($CPUInfo.CurrentClockSpeed / 1KB),2)}
    
                            @{Uptime = "{0:c}" -f $($(Get-Date) - $OSInfo.LastBootUpTime)}
    
                            # Network Stats
                            $RelevantNetworkInterfaces = [System.Net.NetworkInformation.Networkinterface]::GetAllNetworkInterfaces() | Where-Object {
                                $_.NetworkInterfaceType -eq "Ethernet" -or $_.NetworkInterfaceType -match "Wireless" -and $_.OperationalStatus -eq "Up"
                            }
                            [System.Collections.ArrayList]$NetStatsInfo = @()
                            foreach ($NetInt in $RelevantNetworkInterfaces) {
                                $IPv4Stats = $NetInt.GetIPv4Statistics()
                                $NetStatsPSObj = [pscustomobject]@{
                                    Name                = $NetInt.Name
                                    Description         = $NetInt.Description
                                    TotalSentBytes      = $IPv4Stats.BytesSent
                                    TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                }
                                $null = $NetStatsInfo.Add($NetStatsPSObj)
                            }
                            @{NetStats = $NetStatsInfo}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Overview$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo equal to
                # $RSSyncHash."Overview$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo = $RSSyncHash."Overview$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            New-UDRow -Endpoint {
                # Restart $RemoteHost
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "RestartComputer"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Restart" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Restart" -Id "RestartComputerForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name 'RestartComputer' -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
                                
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Restart-Computer -Force
                                }
    
                                New-UDInputAction -Toast "Restarting $RemoteHost..." -Duration 10000
                                
                                New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
    
                                #endregion >> Main
                            }
                        }
                    }
                }
    
                # Shutdown $RemoteHost
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "ShutdownComputer"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Shutdown" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Shutdown" -Id "ShutdownComputerForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name "ShutdownComputer" -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Stop-Computer -Force
                                }
    
                                New-UDInputAction -Toast "Shutting down $RemoteHost..." -Duration 10000
                                
                                New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
    
                                #endregion >> Main
                            }
                        }
                    }
                }
                # Enable Disk Metrics
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "EnableDiskMetrics"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Enable Disk Metrics" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Enable Disk Perf" -Id "EnableDiskMetricsForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name "EnableDiskMetrics" -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                try {
                                    $StartDiskPerfFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Start-DiskPerf" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                    $StartDisPerfResult = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:StartDiskPerfFunc
    
                                        Start-DiskPerf
                                    }
    
                                    New-UDInputAction -Toast $($StartDisPerfResult | Out-String) -Duration 10000
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                }
    
                                #endregion >> Main
                            }
                        }
                    }
                }
                # Edit Computer ID
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "EditComputerIDMenu"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Edit Computer ID" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Edit Computer" -Id "ComputerIDForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                $DName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Domain
                                $WGName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Workgroup
    
                                New-UDInputField -Type textbox -Name 'Change_Host_Name' -DefaultValue $HName
                                New-UDInputField -Type textbox -Name 'Join_Domain' -DefaultValue $DName
                                New-UDInputField -Type textbox -Name 'NewDomain_UserName'
                                New-UDInputField -Type textbox -Name 'NewDomain_Password'
                                New-UDInputField -Type textbox -Name 'Join_Workgroup' -DefaultValue $WGName
                            } -Endpoint {
                                param($Change_Host_Name,$Join_Domain,$NewDomain_UserName,$NewDomain_Password,$Join_Workgroup)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Name
                                $DName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Domain
                                $WGName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Workgroup
                                $PartOfDomainCheck = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.PartOfDomain
                                $SetComputerIdFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-ComputerIdentification" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                # Make sure that $Join_Workgroup and $Join_Domain are NOT both filled out
                                if ($($Join_Domain -and $Join_Workgroup) -or $(!$Join_Domain -and !$Join_Workgroup)) {
                                    New-UDInputAction -Toast "Please ensure that either Join_Domain or Join_Workgroup are filled out!" -Duration 10000
                                    return
                                }
    
                                #region >> ONLY Change Host Name
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Domain -eq $null -or $Join_Domain -eq $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Domain Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain aprameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # If we don't have LocalCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming '$HName' to '$Change_Host_Name' and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$Change_Host_Name because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name + '.' + $UpdatedNetworkInfoHT.Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
    
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -ne $null) {
                                        $LocalUName = $Change_Host_Name + '\' + $($Session:CredentialHT.$RemoteHost.LocalCreds.UserName -split "\\")[-1]
                                        $UpdatedLocalCreds = [pscredential]::new($LocalUName,$Session:CredentialHT.$RemoteHost.LocalCreds.Password)
                                    }
                                    else {
                                        $UpdatedLocalCreds = $null
                                    }
    
                                    if ($Session:CredentialHT.$RemoteHost.PSRemotingCredType -eq "Local") {
                                        $UpdatedPSRemotingCreds = $UpdatedLocalCreds
                                    }
                                    else {
                                        $UpdatedPSRemotingCreds = $Session:CredentialHT.$RemoteHost.PSRemotingCreds
                                    }
    
                                    $UpdatedKey = $Change_Host_Name + "Info"
                                    $UpdatedValue = @{
                                        NetworkInfo         = [pscustomobject]$UpdatedNetworkInfoHT
                                        Overview            = @{
                                            LiveDataRSInfo      = $RSSyncHash."Overview$RemoteHost`LiveDataResult"
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                    }
                                    foreach ($DynPage in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                        $DynPageHT = @{
                                            LiveDataRSInfo      = $null
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                        $UpdatedValue.Add($DynPage,$DynPageHT)
                                    }
                                    $global:PUDRSSyncHT.Add($UpdatedKey,$UpdatedValue)
    
                                    $UpdatedValue = @{
                                        DomainCreds         = $Session:CredentialHT.$RemoteHost.DomainCreds
                                        LocalCreds          = $UpdatedLocalCreds
                                        SSHCertPath         = $Session:CredentialHT.$RemoteHost.SSHCertPath
                                        PSRemotingCredType  = $Session:CredentialHT.$RemoteHost.PSRemotingCredType
                                        PSRemotingMethod    = $Session:CredentialHT.$RemoteHost.PSRemotingMethod
                                        PSRemotingCreds     = $UpdatedPSRemotingCreds
                                    }
                                    $Session:CredentialHT.$RemoteHost.Add($UpdatedKey,$UpdatedValue)
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> ONLY Change Host Name
    
                                #region >> ONLY Join Domain
    
                                if ($($Change_Host_Name -eq $HName -or !$Change_Host_Name) -and
                                $($Join_Domain -ne $null -and $Join_Domain -ne $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    # Check to make sure we have $NewDomain_UserName and $NewDomain_Password
                                    if (!$NewDomain_UserName -or !$NewDomain_Password) {
                                        if (!$NewDomain_UserName) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_UserName!" -Duration 10000
    
                                        }
                                        if (!$NewDomain_Password) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_Password!" -Duration 10000
                                        }
                                        return
                                    }
    
                                    $SetComputerIdSplatParams = @{
                                        NewDomain           = $Join_Domain
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain aprameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserNameNew",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("PasswordNew",$NewDomain_Password)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                        $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                        $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
                                    }
                                    else {
                                        # If the $RemoteHost is not part of Domain, then our PSRemoting Credentials must be Local Credentials
                                        # but we don't really need thm for anything in particular...
                                        #$AuthorizationUName = $Session:CredentialHT.$RemoteHost."$RemoteHost`Info".PSRemotingCreds.UserName
                                        #$AuthorizationPwd = $Session:CredentialHT.$RemoteHost."$RemoteHost`Info"..PSRemotingCreds.GetNetworkCredential().Password
    
                                        # In this situation, the Set-ComputerIdentification function interprets -UserName and -Password as
                                        # the New Domain Credentials
                                        $SetComputerIdSplatParams.Add("UserName",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("Password",$NewDomain_Password)
                                    }
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Joining $RemoteHost to $Join_Domain and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.FQDN = $RemoteHost + '.' + $Join_Domain
                                    $UpdatedNetworkInfoHT.Domain = $Join_Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    $NewDomainPwdSecureString = ConvertTo-SecureString $NewDomain_Password -AsPlainText -Force
                                    $UpdatedDomainCreds = [pscredential]::new($NewDomain_UserName,$NewDomainPwdSecureString)
                                    $Session:CredentialHT.$RemoteHost.DomainCreds = $UpdatedDomainCreds
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
                                    return
                                }
    
                                #endregion >> ONLY Join Domain
    
                                #region >> ONLY Join Workgroup
    
                                if ($($Change_Host_Name -eq $HName -or !$Change_Host_Name) -and
                                $($Join_Workgroup -ne $null -and $Join_Workgroup -ne $WGName) -and
                                $Join_Domain -eq $null
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        Workgroup           = $Join_Workgroup
                                        Restart             = $True
                                    }
    
                                    # We need LocalCreds to ensure we can reestablish a PSSession after leaving the Domain
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                        New-UDInputAction -Toast "Joining Workgroup $Join_Workgroup requires Local Credentials!" -Duration 10000
                                        New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                        return
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Leaving the Domain $DName requires credentials from $DName!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserName",$Session:CredentialHT.$RemoteHost.DomainCreds.UserName)
                                        $SetComputerIdSplatParams.Add("Password",$Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password)
                                    }
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Joining Workgroup $Join_Workgroup and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.FQDN = $RemoteHost
                                    $UpdatedNetworkInfoHT.Domain = $null
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
                                    return
                                }
    
                                #endregion >> ONLY Join Workgroup
    
                                #region >> Join Domain AND Rename Computer
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Domain -ne $null -and $Join_Domain -ne $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    # Check to make sure we have $NewDomain_UserName and $NewDomain_Password
                                    if (!$NewDomain_UserName -or !$NewDomain_Password) {
                                        if (!$NewDomain_UserName) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_UserName!" -Duration 10000
    
                                        }
                                        if (!$NewDomain_Password) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_Password!" -Duration 10000
                                        }
                                        return
                                    }
    
                                    $SetComputerIdSplatParams = @{
                                        NewDomain           = $Join_Domain
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain parameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserNameNew",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("PasswordNew",$NewDomain_Password)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # If we don't have LocalCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming $RemoteHost to $Change_Host_Name, joining Domain $Join_Domain, and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name + '.' + $Join_Domain
                                    $UpdatedNetworkInfoHT.Domain = $Join_Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$Change_Host_Name`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    $NewDomainPwdSecureString = ConvertTo-SecureString $NewDomain_Password -AsPlainText -Force
                                    $UpdatedDomainCreds = [pscredential]::new($NewDomain_UserName,$NewDomainPwdSecureString)
                                    $Session:CredentialHT.$RemoteHost.DomainCreds = $UpdatedDomainCreds
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> Join Domain AND Rename Computer
    
                                #region >> Join Workgroup AND Rename Computer
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Workgroup -ne $null -and $Join_Workgroup -ne $WGName) -and
                                $Join_Domain -eq $null
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        Workgroup           = $Join_Workgroup
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # We need LocalCreds regardless
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                        New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                        New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                        return
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds to leave it.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain parameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming $RemoteHost to $Change_Host_Name, joining Workgroup $Join_Workgroup, and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.Domain = $null
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$Change_Host_Name`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> Join Workgroup AND Rename Computer
    
                                #endregion >> Main
                            }
                        }
                    }
                }
            }
            New-UDRow -Endpoint {
                # Disable CredSSP
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "DisableCredSSP"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Disable CredSSP*" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "DisableCredSSP" -Id "DisableCredSSPForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name "Disable_CredSSP" -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                param($Disable_CredSSP)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                $CredSSPChanges = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $Output = @{}
                                    $GetCredSSPStatus = Get-WSManCredSSP
                                    if ($GetCredSSPStatus -match "The machine is configured to allow delegating fresh credentials.") {
                                        Disable-WSManCredSSP -Role Client
                                        $Output.Add("CredSSPClientChange",$True)
                                    }
                                    else {
                                        $Output.Add("CredSSPClientChange",$False)
                                    }
                                    if ($GetCredSSPStatus -match "This computer is configured to receive credentials from a remote client computer.") {
                                        Disable-WSManCredSSP -Role Server
                                        $Output.Add("CredSSPServerChange",$True)
                                    }
                                    else {
                                        $Output.Add("CredSSPServerChange",$False)
                                    }
                                    [PSCustomObject]$Output
                                }
    
                                [System.Collections.ArrayList]$ToastMessage = @()
                                if ($CredSSPChanges.CredSSPClientChange -eq $True) {
                                    $null = $ToastMessage.Add("Disabled CredSSP Client.")
                                }
                                else {
                                    $null = $ToastMessage.Add("CredSSP Client is already disabled.")
                                }
                                if ($CredSSPChanges.CredSSPServerChange -eq $True) {
                                    $null = $ToastMessage.Add("Disabled CredSSP Server.")
                                }
                                else {
                                    $null = $ToastMessage.Add("CredSSP Server is already disabled.")
                                }
                                $ToastMessageFinal = $ToastMessage -join " "
    
                                New-UDInputAction -Toast $ToastMessageFinal -Duration 2000
                                Start-Sleep -Seconds 2
    
                                #Sync-UDElement -Id 'TrackingTable'
    
                                #New-UDInputAction -RedirectUrl "/Overview/$RemoteHost"
    
                                # Reload the page
                                <#
                                New-UDInputAction -Content @(
                                    Add-UDElement -ParentId "RedirectParent" -Content {
                                        New-UDHtml -Markup "<meta http-equiv=`"refresh`" content=`"0; URL='/Overview/$RemoteHost'`" />"
                                    }
                                )
                                #>
                                Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                #endregion >> Main
                            }
                        }
                    }
                }
                # Remote Desktop
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "RemoteDesktop"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Remote Desktop*" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Submit" -Id "RemoteDesktopForm" -Content {
                                $GetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $RemoteDesktopSettings = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRDFunc
                                    Get-RemoteDesktop
                                } -HideComputerName
                                $DefaultValue = if ($RemoteDesktopSettings.allowRemoteDesktop) {"Enabled"} else {"Disabled"}
                                New-UDInputField -Name "Remote_Desktop_Setting" -Type select -Values @("Enabled","Disabled") -DefaultValue $DefaultValue
                            } -Endpoint {
                                param($Remote_Desktop_Setting)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $SetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                if ($Remote_Desktop_Setting -eq "Enabled") {
                                    $SetRemoteDesktopSplatParams = @{
                                        AllowRemoteDesktop        = $True
                                        AllowRemoteDesktopWithNLA = $True
                                    }
                                    $ToastMessage = "Remote Desktop Enabled for $RemoteHost!"
                                }
                                else {
                                    $SetRemoteDesktopSplatParams = @{
                                        AllowRemoteDesktop        = $False
                                        AllowRemoteDesktopWithNLA = $False
                                    }
                                    $ToastMessage = "Remote Desktop Disabled for $RemoteHost!"
                                }
    
                                try {
                                    $SetRemoteDesktopResult = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Set-ItemProperty -Path "HKLM:\SYSTEM\Currentcontrolset\control\Terminal Server" -Name TSServerDrainMode -Value 1
                                    } -ArgumentList $SetRemoteDesktopSplatParams
    
                                    New-UDInputAction -Toast $ToastMessage -Duration 2000
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                }
                                Start-Sleep -Seconds 2
    
                                # Reload the page
                                <#
                                New-UDInputAction -Content @(
                                    Add-UDElement -ParentId "RedirectParent" -Content {
                                        New-UDHtml -Markup "<meta http-equiv=`"refresh`" content=`"0; URL='/Overview/$RemoteHost'`" />"
                                    }
                                )
                                #>
                                Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                #region >> Main
                            }
                        }
                    }
                }
                # Enable SSH
                New-UDColumn -Size 6 -Endpoint {
                    $CollapsibleId = $RemoteHost + "SSH"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "SSH" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Submit" -Id "SSHForm" -Content {
                                New-UDInputField -Name "SSH_Setting" -Type select -Values @("Enabled","Disabled") -DefaultValue "Disabled"
                            } -Endpoint {
    
                            }
                        }
                    }
                }
            }
    
            New-UDRow -Endpoint {
                # Edit Environment Variables
                New-UDColumn -Size 12 -Endpoint {
                    $CollapsibleId = $RemoteHost + "Environment Variables"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Environment Variables" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 12 -Endpoint {
                                    $EnvVarsUdGridSplatParams = @{
                                        Title           = "Environment Variables"
                                        Id              = "EnvVarsGrid"
                                        Headers         = @("Type","Name","Value")
                                        Properties      = @("Type","Name","Value")
                                        PageSize        = 10
                                    }
                                    New-UdGrid @EnvVarsUdGridSplatParams -Endpoint {
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:GetEnvVarsFunc
                                            
                                            $EnvVars = Get-EnvironmentVariables
                                            
                                            [pscustomobject]@{
                                                EnvironmentVariables        = [pscustomobject]$EnvVars
                                            }
                                        }
                                        $Session:EnvironmentVariablesStatic = $StaticInfo.EnvironmentVariables
                                        if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "EnvironmentVariablesStatic") {
                                            $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvironmentVariablesStatic",$Session:EnvironmentVariablesStatic)
                                        }
                                        else {
                                            $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvironmentVariablesStatic = $Session:EnvironmentVariablesStatic
                                        }
    
                                        $Session:EnvironmentVariablesStatic | Out-UDGridData
                                    }
                                }
                            }
    
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 3 -Endpoint {}
                                New-UDColumn -Size 6 -Endpoint {
                                    New-UDHeading -Text "Modify Environment Variables" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarName" -Label "Current Name"
                                    New-UDTextbox -Id "EnvVarNewName" -Label "New Name"
                                    New-UDTextbox -Id "EnvVarValue" -Label "Value"
                                    New-UDSelect -Id "EnvVarType" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
                                    
                                    
                                    New-UDButton -Text "New" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarName"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValue"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarType"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvVarInfo",@{})
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarTypeObject",$EnvVarTypeSelection)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarName",$EnvVarName)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarValue",$EnvVarValue)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarType",$EnvVarType)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("RemoteHost",$RemoteHost)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("CredsUserName",$($Session:CredentialHT.$RemoteHost.PSRemotingCreds.UserName))
                                        
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:NewEnvVarFunc
                                            New-EnvironmentVariable -name $using:EnvVarName -value $using:EnvVarValue -type $using:EnvVarType
                                        }
    
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
    
                                    New-UDButton -Text "Remove" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarName"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValue"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarType"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $EnvVarTypeTextBox.Attributes['value']
    
                                        $RemoveEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Remove-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:RemoveEnvVarFunc
                                            Remove-EnvironmentVariable -name $using:EnvVarName -type $using:EnvVarType
                                        }
                                        
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
    
                                    New-UDButton -Text "Edit" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarName"
                                        $EnvVarNewNameTextBox = Get-UDElement -Id "EnvVarNewName"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValue"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarType"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarNewName = $EnvVarNewNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $EnvVarTypeTextBox.Attributes['value']
    
                                        $SetEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $SetEnvVarSplatParams = @{
                                            oldName     = $EnvVarName
                                            type        = $EnvVarType
                                        }
                                        if ($EnvVarValue) {
                                            $SetEnvVarSplatParams.Add("value",$EnvVarValue)
                                        }
                                        if ($EnvVarNewName) {
                                            $SetEnvVarSplatParams.Add("newName",$EnvVarNewName)
                                        }
                                        else {
                                            $SetEnvVarSplatParams.Add("newName",$EnvVarName)
                                        }
    
                                        # NOTE: Set-EnvironmentVariable outputs @{Status = "Succcess"} otherwise, Error
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:SetEnvVarFunc
                                            $SplatParams = $args[0]
                                            Set-EnvironmentVariable @SplatParams
                                        } -ArgumentList $SetEnvVarSplatParams
                                        
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
                                }
                            }
                            
                            <#
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "New Environment Variable" -SubmitText "Add" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "Value" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$Value,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate the name of the Environment Variable you would like to Add." -Duration 10000
                                            return
                                        }
    
                                        try {
                                            # NOTE: New-EnvironmentVariable does not output anything
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                $using:NewEnvVarFunc
    
                                                New-EnvironmentVariable -name $using:Name -value $using:Value -type $using:Type
                                            }
    
                                            New-UDInputAction -Toast "New $Type Environment Variable $Name was successfully created. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
                                
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "Remove Environment Variable" -SubmitText "Remove" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate which existing Environment Variable you would like to Remove." -Duration 10000
                                            return
                                        }
    
                                        try {
                                            # NOTE: Remove-EnvironmentVariable does not output anything
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                Invoke-Expression $using:RemoveEnvVarFunc
    
                                                Remove-EnvironmentVariable -name $using:Name -type $using:Type
                                            }
    
                                            New-UDInputAction -Toast "Removed $Type Environment Variable $Name successfully. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
    
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "Edit Environment Variable" -SubmitText "Edit" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "NewName" -Type textbox
                                        New-UDInputField -Name "Value" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$NewName,$Value,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate which existing Environment Variable you would like to Edit." -Duration 10000
                                            return
                                        }
    
                                        $SetEnvVarSplatParams = @{
                                            oldName     = $Name
                                            type        = $Type
                                        }
                                        if ($Value) {
                                            $SetEnvVarSplatParams.Add("value",$Value)
                                        }
                                        if ($NewName) {
                                            $SetEnvVarSplatParams.Add("newName",$NewName)
                                        }
                                        else {
                                            $SetEnvVarSplatParams.Add("newName",$Name)
                                        }
    
                                        try {
                                            # NOTE: Set-EnvironmentVariable outputs @{Status = "Succcess"} otherwise, Error
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                Invoke-Expression $using:SetEnvVarFunc
    
                                                $SplatParams = $args[0]
                                                Set-EnvironmentVariable @SplatParams
                                            } -ArgumentList $SetEnvVarSplatParams
    
                                            New-UDInputAction -Toast "Successfully edited Environment Variable. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                            
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
                            }
                            #>
                            #endregion >> Main
                        }
                    }
                }
            }
    
            #endregion >> Controls
    
            #region >> Summary Info
    
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Endpoint {
                    #region >> Check Connection
    
                    $PUDRSSyncHT = $global:PUDRSSyncHT
    
                    # Load PUDAdminCenter Module Functions Within ScriptBlock
                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                    $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                    #endregion >> Check Connection
    
                    New-UDHeading -Text "Summary" -Size 4
    
                    # Summary A
                    $SummaryInfoAGridProperties = @("Computer_Name","Domain","Operating_System","Version","Installed_Memory")
    
                    $SummaryInfoAGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $SrvInv = $Session:ServerInventoryStatic
    
                        [pscustomobject]@{
                            Computer_Name       = $SrvInv.ComputerSystem.Name
                            Domain              = $SrvInv.ComputerSystem.Domain
                            Operating_System    = $SrvInv.OperatingSystem.Caption
                            Version             = $SrvInv.OperatingSystem.Version
                            Installed_Memory    = [Math]::Round($SrvInv.ComputerSystem.TotalPhysicalMemory / 1GB).ToString() + " GB"
                        } | Out-UDTableData -Property $SummaryInfoAGridProperties
                    }
                    $SummaryInfoAUdGridSplatParams = @{
                        Id              = "SummaryInfoA"
                        Headers         = $SummaryInfoAGridProperties
                        Endpoint        = $SummaryInfoAGridEndpoint
                    }
                    New-UdTable @SummaryInfoAUdGridSplatParams
    
                    # Summary B
                    $SummaryInfoBGridProperties = @("C_DiskSpace_FreeVsTotal","Processors","Manufacturer","Model","Logical_Processors")
                    
                    $SummaryBInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $CimDiskResult = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
                        $CimDiskOutput = [Math]::Round($CimDiskResult.FreeSpace / 1GB).ToString() + "GB" +
                        ' / ' + [Math]::Round($CimDiskResult.Size / 1GB).ToString() + "GB"
    
                        $ProcessorsPrep = $($(
                            Get-CimInstance Win32_Processor | foreach {
                                $_.Name.Trim() + $_.Caption.Trim()
                            }
                        ) -replace "[\s]+"," ") | foreach {
                            $($_ -split "[0-9]GHz")[0] + "GHz"
                        }
                        $Processors = $ProcessorsPrep -join " | "
    
                        [pscustomobject]@{
                            ProcessorInfo       = $Processors
                            CimDiskInfo         = $CimDiskOutput
                        }
                    }
    
                    $SummaryInfoBGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $SrvInv = $Session:ServerInventoryStatic
    
                        [pscustomobject]@{
                            C_DiskSpace_FreeVsTotal     = $SummaryBInfo.CimDiskInfo
                            Processors                  = $SummaryBInfo.ProcessorInfo
                            Manufacturer                = $SrvInv.ComputerSystem.Manufacturer
                            Model                       = $SrvInv.ComputerSystem.Model
                            Logical_Processors          = $SrvInv.ComputerSystem.NumberOfLogicalProcessors.ToString()
                        } | Out-UDTableData -Property $SummaryInfoBGridProperties
                    }
                    $SummaryInfoBUdGridSplatParams = @{
                        Id              = "SummaryInfoB"
                        Headers         = $SummaryInfoBGridProperties
                        Endpoint        = $SummaryInfoBGridEndpoint
                    }
                    New-UdTable @SummaryInfoBUdGridSplatParams
    
                    # Summary C
                    $SummaryCInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $using:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                        
                        $DefenderInfo = Get-MpComputerStatus
                        $NicCount = $([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
                            $_.NetworkInterfaceType -eq "Ethernet"
                        }).Count
                        $GetLocalUsersInfo = Get-LocalUsers
    
                        [pscustomobject]@{
                            RealTimeProtectionStatus    = $DefenderInfo.RealTimeProtectionEnabled
                            NicCount                    = $NicCount
                            LocalUserCount              = $GetLocalUsersInfo.Count
                        }
                    }
                    
                    $SummaryInfoCGridProperties = @("Windows_Defender","NICs","Uptime","LocalUserCount")
    
                    $SummaryInfoCGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $UptimeLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($UptimeLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$UptimeLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfUptimeEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Uptime
                            ) | Where-Object {$_ -ne $null}
                        }
    
                        if ($ArrayOfUptimeEntries.Count -eq 0) {
                            $FinalUptime = "00:00:00:00"
                        }
                        else {
                            $FinalUptime = $ArrayOfUptimeEntries[-1]
    
                            if ($($FinalUptime | Get-Member -Type Method).Name -contains "LastIndexOf" -and $FinalUptime -match "\.") {
                                $FinalUptime = $FinalUptime.Substring(0,$FinalUptime.LastIndexOf('.'))
                            }
                            else {
                                $FinalUptime = "00:00:00:00"
                            }
                        }
    
                        [pscustomobject]@{
                            Windows_Defender    = if ($SummaryCInfo.RealTimeProtectionStatus) {"Real-time protection: On"} else {"Real-time protection: Off"}
                            NICs                = $SummaryCInfo.NicCount
                            Uptime              = $FinalUptime
                            LocalUserCount      = $SummaryCInfo.LocalUserCount
                        } | Out-UDTableData -Property $SummaryInfoCGridProperties
                    }
                    $SummaryInfoCUdGridSplatParams = @{
                        Id              = "SummaryInfoC"
                        Headers         = $SummaryInfoCGridProperties
                        AutoRefresh     = $True
                        RefreshInterval = 2
                        Endpoint        = $SummaryInfoCGridEndpoint
                    }
                    New-UdTable @SummaryInfoCUdGridSplatParams
                }
            }
    
            #endregion >> Summary Info
    
            #region >> Monitors
    
            # CPU Utilization and Memory Usage
            New-UDRow -Columns {
                New-UDHeading -Text "Processor (CPU) and Memory (RAM) Info" -Size 4
                New-UDColumn -Size 6 -Endpoint {
                    $CPUTableProperties =@("CPU_Utilization","ClockSpeed","Processes","Threads","Handles")
                    New-UDTable -Id "CPUTable" -Headers $CPUTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $CPULiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($CPULiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$CPULiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfCPUPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.CPUPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfCPUPctEntries.Count -gt 0) {
                                $LatestCPUPctEntry = $ArrayOfCPUPctEntries[-1]
                            }
    
                            $ArrayOfClockSpeedEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ClockSpeed
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfClockSpeedEntries.Count -gt 0) {
                                $LatestClockSpeedEntry = $ArrayOfClockSpeedEntries[-1]
                            }
    
                            $ArrayOfProcessesCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ProcessesCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfProcessesCountEntries.Count -gt 0) {
                                $LatestProcessesEntry = $ArrayOfProcessesCountEntries[-1]
                            }
    
                            $ArrayOfHandlesCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.HandlesCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfHandlesCountEntries.Count -gt 0) {
                                $LatestHandlesEntry = $ArrayOfHandlesCountEntries[-1]
                            }
    
                            $ArrayOfThreadsCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ThreadsCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfThreadsCountEntries.Count -gt 0) {
                                $LatestThreadsEntry = $ArrayOfThreadsCountEntries[-1]
                            }
                        }
    
                        $FinalCPUPct = if (!$LatestCPUPctEntry) {"0"} else {$LatestCPUPctEntry.ToString() + '%'}
                        $FinalSpeed = if (!$LatestClockSpeedEntry) {"0"} else {$LatestClockSpeedEntry.ToString() + 'GHz'}
                        $FinalProcesses = if (!$LatestProcessesEntry) {"0"} else {$LatestProcessesEntry}
                        $FinalHandles = if (!$LatestHandlesEntry) {"0"} else {$LatestHandlesEntry}
                        $FinalThreads = if (!$LatestThreadsEntry) {"0"} else {$LatestThreadsEntry}
    
                        [pscustomobject]@{
                            CPU_Utilization     = $FinalCPUPct
                            ClockSpeed          = $FinalSpeed
                            Processes           = $FinalProcesses
                            Threads             = $FinalThreads
                            Handles             = $FinalHandles
                        } | Out-UDTableData -Property $CPUTableProperties
                    }
    
                    $CPUMonitorEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $CPULiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($CPULiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$CPULiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfCPUPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.CPUPct
                                ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfCPUPctEntries.Count -gt 0) {
                                $LatestCPUPctEntry = $ArrayOfCPUPctEntries[-1]
                            }
                        }
    
                        $FinalCPUPct = if (!$LatestCPUPctEntry) {"0"} else {$LatestCPUPctEntry}
    
                        $FinalCPUPct | Out-UDMonitorData
                    }
    
                    $CPUMonitorSplatParams = @{
                        Title                   = "CPU Utilization %"
                        Type                    = "Line"
                        DataPointHistory        = 20
                        ChartBackgroundColor    = "#80FF6B63"
                        ChartBorderColor        = "#FFFF6B63"
                        AutoRefresh             = $True
                        RefreshInterval         = 5
                        Endpoint                = $CPUMonitorEndpoint
                    }
                    New-UdMonitor @CPUMonitorSplatParams
                }
                New-UDColumn -Size 6 -Endpoint {
                    #New-UDHeading -Text "Memory (RAM) Info" -Size 4
                    #$RamTableProperties = @("RAM_Utilization","Total","InUse","Available","Committed","Cached","PagedPool","NonPagedPool")
                    $RamTableProperties = @("RAM_Utilization","Total","InUse","Available","Committed","Cached")
                    New-UDTable -Id "RamTable" -Headers $RamTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $RamLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($RamLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$RamLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfRamPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPctEntries.Count -gt 0) {
                                $LatestRamPctEntry = $ArrayOfRamPctEntries[-1]
                            }
    
                            $ArrayOfRamTotalGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamTotalGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamTotalGBEntries.Count -gt 0) {
                                $LatestRamTotalGBEntry = $ArrayOfRamTotalGBEntries[-1]
                            }
                            
                            $ArrayOfRamInUseGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamInUseGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamInUseGBEntries.Count -gt 0) {
                                $LatestRamInUseGBEntry = $ArrayOfRamInUseGBEntries[-1]
                            }
    
                            $ArrayOfRamFreeGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamFreeGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamFreeGBEntries.Count -gt 0) {
                                $LatestRamFreeGBEntry = $ArrayOfRamFreeGBEntries[-1]
                            }
    
                            $ArrayOfRamCommittedGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamCommittedGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamCommittedGBEntries.Count -gt 0) {
                                $LatestRamCommittedGBEntry = $ArrayOfRamCommittedGBEntries[-1]
                            }
    
                            $ArrayOfRamCachedGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamCachedGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamCachedGBEntries.Count -gt 0) {
                                $LatestRamCachedGBEntry = $ArrayOfRamCachedGBEntries[-1]
                            }
    
                            $ArrayOfRamPagedPoolMBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPagedPoolMB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPagedPoolMBEntries.Count -gt 0) {
                                $LatestRamPagedPoolMBEntry = $ArrayOfRamPagedPoolMBEntries[-1]
                            }
    
                            $ArrayOfRamNonPagedPoolMBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamNonPagedPoolMB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamNonPagedPoolMBEntries.Count -gt 0) {
                                $LatestRamNonPagedPoolMBEntry = $ArrayOfRamNonPagedPoolMBEntries[-1]
                            }
                        }
    
                        $FinalRamPct = if (!$LatestRamPctEntry) {"0"} else {$LatestRamPctEntry.ToString() + '%'}
                        $FinalRamTotalGB = if (!$LatestRamTotalGBEntry) {"0"} else {$LatestRamTotalGBEntry.ToString() + 'GB'}
                        $FinalRamInUseGB = if (!$LatestRamInUseGBEntry) {"0"} else {$LatestRamInUseGBEntry.ToString() + 'GB'}
                        $FinalRamFreeGB = if (!$LatestRamFreeGBEntry) {"0"} else {$LatestRamFreeGBEntry.ToString() + 'GB'}
                        $FinalRamCommittedGB = if (!$LatestRamCommittedGBEntry) {"0"} else {$LatestRamCommittedGBEntry.ToString() + 'GB'}
                        $FinalRamCachedGB = if (!$LatestRamCachedGBEntry) {"0"} else {$LatestRamCachedGBEntry.ToString() + 'GB'}
                        $FinalRamPagedPoolMB = if (!$LatestRamPagedPoolMBEntry) {"0"} else {$LatestRamPagedPoolMBEntry.ToString() + 'MB'}
                        $FinalRamNonPagedPoolMB = if (!$LatestRamNonPagedPoolMBEntry) {"0"} else {$LatestRamNonPagedPoolMBEntry.ToString() + 'MB'}
                        
                        [pscustomobject]@{
                            RAM_Utilization     = $FinalRamPct
                            Total               = $FinalRamTotalGB
                            InUse               = $FinalRamInUseGB
                            Available           = $FinalRamFreeGB
                            Committed           = $FinalRamCommittedGB
                            Cached              = $FinalRamCachedGB
                            #PagedPool           = $FinalRamPagedPoolMB
                            #NonPagedPool        = $FinalRamNonPagedPoolMB
                        } | Out-UDTableData -Property $RamTableProperties
                    }
    
                    $RamMonitorEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $RamLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($RamLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$RamLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                            
                            $ArrayOfRamPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPctEntries.Count -gt 0) {
                                $LatestRamPctEntry = $ArrayOfRamPctEntries[-1]
                            }
                        }
    
                        $FinalRamPct = if (!$LatestRamPctEntry) {"0"} else {$LatestRamPctEntry}
    
                        $FinalRamPct | Out-UDMonitorData
                    }
    
                    $RAMMonitorSplatParams = @{
                        Title                   = "Memory (RAM) Utilization %"
                        Type                    = "Line"
                        DataPointHistory        = 20
                        ChartBackgroundColor    = "#80FF6B63"
                        ChartBorderColor        = "#FFFF6B63"
                        AutoRefresh             = $True
                        RefreshInterval         = 5
                        Endpoint                = $RamMonitorEndpoint
                    }
                    New-UdMonitor @RAMMonitorSplatParams
                }
            }
    
            # Network Statistics
    
            if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces).Count -eq 1) {
                New-UDRow -Columns {
                    New-UDHeading -Text "Network Interface Info" -Size 4
                    New-UDColumn -Size 6 -Endpoint {
                        $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                        New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
                            #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces
    
                            #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                # being added/removed from the ArrayList, things break
                                #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                
                                # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                # Each PSCustomObject contains:
                                
                                #[pscustomobject]@{
                                #    Name                = $NetInt.Name
                                #    Description         = $NetInt.Description
                                #    TotalSentBytes      = $IPv4Stats.BytesSent
                                #    TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                #}
                                
                                $ArrayOfNetworkEntriesA = @(
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats
                                ) | Where-Object {$_ -ne $null}
                                if ($ArrayOfNetworkEntriesA.Count -gt 0) {
                                    $PreviousNetworkEntryA = $ArrayOfNetworkEntriesA[-2]
                                    $LatestNetworkEntryA = $ArrayOfNetworkEntriesA[-1]
                                }
                            }
    
                            #$PreviousSentBytesTotalA = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                            $PreviousSentBytesTotalA = $PreviousNetworkEntryA.TotalSentBytes
                            $NewSentBytesTotalA = $LatestNetworkEntryA.TotalSentBytes
                            $DifferenceSentBytesA = $NewSentBytesTotalA - $PreviousSentBytesTotalA
                            if ($DifferenceSentBytesA -le 0) {
                                $FinalKBSentA = 0
                            }
                            else {
                                $FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2).ToString() + 'KB'
                            }
                            #$FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2).ToString() + 'KB'
    
                            #$PreviousReceivedBytesTotalA = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                            $PreviousReceivedBytesTotalA = $PreviousNetworkEntryA.TotalReceivedBytes
                            $NewReceivedBytesTotalA = $LatestNetworkEntryA.TotalReceivedBytes
                            $DifferenceReceivedBytesA = $NewReceivedBytesTotalA - $PreviousReceivedBytesTotalA
                            if ($DifferenceReceivedBytesA -le 0) {
                                $FinalKBReceivedA = 0
                            }
                            else {
                                $FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2).ToString() + 'KB'
                            }
                            #$FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2).ToString() + 'KB'
    
                            [pscustomobject]@{
                                Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Name
                                Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Description
                                Sent                        = [Math]::Round($($NewSentBytesTotalA / 1GB),2).ToString() + 'GB'
                                Received                    = [Math]::Round($($NewReceivedBytesTotalA / 1GB),2).ToString() + 'GB'
                                DeltaSent                   = $FinalKBSentA
                                DeltaReceived               = $FinalKBReceivedA
    
                            } | Out-UDTableData -Property $NetworkTableProperties
                        }
                        New-Variable -Name "NetworkMonitorEndpoint" -Force -Value $({
                            $PUDRSSyncHT = $global:PUDRSSyncHT
                            #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces
    
                            #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                # being added/removed from the ArrayList, things break
                                #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                
                                # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                # Each PSCustomObject contains:
                                <#
                                    [pscustomobject]@{
                                        Name                = $NetInt.Name
                                        Description         = $NetInt.Description
                                        TotalSentBytes      = $IPv4Stats.BytesSent
                                        TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                    }
                                #>
                                $ArrayOfNetworkEntries = @(
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats
                                ) | Where-Object {$_ -ne $null}
                                if ($ArrayOfNetworkEntries.Count -gt 0) {
                                    $PreviousNetworkEntry = $ArrayOfNetworkEntries[-2]
                                    $LatestNetworkEntry = $ArrayOfNetworkEntries[-1]
                                }
                            }
    
                            #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                            $PreviousSentBytesTotal = $PreviousNetworkEntry.TotalSentBytes
                            $NewSentBytesTotal = $LatestNetworkEntry.TotalSentBytes
                            $DifferenceSentBytes = $NewSentBytesTotal - $PreviousSentBytesTotal
                            if ($DifferenceSentBytes -le 0) {
                                $FinalKBSent = 0
                            }
                            else {
                                $FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2)
                            }
                            #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB)).ToString() + 'KB'
    
                            #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                            $PreviousReceivedBytesTotal = $PreviousNetworkEntry.TotalReceivedBytes
                            $NewReceivedBytesTotal = $LatestNetworkEntry.TotalReceivedBytes
                            $DifferenceReceivedBytes = $NewReceivedBytesTotal - $PreviousReceivedBytesTotal
                            if ($DifferenceReceivedBytes -le 0) {
                                $FinalKBReceived = 0
                            }
                            else {
                                $FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2)
                            }
                            #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB)).ToString() + 'KB'
    
                            # Update the SyncHash so we have a record of the previous total
                            #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
    
                            $FinalKBSent | Out-UDMonitorData
                        })
    
                        $NetworkMonitorSplatParams = @{
                            Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Name + '"' + ' Interface' + " Delta Sent KB"
                            Type                    = "Line"
                            DataPointHistory        = 20
                            ChartBackgroundColor    = "#80FF6B63"
                            ChartBorderColor        = "#FFFF6B63"
                            AutoRefresh             = $True
                            RefreshInterval         = 5
                            Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint" -ValueOnly)
                        }
                        New-UdMonitor @NetworkMonitorSplatParams
                    }
                    New-UDColumn -Endpoint {
                        $null = $Session:OverviewPageLoadingTracker.Add("FinishedLoading")
                    }
                }
            }
            else {
                New-UDRow -EndPoint {
                    New-UDHeading -Text "Network Interface Info" -Size 4
                }
                for ($i=0; $i -lt @($PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces).Count; $i = $i+2) {
                    New-UDRow -Columns {
                        New-UDColumn -Size 6 -Endpoint {
                            $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                            New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i]
    
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntries = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntries.Count -gt 0) {
                                        $PreviousNetworkEntry = $ArrayOfNetworkEntries[-2]
                                        $LatestNetworkEntry = $ArrayOfNetworkEntries[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotal = $PreviousNetworkEntry.TotalSentBytes
                                $NewSentBytesTotal = $LatestNetworkEntry.TotalSentBytes
                                $DifferenceSentBytes = $NewSentBytesTotal - $PreviousSentBytesTotal
                                if ($DifferenceSentBytes -le 0) {
                                    $FinalKBSent = 0
                                }
                                else {
                                    $FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotal = $PreviousNetworkEntry.TotalReceivedBytes
                                $NewReceivedBytesTotal = $LatestNetworkEntry.TotalReceivedBytes
                                $DifferenceReceivedBytes = $NewReceivedBytesTotal - $PreviousReceivedBytesTotal
                                if ($DifferenceReceivedBytes -le 0) {
                                    $FinalKBReceived = 0
                                }
                                else {
                                    $FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                [pscustomobject]@{
                                    Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                    Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Description
                                    Sent                        = [Math]::Round($($NewSentBytesTotal / 1GB),2).ToString() + 'GB'
                                    Received                    = [Math]::Round($($NewReceivedBytesTotal / 1GB),2).ToString() + 'GB'
                                    DeltaSent                   = $FinalKBSent
                                    DeltaReceived               = $FinalKBReceived
                                } | Out-UDTableData -Property $NetworkTableProperties
                            }
    
                            New-Variable -Name "NetworkMonitorEndpoint$i" -Force -Value $({
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i]
            
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesA = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesA.Count -gt 0) {
                                        $PreviousNetworkEntryA = $ArrayOfNetworkEntriesA[-2]
                                        $LatestNetworkEntryA = $ArrayOfNetworkEntriesA[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalA = $PreviousNetworkEntryA.TotalSentBytes
                                $NewSentBytesTotalA = $LatestNetworkEntryA.TotalSentBytes
                                $DifferenceSentBytesA = $NewSentBytesTotalA - $PreviousSentBytesTotalA
                                if ($DifferenceSentBytesA -le 0) {
                                    $FinalKBSentA = 0
                                }
                                else {
                                    $FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2)
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalA = $PreviousNetworkEntryA.TotalReceivedBytes
                                $NewReceivedBytesTotalA = $LatestNetworkEntryA.TotalReceivedBytes
                                $DifferenceReceivedBytesA = $NewReceivedBytesTotalA - $PreviousReceivedBytesTotalA
                                if ($DifferenceReceivedBytesA -le 0) {
                                    $FinalKBReceivedA = 0
                                }
                                else {
                                    $FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2)
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                # Update the SyncHash so we have a record of the previous total
                                #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
            
                                $FinalKBSentA | Out-UDMonitorData
                            })
            
                            $NetworkMonitorSplatParamsA = @{
                                Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name + '"' + ' Interface' + " Delta Sent KB"
                                Type                    = "Line"
                                DataPointHistory        = 20
                                ChartBackgroundColor    = "#80FF6B63"
                                ChartBorderColor        = "#FFFF6B63"
                                AutoRefresh             = $True
                                RefreshInterval         = 5
                                Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint$i" -ValueOnly)
                            }
                            New-UdMonitor @NetworkMonitorSplatParamsA
                        }
                        New-UDColumn -Size 6 -Endpoint {
                            $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                            New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)]
    
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesB = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesB.Count -gt 0) {
                                        $PreviousNetworkEntryB = $ArrayOfNetworkEntriesB[-2]
                                        $LatestNetworkEntryB = $ArrayOfNetworkEntriesB[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalB = $PreviousNetworkEntryB.TotalSentBytes
                                $NewSentBytesTotalB = $LatestNetworkEntryB.TotalSentBytes
                                $DifferenceSentBytesB = $NewSentBytesTotalB - $PreviousSentBytesTotalB
                                if ($DifferenceSentBytesB -le 0) {
                                    $FinalKBSentB = 0
                                }
                                else {
                                    $FinalKBSentB = [Math]::Round($($DifferenceSentBytesB / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalB = $PreviousNetworkEntryB.TotalReceivedBytes
                                $NewReceivedBytesTotalB = $LatestNetworkEntryB.TotalReceivedBytes
                                $DifferenceReceivedBytesB = $NewReceivedBytesTotalB - $PreviousReceivedBytesTotalB
                                if ($DifferenceReceivedBytesB -le 0) {
                                    $FinalKBReceivedB = 0
                                }
                                else {
                                    $FinalKBReceivedB = [Math]::Round($($DifferenceReceivedBytesB / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                [pscustomobject]@{
                                    Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                    Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Description
                                    Sent                        = [Math]::Round($($NewSentBytesTotalB / 1GB),2).ToString() + 'GB'
                                    Received                    = [Math]::Round($($NewReceivedBytesTotalB / 1GB),2).ToString() + 'GB'
                                    DeltaSent                   = $FinalKBSentB
                                    DeltaReceived               = $FinalKBReceivedB
                                } | Out-UDTableData -Property $NetworkTableProperties
                            }
    
                            New-Variable -Name "NetworkMonitorEndpoint$($i+1)" -Force -Value $({
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)]
            
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesC = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesC.Count -gt 0) {
                                        $PreviousNetworkEntryC = $ArrayOfNetworkEntriesC[-2]
                                        $LatestNetworkEntryC = $ArrayOfNetworkEntriesC[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalC = $PreviousNetworkEntryC.TotalSentBytes
                                $NewSentBytesTotalC = $LatestNetworkEntryC.TotalSentBytes
                                $DifferenceSentBytesC = $NewSentBytesTotalC - $PreviousSentBytesTotalC
                                if ($DifferenceSentBytesC -le 0) {
                                    $FinalKBSentC = 0
                                }
                                else {
                                    $FinalKBSentC = [Math]::Round($($DifferenceSentBytesC / 1KB),2)
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalC = $PreviousNetworkEntryC.TotalReceivedBytes
                                $NewReceivedBytesTotalC = $LatestNetworkEntryC.TotalReceivedBytes
                                $DifferenceReceivedBytesC = $NewReceivedBytesTotalC - $PreviousReceivedBytesTotalC
                                if ($DifferenceReceivedBytesC -le 0) {
                                    $FinalKBReceivedC = 0
                                }
                                else {
                                    $FinalKBReceivedC = [Math]::Round($($DifferenceReceivedBytesC / 1KB),2)
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                # Update the SyncHash so we have a record of the previous total
                                #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
            
                                $FinalKBSentC | Out-UDMonitorData
                            })
            
                            $NetworkMonitorSplatParamsC = @{
                                Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name + '"' + ' Interface' + " Delta Sent KB"
                                Type                    = "Line"
                                DataPointHistory        = 20
                                ChartBackgroundColor    = "#80FF6B63"
                                ChartBorderColor        = "#FFFF6B63"
                                AutoRefresh             = $True
                                RefreshInterval         = 5
                                Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint$($i+1)" -ValueOnly)
                            }
                            New-UdMonitor @NetworkMonitorSplatParamsC
                        }
                    }
                }
                New-UDColumn -Endpoint {
                    $null = $Session:OverviewPageLoadingTracker.Add("FinishedLoading")
                }
            }
    
            #endregion >> Monitors
        }
    }
    $Page = New-UDPage -Url "/Overview/:RemoteHost" -Endpoint $OverviewPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Overview Page
    
    #region >> PSRemoting Creds Page
    
    $PSRemotingCredsPageContent = {
        param($RemoteHost)
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        #$PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        #$ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else 
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:PSRemotingPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.PSRemotingPageLoadingTracker = $Session:HomePageLoadingTracker
            }
            New-UDHeading -Text "Set Credentials for $($RemoteHost.ToUpper())" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:PSRemotingPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Mandatory Local Admin or Domain Admin Credentials for PSRemoting
        New-UDRow -Columns {
            New-UDColumn -Size 12 -Content {
                $Cache:CredsForm = New-UDInput -SubmitText "Set Credentials" -Id "CredsForm" -Content {
                    New-UDInputField -Type textbox -Name 'Local_UserName'
                    New-UDInputField -Type password -Name 'Local_Password'
                    New-UDInputField -Type textbox -Name 'Domain_UserName'
                    New-UDInputField -Type password -Name 'Domain_Password'
                    New-UDInputField -Type textbox -Name 'Path_To_SSH_Public_Cert'
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingCredType' -Values @("Local","Domain") -DefaultValue "Domain"
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values @("WinRM","SSH") -DefaultValue "WinRM"
                } -Endpoint {
                    param(
                        [string]$Local_UserName,
                        [string]$Local_Password,
                        [string]$Domain_UserName,
                        [string]$Domain_Password,
                        [string]$Path_To_SSH_Public_Cert,
                        [string]$Preferred_PSRemotingCredType,
                        [string]$Preferred_PSRemotingMethod
                    )
    
                    # Add the SyncHash to the Page so that we can pass output to other pages
                    $PUDRSSyncHT = $global:PUDRSSyncHT
    
                    # Load PUDAdminCenter Module Functions Within ScriptBlock
                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                    if ($Session:CredentialHT.Keys -notcontains $RemoteHost) {
                        #New-UDInputAction -Toast "`$Session:CredentialHT is not defined!" -Duration 10000
                        $Session:CredentialHT = @{}
                        $RHostCredHT = @{
                            DomainCreds         = $null
                            LocalCreds          = $null
                            SSHCertPath         = $null
                            PSRemotingCredType  = $null
                            PSRemotingMethod    = $null
                            PSRemotingCreds     = $null
                        }
                        $Session:CredentialHT.Add($RemoteHost,$RHostCredHT)
    
                        # TODO: Need to remove this when finished testing
                        #$PUDRSSyncHT."$RemoteHost`Info".CredHT = $Session:CredentialHT
    
                        #New-UDInputAction -Toast "`$Session:CredentialHT was null" -Duration 10000
                    }
    
                    # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                    if (!$Local_UserName -and $Session:CredentialHT.$RemoteHost.LocalCreds -ne $null) {
                        $Local_UserName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                    }
                    if (!$Local_Password -and $Session:CredentialHT.$RemoteHost.LocalCreds -ne $null) {
                        $Local_Password = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                    }
                    if (!$Domain_UserName -and $Session:CredentialHT.$RemoteHost.DomainCreds -ne $null) {
                        $Domain_UserName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                    }
                    if (!$Domain_Password -and $Session:CredentialHT.$RemoteHost.DomainCreds -ne $null) {
                        $Domain_Password = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                    }
                    if (!$Path_To_SSH_Public_Cert -and $Session:CredentialHT.$RemoteHost.SSHCertPath -ne $null) {
                        $Path_To_SSH_Public_Cert = $Session:CredentialHT.$RemoteHost.SSHCertPath
                    }
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$RemoteHost.PSRemotingCredType -ne $null) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$RemoteHost.PSRemotingCredType
                    }
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$RemoteHost.PSRemotingMethod -ne $null) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$RemoteHost.PSRemotingMethod
                    }
    
                    if ($($PSBoundParameters.GetEnumerator()).Value -eq $null) {
                        New-UDInputAction -Toast "You MUST enter UserName/Password for either a Local User or Domain User with access to $RemoteHost!" -Duration 10000
                        #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        New-UDInputAction -Content $Cache:CredsForm
                        return
                    }
    
                    if ($Path_To_SSH_Public_Cert) {
                        if (!$(Test-Path $Path_To_SSH_Public_Cert)) {
                            New-UDInputAction -Toast "The path '$Path_To_SSH_Public_Cert' does not exist on $env:ComputerName!" -Duration 10000
                            #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                            New-UDInputAction -Content $Cache:CredsForm
                            return
                        }
                    }
    
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$RemoteHost.PSRemotingMethod) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$RemoteHost.PSRemotingMethod
                    }
                    if ($Preferred_PSRemotingMethod -eq "SSH" -and !$Path_To_SSH_Public_Cert) {
                        New-UDInputAction -Toast "You indicated that SSH is your Preferred_PSRemotingMethod, however, you did not provide a value for Path_To_SSH_Public_Cert!" -Duration 10000
                        #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        New-UDInputAction -Content $Cache:CredsForm
                        return
                    }
    
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$RemoteHost.PSRemotingCredType) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$RemoteHost.PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain" -and $(!$Domain_UserName -or !$Domain_Password)) {
                        New-UDInputAction -Toast "You indicated that 'Domain' was your Preferred_PSRemotingCredType, however, you did not provide Domain Credentials!" -Duration 10000
                        #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        New-UDInputAction -Content $Cache:CredsForm
                        return
                    }
    
                    if ($Preferred_PSRemotingCredType -eq "Local" -and $(!$Local_UserName -or !$Local_Password)) {
                        New-UDInputAction -Toast "You indicated that 'Local' was your Preferred_PSRemotingCredType, however, you did not provide Local Credentials!" -Duration 10000
                        #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        New-UDInputAction -Content $Cache:CredsForm
                        return
                    }
    
                    if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                    $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                    ) {
                        New-UDInputAction -Toast "Please enter both a UserName and a Password!" -Duration 10000
                        #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        New-UDInputAction -Content $Cache:CredsForm
                        return
                    }
    
                    if ($Local_UserName -and $Local_Password) {
                        # Make sure the $Local_UserName is in format $RemoteHost\$Local_UserName
                        if ($Local_UserName -notmatch "^$RemoteHost\\[a-zA-Z0-9]+$") {
                            $Local_UserName = "$RemoteHost\$Local_UserName"
                        }
    
                        $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                        $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                    }
    
                    if ($Domain_UserName -and $Domain_Password) {
                        $DomainShortName = $($PUDRSSyncHT."$RemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                        # Make sure the $Domain_UserName is in format $RemoteHost\$Domain_UserName
                        if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                            New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                            $Session:CredentialHT.$RemoteHost.DomainCreds = $null
                            #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                            New-UDInputAction -Content $Cache:CredsForm
                            return
                        }
    
                        $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                        $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                    }
    
                    # Test the Credentials
                    [System.Collections.ArrayList]$CredentialsToTest = @()
                    if ($LocalAdminCreds) {
                        $PSObj = [pscustomobject]@{CredType = "LocalUser"; PSCredential = $LocalAdminCreds}
                        $null = $CredentialsToTest.Add($PSObj)
                    }
                    if ($DomainAdminCreds) {
                        $PSObj = [pscustomobject]@{CredType = "DomainUser"; PSCredential = $DomainAdminCreds}
                        $null = $CredentialsToTest.Add($PSObj)
                    }
    
                    [System.Collections.ArrayList]$FailedCredentialsA = @()
                    foreach ($CredObj in $CredentialsToTest) {
                        try {
                            $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
            
                            if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                    #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            else {
                                $null = $FailedCredentialsA.Add($CredObj)
                            }
                        }
                        catch {
                            #New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                            #New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Refreshing page..." -Duration 10000
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                        }
                    }
    
                    if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                    $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                    ) {
                        # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                        $RPCPortOpen = $(TestPort -HostName $RemoteHost -Port 135).Open
    
                        [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            if ($RPCPortOpen) {
                                try {
                                    $null = EnableWinRMViaRPC -RemoteHostNameOrIP $RemoteHost -Credential $CredObj.PSCredential
                                    $null = $EnableWinRMSuccess.Add($CredObj)
                                    break
                                }
                                catch {
                                    #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                }
                            }
                        }
    
                        if ($EnableWinRMSuccess.Count -eq 0) {
                            New-UDInputAction -Toast "Unable to Enable WinRM on $RemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Duration 10000
                            #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                            New-UDInputAction -Content $Cache:CredsForm
                            return
                        }
                        else {
                            [System.Collections.ArrayList]$FailedCredentialsB = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                try {
                                    $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                    
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                        $null = $FailedCredentialsB.Add($CredObj)
                                    }
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                    New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Please try again." -Duration 10000
                                    #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                                    #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                    New-UDInputAction -Content $Cache:CredsForm
                                    return
                                }
                            }
                        }
                    }
    
                    if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                        if ($FailedCredentialsB.Count -gt 0) {
                            foreach ($CredObj in $FailedCredentialsB) {
                                New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                $Session:CredentialHT.$RemoteHost."$CredType`Creds" = $null
                            }
                            #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                            New-UDInputAction -Content $Cache:CredsForm
                            return
                        }
                        if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                            foreach ($CredObj in $FailedCredentialsA) {
                                New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                $Session:CredentialHT.$RemoteHost."$CredType`Creds" = $null
                            }
                            #$null = $Session:PSRemotingPageLoadingTracker.Add("DoneCheckingCredentials")
                            #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                            New-UDInputAction -Content $Cache:CredsForm
                            return
                        }
                    }
    
                    if ($DomainAdminCreds) {
                        $Session:CredentialHT.$RemoteHost.DomainCreds = $DomainAdminCreds
                    }
                    if ($LocalAdminCreds) {
                        $Session:CredentialHT.$RemoteHost.LocalCreds = $LocalAdminCreds
                    }
                    if ($Path_To_SSH_Public_Cert) {
                        $Session:CredentialHT.$RemoteHost.SSHCertPath = $Path_To_SSH_Public_Cert
                    }
                    if ($Preferred_PSRemotingCredType) {
                        $Session:CredentialHT.$RemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingMethod) {
                        $Session:CredentialHT.$RemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                    }
    
                    # Determine $PSRemotingCreds
                    if ($Preferred_PSRemotingCredType -eq "Local") {
                        $Session:CredentialHT.$RemoteHost.PSRemotingCreds = $Session:CredentialHT.$RemoteHost.LocalCreds
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain") {
                        $Session:CredentialHT.$RemoteHost.PSRemotingCreds = $Session:CredentialHT.$RemoteHost.DomainCreds
                    }
    
                    New-UDInputAction -RedirectUrl "/ToolSelect/$RemoteHost"
                }
                $Cache:CredsForm
    
                New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                    try {
                        $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                    }
                    catch {
                        Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                    }
                }
            }
        }
    }
    $Page = New-UDPage -Url "/PSRemotingCreds/:RemoteHost" -Endpoint $PSRemotingCredsPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> PSRemoting Creds Page
    
    #region >> Test Page
    
    $TestPageContent = {
        New-UDTable -Title "Users" -Headers @("Name", "Emails per Day") -Endpoint {
            Import-Module UniversalDashboard.Sparklines
            @(
                [PSCustomObject]@{"Name" = "Adam"; Values = @(12,12,4,2,75,23,54,12); Color = "#234254"}
                [PSCustomObject]@{"Name" = "Jon"; Values = @(2,42,33,21,11,3,32,9); Color = "#453423"}
                [PSCustomObject]@{"Name" = "Bill"; Values = @(1,92,40,21,7,3,2,12); Color = "#923923"}
                [PSCustomObject]@{"Name" = "Ted"; Values = @(112,11,41,2,5,63,74,12); Color = "#A43534"}
                [PSCustomObject]@{"Name" = "Tommy"; Values = @(12,2,42,21,18,26,26,19); Color = "#593493"}
            ) | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Sparkline = New-UDSparkline -Data $_.Values -Color $_.Color
                }
            } | Out-UDTableData -Property @("Name", "Sparkline")
        }
    }
    $Page = New-UDPage -Url "/Test" -Endpoint $TestPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Test Page
    
    #region >> Tool Select Page
    
    $ToolSelectPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, we can't use the $DisconnectedPageContent directly here. It needs to be a different object before it actually outputs
        # UD Elements. Not sure why.
        $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else 
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ToolSelectPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.ToolSelectPageLoadingTracker = $Session:ToolSelectPageLoadingTracker
            }
            #New-UDHeading -Text "Select a Tool" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:ToolSelectPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                #Write-Error "Session:CredentialHT.$RemoteHost.PSRemotingCreds is null"
            }
            else {
                # Check $Session:CredentialHT.$RemoteHost.PSRemotingCreds Credentials. If they don't work, redirect to "/PSRemotingCreds/$RemoteHost"
                try {
                    $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RHostIP -AltCredentials $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ErrorAction Stop
    
                    if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                            Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                            #Write-Error "GetWorkingCredentials A"
                        }
                    }
                    else {
                        Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                        #Write-Error "GetWorkingCredentials B"
                    }
                }
                catch {
                    Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                    #Write-Error $_
                }
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 5 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                <#
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Disconnected"
                                }
                                #>
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            #region >> Gather Some Initial Info From $RemoteHost
    
                            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                Invoke-Expression $using:GetServerInventoryFunc
    
                                [pscustomobject]@{ServerInventoryStatic = Get-ServerInventory}
                            }
                            $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
                            $PUDRSSyncHT."$RemoteHost`Info".ServerInventoryStatic = $Session:ServerInventoryStatic
    
                            #endregion >> Gather Some Initial Info From $RemoteHost
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                            }
                            
                            if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.Count -eq 0) {
                                if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            elseif (@($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                if (@($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            else {
                                $CredSSPStatus = "NotYetDetermined"
                            }
                            $TableData.Add("CredSSP",$CredSSPStatus)
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","CredSSP","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected to $RemoteHost
    
            #region >> Create the Tool Select Content
            
            if ($ConnectionStatus -eq "Connected") {
                [System.Collections.ArrayList]$DynPageRows = @()
                $RelevantDynamicPages = $DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"}
                $ItemsPerRow = 3
                $NumberOfRows = $DynamicPages.Count / $ItemsPerRow
                for ($i=0; $i -lt $NumberOfRows; $i++) {
                    New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force
    
                    if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
                    $jLoopLimit = $j + $($ItemsPerRow - 1)
                    while ($j -le $jLoopLimit) {
                        $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($RelevantDynamicPages[$j])
                        $j++
                    }
    
                    $null = $DynPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
                }
    
                foreach ($DynPageRow in $DynPageRows) {
                    New-UDRow -Endpoint {
                        foreach ($DynPage in $DynPageRow) {
                            # Make sure we're connected before loadting the UDCards
                            $DynPageNoSpace = $DynPage -replace "[\s]",""
                            $CardId = $DynPageNoSpace + "Card"
                            New-UDColumn -Size 4 -Endpoint {
                                if ($DynPage -ne $null) {
                                    $Links = @(New-UDLink -Text $DynPage -Url "/$DynPageNoSpace/$RemoteHost" -Icon dashboard)
                                    New-UDCard -Title $DynPage -Id $CardId -Text "$DynPage Info" -Links $Links
                                }
                            }
                        }
                    }
                }
    
                $null = $Session:ToolSelectPageLoadingTracker.Add("FinishedLoading")
            }
    
            #endregion >> Create the Tool Select Content
        }
    }
    $Page = New-UDPage -Url "/ToolSelect/:RemoteHost" -Endpoint $ToolSelectPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Tool Select Page
    

    #endregion >> Dynamic Pages


    #region >> Static Pages

    #region >> Create Home Page
    
    $HomePageContent = {
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Cache:RHostRefreshAlreadyRan = $False
                $Session:HomePageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.HomePageLoadingTracker = $Session:HomePageLoadingTracker
            }
            New-UDHeading -Text "Remote Hosts" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:HomePageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        #region >> HomePage Main Content
    
        $RHostUDTableEndpoint = {
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            $RHost = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RHostName}
    
            $RHostTableData = @{}
            $RHostTableData.Add("HostName",$RHost.HostName.ToUpper())
            $RHostTableData.Add("FQDN",$RHost.FQDN)
            $IPAddressListAsString = @($RHost.IPAddressList) -join ", "
            $RHostTableData.Add("IPAddress",$IPAddressListAsString)
    
            # Check Ping
            try {
                $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                    $RHost.IPAddressList[0],1000
                ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                $RHostTableData.Add("PingStatus",$PingStatus)
            }
            catch {
                $RHostTableData.Add("PingStatus","Unavailable")
            }
    
            # Check WSMan Ports
            try {
                $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                foreach ($WSManUrl in $WSManUrls) {
                    $Request = [System.Net.WebRequest]::Create($WSManUrl)
                    $Request.Timeout = 1000
                    try {
                        [System.Net.WebResponse]$Response = $Request.GetResponse()
                    }
                    catch {
                        if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                            if ($WSManUrl -match "5985") {
                                $WSMan5985Available = $True
                            }
                            else {
                                $WSMan5986Available = $True
                            }
                        }
                        elseif ($_.Exception.Message -match "The operation has timed out") {
                            if ($WSManUrl -match "5985") {
                                $WSMan5985Available = $False
                            }
                            else {
                                $WSMan5986Available = $False
                            }
                        }
                        else {
                            if ($WSManUrl -match "5985") {
                                $WSMan5985Available = $False
                            }
                            else {
                                $WSMan5986Available = $False
                            }
                        }
                    }
                }
    
                if ($WSMan5985Available -or $WSMan5986Available) {
                    $RHostTableData.Add("WSMan","Available")
    
                    [System.Collections.ArrayList]$WSManPorts = @()
                    if ($WSMan5985Available) {
                        $null = $WSManPorts.Add("5985")
                    }
                    if ($WSMan5986Available) {
                        $null = $WSManPorts.Add("5986")
                    }
    
                    $WSManPortsString = $WSManPorts -join ', '
                    $RHostTableData.Add("WSManPorts",$WSManPortsString)
                }
            }
            catch {
                $RHostTableData.Add("WSMan","Unavailable")
            }
    
            # Check SSH
            try {
                $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                if ($TestSSHResult.Open) {
                    $RHostTableData.Add("SSH","Available")
                }
                else {
                    $RHostTableData.Add("SSH","Unavailable")
                }
            }
            catch {
                $RHostTableData.Add("SSH","Unavailable")
            }
    
            $RHostTableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
            if ($RHostTableData.WSMan -eq "Available" -or $RHostTableData.SSH -eq "Available") {
                # We are within an -Endpoint, so $Session: variables should be available
                #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
                if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                    $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                }
                else {
                    $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                }
            }
            else {
                $RHostTableData.Add("ManageLink","Unavailable")
            }
    
            $RHostTableData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))
            
            [pscustomobject]$RHostTableData | Out-UDTableData -Property @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
        }
        $RHostUDTableEndpointAsString = $RHostUDTableEndpoint.ToString()
    
        $RHostCounter = 0
        #$Session:CredentialHT = @{}
        foreach ($RHost in $PUDRSSyncHT.RemoteHostList) {
            $RHostUDTableEndpoint = [scriptblock]::Create(
                $(
                    "`$RHostName = '$($RHost.HostName)'" + "`n" +
                    $RHostUDTableEndpointAsString
                )
            )
    
            $ResultProperties = @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
            $RHostUDTableSplatParams = @{
                Headers         = $ResultProperties
                AutoRefresh     = $True 
                RefreshInterval = 5
                Endpoint        = $RHostUDTableEndpoint
            }
            New-UDTable @RHostUDTableSplatParams
    
            <#
            # We only want to do this once per Session
            if (!$Session:CredHTCreated) {
                $RHostCredHT = @{
                    DomainCreds         = $null
                    LocalCreds          = $null
                    SSHCertPath         = $null
                    PSRemotingCredType  = $null
                    PSRemotingMethod    = $null
                    PSRemotingCreds     = $null
                }
                $Session:CredentialHT.Add($RHost.HostName,$RHostCredHT)
            }
            #>
    
            # TODO: Comment this out after you're done testing. It's a security vulnerability otherwise...
            #$PUDRSSyncHT."$($RHost.HostName)`Info".CredHT = $Session:CredentialHT
    
            $RHostCounter++
    
            if ($RHostCounter -ge $($PUDRSSyncHT.RemoteHostList.Count-1)) {
                #$HomePageTrackingEPSB = [scriptblock]::Create("`$null = `$Session:HomePageLoadingTracker.Add('$($RHost.HostName)')")
                New-UDColumn -Endpoint {
                    $null = $Session:HomePageLoadingTracker.Add("FinishedLoading")
                    #$Session:CredHTCreated = $True
                }
            }
        }
    
        New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            if ($Cache:HomeFinishedLoading -and !$Cache:RHostRefreshAlreadyRan) {
                # Get all Computers in Active Directory without the ActiveDirectory Module
                [System.Collections.ArrayList]$RemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
                if ($PSVersionTable.PSEdition -eq "Core") {
                    [System.Collections.ArrayList]$RemoteHostListPrep = $RemoteHostListPrep | foreach {$_ -replace "CN=",""}
                }
    
                # Filter Out the Remote Hosts that we can't resolve
                [System.Collections.ArrayList]$RemoteHostList = @()
    
                $null = Clear-DnsClientCache
                foreach ($HName in $RemoteHostListPrep) {
                    try {
                        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop
    
                        $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                    }
                    catch {
                        continue
                    }
                }
                $PUDRSSyncHT.RemoteHostList = $RemoteHostList
    
                $Cache:RHostRefreshAlreadyRan = $True
            }
        }
    
        #endregion >> HomePage Main Content
    }
    # IMPORTANT NOTE: Anytime New-UDPage is used with parameter set '-Name -Content', it appears in the hamburger menu
    # This is REQUIRED for the HomePage, otherwise http://localhost won't load (in otherwords, you can't use the
    # parameter set '-Url -Endpoint' for the HomePage).
    # Also, it is important that the HomePage comes first in the $Pages ArrayList
    $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
    $null = $Pages.Insert(0,$HomePage)
    
    #endregion >> Create Home Page
    

    #endregion >> Static Pages
    
    # Finalize the Site
    $Theme = New-UDTheme -Name "DefaultEx" -Parent Default -Definition @{
        UDDashboard = @{
            BackgroundColor = "rgb(255,255,255)"
        }
    }
    $MyDashboard = New-UDDashboard -Title "PUD Admin Center" -Pages $Pages -Theme $Theme

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}


<#
    
    .SYNOPSIS
        Gets a computer's remote desktop settings.
    
    .DESCRIPTION
        Gets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RemoteDesktop {
    function Get-DenyTSConnectionsValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.fDenyTSConnections
            return $keyValue -ne 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' was not found."
    }
    
    function Get-UserAuthenticationValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
        $exists = Get-ItemProperty -Path $key -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.UserAuthentication
            return $keyValue -eq 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' was not found."
    }
    
    function Get-RemoteAppSetting {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.EnableRemoteApp
            return $keyValue -eq 1
    
        } else {
            return $false;
        }
    }
    
    $denyValue = Get-DenyTSConnectionsValue;
    $nla = Get-UserAuthenticationValue;
    $remoteApp = Get-RemoteAppSetting;
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktop" $denyValue;
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktopWithNLA" $nla;
    $result | Add-Member -MemberType NoteProperty -Name "enableRemoteApp" $remoteApp;
    $result
}


<#
    .SYNOPSIS
        Retrieves the inventory data for a server.
    
    .DESCRIPTION
        Retrieves the inventory data for a server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ServerInventory {
    Set-StrictMode -Version 5.0
    
    import-module CimCmdlets
    
    <#
        .SYNOPSIS
        Converts an arbitrary version string into just 'Major.Minor'
        
        .DESCRIPTION
        To make OS version comparisons we only want to compare the major and 
        minor version.  Build number and/os CSD are not interesting.
    #>
    function convertOsVersion([string] $osVersion) {
        try {
            $version = New-Object Version $osVersion -ErrorAction Stop
    
            if ($version -and $version.Major -ne -1 -and $version.Minor -ne -1) {
                $versionString = "{0}.{1}" -f $version.Major, $version.Minor
    
                return New-Object Version $versionString
            }
        }
        catch {
            # The version string is not in the correct format
            return $null
        }
    }
    
    <#
        .SYNOPSIS
        Determines if CredSSP is enabled for the current server or client.
        
        .DESCRIPTION
        Check the registry value for the CredSSP enabled state.
    #>
    function isCredSSPEnabled() {
        $CredSsp = Get-Item WSMan:\localhost\Service\Auth\CredSSP -ErrorAction SilentlyContinue
        if ($CredSSp) {
            return [System.Convert]::ToBoolean($CredSsp.Value)
        }
    
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V role is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V role is installed when the VMMS service is available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVRoleInstalled() {
        $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue
    
        return $vmmsService -and $vmmsService.Name -eq "VMMS"
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V PowerShell support module is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVPowerShellSupportInstalled() {
        # quicker way to find the module existence. it doesn't load the module.
        return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
    }
    
    <#
        .SYNOPSIS
        Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.
        
        .DESCRIPTION
        Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
        Windows Server 2016.
    #>
    function isWMF5Installed([string] $operatingSystemVersion) {
        Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
        Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')
    
        $version = convertOsVersion $operatingSystemVersion
        if ($version -eq $null) {
            return $false        # Since the OS version string is not properly formatted we cannot know the true installed state.
        }
        
        if ($version -ge $Server2016) {
            # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
            return $true
        } else {
            if ($version -ge $Server2012) {
                # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
                $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
                $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue
        
                if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
                    $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion
        
                    if ($installedWmfVersion -ge [Version]'5.0') {
                        return $true
                    }
                }
            }
        }
        
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the current usser is a system administrator of the current server or client.
        
        .DESCRIPTION
        Determines if the current usser is a system administrator of the current server or client.
    #>
    function isUserAnAdministrator() {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
    
    <#
        .SYNOPSIS
        Determines if the current server supports Failover Clusters Time Series Database.
        
        .DESCRIPTION
        Use the existance of the cluster cmdlet Get-ClusterPerformanceHistory to determine if TSDB 
        is supported or not.
    #>
    function getClusterPerformanceHistoryCmdLet($failoverClusters) {
        return $failoverClusters.ExportedCommands.ContainsKey("Get-ClusterPerformanceHistory")
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the Failover Cluster that is running on this server.
        
        .DESCRIPTION
        Create a basic inventory of the Failover Cluster that may be running in this server.
    #>
    function getClusterInformation() {
        # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
        Import-Module FailoverClusters -ErrorAction SilentlyContinue
    
        $returnValues = @{}
    
        $returnValues.IsTsdbEnabled = $false
        $returnValues.IsCluster = $false
        $returnValues.ClusterFqdn = $null
    
        $failoverClusters = Get-Module FailoverClusters -ErrorAction SilentlyContinue
        if ($failoverClusters) {
            $returnValues.IsTsdbEnabled = getClusterPerformanceHistoryCmdLet $failoverClusters
        }
    
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            $cluster = Get-CimInstance -Namespace root/MSCluster -Query "Select fqdn from MSCluster_Cluster" -ErrorAction SilentlyContinue
            if ($cluster) {
                $returnValues.IsCluster = $true
                $returnValues.ClusterFqdn = $cluster.fqdn
            }
        }
        
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
    #>
    function getComputerFqdn($computerName) {
        return ([System.Net.Dns]::GetHostEntry($computerName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
    #>
    function getHostFqdn($computerSystem) {
        $computerName = $computerSystem.DNSHostName
        if ($computerName -eq $null) {
            $computerName = $computerSystem.Name
        }
    
        return getComputerFqdn $computerName
    }
    
    <#
        .SYNOPSIS
        Are the needed management CIM interfaces available on the current server or client.
        
        .DESCRIPTION
        Check for the presence of the required server management CIM interfaces.
    #>
    function getManagementToolsSupportInformation() {
        $returnValues = @{}
    
        $returnValues.ManagementToolsAvailable = $false
        $returnValues.ServerManagerAvailable = $false
    
        $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    
        if ($namespaces) {
            $returnValues.ManagementToolsAvailable = ($namespaces | Where-Object { $_.Name -ieq "ManagementTools" }) -ne $null
            $returnValues.ServerManagerAvailable = ($namespaces | Where-Object { $_.Name -ieq "ServerManager" }) -ne $null
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    function isRemoteAppEnabled() {
        Set-Variable key -Option Constant -Value "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        Set-Variable enableRemoteAppPropertyName -Option Constant -Value "EnableRemoteApp"
    
        $registryKeyValue = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        
        return $registryKeyValue -and ($registryKeyValue.PSObject.Properties.Name -match $enableRemoteAppPropertyName)
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    
    <#
        .SYNOPSIS
        Get the Win32_OperatingSystem information
        
        .DESCRIPTION
        Get the Win32_OperatingSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getOperatingSystemInfo() {
        return Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType
    }
    
    <#
        .SYNOPSIS
        Get the Win32_ComputerSystem information
        
        .DESCRIPTION
        Get the Win32_ComputerSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getComputerSystemInfo() {
        return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $operatingSystem = getOperatingSystemInfo
    $computerSystem = getComputerSystemInfo
    $isAdministrator = isUserAnAdministrator
    $fqdn = getHostFqdn $computerSystem
    $managementToolsInformation = getManagementToolsSupportInformation
    $isWmfInstalled = isWMF5Installed $operatingSystem.Version
    $clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
    $isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
    $isHyperVRoleInstalled = isHyperVRoleInstalled
    $isCredSSPEnabled = isCredSSPEnabled
    $isRemoteAppEnabled = isRemoteAppEnabled
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
    $result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
    $result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
    $result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInformation.IsTsdbEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'isRemoteAppEnabled' -Value $isRemoteAppEnabled
    
    $result
    
}


<#
    
    .SYNOPSIS
        Creates a new environment variable specified by name, type and data.
    
    .DESCRIPTION
        Creates a new environment variable specified by name, type and data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        return [Environment]::SetEnvironmentVariable($name, $value, $type)
    }
    Else {
        Write-Error "An environment variable of this name and type already exists."
    }
}


<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ScriptBeingRun -Value $ScriptBlock
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            Invoke-Expression -Command $ScriptBlock.ToString() -OutVariable Result
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}


<#
    .SYNOPSIS
        Removes an environment variable specified by name and type.
    
    .DESCRIPTION
        Removes an environment variable specified by name and type.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        Write-Error "An environment variable of this name and type does not exist."
    }
    Else {
        [Environment]::SetEnvironmentVariable($name, $null, $type)
    }
}


<#
    
    .SYNOPSIS
        Sets a computer and/or its domain/workgroup information.
    
    .DESCRIPTION
        Sets a computer and/or its domain/workgroup information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ComputerIdentification {
    param(
        [Parameter(Mandatory = $False)]
        [string]
        $ComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Domain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewDomain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Workgroup = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Password = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserNameNew = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $PasswordNew = '',
    
        [Parameter(Mandatory = $False)]
        [switch]
        $Restart)
    
    function CreateDomainCred($username, $password) {
        $secureString = ConvertTo-SecureString $password -AsPlainText -Force
        $domainCreds = New-Object System.Management.Automation.PSCredential($username, $secureString)
    
        return $domainCreds
    }
    
    function UnjoinDomain($domain) {
        If ($domain) {
            $unjoinCreds = CreateDomainCred $UserName $Password
            Remove-Computer -UnjoinDomainCredential $unjoinCreds -PassThru -Force
        }
    }
    
    If ($NewDomain) {
        $newDomainCreds = $null
        If ($Domain) {
            UnjoinDomain $Domain
            $newDomainCreds = CreateDomainCred $UserNameNew $PasswordNew
        }
        else {
            $newDomainCreds = CreateDomainCred $UserName $Password
        }
    
        If ($NewComputerName) {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($Workgroup) {
        UnjoinDomain $Domain
    
        If ($NewComputerName) {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($NewComputerName) {
        If ($Domain) {
            $domainCreds = CreateDomainCred $UserName $Password
            Rename-Computer -NewName $NewComputerName -DomainCredential $domainCreds -Force -PassThru -Restart:$Restart
        }
        Else {
            Rename-Computer -NewName $NewComputerName -Force -PassThru -Restart:$Restart
        }
    }
}


<#
    
    .SYNOPSIS
        Updates or renames an environment variable specified by name, type, data and previous data.
    
    .DESCRIPTION
        Updates or Renames an environment variable specified by name, type, data and previrous data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $oldName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $newName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    $nameChange = $false
    if ($newName -ne $oldName) {
        $nameChange = $true
    }
    
    If (-not [Environment]::GetEnvironmentVariable($oldName, $type)) {
        @{ Status = "currentMissing" }
        return
    }
    
    If ($nameChange -and [Environment]::GetEnvironmentVariable($newName, $type)) {
        @{ Status = "targetConflict" }
        return
    }
    
    If ($nameChange) {
        [Environment]::SetEnvironmentVariable($oldName, $null, $type)
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }
    Else {
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }    
}


<#
    
    .SYNOPSIS
        Sets a computer's remote desktop settings.
    
    .DESCRIPTION
        Sets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-RemoteDesktop {
    param(
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktop,
        
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktopWithNLA,
        
        [Parameter(Mandatory=$False)]
        [boolean]
        $EnableRemoteApp)
    
    Import-Module NetSecurity
    Import-Module Microsoft.PowerShell.Management
        
    $regKey1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $regKey2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
    $keyProperty1 = "fDenyTSConnections"
    $keyProperty2 = "UserAuthentication"
    $keyProperty3 = "EnableRemoteApp"
    
    $keyPropertyValue1 = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })
    $keyPropertyValue2 = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })
    $keyPropertyValue3 = $(if ($EnableRemoteApp -eq $True) { 1 } else { 0 })
    
    if (!(Test-Path $regKey1)) {
        New-Item -Path $regKey1 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey1 -Name $keyProperty1 -Value $keyPropertyValue1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $regKey1 -Name $keyProperty3 -Value $keyPropertyValue3 -PropertyType DWORD -Force | Out-Null
    
    if (!(Test-Path $regKey2)) {
        New-Item -Path $regKey2 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey2 -Name $keyProperty2 -Value $keyPropertyValue2 -PropertyType DWORD -Force | Out-Null
    
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}


<#
    
    .SYNOPSIS
        Start Disk Performance monitoring.
    
    .DESCRIPTION
        Start Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 3
    & diskperf -Y
}


<#
    
    .SYNOPSIS
        Stop Disk Performance monitoring.
    
    .DESCRIPTION
        Stop Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 1
    & diskperf -N
}



if (![bool]$(Get-Module UniversalDashboard.Community)) {
    try {
        Import-Module UniversalDashboard.Community -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match "\.Net Framework") {
            try {
                Write-Host "Installing .Net Framework 4.7.2 ... This will take a little while, and you will need to restart afterwards..."
                $InstallDotNet47Result = Install-Program -ProgramName dotnet4.7.2 -ErrorAction Stop
            }
            catch {
                Write-Error $_
                Write-Warning ".Net Framework 4.7.2 was NOT installed successfully."
                Write-Warning "The $ThisModule Module will NOT be loaded. Please run`n    Remove-Module $ThisModule"
                $global:FunctionResult = "1"
                return
            }

            Write-Warning ".Net Framework 4.7.2 was installed successfully, however *****you must restart $env:ComputerName***** before using the $ThisModule Module! Halting!"
            return
        }
        else {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:EnableWinRMViaRPC}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetWorkingCredentials}.Ast.Extent.Text
    ${Function:InstallFeatureDism}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:TestPort}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Get-CertificateOverview}.Ast.Extent.Text
    ${Function:Get-Certificates}.Ast.Extent.Text
    ${Function:Get-CimPnpEntity}.Ast.Extent.Text
    ${Function:Get-EnvironmentVariables}.Ast.Extent.Text
    ${Function:Get-EventLogSummary}.Ast.Extent.Text
    ${Function:Get-LocalUsers}.Ast.Extent.Text
    ${Function:Get-PUDAdminCenter}.Ast.Extent.Text
    ${Function:Get-RemoteDesktop}.Ast.Extent.Text
    ${Function:Get-ServerInventory}.Ast.Extent.Text
    ${Function:New-EnvironmentVariable}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:Remove-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-ComputerIdentification}.Ast.Extent.Text
    ${Function:Set-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-RemoteDesktop}.Ast.Extent.Text
    ${Function:Start-DiskPerf}.Ast.Extent.Text
    ${Function:Stop-DiskPerf}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU1p1jj/pR8Wqv/AZYcXLODIay
# 3/ygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFk/oRqAD6iuFIGl
# ZhrGNamK6+KOMA0GCSqGSIb3DQEBAQUABIIBAHosdR5xOggV2rohd6tmy1Ko+eAj
# Qxwt5zHk6bnWrH6XwGGP1nvnA9m7fKjE1SAjRVf0KNbVh2rgWmJEJXHolMhsdEqA
# fvp1eHXBvNMPEJEZuUFWT6L62pdGbXAq8cQHAFWQCyV1wbYjdVDuP9byYu7V3xtD
# 01kYv2XOPEzKWSbh6RB7fLtffx8qNh74cVipJpN5rRcWYWROLzvhZyUij2hsAmiv
# aoGkzxnLm49J1XTcniQC+DOWAhjKQMxnn9opXVuIx/RQwsQ5X+b92z7c1RoVLFRK
# LNA57VSeuGlAilG5pKobJ3ul3wVl4iRO1TH1oIkxOJr8HQzoCH4/0s7R+Ds=
# SIG # End signature block
