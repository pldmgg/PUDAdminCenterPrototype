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
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.
    
    .DESCRIPTION
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FirewallProfile {
    Import-Module netsecurity
    
    Get-NetFirewallProfile -PolicyStore ActiveStore | Microsoft.PowerShell.Utility\Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}


<#
    
    .SYNOPSIS
        Get Firewall Rules.
    
    .DESCRIPTION
        Get Firewall Rules.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FirewallRules {
    Import-Module netsecurity
    
    $sidToPrincipalCache = @{};
    
    function getPrincipalForSid($sid) {
    
        if ($sidToPrincipalCache.ContainsKey($sid)) {
        return $sidToPrincipalCache[$sid]
        }
    
        $propertyBag = @{}
        $propertyBag.userName = ""
        $propertyBag.domain = ""
        $propertyBag.principal = ""
        $propertyBag.ssid = $sid
    
        try{
            $win32Sid = [WMI]"root\cimv2:win32_sid.sid='$sid'";
        $propertyBag.userName = $win32Sid.AccountName;
        $propertyBag.domain = $win32Sid.ReferencedDomainName
    
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            try{
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            $propertyBag.principal = $objUser.Value;
            } catch [System.Management.Automation.MethodInvocationException]{
            # the sid couldn't be resolved
            }
    
        } catch [System.Management.Automation.MethodInvocationException]{
            # the sid is invalid
        }
    
        } catch [System.Management.Automation.RuntimeException] {
        # failed to get the user info, which is ok, maybe an old SID
        }
    
        $object = New-Object -TypeName PSObject -Prop $propertyBag
        $sidToPrincipalCache.Add($sid, $object)
    
        return $object
    }
    
    function fillUserPrincipalsFromSddl($sddl, $allowedPrincipals, $skippedPrincipals) {
        if ($sddl -eq $null -or $sddl.count -eq 0) {
        return;
        }
    
        $entries = $sddl.split(@("(", ")"));
        foreach ($entry in $entries) {
        $entryChunks = $entry.split(";");
        $sid = $entryChunks[$entryChunks.count - 1];
        if ($entryChunks[0] -eq "A") {
            $allowed = getPrincipalForSid($sid);
            $allowedPrincipals.Add($allowed) > $null;
        } elseif ($entryChunks[0] -eq "D") {
            $skipped = getPrincipalForSid($sid);
            $skippedPrincipals.Add($skipped) > $null;
        }
        }
    }
    
    $stores = @('PersistentStore','RSOP');
    $allRules = @()
    foreach ($store in $stores){
        $rules = (Get-NetFirewallRule -PolicyStore $store)
    
        $rulesHash = @{}
        $rules | foreach {
        $newRule = ($_ | Microsoft.PowerShell.Utility\Select-Object `
            instanceId, `
            name, `
            displayName, `
            description, `
            displayGroup, `
            group, `
            @{Name="enabled"; Expression={$_.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True}}, `
            profiles, `
            platform, `
            direction, `
            action, `
            edgeTraversalPolicy, `
            looseSourceMapping, `
            localOnlyMapping, `
            owner, `
            primaryStatus, `
            status, `
            enforcementStatus, `
            policyStoreSource, `
            policyStoreSourceType, `
            @{Name="policyStore"; Expression={$store}}, `
            @{Name="addressFilter"; Expression={""}}, `
            @{Name="applicationFilter"; Expression={""}}, `
            @{Name="interfaceFilter"; Expression={""}}, `
            @{Name="interfaceTypeFilter"; Expression={""}}, `
            @{Name="portFilter"; Expression={""}}, `
            @{Name="securityFilter"; Expression={""}}, `
            @{Name="serviceFilter"; Expression={""}})
    
            $rulesHash[$_.CreationClassName] = $newRule
            $allRules += $newRule  }
    
        $addressFilters = (Get-NetFirewallAddressFilter  -PolicyStore $store)
        $applicationFilters = (Get-NetFirewallApplicationFilter  -PolicyStore $store)
        $interfaceFilters = (Get-NetFirewallInterfaceFilter  -PolicyStore $store)
        $interfaceTypeFilters = (Get-NetFirewallInterfaceTypeFilter  -PolicyStore  $store)
        $portFilters = (Get-NetFirewallPortFilter  -PolicyStore $store)
        $securityFilters = (Get-NetFirewallSecurityFilter  -PolicyStore $store)
        $serviceFilters = (Get-NetFirewallServiceFilter  -PolicyStore $store)
    
        $addressFilters | ForEach-Object {
        $newAddressFilter = $_ | Microsoft.PowerShell.Utility\Select-Object localAddress, remoteAddress;
        $newAddressFilter.localAddress = @($newAddressFilter.localAddress)
        $newAddressFilter.remoteAddress = @($newAddressFilter.remoteAddress)
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.addressFilter = $newAddressFilter
        }
        }
    
        $applicationFilters | ForEach-Object {
        $newApplicationFilter = $_ | Microsoft.PowerShell.Utility\Select-Object program, package;
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.applicationFilter = $newApplicationFilter
        }
        }
    
        $interfaceFilters | ForEach-Object {
        $newInterfaceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceAlias"; Expression={}};
        $newInterfaceFilter.interfaceAlias = @($_.interfaceAlias);
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceFilter = $newInterfaceFilter
        }
        }
    
        $interfaceTypeFilters | foreach {
        $newInterfaceTypeFilter  = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceType"; Expression={}};
        $newInterfaceTypeFilter.interfaceType = $_.PSbase.CimInstanceProperties["InterfaceType"].Value;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceTypeFilter = $newInterfaceTypeFilter
        }
        }
    
        $portFilters | foreach {
        $newPortFilter = $_ | Microsoft.PowerShell.Utility\Select-Object dynamicTransport, icmpType, localPort, remotePort, protocol;
        $newPortFilter.localPort = @($newPortFilter.localPort);
        $newPortFilter.remotePort = @($newPortFilter.remotePort);
        $newPortFilter.icmpType = @($newPortFilter.icmpType);
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.portFilter = $newPortFilter
        }
        }
    
        $securityFilters | ForEach-Object {
        $allowedLocalUsers = New-Object System.Collections.ArrayList;
        $skippedLocalUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.localUser -allowedprincipals $allowedLocalUsers -skippedPrincipals $skippedLocalUsers;
    
        $allowedRemoteMachines = New-Object System.Collections.ArrayList;
        $skippedRemoteMachines = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteMachine -allowedprincipals $allowedRemoteMachines -skippedPrincipals $skippedRemoteMachines;
    
        $allowedRemoteUsers = New-Object System.Collections.ArrayList;
        $skippedRemoteUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteUser -allowedprincipals $allowedRemoteUsers -skippedPrincipals $skippedRemoteUsers;
    
        $newSecurityFilter = $_ | Microsoft.PowerShell.Utility\Select-Object authentication, `
        encryption, `
        overrideBlockRules, `
        @{Name="allowedLocalUsers"; Expression={}}, `
        @{Name="skippedLocalUsers"; Expression={}}, `
        @{Name="allowedRemoteMachines"; Expression={}}, `
        @{Name="skippedRemoteMachines"; Expression={}}, `
        @{Name="allowedRemoteUsers"; Expression={}}, `
        @{Name="skippedRemoteUsers"; Expression={}};
    
        $newSecurityFilter.allowedLocalUsers = $allowedLocalUsers.ToArray()
        $newSecurityFilter.skippedLocalUsers = $skippedLocalUsers.ToArray()
        $newSecurityFilter.allowedRemoteMachines = $allowedRemoteMachines.ToArray()
        $newSecurityFilter.skippedRemoteMachines = $skippedRemoteMachines.ToArray()
        $newSecurityFilter.allowedRemoteUsers = $allowedRemoteUsers.ToArray()
        $newSecurityFilter.skippedRemoteUsers = $skippedRemoteUsers.ToArray()
    
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.securityFilter = $newSecurityFilter
        }
        }
    
        $serviceFilters | ForEach-Object {
        $newServiceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object serviceName;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.serviceFilter = $newServiceFilter
        }
        }
    }
    
    $allRules
    
}


<#
    
    .SYNOPSIS
        Gets the local groups.
    
    .DESCRIPTION
        Gets the local groups. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalGroups {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup -SID $SID | Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID.Value
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True' AND SID='$SID'" | Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup | Microsoft.PowerShell.Utility\Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID.Value
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Description,Name,SID,ObjectClass | foreach {
                [pscustomobject]@{
                    Description         = $_.Description
                    Name                = $_.Name
                    SID                 = $_.SID
                    ObjectClass         = $_.ObjectClass
                    Members             = Get-LocalGroupUsers -group $_.Name
                }
            }
        }
    }    
}


<#
    
    .SYNOPSIS
        Get users belong to group.
    
    .DESCRIPTION
        Get users belong to group. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalGroupUsers {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $group
    )
    
    # ADSI does NOT support 2016 Nano, meanwhile Get-LocalGroupMember does NOT support downlevel and also has bug
    $ComputerName = $env:COMPUTERNAME
    try {
        $groupconnection = [ADSI]("WinNT://localhost/$group,group")
        $contents = $groupconnection.Members() | ForEach-Object {
            $path=$_.GetType().InvokeMember("ADsPath", "GetProperty", $NULL, $_, $NULL)
            # $path will looks like:
            #   WinNT://ComputerName/Administrator
            #   WinNT://DomainName/Domain Admins
            # Find out if this is a local or domain object and trim it accordingly
            if ($path -like "*/$ComputerName/*"){
                $start = 'WinNT://' + $ComputerName + '/'
            }
            else {
                $start = 'WinNT://'
            }
            $name = $path.Substring($start.length)
            $name.Replace('/', '\') #return name here
        }
        return $contents
    }
    catch { # if above block failed (say in 2016Nano), use another cmdlet
        # clear existing error info from try block
        $Error.Clear()
        #There is a known issue, in some situation Get-LocalGroupMember return: Failed to compare two elements in the array.
        $contents = Get-LocalGroupMember -group $group
        $names = $contents.Name | ForEach-Object {
            $name = $_
            if ($name -like "$ComputerName\*") {
                $name = $name.Substring($ComputerName.length+1)
            }
            $name
        }
        return $names
    }
    
}


<#
    
    .SYNOPSIS
        Get a local user belong to group list.
    
    .DESCRIPTION
        Get a local user belong to group list. The supported Operating Systems are
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
function Get-LocalUserBelongGroups {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $version = [version]$operatingSystem.Version
    # product type 3 is server, version number ge 10 is server 2016
    $isWinServer2016OrNewer = ($operatingSystem.ProductType -eq 3) -and ($version -ge '10.0')
    
    # ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
    
    # Step 1: get the list of local groups
    if ($isWinServer2016OrNewer) {
        $grps = net localgroup | Where-Object {$_ -AND $_ -match "^[*]"}  # group member list as "*%Fws\r\n"
        $groups = $grps.trim('*')
    }
    else {
        $grps = Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Name
        $groups = $grps.Name
    }
    
    # Step 2: in each group, list members and find match to target $UserName
    $groupNames = @()
    $regex = '^' + $UserName + '\b'
    foreach ($group in $groups) {
        $found = $false
        #find group members
        if ($isWinServer2016OrNewer) {
            $members = net localgroup $group | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Microsoft.PowerShell.Utility\Select-Object -skip 4
            if ($members -AND $members.contains($UserName)) {
                $found = $true
            }
        }
        else {
            $groupconnection = [ADSI]("WinNT://localhost/$group,group")
            $members = $groupconnection.Members()
            ForEach ($member in $members) {
                $name = $member.GetType().InvokeMember("Name", "GetProperty", $NULL, $member, $NULL)
                if ($name -AND ($name -match $regex)) {
                    $found = $true
                    break
                }
            }
        }
        #if members contains $UserName, add group name to list
        if ($found) {
            $groupNames = $groupNames + $group
        }
    }
    return $groupNames
    
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
            Get-LocalUser -SID $SID | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpires",
                "Description",
                "Enabled",
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "UserMayChangePassword"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpires
                    Description             = $_.Description
                    Enabled                 = $_.Enabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.UserMayChangePassword
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpirationDate",
                "Description",
                "Disabled"
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "PasswordChangeable"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpirationDate
                    Description             = $_.Description
                    Enabled                 = !$_.Disabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.PasswordChangeable
                }
            }
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpires",
                "Description",
                "Enabled",
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "UserMayChangePassword"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpires
                    Description             = $_.Description
                    Enabled                 = $_.Enabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.UserMayChangePassword
                }
            }
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object @(
                "AccountExpirationDate",
                "Description",
                "Disabled"
                "FullName",
                "LastLogon",
                "Name",
                "ObjectClass",
                "PasswordChangeableDate",
                "PasswordExpires",
                "PasswordLastSet",
                "PasswordRequired",
                "SID",
                "PasswordChangeable"
            ) | foreach {
                [pscustomobject]@{
                    AccountExpires          = $_.AccountExpirationDate
                    Description             = $_.Description
                    Enabled                 = !$_.Disabled
                    FullName                = $_.FullName
                    LastLogon               = $_.LastLogon
                    Name                    = $_.Name
                    GroupMembership         = Get-LocalUserBelongGroups -UserName $_.Name
                    ObjectClass             = $_.ObjectClass
                    PasswordChangeableDate  = $_.PasswordChangeableDate
                    PasswordExpires         = $_.PasswordExpires
                    PasswordLastSet         = $_.PasswordLastSet
                    PasswordRequired        = $_.PasswordRequired
                    SID                     = $_.SID.Value
                    UserMayChangePassword   = $_.PasswordChangeable
                }
            }
        }
    }    
}


<#
    .SYNOPSIS
        Gets the network ip configuration.
    
    .DESCRIPTION
        Gets the network ip configuration. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-Networks {
    Import-Module NetAdapter
    Import-Module NetTCPIP
    Import-Module DnsClient
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Get all net information
    $netAdapter = Get-NetAdapter
    
    # conditions used to select the proper ip address for that object modeled after ibiza method.
    # We only want manual (set by user manually), dhcp (set up automatically with dhcp), or link (set from link address)
    # fe80 is the prefix for link local addresses, so that is the format want if the suffix origin is link
    # SkipAsSource -eq zero only grabs ip addresses with skipassource set to false so we only get the preffered ip address
    $ipAddress = Get-NetIPAddress | Where-Object {
        ($_.SuffixOrigin -eq 'Manual') -or
        ($_.SuffixOrigin -eq 'Dhcp') -or 
        (($_.SuffixOrigin -eq 'Link') -and (($_.IPAddress.StartsWith('fe80:')) -or ($_.IPAddress.StartsWith('2001:'))))
    }
    
    $netIPInterface = Get-NetIPInterface
    $netRoute = Get-NetRoute -PolicyStore ActiveStore
    $dnsServer = Get-DnsClientServerAddress
    
    # Load in relevant net information by name
    Foreach ($currentNetAdapter in $netAdapter) {
        $result = New-Object PSObject
    
        # Net Adapter information
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceAlias' -Value $currentNetAdapter.InterfaceAlias
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceIndex' -Value $currentNetAdapter.InterfaceIndex
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceDescription' -Value $currentNetAdapter.InterfaceDescription
        $result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $currentNetAdapter.Status
        $result | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value $currentNetAdapter.MacAddress
        $result | Add-Member -MemberType NoteProperty -Name 'LinkSpeed' -Value $currentNetAdapter.LinkSpeed
    
        # Net IP Address information
        # Primary addresses are used for outgoing calls so SkipAsSource is false (0)
        # Should only return one if properly configured, but it is possible to set multiple, so collect all
        $primaryIPv6Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv6Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            $linkLocalArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv6Addresses) {
                if ($address -ne $null -and $address.IPAddress -ne $null -and $address.IPAddress.StartsWith('fe80')) {
                    $linkLocalArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
                else {
                    $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv6Address' -Value $ipArray
            $result | Add-Member -MemberType NoteProperty -Name 'LinkLocalIPv6Address' -Value $linkLocalArray
        }
    
        $primaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv4Address' -Value $ipArray
        }
    
        # Secondary addresses are not used for outgoing calls so SkipAsSource is true (1)
        # There will usually not be secondary addresses, but collect them just in case
        $secondaryIPv6Adresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv6Adresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv6Adresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv6Address' -Value $ipArray
        }
    
        $secondaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv4Address' -Value $ipArray
        }
    
        # Net IP Interface information
        $currentDhcpIPv4 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4')}
        if ($currentDhcpIPv4) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv4' -Value $currentDhcpIPv4.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $false
        }
    
        $currentDhcpIPv6 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6')}
        if ($currentDhcpIPv6) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv6' -Value $currentDhcpIPv6.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $false
        }
    
        # Net Route information
        # destination prefix for selected ipv6 address is always ::/0
        $currentIPv6DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '::/0')}
        if ($currentIPv6DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DefaultGateway' -Value $ipArray
        }
    
        # destination prefix for selected ipv4 address is always 0.0.0.0/0
        $currentIPv4DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '0.0.0.0/0')}
        if ($currentIPv4DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DefaultGateway' -Value $ipArray
        }
    
        # DNS information
        # dns server util code for ipv4 is 2
        $currentIPv4DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 2)}
        if ($currentIPv4DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DNSServer' -Value $ipArray
        }
    
        # dns server util code for ipv6 is 23
        $currentIPv6DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 23)}
        if ($currentIPv6DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DNSServer' -Value $ipArray
        }
    
        $adapterGuid = $currentNetAdapter.InterfaceGuid
        if ($adapterGuid) {
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapterGuid)"
          $ipv4Properties = Get-ItemProperty $regPath
          if ($ipv4Properties -and $ipv4Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $false
          }
    
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($adapterGuid)"
          $ipv6Properties = Get-ItemProperty $regPath
          if ($ipv6Properties -and $ipv6Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $false
          }
        }
    
        $result
    }
    
}


<#    
    .SYNOPSIS   
        Retrieves the updates waiting to be installed from WSUS
        
    .DESCRIPTION   
        Retrieves the updates waiting to be installed from WSUS
        
    .PARAMETER Computername 
        Computer or computers to find updates for.

    .EXAMPLE   
        Get-PendingUpdates 

        Description
        -----------
        Retrieves the updates that are available to install on the local system
    
    .NOTES
        Author: Boe Prox
#>
Function Get-PendingUpdates {
    [CmdletBinding(DefaultParameterSetName = 'computer')] 
    Param ( 
        [Parameter(ValueFromPipeline = $True)] 
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    Process {
        foreach ($computer in $Computername) {
            If (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                Try {
                    # Create Session COM object
                    Write-Verbose "Creating COM object for WSUS Session"
                    $updatesession =  [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$computer))
                }
                Catch {
                    Write-Warning "$($Error[0])"
                    Break
                } 
 
                # Configure Session COM Object
                Write-Verbose "Creating COM object for WSUS update Search"
                $updatesearcher = $updatesession.CreateUpdateSearcher()
 
                # Configure Searcher object to look for Updates awaiting installation
                Write-Verbose "Searching for WSUS updates on client"
                $searchresult = $updatesearcher.Search("IsInstalled=0")
             
                # Verify if Updates need installed
                Write-Verbose "Verifing that updates are available to install"
                If ($searchresult.Updates.Count -gt 0) {
                    # Updates are waiting to be installed
                    Write-Verbose "Found $($searchresult.Updates.Count) update\s!"
                    # Cache the count to make the For loop run faster
                    $count = $searchresult.Updates.Count
                 
                    # Begin iterating through Updates available for installation
                    Write-Verbose "Iterating through list of updates"
                    For ($i=0; $i -lt $Count; $i++) {
                        # Create object holding update
                        $Update = $searchresult.Updates.Item($i)
                        [pscustomobject]@{
                            Computername        = $Computer
                            Title               = $Update.Title
                            KB                  = $($Update.KBArticleIDs)
                            SecurityBulletin    = $($Update.SecurityBulletinIDs)
                            MsrcSeverity        = $Update.MsrcSeverity
                            IsDownloaded        = $Update.IsDownloaded
                            Url                 = $($Update.MoreInfoUrls)
                            Categories          = ($Update.Categories | Select-Object -ExpandProperty Name)
                            BundledUpdates      = @($Update.BundledUpdates) | foreach {
                               [pscustomobject]@{
                                    Title = $_.Title
                                    DownloadUrl = @($_.DownloadContents).DownloadUrl
                                }
                            }
                        } 
                    }
                } 
                Else { 
                    #Nothing to install at this time
                    Write-Verbose "No updates to install."
                }
            }
            Else {
                #Nothing to install at this time
                Write-Warning "$($c): Offline"
            }
        }
    }
}


<#
    
    .SYNOPSIS
        Gets information about the processes running in computer.
    
    .DESCRIPTION
        Gets information about the processes running in computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .COMPONENT
        ProcessList_Body
    
#>
function Get-Processes {
    param
    (
        [Parameter(Mandatory = $true)]
        [boolean]
        $isLocal
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $processes = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess
    
    $powershellProcessList = @{}
    $powerShellProcesses = Get-Process -ErrorAction SilentlyContinue
    
    foreach ($process in $powerShellProcesses) {
        $powershellProcessList.Add([int]$process.Id, $process)
    }
    
    if ($isLocal) {
        # critical processes taken from task manager code
        # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
        $criticalProcesses = (
            "$($env:windir)\system32\winlogon.exe",
            "$($env:windir)\system32\wininit.exe",
            "$($env:windir)\system32\csrss.exe",
            "$($env:windir)\system32\lsass.exe",
            "$($env:windir)\system32\smss.exe",
            "$($env:windir)\system32\services.exe",
            "$($env:windir)\system32\taskeng.exe",
            "$($env:windir)\system32\taskhost.exe",
            "$($env:windir)\system32\dwm.exe",
            "$($env:windir)\system32\conhost.exe",
            "$($env:windir)\system32\svchost.exe",
            "$($env:windir)\system32\sihost.exe",
            "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:windir)\explorer.exe"
        )
    
        $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
        $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"
    
        $edgeProcesses = (
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
            "$($env:windir)\system32\browser_broker.exe"
        )
    
        foreach ($process in $processes) {
    
            if ($powershellProcessList.ContainsKey([int]$process.ProcessId)) {
                $psProcess = $powershellProcessList.Get_Item([int]$process.ProcessId)
                $hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0
                $process | Add-Member -MemberType NoteProperty -Name "HasChildWindow" -Value $hasChildWindow
                if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $psProcess.MainModule.FileVersionInfo.FileDescription
                }
            }
    
            if ($edgeProcesses -contains $nativeProcess.executablePath) {
                # special handling for microsoft edge used by task manager
                # group all edge processes into applications
                $edgeLabel = 'Microsoft Edge'
                if ($process.fileDescription) {
                    $process.fileDescription = $edgeLabel
                }
                else {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $edgeLabel
                }
    
                $processType = 'application'
            }
            elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                    -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                # process is windows if its executable path is a critical process, defined by Task Manager
                # if the process has no executable path recorded, fallback to use the name to match to critical process
                $processType = 'windows'
            }
            elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                $processType = 'application'
            }
            else {
                $processType = 'background'
            }
    
            $process | Add-Member -MemberType NoteProperty -Name "ProcessType" -Value $processType
        }
    }
    
    $processes
    
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
            $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
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
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $StaticInfo.RootDirItem
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
    
            New-UDCollapsible -Items {
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
                                $FullPathToExplore = if ($($Session:RootDirItem.FullName | Split-Path -Parent) -eq "") {$Session:RootDirItem.FullName} else {$Session:RootDirItem.FullName | Split-Path -Parent}
    
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
    
    $FirewallPageContent = {
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
                $Session:FirewallPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:FirewallPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetFirewallProfileFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallProfile" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetFirewallRulesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallRules" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetFirewallProfileFunc,$GetFirewallRulesFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
                
                $FirewallSummary = Get-FirewallProfile -ErrorAction SilentlyContinue | foreach {
                    [pscustomobject]@{
                        Name                    = $_.Name
                        Status                  = if ($_.Enabled) {"Enabled"} else {"Disabled"}
                        DefaultInboundAction    = $_.DefaultInboundAction.ToString()
                        DefaultOutboundAction   = $_.DefaultOutboundAction.ToString()
                    }
                }
    
                $FirewallRulesPrep = Get-FirewallRules -ErrorAction SilentlyContinue
                $FirewallRules = foreach ($Rule in $FirewallRulesPrep) {
                    $Profiles = switch (@($Rule.profiles)) {
                        0 {"All"}
                        1 {"Domain"}
                        2 {"Private"}
                        3 {"Domain, Private"}
                        4 {"Public"}
                        5 {"Domain, Public"}
                        6 {"Private, Public"}
                    }
    
                    [pscustomobject]@{
                        DisplayName         = $Rule.DisplayName
                        Direction           = $Rule.Direction.ToString()
                        Action              = $Rule.Action.ToString()
                        DisplayGroup        = $Rule.DisplayGroup
                        Status              = if ($Rule.enabled) {"Enabled"} else {"Disabled"}
                        Profile             = $Profiles
                        Program             = @($Rule.applicationFilter.Program) -join ", "
                        Protocol            = @($Rule.portFilter.Protocol) -join ", "
                        LocalPort           = @($Rule.portFilter.LocalPort) -join ", "
                        RemotePort          = @($Rule.portFilter.RemotePort) -join ", "
                    }
                }
    
                [pscustomobject]@{
                    FirewallSummary     = $FirewallSummary
                    FirewallRules       = $FirewallRules
                }
            }
            $Session:FirewallSummaryStatic = $StaticInfo.FirewallSummary
            $Session:FirewallRulesStatic = $StaticInfo.FirewallRules
            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallSummary",$Session:FirewallSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallSummary = $Session:FirewallSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallRules") {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallRules",$Session:FirewallRulesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallRules = $Session:FirewallRulesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Firewall (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetFirewallFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Firewall" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetFirewallFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Firewall$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Firewall$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllFirewall = Get-Firewall}
                            }
    
                            # Operations that you want to run once every second go here
                            @{FirewallSummary = Get-FirewallOverview -channel "Microsoft-Windows-FirewallervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Firewall$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo equal to
                # $RSSyncHash."Firewall$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo = $RSSyncHash."Firewall$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $FirewallOverviewProperties = @("Name","Status","DefaultInboundAction","DefaultOutboundAction")
            $FirewallOverviewUDGridSplatParams = @{
                Id              = "FirewallOverviewUDGrid"
                Headers         = $FirewallOverviewProperties
                Properties      = $FirewallOverviewProperties
            }
            New-UDGrid @FirewallOverviewUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetFirewallProfileFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallProfile" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetFirewallProfileFunc
                    
                    $FirewallSummary = Get-FirewallProfile -ErrorAction SilentlyContinue | foreach {
                        [pscustomobject]@{
                            Name                    = $_.Name
                            Status                  = if ($_.Enabled) {"Enabled"} else {"Disabled"}
                            DefaultInboundAction    = $_.DefaultInboundAction.ToString()
                            DefaultOutboundAction   = $_.DefaultOutboundAction.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        FirewallSummary     = $FirewallSummary
                    }
                }
                $Session:FirewallSummaryStatic = $StaticInfo.FirewallSummary
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallSummary") {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallSummary",$Session:FirewallSummaryStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallSummary = $Session:FirewallSummaryStatic
                }
    
                $Session:FirewallSummaryStatic | Out-UDGridData
            }
    
            $FirewallRulesProperties = @("DisplayName","Direction","Action","DisplayGroup","Status","Profile","Program","Protocol","LocalPort","RemotePort")
            $FirewallRulesUDGridSplatParams = @{
                Id              = "FirewallRulesUDGrid"
                Headers         = $FirewallRulesProperties
                Properties      = $FirewallRulesProperties
            }
            New-UDGrid @FirewallRulesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetFirewallRulesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallRules" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetFirewallRulesFunc
                    
                    $FirewallRulesPrep = Get-FirewallRules -ErrorAction SilentlyContinue
    
                    $FirewallRules = foreach ($Rule in $FirewallRulesPrep) {
                        $Profiles = switch (@($Rule.profiles)) {
                            0 {"All"}
                            1 {"Domain"}
                            2 {"Private"}
                            3 {"Domain, Private"}
                            4 {"Public"}
                            5 {"Domain, Public"}
                            6 {"Private, Public"}
                        }
    
                        [pscustomobject]@{
                            DisplayName         = $Rule.DisplayName
                            Direction           = $Rule.Direction.ToString()
                            Action              = $Rule.Action.ToString()
                            DisplayGroup        = $Rule.DisplayGroup
                            Status              = if ($Rule.enabled) {"Enabled"} else {"Disabled"}
                            Profile             = $Profiles
                            Program             = @($Rule.applicationFilter.Program) -join ", "
                            Protocol            = @($Rule.portFilter.Protocol) -join ", "
                            LocalPort           = @($Rule.portFilter.LocalPort) -join ", "
                            RemotePort          = @($Rule.portFilter.RemotePort) -join ", "
                        }
                    }
    
                    [pscustomobject]@{
                        FirewallRules       = $FirewallRules
                    }
                }
                $Session:FirewallRulesStatic = $StaticInfo.FirewallRules
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallRules") {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallRules",$Session:FirewallRulesStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallRules = $Session:FirewallRulesStatic
                }
    
                $Session:FirewallRulesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:FirewallPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Firewall/:RemoteHost" -Endpoint $FirewallPageContent
    $null = $Pages.Add($Page)
    
    $NetworkPageContent = {
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
                $Session:NetworkPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:NetworkPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetNetworksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Networks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $TestIsValidIPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function TestIsValidIPAddress" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetNetworksFunc
                Invoke-Expression $using:TestIsValidIPFunc
                
                $Networks = Get-Networks | foreach {
                    $PrimaryIPv4AddressesUpdatedFormat = foreach ($ArrayObj in $_.PrimaryIPv4Address) {
                        foreach ($IPString in $ArrayObj) {
                            if (TestIsValidIPAddress -IPAddress $IPString) {
                                $IPString
                            }
                        }
                    }
                    $IPv4DNSServerAddressesUpdatedFormat = foreach ($ArrayObj in $_.IPv4DNSServer) {
                        foreach ($IPString in $ArrayObj) {
                            if (TestIsValidIPAddress -IPAddress $IPString) {
                                $IPString
                            }
                        }
                    }
    
                    [pscustomobject]@{
                        InterfaceAlias              = $_.InterfaceAlias
                        InterfaceIndex              = $_.InterfaceIndex
                        InterfaceDescription        = $_.InterfaceDescription
                        Status                      = $_.Status
                        MacAddress                  = $_.MacAddress
                        LinkSpeed                   = $_.LinkSpeed
                        PrimaryIPv6Address          = $_.PrimaryIPv6Address -join ", "
                        LinkLocalIPv6Address        = $_.LinkLocalIPv6Address -join ", "
                        PrimaryIPv4Address          = $PrimaryIPv4AddressesUpdatedFormat -join ", "
                        DhcpIPv4                    = if ($_.DhcpIPv4) {$_.DhcpIPv4.ToString()} else {$null}
                        IPv6Enabled                 = $_.IPv6Enabled.ToString()
                        IPv4DefaultGateway          = $_.IPv4DefaultGateway -join ", "
                        IPv4DNSServer               = $IPv4DNSServerAddressesUpdatedFormat -join ", "
                        IPv6DNSServer               = $_.IPv6DNSServer -join ", "
                        IPv4DnsManuallyConfigured   = $_.IPv4DnsManuallyConfigured.ToString()
                    }
                }
    
                [pscustomobject]@{
                    NetworksInfo    = $Networks
                }
            }
            $Session:NetworksInfoStatic = $StaticInfo.NetworksInfo
            if ($PUDRSSyncHT."$RemoteHost`Info".Network.Keys -notcontains "NetworksInfo") {
                $PUDRSSyncHT."$RemoteHost`Info".Network.Add("NetworksInfo",$Session:NetworksInfoStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Network.NetworksInfo = $Session:NetworksInfoStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Network (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetNetworkificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-NetworkificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetNetworkFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Network" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetNetworkificateOverviewFunc,$GetNetworkFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Network$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Network$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllNetworks = Get-Network}
                            }
    
                            # Operations that you want to run once every second go here
                            @{NetworkSummary = Get-NetworkificateOverview -channel "Microsoft-Windows-NetworkervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Network$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo equal to
                # $RSSyncHash."Network$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo = $RSSyncHash."Network$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $NetworksInfoProperties = @(
                "InterfaceAlias"
                "InterfaceIndex"
                "InterfaceDescription"
                "Status"
                "MacAddress"
                "LinkSpeed"
                "PrimaryIPv6Address"
                "LinkLocalIPv6Address"
                "PrimaryIPv4Address"
                "DhcpIPv4"
                "IPv6Enabled"
                "IPv4DefaultGateway"
                "IPv4DNSServer"
                "IPv6DNSServer"
                "IPv4DnsManuallyConfigured"
            )
            $AllNetworksUDGridSplatParams = @{
                Headers         = $NetworksInfoProperties
                Properties      = $NetworksInfoProperties
                NoPaging        = $True
            }
            New-UDGrid @AllNetworksUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetNetworksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Networks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $TestIsValidIPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function TestIsValidIPAddress" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetNetworksFunc
                    Invoke-Expression $using:TestIsValidIPFunc
                    
                    $Networks = Get-Networks | foreach {
                        $PrimaryIPv4AddressesUpdatedFormat = foreach ($ArrayObj in $_.PrimaryIPv4Address) {
                            foreach ($IPString in $ArrayObj) {
                                if (TestIsValidIPAddress -IPAddress $IPString) {
                                    $IPString
                                }
                            }
                        }
                        $IPv4DNSServerAddressesUpdatedFormat = foreach ($ArrayObj in $_.IPv4DNSServer) {
                            foreach ($IPString in $ArrayObj) {
                                if (TestIsValidIPAddress -IPAddress $IPString) {
                                    $IPString
                                }
                            }
                        }
    
                        [pscustomobject]@{
                            InterfaceAlias              = $_.InterfaceAlias
                            InterfaceIndex              = $_.InterfaceIndex
                            InterfaceDescription        = $_.InterfaceDescription
                            Status                      = $_.Status
                            MacAddress                  = $_.MacAddress
                            LinkSpeed                   = $_.LinkSpeed
                            PrimaryIPv6Address          = $_.PrimaryIPv6Address -join ", "
                            LinkLocalIPv6Address        = $_.LinkLocalIPv6Address -join ", "
                            PrimaryIPv4Address          = $PrimaryIPv4AddressesUpdatedFormat -join ", "
                            DhcpIPv4                    = if ($_.DhcpIPv4) {$_.DhcpIPv4.ToString()} else {$null}
                            IPv6Enabled                 = $_.IPv6Enabled.ToString()
                            IPv4DefaultGateway          = $_.IPv4DefaultGateway -join ", "
                            IPv4DNSServer               = $IPv4DNSServerAddressesUpdatedFormat -join ", "
                            IPv6DNSServer               = $_.IPv6DNSServer -join ", "
                            IPv4DnsManuallyConfigured   = $_.IPv4DnsManuallyConfigured.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        NetworksInfo    = $Networks
                    }
                }
                $Session:NetworksInfoStatic = $StaticInfo.NetworksInfo
                if ($PUDRSSyncHT."$RemoteHost`Info".Network.Keys -notcontains "NetworksInfo") {
                    $PUDRSSyncHT."$RemoteHost`Info".Network.Add("NetworksInfo",$Session:NetworksInfoStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Network.NetworksInfo = $Session:NetworksInfoStatic
                }
    
                $Session:NetworksInfoStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:NetworkPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Network/:RemoteHost" -Endpoint $NetworkPageContent
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
                            New-UDInput -SubmitText "Disable CredSSP" -Id "DisableCredSSPForm" -Content {
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
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "New Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameA" -Label "Name"
                                    New-UDTextbox -Id "EnvVarValueA" -Label "Value"
                                    New-UDSelect -Id "EnvVarTypeA" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
                                    
                                    New-UDButton -Text "New" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameA"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValueA"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeA"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        <#
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvVarInfo",@{})
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarTypeObject",$EnvVarTypeSelection)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarName",$EnvVarName)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarNewName",$EnvVarNewName)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarValue",$EnvVarValue)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarType",$EnvVarType)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("RemoteHost",$RemoteHost)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("CredsUserName",$($Session:CredentialHT.$RemoteHost.PSRemotingCreds.UserName))
                                        #>
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:NewEnvVarFunc
                                            New-EnvironmentVariable -name $using:EnvVarName -value $using:EnvVarValue -type $using:EnvVarType
                                        }
    
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
                                }
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "Edit Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameB" -Label "Name"
                                    New-UDTextbox -Id "EnvVarNewNameB" -Label "New Name"
                                    New-UDTextbox -Id "EnvVarValueB" -Label "Value"
                                    New-UDSelect -Id "EnvVarTypeB" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
    
                                    New-UDButton -Text "Edit" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameB"
                                        $EnvVarNewNameTextBox = Get-UDElement -Id "EnvVarNewNameB"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValueB"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeB"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarNewName = $EnvVarNewNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
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
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "Remove Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameC" -Label "Name"
                                    New-UDSelect -Id "EnvVarTypeC" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
    
                                    New-UDButton -Text "Remove" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameC"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeC"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        $RemoveEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Remove-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:RemoveEnvVarFunc
                                            Remove-EnvironmentVariable -name $using:EnvVarName -type $using:EnvVarType
                                        }
                                        
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
    
    $ProcessesPageContent = {
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
                $Session:ProcessesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ProcessesPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetProcessesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Processes" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetProcessesFunc
    
                # Returns an array of CimInstance Objects
                $AllProcesses = Get-Processes -isLocal $True
    
                [pscustomobject]@{
                    AllProcesses = $AllProcesses
                }
            }
            $Session:AllProcessesStatic = $StaticInfo.AllProcesses
            if ($PUDRSSyncHT."$RemoteHost`Info".Processes.Keys -notcontains "AllProcesses") {
                $PUDRSSyncHT."$RemoteHost`Info".Processes.Add("AllProcesses",$Session:AllProcessesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Processes.AllProcesses = $Session:AllProcessesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Processes (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetProcessesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Processes" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetProcessesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Processes$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Processes$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 5 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 5) -eq 0) {
                                @{AllProcesses = [pscustomobject]@{ProcessesCollection = Get-Processes -isLocal $True}}
                            }
    
                            # Operations that you want to run once every second go here
                            # @{AllProcesses = Get-Processes -isLocal $True}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Processes$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo equal to
                # $RSSyncHash."Processes$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo = $RSSyncHash."Processes$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            # Live Data Element Example
            # For ProcessStatus, 2 = Suspended, 1 = Running
            # WorkingSetSize is in KB
            $AllProcessesProperties = @("Name","ProcessId","ProcessStatus","CPUPercent","UserName","WorkingSetSize")
            $AllProcessesUDGridSplatParams = @{
                Headers                 = $AllProcessesProperties
                Properties              = $AllProcessesProperties
                DefaultSortColumn       = "CPUPercent"
                DefaultSortDescending   = $True
                AutoRefresh             = $True 
                RefreshInterval         = 5
                NoPaging                = $True
            }
            New-UDGrid @AllProcessesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllProcessesLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Count
                if ($AllProcessesLiveOutputCount -gt 0) {
                    $ArrayOfAllProcessesEntries = @(
                        $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous.AllProcesses
                    ) | Where-Object {$_ -ne $null}
                    if ($ArrayOfAllProcessesEntries.Count -gt 0) {
                        $AllProcessesGridData = $ArrayOfAllProcessesEntries[-1].ProcessesCollection | foreach {
                            [pscustomobject]@{
                                Name            = $_.Name
                                ProcessId       = $_.ProcessId
                                ProcessStatus   = if ($_.ProcessStatus -eq 2) {"Suspended"} else {"Running"}
                                CPUPercent      = [Math]::Round($_.CPUPercent,2).ToString() + '%'
                                UserName        = $_.UserName
                                WorkingSetSize  = [Math]::Round($($_.WorkingSetSize / 1KB),2).ToString() + 'KB'
                            }
                        } | Out-UDGridData
                    }
                }
                if (!$AllProcessesGridData) {
                    $AllProcessesGridData = [pscustomobject]@{
                        Name            = "Collecting Info"
                        ProcessId       = "Collecting Info"
                        ProcessStatus   = "Collecting Info"
                        CPUPercent      = "CollectingInfo"
                        UserName        = "Collecting Info"
                        WorkingSetSize  = "Collecting Info"
                    } | Out-UDGridData
                }
    
                $AllProcessesGridData
            }
    
            # Remove the Loading  Indicator
            $null = $Session:ProcessesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Processes/:RemoteHost" -Endpoint $ProcessesPageContent
    $null = $Pages.Add($Page)
    
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
                    New-UDInputField -Type textarea -Name 'SSH_Public_Cert'
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
    
    $RegistryPageContent = {
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
                $Session:RegistryPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:RegistryPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Clone()
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
            if (!$Session:HKLMChildKeys -or !$Session:HKCUChildKeys -or !$Session:HKCRChildKeys -or !$Session:HKUChildKeys -or !$Session:HKCCChildKeys) {
                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $null = Invoke-Expression $using:GetRegistrySubKeysFunc
                    $null = Invoke-Expression $using:GetRegistryValuesFunc
    
                    # HKLM and HKCU are already defined by default...
                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                    <#
                    'Get-RegistryValues -path HKLM:\SYSTEM\CurrentControlSet\Control\Network\Connections' Output Example
                    Name                 type data
                    ----                 ---- ----
                    ClassManagers MultiString {{B4C8DF59-D16F-4042-80B7-3557A254B7C5}, {BA126AD3-2166-11D1-B1D0-00805FC1270E}, {BA126AD5-2166-11D1-B1D0-00805FC1270E}, {BA126ADD-2166-11D1-B1D0-00805FC1270E}}
    
    
                    'Get-RegistrySubKeys -path HKLM:\SYSTEM\CurrentControlSet\Control\Network' Output Example
                    Name                                   Path                                                                                                                                   childCount
                    ----                                   ----                                                                                                                                   ----------
                    {4D36E972-E325-11CE-BFC1-08002BE10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}          8
                    {4d36e973-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e973-e325-11ce-bfc1-08002be10318}          1
                    {4d36e974-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}          9
                    {4d36e975-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e975-e325-11ce-bfc1-08002be10318}         19
                    Connections                            Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\Connections                                     0
                    LightweightCallHandlers                Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\LightweightCallHandlers                         2
                    NetworkLocationWizard                  Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\NetworkLocationWizard                           0
                    SharedAccessConnection                 Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\SharedAccessConnection                          0
                    #>
    
                    $HKLMChildKeys = Get-RegistrySubKeys -path "HKLM:\" -ErrorAction SilentlyContinue
                    $HKLMValues = Get-RegistryValues -path "HKLM:\" -ErrorAction SilentlyContinue
                    $HKLMCurrentDir = "HKLM:\"
    
                    $HKCUChildKeys = Get-RegistrySubKeys -path "HKCU:\" -ErrorAction SilentlyContinue
                    $HKCUValues = Get-RegistryValues -path "HKCU:\" -ErrorAction SilentlyContinue
                    $HKCUCurrentDir = "HKCU:\"
    
                    $HKCRChildKeys = Get-RegistrySubKeys -path "HKCR:\" -ErrorAction SilentlyContinue
                    $HKCRValues = Get-RegistryValues -path "HKCR:\" -ErrorAction SilentlyContinue
                    $HKCRCurrentDir = "HKCR:\"
                    
                    $HKUChildKeys = Get-RegistrySubKeys -path "HKU:\" -ErrorAction SilentlyContinue
                    $HKUValues = Get-RegistryValues -path "HKU:\" -ErrorAction SilentlyContinue
                    $HKUCurrentDir = "HKU:\"
                    
                    $HKCCChildKeys = Get-RegistrySubKeys -path "HKCC:\" -ErrorAction SilentlyContinue
                    $HKCCValues = Get-RegistryValues -path "HKCC:\" -ErrorAction SilentlyContinue
                    $HKCCCurrentDir = "HKCC:\"
    
                    [pscustomobject]@{
                        HKLMChildKeys   = $HKLMChildKeys
                        HKLMValues      = $HKLMValues
                        HKLMCurrentDir  = $HKLMCurrentDir
                        HKCUChildKeys   = $HKCUChildKeys
                        HKCUValues      = $HKCUValues
                        HKCUCurrentDir  = $HKCUCurrentDir
                        HKCRChildKeys   = $HKCRChildKeys
                        HKCRValues      = $HKCRValues
                        HKCRCurrentDir  = $HKCRCurrentDir
                        HKUChildKeys    = $HKUChildKeys
                        HKUValues       = $HKUValues
                        HKUCurrentDir   = $HKUCurrentDir
                        HKCCChildKeys   = $HKCCChildKeys
                        HKCCValues      = $HKCCValues
                        HKCCCurrentDir  = $HKCCCurrentDir
                    }
                }
                $Session:HKLMChildKeys = $StaticInfo.HKLMChildKeys
                $Session:HKLMValues = $StaticInfo.HKLMValues
                $Session:HKLMCurrentDir = $StaticInfo.HKLMCurrentDir
                [System.Collections.ArrayList]$HKLMObjectsForGridPrep = @()
                if (@($Session:HKLMChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKLMChildKeys) {
                        if ($obj.Name) {
                            $null = $HKLMObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKLMValues).Count -gt 0) {
                    foreach ($Obj in $Session:HKLMValues) {
                        if ($obj.Name) {
                            $null = $HKLMObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKLMObjectsForGrid = $HKLMObjectsForGridPrep
    
                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                $Session:HKCUValues = $StaticInfo.HKCUValues
                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                [System.Collections.ArrayList]$HKCUObjectsForGridPrep = @()
                if (@($Session:HKCUChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCUChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKCUValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCUValues) {
                        if ($obj.Name) {
                            $null = $HKCUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCUObjectsForGrid = $HKCUObjectsForGridPrep
    
                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                $Session:HKCRValues = $StaticInfo.HKCRValues
                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                [System.Collections.ArrayList]$HKCRObjectsForGridPrep = @()
                if (@($Session:HKCRChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCRChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCRObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKCRValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCRValues) {
                        if ($obj.Name) {
                            $null = $HKCRObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCRObjectsForGrid = $HKCRObjectsForGridPrep
                
                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                $Session:HKUValues = $StaticInfo.HKUValues
                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                [System.Collections.ArrayList]$HKUObjectsForGridPrep = @()
                if (@($Session:HKUChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCUChildKeys) {
                        if ($obj.Name) {
                            $null = $HKUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKUValues).Count -gt 0) {
                    foreach ($obj in $Session:HKUValues) {
                        if ($obj.Name) {
                            $null = $HKUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKUObjectsForGrid = $HKUObjectsForGridPrep
                
                $Session:HKCCChildKeys  = $StaticInfo.HKCCChildKeys
                $Session:HKCCValues = $StaticInfo.HKCCValues
                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                [System.Collections.ArrayList]$HKCCObjectsForGridPrep = @()
                if (@($Session:HKCCChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCCChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCCObjectsForGridPrep.Add($Session:HKCCChildKeys)
                        }
                    }
                }
                if (@($Session:HKCCValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCCValues) {
                        if ($obj.Name) {
                            $null = $HKCCObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCCObjectsForGrid = $HKCCObjectsForGridPrep
    
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMChildKeys",$StaticInfo.HKLMChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $StaticInfo.HKLMChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMValues",$StaticInfo.HKLMValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $StaticInfo.HKLMValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMCurrentDir",$StaticInfo.HKLMCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $StaticInfo.HKLMCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUChildKeys",$StaticInfo.HKCUChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUValues",$StaticInfo.HKCUValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUCurrentDir",$StaticInfo.HKCUCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRChildKeys",$StaticInfo.HKCRChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRValues",$StaticInfo.HKCRValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRCurrentDir",$StaticInfo.HKCRCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUChildKeys",$StaticInfo.HKUChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUValues",$StaticInfo.HKUValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUCurrentDir",$StaticInfo.HKUCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCChildKeys",$StaticInfo.HKCCChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCValues",$StaticInfo.HKCCValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCCurrentDir",$StaticInfo.HKCCCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                }
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Registry (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
    
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Registry$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Registry$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{RootRegistry = Get-ChildItem -Path "$env:SystemDrive\" }
                            }
    
                            # Operations that you want to run once every second go here
                            @{RootRegistry = Get-ChildItem -Path "$env:SystemDrive\"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Registry$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo equal to
                # $RSSyncHash."Registry$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo = $RSSyncHash."Registry$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
    
            # Static Data Element Example
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_LOCAL_MACHINE" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKLMGridObjects" -Tag div -EndPoint {
                        $Session:HKLMGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKLMObjectsForGridPrep = @()
                        if (@($Session:HKLMChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKLMChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKLMObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKLMValues).Count -gt 0) {
                            foreach ($obj in $Session:HKLMValues) {
                                if ($obj.Name) {
                                    $null = $HKLMObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKLMObjectsForGrid = $HKLMObjectsForGridPrep
    
                        $Session:HKLMGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKLMRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_LOCAL_MACHINE\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                $CurrentDirectory = $Session:HKLMChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKLMCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKLMRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKLMRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKLMRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKLMChildKeys   = $HKLMChildKeys
                                        HKLMValues      = $HKLMValues
                                        HKLMCurrentDir  = $HKLMCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $Session:HKLMValues = $NewPathInfo.HKLMValues
                                $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
    
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_LOCAL_MACHINE\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                $FullPathToExplorePrep = $Session:HKLMChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKLMCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKLMCurrentDir
                                }
                                else {
                                    $Session:HKLMCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKLMChildKeys   = $HKLMChildKeys
                                        HKLMValues      = $HKLMValues
                                        HKLMCurrentDir  = $HKLMCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $Session:HKLMValues = $NewPathInfo.HKLMValues
                                $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
    
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKLMUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKLMChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKLMGridRefreshed = $False
                                try {
                                    $Session:HKLMObjectsForGrid | foreach {
                                        if ($_.Path) {
                                            $RootDirSlashCheck = $_.Path -split "HKEY_LOCAL_MACHINE\\"
                                            $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                            $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                        }
    
                                        #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                        [pscustomobject]@{
                                            Name            = $_.Name
                                            Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                            Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                            Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                            ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                            Explore         = if (!$_.Path) {'-'} else {
                                                New-UDButton -Text "Explore" -OnClick {
                                                    $Session:HKLMUDGridLoadingTracker = "Loading"
                                                    #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                    $FullPathToExplore = $PathUpdatedFormat
    
                                                    $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                    $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                        Invoke-Expression $using:GetRegistrySubKeysFunc
                                                        Invoke-Expression $using:GetRegistryValuesFunc
    
                                                        $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                        $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                        $HKLMCurrentDir = $args[0]
    
                                                        [pscustomobject]@{
                                                            HKLMChildKeys   = $HKLMChildKeys
                                                            HKLMValues      = $HKLMValues
                                                            HKLMCurrentDir  = $HKLMCurrentDir
                                                        }
                                                    } -ArgumentList $FullPathToExplore
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                                    $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                                    $Session:HKLMValues = $NewPathInfo.HKLMValues
                                                    $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                                    
                                                    $Session:HKLMGridItemsRefreshed = $False
                                                    Sync-UDElement -Id "NewHKLMRootDirTB"
                                                    Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                                    Sync-UDElement -Id "UpdateHKLMGridObjects"
                                                    while (!$Session:HKLMGridItemsRefreshed) {
                                                        Start-Sleep -Seconds 2
                                                    }
                                                    Sync-UDElement -Id "HKLMChildItemsUDGrid"
                                                }
                                            }
                                        }
                                    } | Out-UDGridData
                                }
                                catch {}
    
                                $HKLMGridRefreshed = $True
                                $Session:HKLMUDGridLoadingTracker = "FinishedLoading"
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CURRENT_USER" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCUGridObjects" -Tag div -EndPoint {
                        $Session:HKCUGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCUObjectsForGridPrep = @()
                        if (@($Session:HKCUChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCUChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCUValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCUValues) {
                                if ($obj.Name) {
                                    $null = $HKCUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCUObjectsForGrid = $HKCUObjectsForGridPrep
    
                        $Session:HKCUGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCURootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCUChildKeys[0].Path -split "HKEY_CURRENT_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                $CurrentDirectory = $Session:HKCUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCUCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCURootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCURootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCURootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKCUChildKeys = Get-RegistrySubKeys -path "HKCU:\" -ErrorAction SilentlyContinue
                                    $HKCUValues = Get-RegistryValues -path "HKCU:\" -ErrorAction SilentlyContinue
                                    $HKCUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCUChildKeys   = $HKCUChildKeys
                                        HKCUValues      = $HKCUValues
                                        HKCUCurrentDir  = $HKCUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $Session:HKCUValues = $StaticInfo.HKCUValues
                                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_CURRENT_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                $FullPathToExplorePrep = $Session:HKCUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKCUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKCUCurrentDir
                                }
                                else {
                                    $Session:HKCUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKCUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCUChildKeys   = $HKCUChildKeys
                                        HKCUValues      = $HKCUValues
                                        HKCUCurrentDir  = $HKCUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $Session:HKCUValues = $StaticInfo.HKCUValues
                                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCUUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCUChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKCUGridRefreshed = $False
                                while (!$HKCUGridRefreshed) {
                                    try {
                                        $Session:HKCUObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CURRENT_USER\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCUUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $HKCUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCUCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCUChildKeys   = $HKCUChildKeys
                                                                    HKCUValues      = $HKCUValues
                                                                    HKCUCurrentDir  = $HKCUCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                                            $Session:HKCUValues = $StaticInfo.HKCUValues
                                                            $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                                            $Session:HKCUGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCURootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCURootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCUGridObjects"
                                                            while (!$Session:HKCUGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCUChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCUGridRefreshed = $True
                                        $Session:HKCUUDGridLoadingTracker = "FinishedLoading"
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CLASSES_ROOT" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCRGridObjects" -Tag div -EndPoint {
                        $Session:HKCRGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCRObjectsForGridPrep = @()
                        if (@($Session:HKCRChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCRChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCRObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCRValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCRValues) {
                                if ($obj.Name) {
                                    $null = $HKCRObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCRObjectsForGrid = $HKCRObjectsForGridPrep
    
                        $Session:HKCRGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCRRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCRChildKeys[0].Path -split "HKEY_CLASSES_ROOT\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                $CurrentDirectory = $Session:HKCRChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCRCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCRRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCRRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCRRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                    $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCRChildKeys   = $HKCRChildKeys
                                        HKCRValues      = $HKCRValues
                                        HKCRCurrentDir  = $HKCRCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $Session:HKCRValues = $StaticInfo.HKCRValues
                                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKCRChildKeys[0].Path -split "HKEY_CLASSES_ROOT\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                $FullPathToExplorePrep = $Session:HKCRChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKCRCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKCRCurrentDir
                                }
                                else {
                                    $Session:HKCRCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                    $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCRChildKeys   = $HKCRChildKeys
                                        HKCRValues      = $HKCRValues
                                        HKCRCurrentDir  = $HKCRCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $Session:HKCRValues = $StaticInfo.HKCRValues
                                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCRUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCRChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKCRGridRefreshed = $False
                                while (!$HKCRGridRefreshed) {
                                    try {
                                        $Session:HKCRObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CLASSES_ROOT\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCRUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                                                $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCRCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCRChildKeys   = $HKCRChildKeys
                                                                    HKCRValues      = $HKCRValues
                                                                    HKCRCurrentDir  = $HKCRCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                                            $Session:HKCRValues = $StaticInfo.HKCRValues
                                                            $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                                            $Session:HKCRGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCRRootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCRGridObjects"
                                                            while (!$Session:HKCRGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCRChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCRGridRefreshed = $True
                                        $Session:HKCRUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_USERS" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKUGridObjects" -Tag div -EndPoint {
                        $Session:HKUGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKUObjectsForGridPrep = @()
                        if (@($Session:HKUChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKUChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKUValues).Count -gt 0) {
                            foreach ($obj in $Session:HKUValues) {
                                if ($obj.Name) {
                                    $null = $HKUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKUObjectsForGrid = $HKUObjectsForGridPrep
    
                        $Session:HKUGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKURootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USERS\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $CurrentDirectory = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKUCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKURootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKURootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKURootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                    $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKUChildKeys    = $HKUChildKeys
                                        HKUValues       = $HKUValues
                                        HKUCurrentDir   = $HKUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                $Session:HKUValues = $StaticInfo.HKUValues
                                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $FullPathToExplorePrep = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKUCurrentDir
                                }
                                else {
                                    $Session:HKUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                    $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKUChildKeys    = $HKUChildKeys
                                        HKUValues       = $HKUValues
                                        HKUCurrentDir   = $HKUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                $Session:HKUValues = $StaticInfo.HKUValues
                                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKUUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKUChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKUGridRefreshed = $False
                                while (!$HKUGridRefreshed) {
                                    try {
                                        $Session:HKUObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_USERS\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKUUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                                                $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKUCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKUChildKeys    = $HKUChildKeys
                                                                    HKUValues       = $HKUValues
                                                                    HKUCurrentDir   = $HKUCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                                            $Session:HKUValues = $StaticInfo.HKUValues
                                                            $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                                            $Session:HKUGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKURootDirTB"
                                                            Sync-UDElement -Id "CurrentHKURootDirTB"
                                                            Sync-UDElement -Id "UpdateHKUGridObjects"
                                                            while (!$Session:HKUGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKUChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKUGridRefreshed = $True
                                        $Session:HKUUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CURRENT_CONFIG" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCCGridObjects" -Tag div -EndPoint {
                        $Session:HKCCGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCCObjectsForGridPrep = @()
                        if (@($Session:HKCCChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCCChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCCObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCCValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCCValues) {
                                if ($obj.Name) {
                                    $null = $HKCCObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCCObjectsForGrid = $HKCCObjectsForGridPrep
    
                        $Session:HKCCGridItemsRefreshed = $False
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCCRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCCChildKeys[0].Path -split "HKEY_CURRENT_CONFIG\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCC:"} else {"HKCC:\"}
                                $CurrentDirectory = $Session:HKCCChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCCCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCCRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCCRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCCRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                    $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCCChildKeys   = $HKCCChildKeys
                                        HKCCValues      = $HKCCValues
                                        HKCCCurrentDir  = $HKCCCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $Session:HKCCValues = $StaticInfo.HKCCValues
                                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $FullPathToExplorePrep = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKUCurrentDir
                                }
                                else {
                                    $Session:HKUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                    $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCCChildKeys   = $HKCCChildKeys
                                        HKCCValues      = $HKCCValues
                                        HKCCCurrentDir  = $HKCCCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $Session:HKCCValues = $StaticInfo.HKCCValues
                                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCCUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCCChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $HKCCGridRefreshed = $False
                                while (!$HKCCGridRefreshed) {
                                    try {
                                        $Session:HKCCObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CURRENT_CONFIG\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCC:"} else {"HKCC:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCCUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                                                $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCCCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCCChildKeys   = $HKCCChildKeys
                                                                    HKCCValues      = $HKCCValues
                                                                    HKCCCurrentDir  = $HKCCCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                                            $Session:HKCCValues = $StaticInfo.HKCCValues
                                                            $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                                            $Session:HKCCGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCCRootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCCGridObjects"
                                                            while (!$Session:HKCCGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCCChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCCGridRefreshed = $True
                                        $Session:HKCCUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:RegistryPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Registry/:RemoteHost" -Endpoint $RegistryPageContent
    $null = $Pages.Add($Page)
    
    $RolesAndFeaturesPageContent = {
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
                $Session:RolesAndFeaturesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:RolesAndFeaturesPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $OSInfo = Get-CimInstance Win32_OperatingSystem
                if ($OSInfo.Caption -match "Server") {
                    Import-Module ServerManager
                    $RolesAndFeaturesInfo = Get-WindowsFeature
                }
                else {
                    try {
                        Import-Module "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Dism\Dism.psd1" -ErrorAction Stop
                        $RolesAndFeaturesInfo = Get-WindowsOptionalFeature -Online
                    }
                    catch {
                        $RolesAndFeaturesInfo = [pscustomobject]@{
                            FeatureName         = "Unable to load Dism Module!"
                            State               = "Unable to load Dism Module!"
                            Path                = "Unable to load Dism Module!"
                            Online              = "Unable to load Dism Module!"
                            WinPath             = "Unable to load Dism Module!"
                            SysDrivePath        = "Unable to load Dism Module!"
                            RestartNeeded       = "Unable to load Dism Module!"
                            LogPath             = "Unable to load Dism Module!"
                            ScratchDirectory    = "Unable to load Dism Module!"
                            LogLevel            = "Unable to load Dism Module!"
                        }
                    }
                }
    
                [pscustomobject]@{
                    RolesAndFeaturesInfo    = $RolesAndFeaturesInfo
                }
            }
            $Session:RolesAndFeaturesInfoStatic = $StaticInfo.RolesAndFeaturesInfo
            if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.Keys -notcontains "RolesAndFeaturesInfo") {
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.Add("RolesAndFeaturesInfo",$Session:RolesAndFeaturesInfoStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.RolesAndFeaturesInfo = $Session:RolesAndFeaturesInfoStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "RolesAndFeatures (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetRolesAndFeaturesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RolesAndFeaturesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetRolesAndFeaturesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RolesAndFeatures" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetRolesAndFeaturesOverviewFunc,$GetRolesAndFeaturesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "RolesAndFeatures$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "RolesAndFeatures$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllRolesAndFeaturess = Get-RolesAndFeatures}
                            }
    
                            # Operations that you want to run once every second go here
                            @{RolesAndFeaturesSummary = Get-RolesAndFeaturesOverview -channel "Microsoft-Windows-RolesAndFeatureservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "RolesAndFeatures$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo equal to
                # $RSSyncHash."RolesAndFeatures$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo = $RSSyncHash."RolesAndFeatures$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            # Dism 'Get-WindowsOptionalFeature -Online' Properties
            <#
                FeatureName      : ADCertificateServicesRole
                State            : Disabled
                Path             :
                Online           : True
                WinPath          :
                SysDrivePath     :
                RestartNeeded    : False
                LogPath          : C:\Windows\Logs\DISM\dism.log
                ScratchDirectory :
                LogLevel         : WarningsInfo
            #>
    
            # ServerManager Get-WindowsFeature Properties
            <#
                Name                      : AD-Certificate
                DisplayName               : Active Directory Certificate Services
                Description               : Active Directory Certificate Services (AD CS) is used to create certification authorities and related role services that allow you to issue and manage certificates used in a variety of applications.
                Installed                 : False
                InstallState              : Available
                FeatureType               : Role
                Path                      : Active Directory Certificate Services
                Depth                     : 1
                DependsOn                 : {}
                Parent                    :
                ServerComponentDescriptor : ServerComponent_AD_Certificate
                SubFeatures               : {ADCS-Cert-Authority, ADCS-Enroll-Web-Pol, ADCS-Enroll-Web-Svc, ADCS-Web-Enrollment...}
                SystemService             : {}
                Notification              : {}
                BestPracticesModelId      : Microsoft/Windows/CertificateServices
                EventQuery                : ActiveDirectoryCertificateServices.Events.xml
                PostConfigurationNeeded   : False
                AdditionalInfo            : {MajorVersion, MinorVersion, NumericId, InstallName}
            #>
    
            $RolesAndFeaturesProperties = @("Name","State","Parent","SubFeatures","DependsOn")
            $RolesAndFeaturesUDGridSplatParams = @{
                Headers         = $RolesAndFeaturesProperties
                Properties      = $RolesAndFeaturesProperties
                NoPaging        = $True
            }
            New-UDGrid @RolesAndFeaturesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $OSInfo = Get-CimInstance Win32_OperatingSystem
    
                    if ($OSInfo.Caption -match "Server") {
                        Import-Module ServerManager
                        $RolesAndFeaturesInfo = Get-WindowsFeature
                    }
                    else {
                        try {
                            Import-Module "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Dism\Dism.psd1" -ErrorAction Stop
                            $RolesAndFeaturesInfo = Get-WindowsOptionalFeature -Online
                        }
                        catch {
                            $RolesAndFeaturesInfo = [pscustomobject]@{
                                FeatureName         = "Unable to load Dism Module!"
                                State               = "Unable to load Dism Module!"
                                Path                = "Unable to load Dism Module!"
                                Online              = "Unable to load Dism Module!"
                                WinPath             = "Unable to load Dism Module!"
                                SysDrivePath        = "Unable to load Dism Module!"
                                RestartNeeded       = "Unable to load Dism Module!"
                                LogPath             = "Unable to load Dism Module!"
                                ScratchDirectory    = "Unable to load Dism Module!"
                                LogLevel            = "Unable to load Dism Module!"
                            }
                        }
                    }
        
                    [pscustomobject]@{
                        RolesAndFeaturesInfo    = $RolesAndFeaturesInfo
                    }
                }
                
                if ($($StaticInfo.RolesAndFeaturesInfo[0] | Get-Member -MemberType Property).Name -contains "FeatureName") {
                    $Session:RolesAndFeaturesInfoStatic = foreach ($obj in $StaticInfo.RolesAndFeaturesInfo) {
                        [pscustomobject]@{
                            Name            = $obj.FeatureName
                            State           = $obj.State # Enabled/Disabled
                            Parent          = "Info Not Available"
                            SubFeatures     = "Info Not Available"
                            DependsOn       = "Info Not Available"
                        }
                    }
                }
                else {
                    $Session:RolesAndFeaturesInfoStatic = foreach ($obj in $StaticInfo.RolesAndFeaturesInfo) {
                        [pscustomobject]@{
                            Name            = $obj.Name
                            State           = if ($obj.Installed) {"Enabled"} else {"Disabled"}
                            Parent          = $obj.Parent
                            SubFeatures     = $obj.SubFeatures -join ", "
                            DependsOn       = $obj.DependsOn -join ", "
                        }
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.RolesAndFeaturesInfo = $Session:RolesAndFeaturesInfoStatic
                
                $Session:RolesAndFeaturesInfoStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:RolesAndFeaturesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/RolesAndFeatures/:RemoteHost" -Endpoint $RolesAndFeaturesPageContent
    $null = $Pages.Add($Page)
    
    $ScheduledTasksPageContent = {
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
                $Session:ScheduledTasksPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ScheduledTasksPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetScheduledTasksFunc
                
                $AllScheduledTasks = Get-ScheduledTasks
    
                [pscustomobject]@{
                    AllScheduledTasks   = $AllScheduledTasks
                }
            }
            $Session:AllScheduledTasksStatic = $StaticInfo.AllScheduledTasks
            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Keys -notcontains "AllScheduledTasks") {
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Add("AllScheduledTasks",$Session:AllScheduledTasksStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "ScheduledTasks (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetScheduledTasksOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasksOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetScheduledTasksOverviewFunc,$GetScheduledTasksFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "ScheduledTasks$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "ScheduledTasks$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllScheduledTaskss = Get-ScheduledTasks}
                            }
    
                            # Operations that you want to run once every second go here
                            @{ScheduledTasksSummary = Get-ScheduledTasksOverview -channel "Microsoft-Windows-ScheduledTaskservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "ScheduledTasks$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo equal to
                # $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo = $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTaskInfo
    
                LastRunTime        : 8/28/2018 10:50:50 PM
                LastTaskResult     : 0
                NextRunTime        : 8/29/2018 10:50:50 PM
                NumberOfMissedRuns : 0
                TaskName           : GoogleUpdateTaskMachineCore
                TaskPath           : \
                PSComputerName     :
    
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask
    
                TaskPath                                       TaskName                          State
                --------                                       --------                          -----
                \                                              GoogleUpdateTaskMachineCore       Ready
    
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask | fl *
    
                status                : Ready
                TriggersEx            : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
                State                 : Ready
                Actions               : {MSFT_TaskExecAction}
                Author                :
                Date                  :
                Description           : Keeps your Google software up to date. If this task is disabled or stopped, your Google software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not
                                        work. This task uninstalls itself when there is no Google software using it.
                Documentation         :
                Principal             : MSFT_TaskPrincipal2
                SecurityDescriptor    :
                Settings              : MSFT_TaskSettings3
                Source                :
                TaskName              : GoogleUpdateTaskMachineCore
                TaskPath              : \
                Triggers              : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
                URI                   : \GoogleUpdateTaskMachineCore
                Version               : 1.3.33.17
                PSComputerName        :
                CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
                CimInstanceProperties : {Actions, Author, Date, Description...}
                CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties
    
    
            Trigger Value: $($($($($($($SchTsks.ScheduledTask[6].Triggers | gm).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}) -match "Trigger") -replace "MSFT_Task") -replace "Trigger") -join ", "
            
            #>
    
            $AllScheduledTasksProperties = @("Name","Status","Triggers","NextRunTime","LastRunTime","LastRunResult","Author","Created")
            $AllScheduledTasksUDTableSplatParams = @{
                Headers         = $AllScheduledTasksProperties
                Properties      = $AllScheduledTasksProperties
                PageSize        = 20
            }
            New-UDGrid @AllScheduledTasksUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $SchTsksInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetScheduledTasksFunc
                    
                    $AllScheduledTasks = Get-ScheduledTasks
        
                    [pscustomobject]@{
                        AllScheduledTasks   = $AllScheduledTasks
                    }
                }
                
                $Session:AllScheduledTasksStatic = foreach ($obj in $SchTsksInfo.AllScheduledTasks) {
                    [array]$TriggersPrepA = @($obj.ScheduledTask.Triggers | Where-Object {$_})
                    if ($TriggersPrepA.Count -gt 0) {
                        $TriggersPrep = $($($TriggersPrepA | Get-Member).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}
                        $Triggers = $($($TriggersPrepA -match "Trigger") -replace "MSFT_Task") -replace "Trigger"
                    }
                    else {
                        $Triggers = $null
                    }
    
                    # LastRunResult Translation
                    # From: https://en.wikipedia.org/wiki/Windows_Task_Scheduler
                    $LastRunResult = switch ($obj.ScheduledTaskInfo.LastTaskResult) {
                        {$('{0:X}' -f $_) -eq '0'}          { "The operation completed successfully." }
                        {$('{0:X}' -f $_) -eq '1'}          { "Incorrect function called or unknown function called." }
                        {$('{0:X}' -f $_) -eq '2'}          { "File not found." }
                        {$('{0:X}' -f $_) -eq '10'}         { "The environment is incorrect." }
                        {$('{0:X}' -f $_) -eq '41300'}      { "Task is ready to run at its next scheduled time." }
                        {$('{0:X}' -f $_) -eq '41301'}      { "The task is currently running." }
                        {$('{0:X}' -f $_) -eq '41302'}      { "The task has been disabled." }
                        {$('{0:X}' -f $_) -eq '41303'}      { "The task has not yet run." }
                        {$('{0:X}' -f $_) -eq '41304'}      { "There are no more runs scheduled for this task." }
                        {$('{0:X}' -f $_) -eq '41305'}      { "One or more of the properties that are needed to run this task have not been set." }
                        {$('{0:X}' -f $_) -eq '41306'}      { "The last run of the task was terminated by the user." }
                        {$('{0:X}' -f $_) -eq '41307'}      { "Either the task has no triggers or the existing triggers are disabled or not set." }
                        {$('{0:X}' -f $_) -eq '41308'}      { "Event triggers do not have set run times." }
                        {$('{0:X}' -f $_) -eq '80010002'}   { "Call was canceled by the message filter." }
                        {$('{0:X}' -f $_) -eq '80041309'}   { "A task's trigger is not found." }
                        {$('{0:X}' -f $_) -eq '8004130A'}   { "One or more of the properties required to run this task have not been set." }
                        {$('{0:X}' -f $_) -eq '8004130B'}   { "There is no running instance of the task." }
                        {$('{0:X}' -f $_) -eq '8004130C'}   { "The Task Scheduler service is not installed on this computer." }
                        {$('{0:X}' -f $_) -eq '8004130D'}   { "The task object could not be opened." }
                        {$('{0:X}' -f $_) -eq '8004130E'}   { "The object is either an invalid task object or is not a task object." }
                        {$('{0:X}' -f $_) -eq '8004130F'}   { "No account information could be found in the Task Scheduler security database for the task indicated." }
                        {$('{0:X}' -f $_) -eq '80041310'}   { "Unable to establish existence of the account specified." }
                        {$('{0:X}' -f $_) -eq '80041311'}   { "Corruption was detected in the Task Scheduler security database." }
                        {$('{0:X}' -f $_) -eq '80041312'}   { "Task Scheduler security services are available only on Windows NT." }
                        {$('{0:X}' -f $_) -eq '80041313'}   { "The task object version is either unsupported or invalid." }
                        {$('{0:X}' -f $_) -eq '80041314'}   { "The task has been configured with an unsupported combination of account settings and run time options." }
                        {$('{0:X}' -f $_) -eq '80041315'}   { "The Task Scheduler Service is not running." }
                        {$('{0:X}' -f $_) -eq '80041316'}   { "The task XML contains an unexpected node." }
                        {$('{0:X}' -f $_) -eq '80041317'}   { "The task XML contains an element or attribute from an unexpected namespace." }
                        {$('{0:X}' -f $_) -eq '80041318'}   { "The task XML contains a value which is incorrectly formatted or out of range." }
                        {$('{0:X}' -f $_) -eq '80041319'}   { "The task XML is missing a required element or attribute." }
                        {$('{0:X}' -f $_) -eq '8004131A'}   { "The task XML is malformed." }
                        {$('{0:X}' -f $_) -eq '0004131B'}   { "The task is registered, but not all specified triggers will start the task." }
                        {$('{0:X}' -f $_) -eq '0004131C'}   { "The task is registered, but may fail to start. Batch logon privilege needs to be enabled for the task principal." }
                        {$('{0:X}' -f $_) -eq '8004131D'}   { "The task XML contains too many nodes of the same type." }
                        {$('{0:X}' -f $_) -eq '8004131E'}   { "The task cannot be started after the trigger end boundary." }
                        {$('{0:X}' -f $_) -eq '8004131F'}   { "An instance of this task is already running." }
                        {$('{0:X}' -f $_) -eq '80041320'}   { "The task will not run because the user is not logged on." }
                        {$('{0:X}' -f $_) -eq '80041321'}   { "The task image is corrupt or has been tampered with." }
                        {$('{0:X}' -f $_) -eq '80041322'}   { "The Task Scheduler service is not available." }
                        {$('{0:X}' -f $_) -eq '80041323'}   { "The Task Scheduler service is too busy to handle your request. Please try again later." }
                        {$('{0:X}' -f $_) -eq '80041324'}   { "The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition." }
                        {$('{0:X}' -f $_) -eq '00041325'}   { "The Task Scheduler service has asked the task to run." }
                        {$('{0:X}' -f $_) -eq '80041326'}   { "The task is disabled." }
                        {$('{0:X}' -f $_) -eq '80041327'}   { "The task has properties that are not compatible with earlier versions of Windows." }
                        {$('{0:X}' -f $_) -eq '80041328'}   { "The task settings do not allow the task to start on demand." }
                        {$('{0:X}' -f $_) -eq 'C000013A'}   { "The application terminated as a result of a CTRL+C." }
                        {$('{0:X}' -f $_) -eq 'C0000142'}   { "The application failed to initialize properly." }
                        Default                             { $null }
                    }
    
                    [pscustomobject]@{
                        Name            = $obj.ScheduledTask.TaskName
                        Status          = $obj.ScheduledTask.status
                        Triggers        = $Triggers
                        NextRunTime     = if ($obj.ScheduledTaskInfo.NextRunTime) {Get-Date $obj.ScheduledTaskInfo.NextRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                        LastRunTime     = if ($obj.ScheduledTaskInfo.LastRunTime) {Get-Date $obj.ScheduledTaskInfo.LastRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                        LastRunResult   = $LastRunResult
                        Author          = $obj.ScheduledTask.Author
                        Created         = if ($obj.ScheduledTask.Date) {Get-Date $obj.ScheduledTask.Date -Format MM-dd-yy_hh:mm:sstt} else {$null}
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
                
                $Session:AllScheduledTasksStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:ScheduledTasksPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/ScheduledTasks/:RemoteHost" -Endpoint $ScheduledTasksPageContent
    $null = $Pages.Add($Page)
    
    $ServicesPageContent = {
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
                $Session:ServicesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ServicesPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $AllServices = Get-CimInstance Win32_Service
    
                [pscustomobject]@{
                    AllServices             = [pscustomobject]$AllServices
                }
            }
            $Session:AllServicesStatic = $StaticInfo.AllServices
            if ($PUDRSSyncHT."$RemoteHost`Info".Services.Keys -notcontains "AllServices") {
                $PUDRSSyncHT."$RemoteHost`Info".Services.Add("AllServices",$Session:AllServicesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Services.AllServices = $Session:AllServicesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Services (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetServicesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServicesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetServicesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Services" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetServicesOverviewFunc,$GetServicesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Services$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Services$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllServicess = Get-Services}
                            }
    
                            # Operations that you want to run once every second go here
                            @{ServicesSummary = Get-ServicesOverview -channel "Microsoft-Windows-ServiceservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Services$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo equal to
                # $RSSyncHash."Services$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo = $RSSyncHash."Services$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                Name                    : AJRouter
                Status                  : OK
                ExitCode                : 1077
                DesktopInteract         : False
                ErrorControl            : Normal
                PathName                : C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
                ServiceType             : Share Process
                StartMode               : Manual
                Caption                 : AllJoyn Router Service
                Description             : Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run.
                InstallDate             :
                CreationClassName       : Win32_Service
                Started                 : False
                SystemCreationClassName : Win32_ComputerSystem
                SystemName              : ZEROTESTING
                AcceptPause             : False
                AcceptStop              : False
                DisplayName             : AllJoyn Router Service
                ServiceSpecificExitCode : 0
                StartName               : NT AUTHORITY\LocalService
                State                   : Stopped
                TagId                   : 0
                CheckPoint              : 0
                DelayedAutoStart        : False
                ProcessId               : 0
                WaitHint                : 0
                PSComputerName          :
                CimClass                : root/cimv2:Win32_Service
                CimInstanceProperties   : {Caption, Description, InstallDate, Name...}
                CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
            
            #>
    
            $AllServicesProperties = @("Name","DisplayName","Status","State","StartMode","PathName","Description")
            $AllServicesUDGridSplatParams = @{
                Headers         = $AllServicesProperties
                Properties      = $AllServicesProperties
                PageSize        = 20
            }
            New-UDGrid @AllServicesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $AllServices = Get-CimInstance Win32_Service
        
                    [pscustomobject]@{
                        AllServices             = [pscustomobject]$AllServices
                    }
                }
                $Session:AllServicesStatic = $StaticInfo.AllServices
                $PUDRSSyncHT."$RemoteHost`Info".Services.AllServices = $Session:AllServicesStatic
                
                $Session:AllServicesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:ServicesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Services/:RemoteHost" -Endpoint $ServicesPageContent
    $null = $Pages.Add($Page)
    
    $StoragePageContent = {
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
                $Session:StoragePageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:StoragePageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetStorageDiskFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageDisk" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetStorageFileShareFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageFileShare" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetStorageVolumeFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageVolume" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetStorageDiskFunc,$GetStorageFileShareFunc,$GetStorageVolumeFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
                
                $DiskSummary = Get-StorageDisk
                $VolumeSummary = Get-StorageVolume
                $FileShareSummary = Get-StorageFileShare
    
                [pscustomobject]@{
                    DiskSummary         = $DiskSummary | foreach {[pscustomobject]$_}
                    VolumeSummary       = $VolumeSummary | foreach {[pscustomobject]$_}
                    FileShareSummary    = $FileShareSummary | foreach {[pscustomobject]$_}
                }
            }
            $Session:DiskSummaryStatic = $StaticInfo.DiskSummary
            $Session:VolumeSummaryStatic = $StaticInfo.VolumeSummary
            $Session:FileShareSummaryStatic = $StaticInfo.FileShareSummary
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "DiskSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("DiskSummary",$StaticInfo.DiskSummary)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.DiskSummary = $StaticInfo.DiskSummary
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "VolumeSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("VolumeSummary",$Session:VolumeSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.VolumeSummary = $Session:VolumeSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "FileShareSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("FileShareSummary",$Session:FileShareSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.FileShareSummary = $Session:FileShareSummaryStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Storage (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetStorageOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetStorageFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Storage" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetStorageOverviewFunc,$GetStorageFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Storage$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Storage$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllStorages = Get-Storage}
                            }
    
                            # Operations that you want to run once every second go here
                            @{StorageSummary = Get-StorageOverview -channel "Microsoft-Windows-StorageervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Storage$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo equal to
                # $RSSyncHash."Storage$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo = $RSSyncHash."Storage$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#        
                PS C:\Users\zeroadmin> Get-StorageDisk
    
                Name                           Value
                ----                           -----
                UniqueId                       60022480D969B073D0ADAF27131151DF
                SerialNumber
                ProvisioningType               1
                IsSystem                       True
                LogicalSectorSize              512
                Number                         0
                IsHighlyAvailable              False
                HealthStatus                   0
                volumeIds                      {\\?\Volume{96ae8ad0-e1c2-4cd0-9109-83a47970250f}\, \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\}
                PhysicalSectorSize             4096
                NumberOfPartitions             4
                Model                          Virtual Disk
                IsReadOnly                     False
                OperationalStatus              {53264}
                IsScaleOut                     False
                IsClustered                    False
                IsOffline                      False
                FirmwareVersion                1.0
                LargestFreeExtent              0
                BootFromDisk                   True
                BusType                        10
                Size                           68719476736
                OfflineReason                  0
                AllocatedSize                  68719476736
                Location                       Integrated : Adapter 0 : Port 0 : Target 0 : LUN 0
                IsBoot                         True
                FriendlyName                   Msft Virtual Disk
                UniqueIdFormat                 3
                Path                           \\?\scsi#disk&ven_msft&prod_virtual_disk#000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
                PartitionStyle                 2
                Signature
                
    
                PS C:\Users\zeroadmin> Get-StorageVolume
    
                Name                           Value
                ----                           -----
                UniqueId                       \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\
                FileSystemLabel
                Name                           (C:)
                IsSystem                       False
                FileSystemType                 14
                DiskNumber                     0
                FileSystem                     NTFS
                IsBoot                         True
                SizeRemaining                  43436892160
                IsActive                       False
                OperationalStatus              {2}
                HealthStatus                   0
                DriveType                      3
                PartitionNumber                4
                DriveLetter                    C
                AllocationUnitSize             4096
                Size                           68124930048
                DedupMode                      4
                Path                           \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\
                
    
                PS C:\Users\zeroadmin> Get-StorageFileShare
    
                Name                           Value
                ----                           -----
                UniqueId                       smb|ZeroTesting.zero.lab/C$
                Description                    Default share
                EncryptData                    False
                ContinuouslyAvailable          False
                IsHidden                       True
                ShareState                     1
                Name                           C$
                FileSharingProtocol            3
                HealthStatus                   0
                OperationalStatus              {53264}
                VolumePath                     \
    
            #>
    
            # Disk Summary
            $DiskSummaryProperties = @("Number","Name","Health","Status","Unallocated","Capacity","BootDisk")
            $DiskSummaryUDGridSplatParams = @{
                Title           = "Disk Summary"
                Headers         = $DiskSummaryProperties
                Properties      = $DiskSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @DiskSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageDiskFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageDisk" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageDiskFunc
                    
                    $DiskSummary = Get-StorageDisk
    
                    [pscustomobject]@{
                        DiskSummary         = $DiskSummary | foreach {[pscustomobject]$_}
                    }
                }
                $Session:DiskSummaryStatic = foreach ($obj in $StaticInfo.DiskSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Number          = $obj.Number
                        Name            = $obj.FriendlyName
                        Health          = $Health
                        Status          = if ($obj.isOffline) {"Offline"} else {"Online"}
                        Unallocated     = [Math]::Round($($($obj.Size - $obj.AllocatedSize) / 1GB),2).ToString() + 'GB'
                        Capacity        = [Math]::Round($($obj.Size / 1GB),2).ToString() + 'GB'
                        BootDisk        = if ($obj.isBoot) {"True"} else {"False"}
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Storage.DiskSummary = $Session:DiskSummaryStatic
                
                $Session:DiskSummaryStatic | Out-UDGridData
            }
    
            # Volume Summary
            $VolumeSummaryProperties = @("Name","DiskNumber","BootVolume","DriveType","FileSystem","Health","SpaceRemaining","Size")
            $VolumeSummaryUDGridSplatParams = @{
                Title           = "Volume Summary"
                Headers         = $VolumeSummaryProperties
                Properties      = $VolumeSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @VolumeSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageVolumeFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageVolume" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageVolumeFunc
                    
                    $VolumeSummary = Get-StorageVolume
    
                    [pscustomobject]@{
                        VolumeSummary       = $VolumeSummary | foreach {[pscustomobject]$_}
                    }
                }
                $Session:VolumeSummaryStatic = foreach ($obj in $StaticInfo.VolumeSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    $DriveType = switch ($obj.DriveType) {
                        '0'     {"Unknown"}
                        '1'     {"No Root Directory"}
                        '2'     {"Removeable Disk"}
                        '3'     {"Local Disk"}
                        '4'     {"Network Drive"}
                        '5'     {"Compact Disk"}
                        '6'     {"RAM Disk"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Name            = $obj.Name
                        DiskNumber      = $obj.DiskNumber
                        BootVolume      = $obj.isBoot.ToString()
                        DriveType       = $DriveType
                        FileSystem      = $obj.FileSystem
                        Health          = $Health
                        SpaceRemaining  = [Math]::Round($($obj.SizeRemaining / 1GB),2).ToString() + 'GB'
                        Size            = [Math]::Round($($obj.Size / 1GB),2).ToString() + 'GB'
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Storage.VolumeSummary = $Session:VolumeSummaryStatic
                
                $Session:VolumeSummaryStatic | Out-UDGridData
            }
    
            # FileShare Summary
            $FileShareSummaryProperties = @("Name","Health","ShareState","FileSharingProtocol","EncryptData","Hidden")
            $FileShareSummaryUDGridSplatParams = @{
                Title           = "FileShare Summary"
                Headers         = $FileShareSummaryProperties
                Properties      = $FileShareSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @FileShareSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageFileShareFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageFileShare" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageFileShareFunc
                    
                    $FileShareSummary = Get-StorageFileShare
    
                    [pscustomobject]@{
                        FileShareSummary    = $FileShareSummary | foreach {[pscustomobject]$_}
                    }
                }
                # See: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/stormgmt/msft-fileshare
                $Session:FileShareSummaryStatic = foreach ($obj in $StaticInfo.FileShareSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    $ShareState = switch ($obj.ShareState) {
                        '0'     {"Pending"}
                        '1'     {"Online"}
                        '2'     {"Offline"}
                        Default {$null}
                    }
    
                    $FileSharingProtocol = switch ($obj.FileSharingProtocol) {
                        '2'     {"NFS"}
                        '3'     {"CIFS(SMB)"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Name                = $obj.Name
                        Health              = $Health
                        ShareState          = $ShareState
                        FileSharingProtocol = $FileSharingProtocol
                        EncryptData         = $obj.EncryptData.ToString()
                        Hidden              = $obj.IsHidden.ToString()
                    }
                }
                
                $PUDRSSyncHT."$RemoteHost`Info".Storage.FileShareSummary = $Session:FileShareSummaryStatic
                
                $Session:FileShareSummaryStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:StoragePageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Storage/:RemoteHost" -Endpoint $StoragePageContent
    $null = $Pages.Add($Page)
    
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
    
    $UpdatesPageContent = {
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
                $Session:UpdatesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:UpdatesPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetWUAHistoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-WUAHistory" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetPendingUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-PendingUpdates" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetPendingUpdatesFunc
                Invoke-Expression $using:GetWUAHistoryFunc
                
                $UpdatesHistory = Get-WUAHistory
                $PendingUpdates = Get-PendingUpdates
    
                [pscustomobject]@{
                    UpdatesHistory      = $UpdatesHistory
                    PendingUpdates      = $PendingUpdates
                }
            }
            $Session:UpdatesHistoryStatic = $StaticInfo.UpdatesHistory
            $Session:PendingUpdatesStatic = $StaticInfo.PendingUpdates
            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.Keys -notcontains "UpdatesHistory") {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.Add("UpdatesHistory",$Session:UpdatesHistoryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.UpdatesHistory = $Session:UpdatesHistoryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.Keys -notcontains "PendingUpdates") {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.Add("PendingUpdates",$Session:PendingUpdatesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.PendingUpdates = $Session:PendingUpdatesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Updates (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetUpdatesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UpdatesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Updates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetUpdatesOverviewFunc,$GetUpdatesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Updates$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Updates$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllUpdatess = Get-Updates}
                            }
    
                            # Operations that you want to run once every second go here
                            @{UpdatesSummary = Get-UpdatesOverview -channel "Microsoft-Windows-UpdateservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Updates$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo equal to
                # $RSSyncHash."Updates$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo = $RSSyncHash."Updates$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                PS C:\Users\zeroadmin> $testWUAHist[0]
    
                Result              : Succeeded
                UpdateId            : 7aea2f20-80a5-44b7-aab1-f1f491651c13
                RevisionNumber      : 200
                Product             : Windows Defender
                Operation           : 1
                ResultCode          : 2
                HResult             : 0
                Date                : 8/29/2018 9:36:50 PM
                UpdateIdentity      : System.__ComObject
                Title               : Definition Update for Windows Defender Antivirus - KB2267602 (Definition 1.275.400.0)
                Description         : Install this update to revise the definition files that are used to detect viruses, spyware, and other potentially unwanted software. Once you have installed this item, it cannot be removed.
                UnmappedResultCode  : 0
                ClientApplicationID : Windows Defender (77BDAF73-B396-481F-9042-AD358843EC24)
                ServerSelection     : 2
                ServiceID           :
                UninstallationSteps : System.__ComObject
                UninstallationNotes :
                SupportUrl          : https://go.microsoft.com/fwlink/?LinkId=52661
                Categories          : System.__ComObject
    
    
                PS C:\Users\zeroadmin> $testPendUp[0]
    
                Computername     : ZEROTESTING
                Title            : Windows Malicious Software Removal Tool x64 - August 2018 (KB890830)
                KB               : 890830
                SecurityBulletin :
                MsrcSeverity     :
                IsDownloaded     : False
                Url              : http://support.microsoft.com/kb/890830
                Categories       : {Update Rollups, Windows Server 2016}
                BundledUpdates   : @{Title=Windows Malicious Software Removal Tool - August 2018 (KB890830) Multi-Lingual - Delta 5;
                                DownloadUrl=http://download.windowsupdate.com/c/msdownload/update/software/uprl/2018/08/windows-kb890830-x64-v5.63-delta_6ba4a8c5a8bd8441bbbca3dcbf38f337fefc1a82.exe}
            
            #>
    
            $UpdatesHistoryProperties = @("Title","Result","Product","KB","Date","Description","SupportUrl")
            $UpdatesHistoryUDGridSplatParams = @{
                Title           = "Updates History"
                Headers         = $UpdatesHistoryProperties
                Properties      = $UpdatesHistoryProperties
                PageSize        = 10
            }
            New-UDGrid @UpdatesHistoryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetWUAHistoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-WUAHistory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetWUAHistoryFunc
                    
                    $UpdatesHistory = Get-WUAHistory
    
                    [pscustomobject]@{
                        UpdatesHistory      = $UpdatesHistory
                    }
                }
                $Session:UpdatesHistoryStatic = foreach ($obj in $StaticInfo.UpdatesHistory) {
                    [pscustomobject]@{
                        Title       = $obj.Title
                        Result      = $obj.Result
                        Product     = $obj.Product
                        KB          = $($obj.Title | Select-String -Pattern "KB[0-9]+").Matches.Value
                        Date        = Get-Date $obj.Date -Format MM-dd-yy_hh:mm:sstt
                        Description = $obj.Description
                        SupportUrl  = $obj.SupportUrl
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Updates.UpdatesHistory = $Session:UpdatesHistoryStatic
                
                $Session:UpdatesHistoryStatic | Out-UDGridData
            }
    
            $PendingUpdatesProperties = @("Title","KB","MsrcSeverity","IsDownloaded","Url","Categories")
            $PendingUpdatesUDGridSplatParams = @{
                Title           = "Pending Updates"
                Headers         = $PendingUpdatesProperties
                Properties      = $PendingUpdatesProperties
                PageSize        = 10
            }
            New-UDGrid @PendingUpdatesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetPendingUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-PendingUpdates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetPendingUpdatesFunc
                    
                    $PendingUpdates = Get-PendingUpdates
    
                    [pscustomobject]@{
                        PendingUpdates      = $PendingUpdates
                    }
                }
                $Session:PendingUpdatesStatic = foreach ($obj in $StaticInfo.PendingUpdates) {
                    [pscustomobject]@{
                        Title               = $obj.Title
                        KB                  = 'KB' + $obj.KB
                        MsrcSeverity        = $obj.MsrcSeverity
                        IsDownloaded        = $obj.IsDownloaded
                        Url                 = $obj.Url
                        Categories          = $obj.Categories -join ", "
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Updates.PendingUpdates = $Session:PendingUpdatesStatic
                
                $Session:PendingUpdatesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:UpdatesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Updates/:RemoteHost" -Endpoint $UpdatesPageContent
    $null = $Pages.Add($Page)
    
    $UsersAndGroupsPageContent = {
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
                $Session:UsersAndGroupsPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:UsersAndGroupsPageLoadingTracker -notcontains "FinishedLoading") {
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
                            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Clone()
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
    
            $GetLocalUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalGroupUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroupUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalUserBelongGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUserBelongGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetLocalUsersFunc,$GetLocalGroupsFunc,$GetLocalGroupUsersFunc,$GetLocalUserBelongGroupsFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                $LocalUsersInfo = Get-LocalUsers | foreach {
                    [pscustomobject]@{
                        AccountExpires          = if ($_.AccountExpires) {$_.AccountExpires.ToString()} else {$null}
                        Description             = $_.Description
                        Enabled                 = $_.Enabled
                        FullName                = $_.FullName
                        LastLogon               = if ($_.LastLogon) {$_.LastLogon.ToString()} else {$null}
                        Name                    = $_.Name
                        GroupMembership         = $_.GroupMembership
                        ObjectClass             = $_.ObjectClass
                        PasswordChangeableDate  = if ($_.PasswordChangeableDate) {$_.PasswordChangeableDate.ToString()} else {$null}
                        PasswordExpires         = if ($_.PasswordExpires) {$_.PasswordExpires.ToString()} else {$null}
                        PasswordLastSet         = if ($_.PasswordLastSet) {$_.PasswordLastSet.ToString()} else {$null}
                        PasswordRequired        = $_.PasswordRequired
                        SID                     = $_.SID.Value
                        UserMayChangePassword   = $_.UserMayChangePassword
                    }
                }
                $LocalGroupsInfo = Get-LocalGroups 
    
                [pscustomobject]@{
                    LocalUsers      = $LocalUsersInfo
                    LocalGroups     = $LocalGroupsInfo
                }
            }
            $Session:LocalUsersStatic = $StaticInfo.LocalUsers
            $Session:LocalGroupsStatic = $StaticInfo.LocalGroups
            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalUsers") {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalUsers",$Session:LocalUsersStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalUsers = $Session:LocalUsersStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalGroups") {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalGroups",$Session:LocalGroupsStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalGroups = $Session:LocalGroupsStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "UsersAndGroups (In Progress)" -Size 3
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
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetUsersAndGroupsificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UsersAndGroupsificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetUsersAndGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UsersAndGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetUsersAndGroupsificateOverviewFunc,$GetUsersAndGroupsFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "UsersAndGroups$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "UsersAndGroups$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
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
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllUsersAndGroupss = Get-UsersAndGroups}
                            }
    
                            # Operations that you want to run once every second go here
                            @{UsersAndGroupsSummary = Get-UsersAndGroupsificateOverview -channel "Microsoft-Windows-UsersAndGroupservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "UsersAndGroups$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo equal to
                # $RSSyncHash."UsersAndGroups$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo = $RSSyncHash."UsersAndGroups$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            #$LocalUsersProperties = @("Name","FullName","SID","Enabled","GroupMembership","LastLogon","PasswordChangeableDate","PasswordExpires","PasswordLastSet","PasswordRequired","UserMayChangePassword")
            $LocalUsersProperties = @("Name","Enabled","GroupMembership","LastLogon","AccountExpires","PasswordChangeableDate","PasswordExpires","UserMayChangePassword")
            $LocalUsersUDGridSplatParams = @{
                Title           = "Local Users"
                Headers         = $LocalUsersProperties
                Properties      = $LocalUsersProperties
                PageSize        = 10
            }
            New-UDGrid @LocalUsersUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetLocalUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetLocalUserBelongGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUserBelongGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $FunctionsToLoad = @($GetLocalUsersFunc,$GetLocalUserBelongGroupsFunc)
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                    $LocalUsersInfo = Get-LocalUsers | foreach {
                        [pscustomobject]@{
                            AccountExpires          = if ($_.AccountExpires) {$_.AccountExpires.ToString()} else {$null}
                            Description             = $_.Description
                            Enabled                 = $_.Enabled.ToString()
                            FullName                = $_.FullName
                            LastLogon               = if ($_.LastLogon) {$_.LastLogon.ToString()} else {$null}
                            Name                    = $_.Name
                            GroupMembership         = $_.GroupMembership -join ", "
                            PasswordChangeableDate  = if ($_.PasswordChangeableDate) {$_.PasswordChangeableDate.ToString()} else {$null}
                            PasswordExpires         = if ($_.PasswordExpires) {$_.PasswordExpires.ToString()} else {$null}
                            PasswordLastSet         = if ($_.PasswordLastSet) {$_.PasswordLastSet.ToString()} else {$null}
                            PasswordRequired        = $_.PasswordRequired.ToString()
                            SID                     = $_.SID.Value
                            UserMayChangePassword   = $_.UserMayChangePassword.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        LocalUsers      = $LocalUsersInfo
                    }
                }
                $Session:LocalUsersStatic = $StaticInfo.LocalUsers
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalUsers") {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalUsers",$Session:LocalUsersStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalUsers = $Session:LocalUsersStatic
                }
    
                $Session:LocalUsersStatic | Out-UDGridData
            }
    
            $LocalGroupsProperties = @("Name","Description","SID","Members")
            $LocalGroupsUDGridSplatParams = @{
                Title           = "Local Groups"
                Headers         = $LocalGroupsProperties
                Properties      = $LocalGroupsProperties
                PageSize        = 10
            }
            New-UDGrid @LocalGroupsUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetLocalGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetLocalGroupUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroupUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $FunctionsToLoad = @($GetLocalGroupsFunc,$GetLocalGroupUsersFunc)
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                    $LocalGroupsInfo = Get-LocalGroups | foreach {
                        [pscustomobject]@{
                            Description         = $_.Description
                            Name                = $_.Name
                            SID                 = $_.SID
                            Members             = $_.Members -join ", "
                        }
                    }
    
                    [pscustomobject]@{
                        LocalGroups     = $LocalGroupsInfo
                    }
                }
                $Session:LocalGroupsStatic = $StaticInfo.LocalGroups
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalGroups") {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalGroups",$Session:LocalGroupsStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalGroups = $Session:LocalGroupsStatic
                }
    
                $Session:LocalGroupsStatic | Out-UDGridData
            }
    
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:UsersAndGroupsPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/UsersAndGroups/:RemoteHost" -Endpoint $UsersAndGroupsPageContent
    $null = $Pages.Add($Page)
    

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
        Return subkeys based on the path.
    
    .DESCRIPTION
        Return subkeys based on the path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RegistrySubKeys {
    Param([Parameter(Mandatory = $true)][string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $keyArray = @()
    $key = Get-Item $path
    foreach ($sub in $key.GetSubKeyNames() | Sort-Object)
    {
        $keyEntry = New-Object System.Object
        $keyEntry | Add-Member -type NoteProperty -name Name -value $sub  
        $subKeyPath = $key.PSPath+'\'+$sub
        $keyEntry | Add-Member -type NoteProperty -name Path -value $subKeyPath
        $keyEntry | Add-Member -type NoteProperty -name childCount -value @( Get-ChildItem $subKeyPath -ErrorAction SilentlyContinue ).Length
        $keyArray += $keyEntry
    }
    $keyArray
    
}


<#
    
    .SYNOPSIS
        Return values based on the key path.
    
    .DESCRIPTION
        Return values based on the key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RegistryValues {
    Param([string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $valueArray = @()
    $values = Get-Item  -path $path
    foreach ($val in $values.Property)
      {
        $valueEntry = New-Object System.Object
    
    
        if ($val -eq '(default)'){
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind('')
            $valueEntry | Add-Member -type NoteProperty -name data -value (get-itemproperty -literalpath $path).'(default)'
            }
        else{
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val 
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind($val)
            $valueEntry | Add-Member -type NoteProperty -name data -value $values.GetValue($val)
        }
    
        $valueArray += $valueEntry
      }
      $valueArray    
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
        Script to get list of scheduled tasks.
    
    .DESCRIPTION
        Script to get list of scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ScheduledTasks {
    param (
      [Parameter(Mandatory = $false)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $false)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    function New-TaskWrapper
    {
      param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        $task
      )
    
      $task | Add-Member -MemberType NoteProperty -Name 'status' -Value $task.state.ToString()
      $info = Get-ScheduledTaskInfo $task
    
      $triggerCopies = @()
      for ($i=0;$i -lt $task.Triggers.Length;$i++)
      {
        $trigger = $task.Triggers[$i];
        $triggerCopy = $trigger.PSObject.Copy();
        if ($trigger -ne $null) {
            if ($trigger.StartBoundary -eq $null -or$trigger.StartBoundary -eq '') 
            {
                $startDate = $null;
            }
            else 
            {
                $startDate = [datetime]($trigger.StartBoundary)
            }
          
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerAtDate' -Value $startDate -TypeName System.DateTime
    
            if ($trigger.EndBoundary -eq $null -or$trigger.EndBoundary -eq '') 
            {
                $endDate = $null;
            }
            else 
            {
                $endDate = [datetime]($trigger.EndBoundary)
            }
            
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerEndDate' -Value $endDate -TypeName System.DateTime
    
            $triggerCopies += $triggerCopy
        }
    
      }
    
      $task | Add-Member -MemberType NoteProperty -Name 'TriggersEx' -Value $triggerCopies
    
      New-Object -TypeName PSObject -Property @{
          
          ScheduledTask = $task
          ScheduledTaskInfo = $info
      }
    }
    
    if ($taskPath -and $taskName) {
      try
      {
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        New-TaskWrapper $task
      }
      catch
      {
      }
    } else {
        Get-ScheduledTask | ForEach-Object {
          New-TaskWrapper $_
        }
    }
    
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
        Enumerates all of the local disks of the system.
    
    .DESCRIPTION
        Enumerates all of the local disks of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-StorageDisk {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $DiskId
    )
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Utility
    
    <#
    .Synopsis
        Name: Get-Disks
        Description: Gets all the local disks of the machine.
    
    .Parameters
        $DiskId: The unique identifier of the disk desired (Optional - for cases where only one disk is desired).
    
    .Returns
        The local disk(s).
    #>
    function Get-DisksInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $DiskId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace Root\Microsoft\Windows\Storage | Where-Object { !$_.IsClustered };
        }
        else
        {
            $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage| Where-Object { $_.FriendlyName -like "Win*" };
            $disks = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Disk;
        }
    
        if ($DiskId)
        {
            $disks = $disks | Where-Object { $_.UniqueId -eq $DiskId };
        }
    
    
        $disks | %{
        $partitions = $_ | Get-CimAssociatedInstance -ResultClassName MSFT_Partition
        $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume
        $volumeIds = @()
        $volumes | %{
            
            $volumeIds += $_.path 
        }
            
        $_ | Add-Member -NotePropertyName VolumeIds -NotePropertyValue $volumeIds
    
        }
    
        $disks = $disks | ForEach-Object {
    
           $disk = @{
                AllocatedSize = $_.AllocatedSize;
                BootFromDisk = $_.BootFromDisk;
                BusType = $_.BusType;
                FirmwareVersion = $_.FirmwareVersion;
                FriendlyName = $_.FriendlyName;
                HealthStatus = $_.HealthStatus;
                IsBoot = $_.IsBoot;
                IsClustered = $_.IsClustered;
                IsOffline = $_.IsOffline;
                IsReadOnly = $_.IsReadOnly;
                IsSystem = $_.IsSystem;
                LargestFreeExtent = $_.LargestFreeExtent;
                Location = $_.Location;
                LogicalSectorSize = $_.LogicalSectorSize;
                Model = $_.Model;
                NumberOfPartitions = $_.NumberOfPartitions;
                OfflineReason = $_.OfflineReason;
                OperationalStatus = $_.OperationalStatus;
                PartitionStyle = $_.PartitionStyle;
                Path = $_.Path;
                PhysicalSectorSize = $_.PhysicalSectorSize;
                ProvisioningType = $_.ProvisioningType;
                SerialNumber = $_.SerialNumber;
                Signature = $_.Signature;
                Size = $_.Size;
                UniqueId = $_.UniqueId;
                UniqueIdFormat = $_.UniqueIdFormat;
                volumeIds = $_.volumeIds;
                Number = $_.Number;
            }
            if (-not $isDownLevel)
            {
                $disk.IsHighlyAvailable = $_.IsHighlyAvailable;
                $disk.IsScaleOut = $_.IsScaleOut;
            }
            return $disk;
        }
    
        if ($isDownlevel)
        {
            $healthStatusMap = @{
                0 = 3;
                1 = 0;
                4 = 1;
                8 = 2;
            };
    
            $operationalStatusMap = @{
                0 = @(0);      # Unknown
                1 = @(53264);  # Online
                2 = @(53265);  # Not ready
                3 = @(53266);  # No media
                4 = @(53267);  # Offline
                5 = @(53268);  # Error
                6 = @(13);     # Lost communication
            };
    
            $disks = $disks | ForEach-Object {
                $_.HealthStatus = $healthStatusMap[[int32]$_.HealthStatus];
                $_.OperationalStatus = $operationalStatusMap[[int32]$_.OperationalStatus[0]];
                $_;
            };
        }
    
        return $disks;
    }
    
    if ($DiskId)
    {
        Get-DisksInternal -DiskId $DiskId
    }
    else
    {
        Get-DisksInternal
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local file shares of the system.
    
    .DESCRIPTION
        Enumerates all of the local file shares of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER FileShareId
        The file share ID.

#>
function Get-StorageFileShare {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $FileShareId
    )
    
    Import-Module CimCmdlets
    
    <#
    .Synopsis
        Name: Get-FileShares-Internal
        Description: Gets all the local file shares of the machine.
    
    .Parameters
        $FileShareId: The unique identifier of the file share desired (Optional - for cases where only one file share is desired).
    
    .Returns
        The local file share(s).
    #>
    function Get-FileSharesInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $FileShareId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            # Map downlevel status to array of [health status, operational status, share state] uplevel equivalent
            $statusMap = @{
                "OK" =         @(0, 2, 1);
                "Error" =      @(2, 6, 2);
                "Degraded" =   @(1, 3, 2);
                "Unknown" =    @(5, 0, 0);
                "Pred Fail" =  @(1, 5, 2);
                "Starting" =   @(1, 8, 0);
                "Stopping" =   @(1, 9, 0);
                "Service" =    @(1, 11, 1);
                "Stressed" =   @(1, 4, 1);
                "NonRecover" = @(2, 7, 2);
                "No Contact" = @(2, 12, 2);
                "Lost Comm" =  @(2, 13, 2);
            };
            
            $shares = Get-CimInstance -ClassName Win32_Share |
                ForEach-Object {
                    return @{
                        ContinuouslyAvailable = $false;
                        Description = $_.Description;
                        EncryptData = $false;
                        FileSharingProtocol = 3;
                        HealthStatus = $statusMap[$_.Status][0];
                        IsHidden = $_.Name.EndsWith("`$");
                        Name = $_.Name;
                        OperationalStatus = ,@($statusMap[$_.Status][1]);
                        ShareState = $statusMap[$_.Status][2];
                        UniqueId = "smb|" + (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain + "\" + $_.Name;
                        VolumePath = $_.Path;
                    }
                }
        }
        else
        {        
            $shares = Get-CimInstance -ClassName MSFT_FileShare -Namespace Root\Microsoft\Windows/Storage |
                ForEach-Object {
                    return @{
                        IsHidden = $_.Name.EndsWith("`$");
                        VolumePath = $_.VolumeRelativePath;
                        ContinuouslyAvailable = $_.ContinuouslyAvailable;
                        Description = $_.Description;
                        EncryptData = $_.EncryptData;
                        FileSharingProtocol = $_.FileSharingProtocol;
                        HealthStatus = $_.HealthStatus;
                        Name = $_.Name;
                        OperationalStatus = $_.OperationalStatus;
                        UniqueId = $_.UniqueId;
                        ShareState = $_.ShareState;
                    }
                }
        }
    
        if ($FileShareId)
        {
            $shares = $shares | Where-Object { $_.UniqueId -eq $FileShareId };
        }
    
        return $shares;
    }
    
    if ($FileShareId)
    {
        Get-FileSharesInternal -FileShareId $FileShareId;
    }
    else
    {
        Get-FileSharesInternal;
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local volumes of the system.
    
    .DESCRIPTION
        Enumerates all of the local volumes of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER VolumeId
        The volume ID
    
#>
function Get-StorageVolume {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $VolumeId
    )
    
    ############################################################################################################################
    
    # Global settings for the script.
    
    ############################################################################################################################
    
    $ErrorActionPreference = "Stop"
    
    Set-StrictMode -Version 3.0
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Management
    Import-Module Microsoft.PowerShell.Utility
    Import-Module Storage
    
    ############################################################################################################################
    
    # Helper functions.
    
    ############################################################################################################################
    
    <# 
    .Synopsis
        Name: Get-VolumePathToPartition
        Description: Gets the list of partitions (that have volumes) in hashtable where key is volume path.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-VolumePathToPartition
    {
        $volumePaths = @{}
    
        foreach($partition in Get-Partition)
        {
            foreach($volumePath in @($partition.AccessPaths))
            {
                if($volumePath -and (-not $volumePaths.Contains($volumePath)))
                {
                    $volumePaths.Add($volumePath, $partition)
                }
            }
        }
        
        $volumePaths
    }
    
    <# 
    .Synopsis
        Name: Get-DiskIdToDisk
        Description: Gets the list of all the disks in hashtable where key is:
                     "Disk.Path" in case of WS2016 and above.
                     OR
                     "Disk.ObjectId" in case of WS2012 and WS2012R2.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-DiskIdToDisk
    {    
        $diskIds = @{}
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        # In downlevel Operating systems. MSFT_Partition.DiskId is equal to MSFT_Disk.ObjectId
        # However, In WS2016 and above,   MSFT_Partition.DiskId is equal to MSFT_Disk.Path
    
        foreach($disk in Get-Disk)
        {
            if($isDownlevel)
            {
                $diskId = $disk.ObjectId
            }
            else
            {
                $diskId = $disk.Path
            }
    
            if(-not $diskIds.Contains($diskId))
            {
                $diskIds.Add($diskId, $disk)
            }
        }
    
        return $diskIds
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2012 and Ws2012R2 Operating Systems.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeDownlevelOS
    {
        $volumes = @()
        
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
           $partition = $script:partitions.Get_Item($volume.Path)
    
           # Check if this volume is associated with a partition.
           if($partition)
           {
                # If this volume is associated with a partition, then get the disk to which this partition belongs.
                $disk = $script:disks.Get_Item($partition.DiskId)
    
                # If the disk is a clustered disk then simply ignore this volume.
                if($disk -and $disk.IsClustered) {continue}
           }
      
           $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2016 and above Operating System.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeWs2016AndAboveOS
    {
        $volumes = @()
        
        $applicableVolumePaths = @{}
    
        $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" }
    
        foreach($volume in @($subSystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path))
            {
                $applicableVolumePaths.Add($volume.Path, $null)
            }
        }
    
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path)) { continue }
    
            $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumesList
        Description: Gets the list of all applicable volumes w.r.t to the target Operating System.
                     
    .Returns
        The list of all applicable volumes.
    #>
    function Get-VolumesList
    {
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        if($isDownlevel)
        {
             return Get-VolumeDownlevelOS
        }
    
        Get-VolumeWs2016AndAboveOS
    }
    
    ############################################################################################################################
    
    # Helper Variables
    
    ############################################################################################################################
    
    $script:fixedDriveType = 3
    
    $script:disks = Get-DiskIdToDisk
    
    $script:partitions = Get-VolumePathToPartition
    
    ############################################################################################################################
    
    # Main script.
    
    ############################################################################################################################
    
    $resultantVolumes = @()
    
    $volumes = Get-VolumesList
    
    foreach($volume in $volumes)
    {
        $partition = $script:partitions.Get_Item($volume.Path)
    
        if($partition -and $volume.DriveType -eq $script:fixedDriveType)
        {
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $partition.IsSystem
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $partition.IsBoot
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $partition.IsActive
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue $partition.PartitionNumber
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue $partition.DiskNumber
    
        }
        else
        {
            # This volume is not associated with partition, as such it is representing devices like CD-ROM, Floppy drive etc.
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue -1
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue -1
        }
           
        $resultantVolumes += $volume
    }
    
    $resultantVolumes | % {
        [String] $name = '';
     
        # On the downlevel OS, the drive letter is showing charachter. The ASCII code for that char is 0.
        # So rather than checking null or empty, code is checking the ASCII code of the drive letter and updating 
        # the drive letter field to null explicitly to avoid discrepencies on UI.
        if ($_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
             $name = $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"
        } 
        elseif (!$_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
              $name =  "(" + $_.DriveLetter + ":)" 
        }
        elseif ($_.FileSystemLabel -and [byte]$_.DriveLetter -eq 0)
        {
             $name = $_.FileSystemLabel
        }
        else 
        {
             $name = ''
        }
    
        if ([byte]$_.DriveLetter -eq 0)
        {
            $_.DriveLetter = $null
        }
    
        $_ | Add-Member -Force -NotePropertyName "Name" -NotePropertyValue $name
          
    }
    
    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    $resultantVolumes = $resultantVolumes | ForEach-Object {
    
    $volume = @{
            Name = $_.Name;
            DriveLetter = $_.DriveLetter;
            HealthStatus = $_.HealthStatus;
            DriveType = $_.DriveType;
            FileSystem = $_.FileSystem;
            FileSystemLabel = $_.FileSystemLabel;
            Path = $_.Path;
            PartitionNumber = $_.PartitionNumber;
            DiskNumber = $_.DiskNumber;
            Size = $_.Size;
            SizeRemaining = $_.SizeRemaining;
            IsSystem = $_.IsSystem;
            IsBoot = $_.IsBoot;
            IsActive = $_.IsActive;
        }
    
    if ($isDownlevel)
    {
        $volume.FileSystemType = $_.FileSystem;
    } 
    else {
    
        $volume.FileSystemType = $_.FileSystemType;
        $volume.OperationalStatus = $_.OperationalStatus;
        $volume.HealthStatus = $_.HealthStatus;
        $volume.DriveType = $_.DriveType;
        $volume.DedupMode = $_.DedupMode;
        $volume.UniqueId = $_.UniqueId;
        $volume.AllocationUnitSize = $_.AllocationUnitSize;
      
       }
    
       return $volume;
    }                                    
    
    #
    # Return results back to the caller.
    #
    if($VolumeId)
    {
        $resultantVolumes  | Where-Object {$_.Path -eq $resultantVolumes}
    }
    else
    {
        $resultantVolumes   
    }
    
    
}


# From: https://stackoverflow.com/a/41626130
function Get-WuaHistory {
    #region >> Helper Functions

    function Convert-WuaResultCodeToName {
        param(
            [Parameter(Mandatory=$True)]
            [int]$ResultCode
        )
    
        $Result = $ResultCode
        switch($ResultCode) {
          2 {$Result = "Succeeded"}
          3 {$Result = "Succeeded With Errors"}
          4 {$Result = "Failed"}
        }
    
        return $Result
    }

    #endregion >> Helper Functions

    # Get a WUA Session
    $session = (New-Object -ComObject 'Microsoft.Update.Session')

    # Query the latest 1000 History starting with the first recordp     
    $history = $session.QueryHistory("",0,1000) | foreach {
        $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode

        # Make the properties hidden in com properties visible.
        $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
        $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
        $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
        $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru

        Write-Output $_
    } 

    #Remove null records and only return the fields we want
    $history | Where-Object {![String]::IsNullOrWhiteSpace($_.title)}
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
    ${Function:Get-FirewallProfile}.Ast.Extent.Text
    ${Function:Get-FirewallRules}.Ast.Extent.Text
    ${Function:Get-LocalGroups}.Ast.Extent.Text
    ${Function:Get-LocalGroupUsers}.Ast.Extent.Text
    ${Function:Get-LocalUserBelongGroups}.Ast.Extent.Text
    ${Function:Get-LocalUsers}.Ast.Extent.Text
    ${Function:Get-Networks}.Ast.Extent.Text
    ${Function:Get-PendingUpdates}.Ast.Extent.Text
    ${Function:Get-Processes}.Ast.Extent.Text
    ${Function:Get-PUDAdminCenter}.Ast.Extent.Text
    ${Function:Get-RegistrySubKeys}.Ast.Extent.Text
    ${Function:Get-RegistryValues}.Ast.Extent.Text
    ${Function:Get-RemoteDesktop}.Ast.Extent.Text
    ${Function:Get-ScheduledTasks}.Ast.Extent.Text
    ${Function:Get-ServerInventory}.Ast.Extent.Text
    ${Function:Get-StorageDisk}.Ast.Extent.Text
    ${Function:Get-StorageFileShare}.Ast.Extent.Text
    ${Function:Get-StorageVolume}.Ast.Extent.Text
    ${Function:Get-WUAHistory}.Ast.Extent.Text
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAAkqDdOUDAiVBymnr+L2ElXi
# oFugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMh3aJ0dumnjLVhS
# 2y7TdpJuDWolMA0GCSqGSIb3DQEBAQUABIIBAMMPJRQbe5MkQ44Ulywf1t5qOk+L
# zL9kAF/HkBLyJJui52QvX/vSsxcwaqt3eA+76QGGT21pZ+ibZg4CnECfig9hJZG/
# sKp0hcvkN5hnbmrlfxfPRy+x8uZ87102He3SSncOKGqzial5tpnI0y5kOYIo4nJY
# XgNxAGHGj/TeRKrjW8cT/if2CrN9AMo4ESJKaKUQYgFUqNEF0vZsvr82OaaDNXEN
# Z0e/MPvE9jhqRUnkbkvirmGePfqqKgRrQpC440c/bvs9CzZEur+H/PomrUzjDvQg
# EuqISEIhshSyR6/1cQcE5s0kNTBdon/Hjw7+SbqBfq7GJ2NjpCEQiuCXXmM=
# SIG # End signature block
