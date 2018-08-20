#region >> Create Home Page

$HomePageContent = {
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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
            # We are within an -Endpoint, so $Session: variables should be available
            #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
            if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
            }
            else {
                $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
            }
        }
        else {
            $GridData.Add("ManageLink","Unavailable")
        }

        $GridData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))
        
        [pscustomobject]$GridData | Out-UDTableData -Property @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
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
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgeAvN0HP7mb2IzxYF/Hzgicb
# ccCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHJqKTomYGiv4m5Y
# b9xceu46LP2NMA0GCSqGSIb3DQEBAQUABIIBAGLR/ppHM2TxpLpk6AbIP4Pwx+HD
# wGbyMrPuTNZSwemaHLHcPrLY2YiYQDKtETXXAfNIpzeEIBZaKkmhqOop2fakWD84
# XiIZXTP88SsBQXSW2CFc06DMFZzm4hEScp7VFHGY0t7TFGuPSBFC0s4GYdv5LcnO
# aR2qdfnAQ/GTmsdV7LSr+Lp8m+nI3jr+30AvT7Kf/tXHzPIIyYp52xKOCgFZcSRz
# 43vRJqBJmxM/hpYgzHmcEW6dtbVsw4p+oNp/VX0yhlnbGQpQFY0tfKel7/FhKTpt
# dtu0RFZjHgj6IBVKrOLN3WjKKNuJGctRw+UnZpqgA0Jvj8gYd3HuLTbUK6A=
# SIG # End signature block
