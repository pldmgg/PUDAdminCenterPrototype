#region >> Disconnected Page

$DisconnectedPageContent = {
    param($RemoteHost)

    # Add the SyncHash to the Page so that we can pass output to other pages
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUj8ydGGMP9zgjIOGbM1N2hIeg
# GySgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJ15sjVWzMubeFo0
# BTedsYjv9TExMA0GCSqGSIb3DQEBAQUABIIBADbl15B7IEIUd/s8h2QtswLl7ktX
# AsV80CpVPayxhokuYWfxZBlyBLL+oknlVkZq/RGAq5LaXzSmiWd6oPEaerYQIEJ/
# snBfEJsdphuf9KxculN+9Jca1PhjO4lO8gINKj8YUErLp+6CXU+213aoUjDrD8Z8
# CZ3ov6/SYDMADAycrVBwOvZnrO3/J9Or4ekY3lkWAA40e8qCt+AqE3i+Dv5Za7GQ
# /qImwz7gNsmDEp5D/ekAK3WE2Asi658i9pXjSEp/EZcH/XndR0sVMbPP2RHrDkAb
# P0xHXl6v/1ntikQpI3SRq7VcNYWDSZC2lvUlMxpcrhVtdwu0Qfo86d6DC0g=
# SIG # End signature block
