#region >> Tool Select Page

$ToolSelectPageContent = {
    param($RemoteHost)

    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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

        # Load PUDWinAdminCenter Module Functions Within ScriptBlock
        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)

        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]

        if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
            Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
        }
        else {
            # Check $Session:CredentialHT.$RemoteHost.PSRemotingCreds Credentials. If they don't work, redirect to "/PSRemotingCreds/$RemoteHost"
            try {
                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RHostIP -AltCredentials $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ErrorAction Stop

                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                        Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                    }
                }
                else {
                    Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                }
            }
            catch {
                Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
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

                        # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEjVKp32ch1X9aRXeuPszYWn6
# XMugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAISQ84O2MtPVJq9
# TyZxhTRcjJlHMA0GCSqGSIb3DQEBAQUABIIBAKBPkyIL0ViG4sK2cj31EFyNXDDP
# pMxFFF8T62GNYgRcEpE5J4fEuqdg2t+3DiryUQPUQeGvSRGjT02pQhCcLJeHfXgz
# p9PZhMDKzvpCEm4/1qg1NrszhWUPv9GgP7ONXJX8syuK7+ZZ17OnLBULfuZhi5F6
# RwiSx6QvPsuU/bcuMN9/Cs+9smR9Ihk4OVxc5IrxhcQz+t8HV+2RPezMnsSvrH7G
# ycFzJtyUWYMZa/H7LpkY8ru75m+8VSuM6ljQWdg0ShtfHLtWyGp8ziNa5I6AEyuG
# NRQJXusZUlPAenu8IMK0oN+2XYqHHY40lrGYbeOXqrpMN8dx8YIuRNbVUCY=
# SIG # End signature block
