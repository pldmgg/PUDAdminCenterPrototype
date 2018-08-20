#region >> PSRemoting Creds Page

$PSRemotingCredsPageContent = {
    param($RemoteHost)

    # Add the SyncHash to the Page so that we can pass output to other pages
    #$PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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

                # Load PUDWinAdminCenter Module Functions Within ScriptBlock
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

                if ($Session:CredentialHT -eq $null) {
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
                    #$Session:CredentialHT = $PUDRSSyncHT."$RemoteHost`Info".CredHT = $Session:CredentialHT
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
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUz4AoIiQC90y69vxnWwkyp192
# F0ugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDD6vsGb87MqC11+
# 7vlqlGv9A+OxMA0GCSqGSIb3DQEBAQUABIIBACDVbbhGv0yWD+xmYSTMDAiKkeyk
# 7kFBQLQoSEoeagg+AbVo7c8D7Khf8JzreuDsviTTRU1cd3fGZApT0gAM0RW6Tg7D
# 9f1dPq7TP8eMpUhmFVxjjqmqVRMJOMtBQ5Zv2ax49pJkYz427gVAFsKGvlTHAcK2
# xB6oLWRJe5QBicfNRc0UghSFXmkylObRNngmjmMNrjCHB53R2+W5YCXnXOSKyHC8
# zQo2iwuFZrpY22DTwcCoLCLXigvgpoCt2gaXpc2nce7FoHwcKoDLSVDpYdPQoevy
# ZEY/5Hbmi8mOsRm6vhcB0M3UTiINtUvp6HCZ1vHgCJ3xwnaY9jggKqhDoAc=
# SIG # End signature block
