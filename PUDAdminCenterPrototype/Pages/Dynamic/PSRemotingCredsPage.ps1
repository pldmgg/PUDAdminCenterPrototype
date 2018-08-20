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