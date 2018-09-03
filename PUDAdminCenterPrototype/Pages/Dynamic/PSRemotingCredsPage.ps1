#region >> PSRemoting Creds Page

$PSRemotingCredsPageContent = {
    param($RemoteHost)

    New-UDColumn -Endpoint {$Session:ThisRemoteHost = $RemoteHost}

    # Add the SyncHash to the Page so that we can pass output to other pages
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

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
            $Session:NoCredsEntered = $False
            $Session:InvalidSSHPubCert = $False
            $Session:SSHRemotingMethodNoCert = $False
            $Session:DomainRemotingMethodNoCreds = $False
            $Session:LocalRemotingMethodNoCreds = $False
            $Session:UserNameAndPasswordRequired = $False
            $Session:BadFormatDomainUserName = $False
            $Session:EnableWinRMFailure = $False
            $Session:GetWorkingCredsFailure = $False
            $Session:InvalidCreds = $False
            $Session:CheckingCredentials = $False
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

        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
            New-UDElement -Id "CheckingCredentials" -Tag div -EndPoint {
                if ($Session:CheckingCredentials) {
                    New-UDHeading -Text "Checking Credentials for $Session:ThisRemoteHost...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }

        New-UDColumn -EndPoint {
            New-UDElement -Id "ValidateCredsMsg" -Tag div -EndPoint {
                #New-UDHeading -Text "RemoteHost is $Session:ThisRemoteHost!" -Size 6 -Color red

                if ($Session:NoCredsEntered) {
                    New-UDHeading -Text "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Size 6 -Color red
                    $Session:NoCredsEntered = $False
                }
                if ($Session:InvalidSSHPubCert) {
                    New-UDHeading -Text "The string provided is not a valid SSH Public Certificate!" -Size 6 -Color red
                    $Session:InvalidSSHPubCert = $False
                }
                if ($Session:SSHRemotingMethodNoCert) {
                    New-UDHeading -Text "You indicated that SSH is your Preferred_PSRemotingMethod, however, you did not provide a value for Path_To_SSH_Public_Cert!" -Size 6 -Color red
                    $Session:SSHRemotingMethodNoCert = $False
                }
                if ($Session:DomainRemotingMethodNoCreds) {
                    New-UDHeading -Text "You indicated that 'Domain' was your Preferred_PSRemotingCredType, however, you did not provide Domain Credentials!" -Size 6 -Color red
                    $Session:DomainRemotingMethodNoCreds = $False
                }
                if ($Session:LocalRemotingMethodNoCreds) {
                    New-UDHeading -Text "You indicated that 'Local' was your Preferred_PSRemotingCredType, however, you did not provide Local Credentials!" -Size 6 -Color red
                    $Session:LocalRemotingMethodNoCreds = $False
                }
                if ($Session:UserNameAndPasswordRequired) {
                    New-UDHeading -Text "Please enter both a UserName and a Password!" -Size 6 -Color red
                    $Session:UserNameAndPasswordRequired = $False
                }
                if ($Session:BadFormatDomainUserName) {
                    New-UDHeading -Text "Domain_UserName must be in format 'Domain\DomainUser'!" -Size 6 -Color red
                    $Session:BadFormatDomainUserName = $False
                }
                if ($Session:EnableWinRMFailure) {
                    New-UDHeading -Text "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Size 6 -Color red
                    $Session:EnableWinRMFailure = $False
                }
                if ($Session:GetWorkingCredsFailure) {
                    New-UDHeading -Text "Unable to test Credentials! Please try again." -Size 6 -Color red
                    $Session:GetWorkingCredsFailure = $False
                }
                if ($Session:InvalidCreds) {
                    New-UDHeading -Text "Invalud Credentials! Please try again." -Size 6 -Color red
                    $Session:InvalidCreds = $False
                }
            }
        }
    }

    #endregion >> Loading Indicator

    <#
    New-UDRow -Endpoint {
        New-UDColumn -Size 2 -Content {}
        New-UDColumn -Size 8 -Endpoint {
            New-UDRow -Endpoint {
                New-UDTextbox -Id "LocalUserName" -Label "Local UserName" -Type text
                New-UDTextbox -Id "LocalPassword" -Label "Local Password" -Type password
                New-UDTextbox -Id "DomainUserName" -Label "Domain UserName" -Type text
                New-UDTextbox -Id "DomainPassword" -Label "Domain Password" -Type password
                New-UDTextbox -Id "SSHPublicCert" -Label "SSH Public Certificate" -Type text
                New-UDSelect -Id "PreferredPSRemotingCredType" -Label "Credential Type" -Option {
                    New-UDSelectOption -Name "Domain" -Value "Domain" -Selected
                    New-UDSelectOption -Name "Local" -Value "Local"
                }
                New-UDSelect -Id "PreferredPSRemotingMethod" -Label "PSRemoting Method" -Option {
                    New-UDSelectOption -Name "WinRM" -Value "WinRM" -Selected
                    New-UDSelectOption -Name "SSH" -Value "SSH"
                }
            }
            New-UDRow -EndPoint {
                New-UDButton -Text "Set Credentials" -OnClick {
                    $PUDRSSyncHT = $global:PUDRSSyncHT

                    $Session:CheckingCredentials = $True
                    Sync-UDElement -Id "CheckingCredentials"

                    $LocalUserNameTextBox = Get-UDElement -Id "LocalUserName"
                    $LocalPasswordTextBox = Get-UDElement -Id "LocalPassword"
                    $DomainUserNameTextBox = Get-UDElement -Id "DomainUserName"
                    $DomainPasswordTextBox = Get-UDElement -Id "DomainPassword"
                    $SSHPublicCertTextBox = Get-UDElement -Id "SSHPublicCert"
                    $PrefCredTypeSelection = Get-UDElement -Id "PreferredPSRemotingCredType"
                    $PrefRemotingMethodSelection = Get-UDElement -Id "PreferredPSRemotingMethod"
                    
                    $Local_UserName = $LocalUserNameTextBox.Attributes['value']
                    $Local_Password = $LocalPasswordTextBox.Attributes['value']
                    $Domain_UserName = $DomainUserNameTextBox.Attributes['value']
                    $Domain_Password = $DomainPasswordTextBox.Attributes['value']
                    $SSHPublicCertString = $SSHPublicCertTextBox.Attributes['value']
                    $Preferred_PSRemotingCredType = $($PrefCredTypeSelection.Content | foreach {
                        $_.ToString() | ConvertFrom-Json
                    } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
                    $Preferred_PSRemotingMethod = $($PrefRemotingMethodSelection.Content | foreach {
                        $_.ToString() | ConvertFrom-Json
                    } | Where-Object {$_.attributes.selected.isPresent}).attributes.value

                    $TestingCredsObj = [pscustomobject]@{
                        LocalUserNameTextBox            = $LocalUserNameTextBox
                        LocalPasswordTextBox            = $LocalPasswordTextBox
                        DomainUserNameTextBox           = $DomainUserNameTextBox
                        DomainPasswordTextBox           = $DomainPasswordTextBox
                        SSHPublicCertTextBox            = $SSHPublicCertTextBox
                        PrefCredTypeSelection           = $PrefCredTypeSelection
                        PrefRemotingMethodSelection     = $PrefRemotingMethodSelection
                        Local_UserName                  = $Local_UserName
                        Local_Password                  = $Local_Password
                        Domain_UserName                 = $Domain_UserName
                        Domain_Password                 = $Domain_Password
                        SSHPublicCertString             = $SSHPublicCertString
                        Preferred_PSRemotingCredType    = $Preferred_PSRemotingCredType
                        Preferred_PSRemotingMethod      = $Preferred_PSRemotingMethod
                        RemoteHost                      = $Session:ThisRemoteHost
                    }

                    if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
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
                        $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)

                        # TODO: Need to remove this when finished testing
                        $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT

                        #New-UDInputAction -Toast "`$Session:CredentialHT was null" -Duration 10000
                    }

                    # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                    if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                    }
                    if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                    }
                    if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                    }
                    if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                    }
                    if (!$SSHPublicCertString -and $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath -ne $null) {
                        $SSHPublicCertString = $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath
                    }
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }

                    if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$SSHPublicCertString) {
                        $Session:NoCredsEntered = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if ($SSHPublicCertString) {
                        # TODO: Validate the provided string is a SSH Public Cert
                        if ($BadSSHPubCert) {
                            $Session:InvalidSSHPubCert = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
                    }

                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }
                    if ($Preferred_PSRemotingMethod -eq "SSH" -and !$SSHPublicCertString) {
                        $Session:SSHRemotingMethodNoCert = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain" -and $(!$Domain_UserName -or !$Domain_Password)) {
                        $Session:DomainRemotingMethodNoCreds = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if ($Preferred_PSRemotingCredType -eq "Local" -and $(!$Local_UserName -or !$Local_Password)) {
                        $Session:LocalRemotingMethodNoCreds = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                    $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                    ) {
                        $Session:UserNameAndPasswordRequired = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if ($Local_UserName -and $Local_Password) {
                        # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                        if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                            $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                        }

                        $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                        $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                    }

                    if ($Domain_UserName -and $Domain_Password) {
                        $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                            $Session:BadFormatDomainUserName = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
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
                            $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
            
                            if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            else {
                                $null = $FailedCredentialsA.Add($CredObj)
                            }
                        }
                        catch {}
                    }

                    if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                    $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                    ) {
                        # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                        $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open

                        [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            if ($RPCPortOpen) {
                                try {
                                    $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                    $null = $EnableWinRMSuccess.Add($CredObj)
                                    break
                                }
                                catch {
                                    #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                }
                            }
                        }

                        if ($EnableWinRMSuccess.Count -eq 0) {
                            $Session:EnableWinRMFailure = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
                        else {
                            [System.Collections.ArrayList]$FailedCredentialsB = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                try {
                                    $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                    
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                        $null = $FailedCredentialsB.Add($CredObj)
                                    }
                                }
                                catch {
                                    $Session:GetWorkingCredsFailure = $True
                                    Sync-UDElement -Id "ValidateCredsMsg"
                                    $Session:CheckingCredentials = $False
                                    Sync-UDElement -Id "CheckingCredentials"
                                    return
                                    
                                    #Show-UDToast -Message $_.Exception.Message -Duration 10
                                }
                            }
                        }
                    }

                    if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                        if ($FailedCredentialsB.Count -gt 0) {
                            foreach ($CredObj in $FailedCredentialsB) {
                                $Session:GetWorkingCredsFailure = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                #$Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                            }
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
                        if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                            foreach ($CredObj in $FailedCredentialsA) {
                                $Session:GetWorkingCredsFailure = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                            }
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
                    }

                    if ($DomainAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                    }
                    if ($LocalAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                    }
                    if ($SSHPublicCertString) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath = $SSHPublicCertString
                    }
                    if ($Preferred_PSRemotingCredType) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingMethod) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                    }

                    # Determine $PSRemotingCreds
                    if ($Preferred_PSRemotingCredType -eq "Local") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                    }

                    Invoke-UDRedirect -Url "/ToolSelect/$Session:ThisRemoteHost"
                }
            }
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                try {
                    $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                }
                catch {
                    Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                }
            }
        }
        New-UDColumn -Size 2 -Content {}
    }
    #>

    New-UDRow -Endpoint {
        New-UDColumn -Size 2 -EndPoint {}
        New-UDColumn -Size 8 -EndPoint {
            $PUDRSSyncHT = $global:PUDRSSyncHT

            $Cache:CredsForm = New-UDInput -SubmitText "Set Credentials" -Id "CredsForm" -Content {
                New-UDInputField -Type textbox -Name 'Local_UserName' -Value $null
                New-UDInputField -Type password -Name 'Local_Password' -Value $null
                New-UDInputField -Type textbox -Name 'Domain_UserName' -Value $null
                New-UDInputField -Type password -Name 'Domain_Password' -Value $null
                New-UDInputField -Type textarea -Name 'SSH_Public_Cert' -Value $null
                New-UDInputField -Type select -Name 'Preferred_PSRemotingCredType' -Values @("Local","Domain") -DefaultValue "Domain"
                New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values @("WinRM","SSH") -DefaultValue "WinRM"
            } -Endpoint {
                param(
                    [string]$Local_UserName,
                    [string]$Local_Password,
                    [string]$Domain_UserName,
                    [string]$Domain_Password,
                    [string]$SSHPublicCertString,
                    [string]$Preferred_PSRemotingCredType,
                    [string]$Preferred_PSRemotingMethod
                )

                # Add the SyncHash to the Page so that we can pass output to other pages
                $PUDRSSyncHT = $global:PUDRSSyncHT

                # Load PUDAdminCenter Module Functions Within ScriptBlock
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

                try {
                    if ($Session:CredentialHT.GetType().FullName -ne "System.Collections.Hashtable") {
                        $Session:CredentialHT = @{}
                    }
                }
                catch {
                    $Session:CredentialHT = @{}
                }

                if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
                    $RHostCredHT = @{
                        DomainCreds         = $null
                        LocalCreds          = $null
                        SSHCertPath         = $null
                        PSRemotingCredType  = $null
                        PSRemotingMethod    = $null
                        PSRemotingCreds     = $null
                    }
                    $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)
                }

                # TODO: Need to remove this when finished testing
                $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT

                # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                    $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                }
                if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                    $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                }
                if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                    $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                }
                if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                    $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                }
                if (!$SSHPublicCertString -and $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath -ne $null) {
                    $SSHPublicCertString = $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath
                }
                if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                    $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                }
                if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                    $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                }

                if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$SSHPublicCertString) {
                    #$Session:NoCredsEntered = $True
                    #Sync-UDElement -Id "ValidateCredsMsg"
                    New-UDInputAction -Toast "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                if ($SSHPublicCertString) {
                    if (!$(Test-Path $SSHPublicCertString)) {
                        #$Session:InvalidSSHPubCert = $True
                        #Sync-UDElement -Id "ValidateCredsMsg"
                        New-UDInputAction -Toast "The string '$SSHPublicCertString' is not a falid SSH Public Cert!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                }

                if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                    $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                }
                if ($Preferred_PSRemotingMethod -eq "SSH" -and !$SSHPublicCertString) {
                    #$Session:SSHRemotingMethodNoCert = $True
                    #Sync-UDElement -Id "ValidateCredsMsg"
                    New-UDInputAction -Toast "You indicated that SSH is your Preferred_PSRemotingMethod, however, you did not provide a value for Path_To_SSH_Public_Cert!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                    $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                }
                if ($Preferred_PSRemotingCredType -eq "Domain" -and $(!$Domain_UserName -or !$Domain_Password)) {
                    #$Session:DomainRemotingMethodNoCreds = $True
                    #Sync-UDElement -Id "ValidateCredsMsg"
                    New-UDInputAction -Toast "You indicated that 'Domain' was your Preferred_PSRemotingCredType, however, you did not provide Domain Credentials!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                if ($Preferred_PSRemotingCredType -eq "Local" -and $(!$Local_UserName -or !$Local_Password)) {
                    #$Session:LocalRemotingMethodNoCreds = $True
                    #Sync-UDElement -Id "ValidateCredsMsg"
                    New-UDInputAction -Toast "You indicated that 'Local' was your Preferred_PSRemotingCredType, however, you did not provide Local Credentials!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                ) {
                    #$Session:UserNameAndPasswordRequired = $True
                    #Sync-UDElement -Id "ValidateCredsMsg"
                    New-UDInputAction -Toast "Please enter both a UserName and a Password!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                if ($Local_UserName -and $Local_Password) {
                    # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                    if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                        $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                    }

                    $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                    $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                }

                if ($Domain_UserName -and $Domain_Password) {
                    $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                    # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                    if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                        #$Session:BadFormatDomainUserName = $True
                        #Sync-UDElement -Id "ValidateCredsMsg"
                        New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
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
                        $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
        
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
                        #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$Session:ThisRemoteHost"
                    }
                }

                if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                ) {
                    # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                    $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open

                    [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                    foreach ($CredObj in $CredentialsToTest) {
                        if ($RPCPortOpen) {
                            try {
                                $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                $null = $EnableWinRMSuccess.Add($CredObj)
                                break
                            }
                            catch {
                                #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                            }
                        }
                    }

                    if ($EnableWinRMSuccess.Count -eq 0) {
                        #$Session:EnableWinRMFailure = $True
                        #Sync-UDElement -Id "ValidateCredsMsg"
                        New-UDInputAction -Toast "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                    else {
                        [System.Collections.ArrayList]$FailedCredentialsB = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            try {
                                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                
                                if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                    #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $null = $FailedCredentialsB.Add($CredObj)
                                }
                            }
                            catch {
                                #$Session:GetWorkingCredsFailure = $True
                                #Sync-UDElement -Id "ValidateCredsMsg"
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Please try again." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
                    }
                }

                if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                    if ($FailedCredentialsB.Count -gt 0) {
                        #$Session:InvalidCreds = $True
                        #Sync-UDElement -Id "ValidateCredsMsg"
                        foreach ($CredObj in $FailedCredentialsB) {
                            New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                            $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                        }
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                    if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                        #$Session:InvalidCreds = $True
                        #Sync-UDElement -Id "ValidateCredsMsg"
                        foreach ($CredObj in $FailedCredentialsA) {
                            New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                            $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                        }
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                }

                if ($DomainAdminCreds) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                }
                if ($LocalAdminCreds) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                }
                if ($SSHPublicCertString) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.SSHCertPath = $SSHPublicCertString
                }
                if ($Preferred_PSRemotingCredType) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                }
                if ($Preferred_PSRemotingMethod) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                }

                # Determine $PSRemotingCreds
                if ($Preferred_PSRemotingCredType -eq "Local") {
                    $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                }
                if ($Preferred_PSRemotingCredType -eq "Domain") {
                    $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                }

                New-UDInputAction -RedirectUrl "/ToolSelect/$Session:ThisRemoteHost"
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
        New-UDColumn -Size 2 -EndPoint {}
    }
}
$Page = New-UDPage -Url "/PSRemotingCreds/:RemoteHost" -Endpoint $PSRemotingCredsPageContent
$null = $Pages.Add($Page)

#endregion >> PSRemoting Creds Page