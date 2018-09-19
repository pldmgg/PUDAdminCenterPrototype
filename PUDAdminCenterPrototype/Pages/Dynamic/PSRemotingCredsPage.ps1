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
                    $VaultServerUrl = $SSHPublicCertTextBox.Attributes['value']
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
                        VaultServerUrl             = $VaultServerUrl
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
                            VaultServerUrl      = $null
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
                    if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                        $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                    }
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }

                    if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                        $Session:NoCredsEntered = $True
                        Sync-UDElement -Id "ValidateCredsMsg"
                        $Session:CheckingCredentials = $False
                        Sync-UDElement -Id "CheckingCredentials"
                        return
                    }

                    if ($VaultServerUrl) {
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
                    if ($Preferred_PSRemotingMethod -eq "SSH" -and !$VaultServerUrl) {
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
                    if ($VaultServerUrl) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
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
                New-UDInputField -Type textbox -Name 'VaultServerUrl' -Value $null
                New-UDInputField -Type select -Name 'Preferred_PSRemotingCredType' -Values @("Local","Domain","SSHCertificate") -DefaultValue "Domain"

                [System.Collections.ArrayList]$PSRemotingMethodValues = @("WinRM")
                if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.SSH -eq "Available") {
                    $null = $PSRemotingMethodValues.Add("SSH")
                }
                New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values @("WinRM","SSH") -DefaultValue "WinRM"
            } -Endpoint {
                param(
                    [string]$Local_UserName,
                    [string]$Local_Password,
                    [string]$Domain_UserName,
                    [string]$Domain_Password,
                    [string]$VaultServerUrl,
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
                        VaultServerUrl      = $null
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
                if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                    $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                }
                if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                    $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                }
                if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                    $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                }

                # Make sure *Something* is filled out...
                if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                    New-UDInputAction -Toast "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                <#
                # Set/Check $Preferred_PSRemotingCredType...
                if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                    $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                }
                # Set/Check $Preferred_PSRemotingMethod...
                if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                    $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                }
                #>
                
                if ($Preferred_PSRemotingMethod -eq "SSH") {
                    if ($Preferred_PSRemotingCredType -ne "SSHCertificate") {
                        $Preferred_PSRemotingCredType = "SSHUserNameAndPassword"
                    }
                    
                    if ($Preferred_PSRemotingCredType -eq "Domain") {
                        if ($Local_UserName -or $Local_Password) {
                            New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Local_UserName or Local_Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                        if ($VaultServerUrl) {
                            New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        if (!$Domain_UserName -or !$Domain_Password) {
                            New-UDInputAction -Toast "You must provide a Domain_UserName AND Domain_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
        
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
                    }
                    if ($Preferred_PSRemotingCredType -eq "Local") {
                        if ($Domain_UserName -or $Domain_Password) {
                            New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Domain_UserName or Domain_Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                        if ($VaultServerUrl) {
                            New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        if (!$Local_UserName -or !$Local_Password) {
                            New-UDInputAction -Toast "You must provide a Local_UserName AND Local_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                        if ($Local_UserName -and $Local_Password) {
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
        
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }
                    }
                    if ($Preferred_PSRemotingCredType -eq "SSHUserNameAndPassword") {
                        if (!$($Domain_UserName -and $Domain_Password) -and !$($Local_UserName -and $Local_Password)) {
                            New-UDInputAction -Toast "Since you specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', you MUST provide a Domain_UserName and Domain_Password or Local_UserName and Local_Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                        if ($Local_UserName -and $Local_Password) {
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
        
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }

                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
        
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
                    }
                    if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                        if (!$Domain_UserName -or !$Domain_Password) {
                            New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', which means you must provide Domain_UserName and Domain_Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                        if (!$VaultServerUrl) {
                            New-UDInputAction -Toast "You must provide the VaultServerUrl in order to generate/request/receive a new SSH Certificate!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
        
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }

                        if ($VaultServerUrl) {
                            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

                            # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
                            try {
                                $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerUrl/sys/health"
                                if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
                                $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
                                    throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
                                }
                            }
                            catch {
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
                    }

                    try {
                        # Make sure we have the WinSSH Module Available
                        if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {$null = Install-Module WinSSH -ErrorAction Stop}
                        if ($(Get-Module).Name -notcontains "WinSSH") {$null = Import-Module WinSSH -ErrorAction Stop}

                        # Make sure we have the VaultServer Module Available
                        if ($(Get-Module -ListAvailable).Name -notcontains "VaultServer") {$null = Install-Module VaultServer -ErrorAction Stop}
                        if ($(Get-Module).Name -notcontains "VaultServer") {$null = Import-Module VaultServer -ErrorAction Stop}
                    }
                    catch {
                        New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }

                    if ($(Get-Module).Name -notcontains "WinSSH") {
                        New-UDInputAction -Toast "The WinSSH Module is not available! Halting!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                    if ($(Get-Module).Name -notcontains "VaultServer") {
                        New-UDInputAction -Toast "The VaultServer Module is not available! Halting!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }

                    # Install OpenSSH-Win64 if it isn't already
                    if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64\ssh.exe")) {
                        Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh
                    }
                    else {
                        if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                            $OpenSSHDir ="$env:ProgramFiles\OpenSSH-Win64"
                            # Update PowerShell $env:Path
                            [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                            if ($CurrentEnvPathArray -notcontains $OpenSSHDir) {
                                $CurrentEnvPathArray.Insert(0,$OpenSSHDir)
                                $env:Path = $CurrentEnvPathArray -join ';'
                            }
                            
                            # Update SYSTEM Path
                            $RegistrySystemPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                            $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path
                            [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                            if ($CurrentSystemPathArray -notcontains $OpenSSHDir) {
                                $CurrentSystemPathArray.Insert(0,$OpenSSHDir)
                                $UpdatedSystemPath = $CurrentSystemPathArray -join ";"
                                Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath
                            }
                        }
                        if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                            New-UDInputAction -Toast "Unable to find ssh.exe on $env:ComputerName!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                    }

                    if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                        # Use Domain Credentials to get a new Vault Server Authentication Token, generate new SSH Keys on the PUDAdminCenter Server,
                        # have the Vault Server sign them, add the new private key to the ssh-agent, and output an SSH Public Certificate to $HOME\.ssh
                        # NOTE: The SSH Keys will expire in 24 hours
                        $NewSSHKeyName = $($DomainAdminCreds.UserName -split "\\")[-1] + "_" + $(Get-Date -Format MM-dd-yy_hhmmsstt)
                        $NewSSHCredentialsSplatParams = @{
                            VaultServerBaseUri                  = $VaultServerUrl
                            DomainCredentialsWithAccessToVault  = $DomainAdminCreds
                            NewSSHKeyName                       = $NewSSHKeyName
                            BlankSSHPrivateKeyPwd               = $True
                            AddToSSHAgent                       = $True
                            RemovePrivateKey                    = $True # Removes the Private Key from the filesystem
                            #SSHAgentExpiry                      = 86400 # 24 hours in seconds # Don't use because this makes ALL keys in ssh-agent expire in 24 hours
                        }

                        try {
                            $NewSSHCredsResult = New-SSHCredentials @NewSSHCredentialsSplatParams -ErrorAction Stop
                            $NewSSHCredsResult | Add-Member -Name "PrivateKeyPath" -Value $($NewSSHCredsResult.PublicKeyPath -replace "\.pub","") -MemberType NoteProperty
                        }
                        catch {
                            New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }

                        if ($PUDRSSyncHT.Keys -contains "NewSSHCredsResult") {
                            $PUDRSSyncHT.NewSSHCredsResult = $NewSSHCredsResult
                        }
                        else {
                            $PUDRSSyncHT.Add("NewSSHCredsResult",$NewSSHCredsResult)
                        }

                        # $NewSSHCredsResult (and $GetSSHAuthSanity later on) is a pscustomobject with the following content:
                        <#
                            PublicKeyCertificateAuthShouldWork : True
                            FinalSSHExeCommand                 : ssh zeroadmin@zero@<RemoteHost>
                            PublicKeyPath                      : C:\Users\zeroadmin\.ssh\zeroadmin_071918.pub
                            PublicCertPath                     : C:\Users\zeroadmin\.ssh\zeroadmin_071918-cert.pub
                        #>

                        # If $NewSSHCredsResult.FinalSSHExeCommand looks like...
                        #     ssh -o "IdentitiesOnly=true" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718-cert.pub" zeroadmin@zero@<RemoteHost>
                        # ...or...
                        #     ssh <user>@<RemoteHost>
                        # ...then there are too many identities loaded in the ssh-agent service, which means we need to get the private key from the registry and write it to a file
                        # See: https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/
                        if (!$NewSSHCredsResult.PublicKeyCertificateAuthShouldWork -or 
                        $NewSSHCredsResult.FinalSSHExeCommand -eq "ssh <user>@<RemoteHost>" -or
                        $NewSSHCredsResult.FinalSSHExeCommand -match "IdentitiesOnly=true"
                        ) {
                            # NOTE: Extract-SSHPrivateKeysFromRegistry is from the WinSSH Module and provides output like:
                            <#
                                OriginalPrivateKeyFilePath      = $OriginalPrivateKeyFilePath
                                PrivateKeyContent               = $PrivateKeyContent
                            #>
                            # This should only really be necessary if the ssh-agent has more than 5 entries in it (and the needed key isn't within one of the first 5) and
                            # the RSA Private Key isn't on the filesystem under "$HOME\.ssh". The Get-SSHClientAuthSanity function figures that out for us.
                            $ExtractedPrivateKeys = Extract-SSHPrivateKeysFromRegistry
                            $OriginalPrivateKeyPath = $NewSSHCredsResult.PublicKeyPath -replace "\.pub",""
                            $PrivateKeyContent = $($ExtractedPrivateKeys | Where-Object {$_.OriginalPrivateKeyFilePath -eq $OriginalPrivateKeyPath}).PrivateKeyContent

                            if ($PrivateKeyContent.Count -gt 0) {
                                Set-Content -Path $OriginalPrivateKeyPath -Value $PrivateKeyContent
                                $NeedToRemovePrivateKey = $True
                                $GetSSHAuthSanityCheck = Get-SSHClientAuthSanity -SSHPublicKeyFilePath $NewSSHCredsResult.PublicKeyPath
                                if ($GetSSHAuthSanityCheck.PublicKeyCertificateAuthShouldWork) {
                                    $GetSSHAuthSanity = [pscustomobject]@{
                                        PublicKeyCertificateAuthShouldWork  = $True
                                        FinalSSHExeCommand                  = $GetSSHAuthSanityCheck.FinalSSHExeCommand
                                        PrivateKeyPath                      = $OriginalPrivateKeyPath
                                        PublicKeyPath                       = $NewSSHCredsResult.PublicKeyPath
                                        PublicCertPath                      = $NewSSHCredsResult.PublicKeyPath + '-cert.pub'
                                    }
                                }
                                
                                # The below $FinalSSHExeCommand string should look like:
                                #     ssh -o "IdentitiesOnly=true" -i "$OriginalPrivateKeyPath" -i "$($NewSSHCredsResult.PublicCertPath)" zeroadmin@zero@<RemoteHost>
                                $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand

                                if (!$GetSSHAuthSanity.PublicKeyCertificateAuthShouldWork) {
                                    $UserNamePasswordRequired = $True
                                    $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh private key is not available on the " +
                                    "filesystem or in the ssh-agent. Trying UserName/Password SSH Authentication..."
                                    New-UDInputAction -Toast $ToastMsg -Duration 10000
                                    #Sync-UDElement -Id "CredsForm"
                                    #return
                                }
                            }
                            else {
                                $UserNamePasswordRequired = $True
                                $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh keys and/or " +
                                "ssh cert and/or ssh-agent is not configured properly! Trying UserName/Password SSH Authentication..."
                                New-UDInputAction -Toast $ToastMsg -Duration 10000
                                #Sync-UDElement -Id "CredsForm"
                                #return
                            }
                        }
                        else {
                            $GetSSHAuthSanity = $NewSSHCredsResult
                            
                            # The below $FinalSSHExeCommand string should look like:
                            #     ssh zeroadmin@zero@<RemoteHost>
                            $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand
                        }

                        $SSHCertificate = Get-Content $GetSSHAuthSanity.PublicCertPath

                        if ($PUDRSSyncHT.Keys -contains "GetSSHAuthSanity") {
                            $PUDRSSyncHT.GetSSHAuthSanity = $GetSSHAuthSanity
                        }
                        else {
                            $PUDRSSyncHT.Add("GetSSHAuthSanity",$GetSSHAuthSanity)
                        }
                    }
                }
                if ($Preferred_PSRemotingMethod -eq "WinRM") {
                    if ($VaultServerUrl) {
                        New-UDInputAction -Toast "You provided a Vault Server Url, however, your Preferred_PSRemotingMethod is not SSH!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }

                    if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                    $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                    ) {
                        New-UDInputAction -Toast "Please enter both a UserName and a Password!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }

                    # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                    if ($Local_UserName -and $Local_Password) {
                        if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                            $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                        }
    
                        $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                        $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                    }

                    # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                    if ($Domain_UserName -and $Domain_Password) {
                        $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                        if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                            New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                        $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                    }
                }

                ##### Test the Credentials #####

                if ($Preferred_PSRemotingMethod -eq "SSH") {
                    # Make sure we have pwsh
                    if (!$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
                        $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "C:\Program Files\PowerShell"
                    }
                    
                    # NOTE: The Await Module comes with the WinSSH Module that we made sure was installed/imported earlier
                    try {
                        Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
                    }
                    catch {
                        New-UDInputAction -Toast "Unable to load the Await Module! Halting!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }

                    # If $FinalSSHExeCommand looks like...
                    #     ssh -o "IdentitiesOnly=true" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718-cert.pub" zeroadmin@zero@<RemoteHost>
                    # ...or...
                    #     ssh zeroadmin@zero@<RemoteHost>

                    if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                        # Determine if we're going to do UserName/Password Auth or SSH Certificate Auth
                        if (!$UserNamePasswordRequired) {
                            # NOTE: OpenSSH-Win64's implementation of 'ssh.exe -t' does not work properly...
                            <#
                            [System.Collections.ArrayList][array]$ProbeSSHExeCommand = $FinalSSHExeCommand -split "[\s]"
                            # Remove zeroadmin@zero@<RemoteHost>
                            $ProbeSSHExeCommand.RemoveAt($($ProbeSSHExeCommand.Count-1))

                            # We need to get the UserName from the SSHCertificate
                            [System.Collections.ArrayList][array]$SSHCertInfo = ssh-keygen -L -f $GetSSHAuthSanity.PublicCertPath
                            $PrincipalsLine = $SSHCertInfo | Where-Object {$_ -match "Principals:"}
                            $PrincipalsLineIndex = $SSHCertInfo.IndexOf($PrincipalsLine)
                            $CriticalOptionsLine = $SSHCertInfo | Where-Object {$_ -match "Critical Options:"}
                            $CriticalOptionsLineIndex = $SSHCertInfo.IndexOf($CriticalOptionsLine)
                            [array]$PrincipalsList = @($SSHCertInfo[$PrincipalsLineIndex..$CriticalOptionsLineIndex] | Where-Object {$_ -notmatch "Principals:|Critical Options:"} | foreach {$_.Trim()})
                            
                            # NOTE: The Principal(s) on the SSH Certificate do NOT determine who you are on the Remote Host. What DOES determine who you are on the Remote Host is
                            # 1) The UserName specified via -UserName with *-PSSession cmdlets
                            # 2) The UserName specified via <UserName>@<DomainShortName>@<RemoteHost> with ssh.exe
                            if ($PrincipalsList.Count -eq 1) {
                                $SSHCertUser = $($PrincipalsList[0] -split '@')[0].Trim()
                            }

                            # Get the $DomainShortName from $PUDRSSyncHT.RemoteHostList
                            $DomainShortName = $($($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).Domain -split "\\")[0]
                            # Add finalized string
                            $ProbeSSHExeCommand.Add("$SSHCertUser@$DomainShortName@$Session:RemoteHost")
                            $ProbeSSHExeCommand.Insert($($ProbeSSHExeCommand.Count-2),"-t")
                            $ProbeSSHExeCommand.Add('"echo ConnectionSuccessful"')
                            #>

                            # We need to get the UserName from the SSHCertificate
                            [System.Collections.ArrayList][array]$SSHCertInfo = ssh-keygen -L -f $GetSSHAuthSanity.PublicCertPath
                            $PrincipalsLine = $SSHCertInfo | Where-Object {$_ -match "Principals:"}
                            $PrincipalsLineIndex = $SSHCertInfo.IndexOf($PrincipalsLine)
                            $CriticalOptionsLine = $SSHCertInfo | Where-Object {$_ -match "Critical Options:"}
                            $CriticalOptionsLineIndex = $SSHCertInfo.IndexOf($CriticalOptionsLine)
                            [array]$PrincipalsList = @($SSHCertInfo[$PrincipalsLineIndex..$CriticalOptionsLineIndex] | Where-Object {$_ -notmatch "Principals:|Critical Options:"} | foreach {$_.Trim()})
                            $SSHCertUser = $($PrincipalsList[0] -split '@')[0].Trim()
                            $ShortUserName = $SSHCertUser
                            $DomainShortName = $($($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).Domain -split "\.")[0]
                            $FullUserName = "$DomainShortName\$ShortUserName"
                        }
                        if ($UserNamePasswordRequired) {
                            $ShortUserName = $($Domain_UserName -split "\\")[-1]
                            $DomainShortName = $($($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).Domain -split "\.")[0]
                            $FullUserName = "$DomainShortName\$ShortUserName"
                        }
                    }
                    if ($Preferred_PSRemotingCredType -eq "SSHUserNameAndPassword") {
                        if ($Local_UserName -and $Local_Password) {
                            $FullUserName = $Local_UserName
                        }
                        if ($Domain_UserName -and $Domain_Password) {
                            $FullUserName = $Domain_UserName
                        }
                    }

                    $OSGuess = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.OS_Guess
                    if ($OSGuess) {
                        if ($OSGuess -match "Windows|Microsoft") {
                            $UpdatedOSGuess = "Windows"
                        }
                        elseif ($OSGuess -match "Linux") {
                            $UpdatedOSGuess = "Linux"
                        }
                        else {
                            $UpdatedOSGuess = "Windows"
                        }
                    }
                    if (!$OSGuess) {
                        $UpdatedOSGuess = "Windows"
                    }

                    if ($UpdatedOSGuess -eq "Windows") {
                        # This is basically what we're going for with the below string manipulation:
                        #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
                        $PwshRemoteScriptBlockStringArray = @(
                            '[pscustomobject]@{'
                            '    Output = "ConnectionSuccessful"'
                            '}'
                        ) | foreach {"    $_"}
                        $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
                        [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
                            'Invoke-Command'
                            '-HostName'
                            $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).FQDN
                            '-UserName'
                            $FullUserName
                        )
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
                            $null = $PwshInvCmdStringArray.Add("'$($GetSSHAuthSanity.PublicCertPath)'")
                        }
                        $null = $PwshInvCmdStringArray.Add('-HideComputerName')
                        $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
                        $null = $PwshInvCmdStringArray.Add('|')
                        $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
                        $PwshInvCmdString = $PwshInvCmdStringArray -join " "
                        $PwshCmdStringArray = @(
                            '&'
                            '"' + $(Get-Command pwsh).Source + '"'
                            "-c {$PwshInvCmdString}"
                        )
                        $PwshCmdString = $PwshCmdStringArray -join " "

                        if ($PUDRSSyncHT.Keys -contains "PwshCmdString") {
                            $PUDRSSyncHT.PwshCmdString = $PwshCmdString
                        }
                        else {
                            $PUDRSSyncHT.Add("PwshCmdString",$PwshCmdString)
                        }

                        $null = Start-AwaitSession
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
                        Start-Sleep -Seconds 5

                        # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                        $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        $Counter = 0
                        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
                        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
                        ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
                        ) {
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                                break
                            }
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                        if ($Counter -eq 11) {
                            New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            $CheckResponsesOutput = $CheckForExpectedResponses
                            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                            }
                            else {
                                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                            }
                            return
                        }

                        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
                        if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                            $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                        }
                        else {
                            $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                        }

                        # Make sure we didn't already throw an error
                        if ($CheckResponsesOutput -match "background process reported an error") {
                            $TrySSHExe = $True
                        }

                        #region >> Make Sure Await Module Is Working
                        
                        if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    Stop-Process -Id $PSAwaitProcess.Id
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }

                            $null = Start-AwaitSession
                            Start-Sleep -Seconds 1
                            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                            Start-Sleep -Seconds 1
                            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                            Start-Sleep -Seconds 1
                            $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
                            Start-Sleep -Seconds 5

                            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            $Counter = 0
                            while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
                            $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
                            $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 10
                            ) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                            if ($Counter -eq 11) {
                                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                $CheckResponsesOutput = $CheckForExpectedResponses
                                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                                }
                                else {
                                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                                }
                                return
                            }

                            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
                            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                            }
                            else {
                                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                            }
                        }
                        if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                            New-UDInputAction -Toast "Something went wrong with the PowerShell Await Module! Halting!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"

                            try {
                                $null = Stop-AwaitSession
                            }
                            catch {
                                if ($PSAwaitProcess.Id -eq $PID) {
                                    Write-Error "The PSAwaitSession never spawned! Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                                else {
                                    Stop-Process -Id $PSAwaitProcess.Id
                                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                        Start-Sleep -Seconds 1
                                    }
                                }
                            }

                            return
                        }

                        #endregion >> Make Sure Await Module Is Working

                        if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                            $null = Send-AwaitCommand "yes"
                            Start-Sleep -Seconds 3
                            
                            # This will either not prompt at all or prompt for a password
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                            $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            $Counter = 0
                            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                            ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
                            ) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                            if ($Counter -eq 11) {
                                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }

                            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                            if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                                $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                            }
                            else {
                                $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                            }
                            
                            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                                if ($Local_Password) {
                                    $null = Send-AwaitCommand $Local_Password
                                }
                                if ($Domain_Password) {
                                    $null = Send-AwaitCommand $Domain_Password
                                }
                                Start-Sleep -Seconds 3

                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                                [System.Collections.ArrayList]$JsonOutputPrep = @()
                                $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                $Counter = 0
                                while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                        $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                    }
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                                if ($Counter -eq 10) {
                                    if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepA") {
                                        $PUDRSSyncHT.JsonOutputPrepA = $JsonOutputPrep
                                    }
                                    else {
                                        $PUDRSSyncHT.Add("JsonOutputPrepA",$JsonOutputPrep)
                                    }

                                    New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }

                                [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                                    $null = $JsonOutputPrep.Insert(0,'{')
                                }
                            }
                        }
                        elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                            if ($Local_Password) {
                                $null = Send-AwaitCommand $Local_Password
                            }
                            if ($Domain_Password) {
                                $null = Send-AwaitCommand $Domain_Password
                            }
                            Start-Sleep -Seconds 3

                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                            [System.Collections.ArrayList]$JsonOutputPrep = @()
                            $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            $Counter = 0
                            while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                    $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                }
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                            if ($Counter -eq 10) {
                                if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepB") {
                                    $PUDRSSyncHT.JsonOutputPrepB = $JsonOutputPrep
                                }
                                else {
                                    $PUDRSSyncHT.Add("JsonOutputPrepB",$JsonOutputPrep)
                                }

                                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }

                            [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                                $null = $JsonOutputPrep.Insert(0,'{')
                            }
                        }
                        else {
                            [System.Collections.ArrayList]$JsonOutputPrep = $($CheckResponsesOutput | foreach {$_ -split "`n"}) | Where-Object {
                                $_ -notmatch "^PS " -and ![System.String]::IsNullOrWhiteSpace($_)
                            }
                            $EndOfInputLineContent = $JsonOutputPrep -match [regex]::Escape("ConvertTo-Json}")
                            $JsonOutputIndex = $JsonOutputPrep.IndexOf($EndOfInputLineContent) + 1

                            [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$JsonOutputIndex..$($JsonOutputPrep.Count-1)]

                            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                                $null = $JsonOutputPrep.Insert(0,'{')
                            }
                        }

                        if (!$TrySSHExe) {
                            $IndexesOfOpenBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                                if ($JsonOutputPrep[$i] -match "^{") {
                                    $i
                                }
                            }
                            $LastIndexOfOpenBracket = $($IndexesOfOpenBracket | Measure-Object -Maximum).Maximum
                            $IndexesOfCloseBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                                if ($JsonOutputPrep[$i] -match "^}") {
                                    $i
                                }
                            }
                            $LastIndexOfCloseBracket = $($IndexesOfCloseBracket | Measure-Object -Maximum).Maximum
                            [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$LastIndexOfOpenBracket..$LastIndexOfCloseBracket] | foreach {$_ -split "`n"}
                            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                                $null = $JsonOutputPrep.Insert(0,'{')
                            }

                            if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepC") {
                                $PUDRSSyncHT.JsonOutputPrepC = $JsonOutputPrep
                            }
                            else {
                                $PUDRSSyncHT.Add("JsonOutputPrepC",$JsonOutputPrep)
                            }

                            $FinalJson = $JsonOutputPrep | foreach {if (![System.String]::IsNullOrWhiteSpace($_)) {$_.Trim()}}

                            if ($PUDRSSyncHT.Keys -contains "FinalJson") {
                                $PUDRSSyncHT.FinalJson = $FinalJson
                            }
                            else {
                                $PUDRSSyncHT.Add("FinalJson",$FinalJson)
                            }

                            try {
                                $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
                            }
                            catch {
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                            }
                        }

                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                Stop-Process -Id $PSAwaitProcess.Id
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                }
                            }
                        }

                        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
                            $TrySSHExe = $True
                            New-UDInputAction -Toast "SSH via PowerShell Core 'Invoke-Command' failed!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                        }
                    }

                    if ($UpdatedOSGuess -eq "Linux" -or $TrySSHExe) {
                        # This is what we're going for:
                        # $test = ssh -t pdadmin@Mint18Dev.test2.lab "echo 'ConnectionSuccessful'"
                        $RHostIP = @(
                            $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).IPAddressList | Where-Object {$_ -notmatch "^169"}
                        )[0]

                        [System.Collections.ArrayList]$SSHCmdStringArray = @(
                            'ssh'
                        )
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            $null = $SSHCmdStringArray.Add("-i")
                            $null = $SSHCmdStringArray.Add("'" + $GetSSHAuthSanity.PublicCertPath + "'")
                        }
                        $null = $SSHCmdStringArray.Add("-t")
                        if ($Local_UserName -and $Local_Password) {
                            $UserNameShort = $($Local_UserName -split "\\")[-1]
                            $null = $SSHCmdStringArray.Add("$UserNameShort@$RHostIP")
                        }
                        if ($Domain_UserName -and $Domain_Password) {
                            $UserNameShort = $($Domain_UserName -split "\\")[-1]
                            $DomainNameShort = $($Domain_UserName -split "\\")[0]
                            $null = $SSHCmdStringArray.Add("$UserNameShort@$DomainNameShort@$RHostIP")
                        }
                        $null = $SSHCmdStringArray.Add("`"echo 'ConnectionSuccessful'`"")
                        $SSHCmdString = $SSHCmdStringArray -join " "

                        if ($PUDRSSyncHT.Keys -contains "SSHCmdString") {
                            $PUDRSSyncHT.SSHCmdString = $SSHCmdString
                        }
                        else {
                            $PUDRSSyncHT.Add("SSHCmdString",$SSHCmdString)
                        }

                        $null = Start-AwaitSession
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
                        Start-Sleep -Seconds 1
                        $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
                        Start-Sleep -Seconds 5

                        # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
                        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
                        $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                        $Counter = 0
                        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
                        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
                        ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
                        ) {
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                                break
                            }
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                        if ($Counter -eq 11) {
                            New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            $CheckResponsesOutput = $CheckForExpectedResponses
                            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                            }
                            else {
                                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                            }
                            return
                        }

                        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
                        if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                            $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                        }
                        else {
                            $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                        }

                        if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
                            $null = Send-AwaitCommand "yes"
                            Start-Sleep -Seconds 3
                            
                            # This will either not prompt at all or prompt for a password
                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
                            $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            $Counter = 0
                            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
                            ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
                            ) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                            if ($Counter -eq 11) {
                                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }

                            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
                            if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                                $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                            }
                            else {
                                $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                            }
                            
                            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                                if ($Local_Password) {
                                    $null = Send-AwaitCommand $Local_Password
                                }
                                if ($Domain_Password) {
                                    $null = Send-AwaitCommand $Domain_Password
                                }
                                Start-Sleep -Seconds 3

                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                                [System.Collections.ArrayList]$SSHOutputPrep = @()
                                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                $Counter = 0
                                while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                    }
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                                if ($Counter -eq 10) {
                                    if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepA") {
                                        $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                                    }
                                    else {
                                        $PUDRSSyncHT.Add("SSHOutputPrepA",$SSHOutputPrep)
                                    }

                                    New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
                            }
                        }
                        elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
                            if ($Local_Password) {
                                $null = Send-AwaitCommand $Local_Password
                            }
                            if ($Domain_Password) {
                                $null = Send-AwaitCommand $Domain_Password
                            }
                            Start-Sleep -Seconds 3

                            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                            [System.Collections.ArrayList]$SSHOutputPrep = @()
                            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                            $Counter = 0
                            while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                                }
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                            if ($Counter -eq 10) {
                                if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepB") {
                                    $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                                }
                                else {
                                    $PUDRSSyncHT.Add("SSHOutputPrepB",$SSHOutputPrep)
                                }

                                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
                    }

                    if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful" -and ![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                        New-UDInputAction -Toast "SSH attempts via PowerShell Core 'Invoke-Command' and ssh.exe have failed!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
                }
                if ($Preferred_PSRemotingMethod -eq "WinRM") {
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
                            foreach ($CredObj in $FailedCredentialsB) {
                                New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                            }
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                        if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                            foreach ($CredObj in $FailedCredentialsA) {
                                New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                            }
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                    }
                }

                if ($DomainAdminCreds) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                }
                if ($LocalAdminCreds) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                }
                if ($VaultServerUrl) {
                    $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
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

                if ($Preferred_PSRemotingMethod -eq "SSH") {
                    New-UDInputAction -Toast "SSH was SUCCESSFUL, however, ssh functionality has not been fully implemented yet. Please use WinRM instead." -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
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