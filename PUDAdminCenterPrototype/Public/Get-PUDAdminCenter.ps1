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

        PS C:\Users\zeroadmin> Get-UDNetMon
        
#>
function Get-PUDAdminCenter {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True,

        [Parameter(Mandatory=$False)]
        [pscredential]$UniversalPSRemotingCreds
    )

    #region >> Prep

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

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

    # Get all Computers in Active Directory without the ActiveDirectory Module
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

    [System.Collections.ArrayList]$Pages = @()

    $Cache:InfoPages = $InfoPages = @(
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

    $Cache:ThisModuleFunctionsStringArray = $ThisModuleFunctionsStringArray =  $(Get-Module PUDWinAdminCenter).Invoke({$FunctionsForSBUse})

    # Remove All Runspaces to Remote Hosts
    Get-PSSession | Remove-PSSession
    $RunspacesToDispose = @(
        Get-Runspace | Where-Object {$_.Type -eq "Remote"}
    )
    if ($RunspacesToDispose.Count -gt 0) {
        foreach ($RSpace in $RunspacesToDispose) {$_.Dispose()}
    }

    # Create Runspace SyncHash so that we can pass variables between Pages regardless of them being within an Endpoint
    # This also allows us to communicate with our own custom Runspace(s) that handle Live Data.
    # See below: New-Runspace -RunspaceName ...
    Remove-Variable -Name PUDRSSyncHT -Scope Global -Force -ErrorAction SilentlyContinue
    $global:PUDRSSyncHT = [hashtable]::Synchronized(@{})
    $global:PUDRSSyncHT.Add("RemoteHostList",$InitialRemoteHostList)
    foreach ($InfoPage in $InfoPages) {
        $global:PUDRSSyncHT.Add("$InfoPage`LoadingTracker",[System.Collections.ArrayList]::new())
    }
    $global:PUDRSSyncHT.Add("HomePageLoadingTracker",[System.Collections.ArrayList]::new())
    $global:PUDRSSyncHT.Add("PSRemotingPageLoadingTracker",[System.Collections.ArrayList]::new())
    $global:PUDRSSyncHT.Add("ToolSelectPageLoadingTracker",[System.Collections.ArrayList]::new())

    if ($UniversalPSRemotingCreds) {
        $global:PUDRSSyncHT.Add("UniversalPSRemotingCreds",$UniversalPSRemotingCreds)
    }

    # IMPORTANT NOTE: The following needs to be added to the top of every PAGE and ENDPOINT if we want them available
    <#
        $PUDRSSyncHT = $global:PUDRSSyncHT

        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    #>
    
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
        $global:PUDRSSyncHT.Add($Key,$Value)
    }

    #endregion >> Prep

    #region >> Dynamic Pages

    #region >> Test Page

    $TestPageContent = {
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT

        # Load PUDWinAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

        [System.Collections.ArrayList]$InfoPageRows = @()
        $ItemsPerRow = 3
        $NumberOfRows = $InfoPages.Count / $ItemsPerRow
        for ($i=0; $i -lt $NumberOfRows; $i++) {
            New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force

            if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
            $jLoopLimit = $j + $($ItemsPerRow - 1)
            while ($j -le $jLoopLimit) {
                $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($InfoPages[$j])
                $j++
            }

            $null = $InfoPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
        }

        foreach ($InfoPageRow in $InfoPageRows) {
            New-UDRow -Endpoint {
                foreach ($InfoPage in $InfoPageRow) {
                    $InfoPageNoSpace = $InfoPage -replace "[\s]",""
                    $CardId = $InfoPageNoSpace + "Card"
                    New-UDColumn -Size 4 -Endpoint {
                        if ($InfoPage -ne $null) {
                            $Links = @(New-UDLink -Text $InfoPage -Url "/$InfoPageNoSpace/$RemoteHost" -Icon dashboard)
                            New-UDCard -Title $InfoPage -Id $CardId -Text "$InfoPage Info" -Links $Links -Size small -TextSize small
                        }
                    }
                }
            }
        }
    }
    $Page = New-UDPage -Url "/Test" -Endpoint $TestPageContent
    $null = $Pages.Add($Page)

    #endregion >> Test Page

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

    #region >> PSRemoting Creds Page

    $PSRemotingPageContent = {
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
                        $Session:CredentialHT = $PUDRSSyncHT."$RemoteHost`Info".CredHT = $Session:CredentialHT
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
    $Page = New-UDPage -Url "/PSRemotingCreds/:RemoteHost" -Endpoint $PSRemotingPageContent
    $null = $Pages.Add($Page)

    #endregion >> PSRemoting Creds Page


    #region >> Tool Select Page

    # Create Tool Select Page Based On Remote Host Name
    $ManagementTools = {
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
                [System.Collections.ArrayList]$InfoPageRows = @()
                $ItemsPerRow = 3
                $NumberOfRows = $InfoPages.Count / $ItemsPerRow
                for ($i=0; $i -lt $NumberOfRows; $i++) {
                    New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force

                    if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
                    $jLoopLimit = $j + $($ItemsPerRow - 1)
                    while ($j -le $jLoopLimit) {
                        $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($InfoPages[$j])
                        $j++
                    }

                    $null = $InfoPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
                }

                foreach ($InfoPageRow in $InfoPageRows) {
                    New-UDRow -Endpoint {
                        foreach ($InfoPage in $InfoPageRow) {
                            # Make sure we're connected before loadting the UDCards
                            $InfoPageNoSpace = $InfoPage -replace "[\s]",""
                            $CardId = $InfoPageNoSpace + "Card"
                            New-UDColumn -Size 4 -Endpoint {
                                if ($InfoPage -ne $null) {
                                    $Links = @(New-UDLink -Text $InfoPage -Url "/$InfoPageNoSpace/$RemoteHost" -Icon dashboard)
                                    New-UDCard -Title $InfoPage -Id $CardId -Text "$InfoPage Info" -Links $Links
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
    $Page = New-UDPage -Url "/ToolSelect/:RemoteHost" -Endpoint $ManagementTools
    $null = $Pages.Add($Page)

    #endregion >> Tool Select Page
    

    #endregion >> Dynamic Pages


    #region >> Create Home Page
    
    # Create Home Page
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
    # parameter set '-Url -Endpoint' for the HomePage)
    $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
    $null = $Pages.Insert(0,$HomePage)

    #endregion >> Create Home Page
    
    # Finalize the Site
    $Theme = New-UDTheme -Name "DefaultEx" -Parent Default -Definition @{
        UDDashboard = @{
            BackgroundColor = "rgb(255,255,255)"
        }
    }
    $MyDashboard = New-UDDashboard -Title "Honolulu Redux" -Pages $Pages -Theme $Theme

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuHrqPm1qIiNfVXQF2CmlXCgw
# 8ougggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMWNTup2iLb2/xxM
# s59LgCiUPlQ+MA0GCSqGSIb3DQEBAQUABIIBACaZKJiS7GjwnEaj+vxKMhpa6aQW
# XNxrI5Jel42mW/iaqYf5Svu1h6O3mr9sLCdjyYNJL2B0h+7GNq0J3yISSNo96PQH
# brFvooG0cbwX5sUIodGooDFEsAWEAxJ3HsOCSqOj8af2sFRCEPJc4GJc8j7qHNM7
# 8MmOkAzQo0i9M6hAeHpIqIQOQ5qdIFxbRXLBrsilzXuE1EZqxywc1qSsDV3wrk9O
# zDT5i96KOL9943JuqXPOgB7ZbvkKEx7u+5khiUP8mQOmdV/tZX5cxzgsNc1D+aDh
# swPv1KQn4TivFLb/9rdUSEGVQH/NLpsjdxtAIcRqoHFcrqmAczv6w5X4ShQ=
# SIG # End signature block
