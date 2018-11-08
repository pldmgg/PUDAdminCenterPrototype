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
            $ConnectionStatus = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
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

                        #$WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                        #$WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open

                        $ConnectionStatus = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}

                        if ($ConnectionStatus -eq "Connected") {
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

        $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
                                    $ToolNameNoSpaces = $ToolName -replace "[\s]",""
                                    New-UDLink -Text $ToolName -Url "/$ToolNameNoSpaces/$RemoteHost" -Icon dashboard
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
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
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
            
                $LiveDataPSSession = New-PSSession -Name "RolesAndFeatures$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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

            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
