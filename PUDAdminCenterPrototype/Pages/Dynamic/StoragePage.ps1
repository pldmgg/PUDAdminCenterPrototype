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
        $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo -ne $null) {
                $PSSessionRunspacePrep = @(
                    Get-Runspace | Where-Object {
                        $_.RunspaceIsRemote -and
                        $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.ThisRunspace.Id -and
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
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
            
                $LiveDataPSSession = New-PSSession -Name "Storage$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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