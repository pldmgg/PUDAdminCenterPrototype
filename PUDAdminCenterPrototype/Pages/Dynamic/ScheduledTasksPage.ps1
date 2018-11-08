$ScheduledTasksPageContent = {
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
            $Session:ScheduledTasksPageLoadingTracker = [System.Collections.ArrayList]::new()
        }
        New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
            if ($Session:ScheduledTasksPageLoadingTracker -notcontains "FinishedLoading") {
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
                        if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous -eq $null) {
                                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
                            }
                            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Count -gt 0) {
                                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Clone()
                            }
                            $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
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

        $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
        $StaticInfo = Invoke-Command -ComputerName $RemoteHosts -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
            Invoke-Expression $using:GetScheduledTasksFunc
            
            $AllScheduledTasks = Get-ScheduledTasks

            [pscustomobject]@{
                AllScheduledTasks   = $AllScheduledTasks
            }
        }
        $Session:AllScheduledTasksStatic = $StaticInfo.AllScheduledTasks
        if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Keys -notcontains "AllScheduledTasks") {
            $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Add("AllScheduledTasks",$Session:AllScheduledTasksStatic)
        }
        else {
            $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
        }

        #endregion >> Gather Some Initial Info From $RemoteHost

        #region >> Page Name and Horizontal Nav

        New-UDRow -Endpoint {
            New-UDColumn -Content {
                New-UDHeading -Text "ScheduledTasks (In Progress)" -Size 3
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
            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo -ne $null) {
                $PSSessionRunspacePrep = @(
                    Get-Runspace | Where-Object {
                        $_.RunspaceIsRemote -and
                        $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Id -and
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
                    }
                )
                if ($PSSessionRunspacePrep.Count -gt 0) {
                    $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                }
                $PSSessionRunspace.Dispose()
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Dispose()
            }

            # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
            $GetScheduledTasksOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasksOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $LiveDataFunctionsToLoad = @($GetScheduledTasksOverviewFunc,$GetScheduledTasksFunc)
            
            # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
            New-Runspace -RunspaceName "ScheduledTasks$RemoteHost`LiveData" -ScriptBlock {
                $PUDRSSyncHT = $global:PUDRSSyncHT
            
                $LiveDataPSSession = New-PSSession -Name "ScheduledTasks$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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

                    # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        # Place most resource intensive operations first

                        # Operations that you only want running once every 30 seconds go within this 'if; block
                        # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                        if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                            #@{AllScheduledTaskss = Get-ScheduledTasks}
                        }

                        # Operations that you want to run once every second go here
                        @{ScheduledTasksSummary = Get-ScheduledTasksOverview -channel "Microsoft-Windows-ScheduledTaskservicesClient-Lifecycle-System*"}

                    } | foreach {$null = $LiveOutput.Add($_)}

                    $RSLoopCounter++

                    [GC]::Collect()

                    Start-Sleep -Seconds 1
                }
            }
            # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
            # the Runspace we just created can be found in $global:RSSyncHash's "ScheduledTasks$RemoteHost`LiveDataResult" Property - which is just
            # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo equal to
            # $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
            # to get the latest data from $RemoteHost.
            $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo = $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult"
        }
        #>

        #endregion >> Setup LiveData

        #region >> Controls

        # Static Data Element Example

        <#
            PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTaskInfo

            LastRunTime        : 8/28/2018 10:50:50 PM
            LastTaskResult     : 0
            NextRunTime        : 8/29/2018 10:50:50 PM
            NumberOfMissedRuns : 0
            TaskName           : GoogleUpdateTaskMachineCore
            TaskPath           : \
            PSComputerName     :

            PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask

            TaskPath                                       TaskName                          State
            --------                                       --------                          -----
            \                                              GoogleUpdateTaskMachineCore       Ready

            PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask | fl *

            status                : Ready
            TriggersEx            : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
            State                 : Ready
            Actions               : {MSFT_TaskExecAction}
            Author                :
            Date                  :
            Description           : Keeps your Google software up to date. If this task is disabled or stopped, your Google software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not
                                    work. This task uninstalls itself when there is no Google software using it.
            Documentation         :
            Principal             : MSFT_TaskPrincipal2
            SecurityDescriptor    :
            Settings              : MSFT_TaskSettings3
            Source                :
            TaskName              : GoogleUpdateTaskMachineCore
            TaskPath              : \
            Triggers              : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
            URI                   : \GoogleUpdateTaskMachineCore
            Version               : 1.3.33.17
            PSComputerName        :
            CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
            CimInstanceProperties : {Actions, Author, Date, Description...}
            CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties


        Trigger Value: $($($($($($($SchTsks.ScheduledTask[6].Triggers | gm).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}) -match "Trigger") -replace "MSFT_Task") -replace "Trigger") -join ", "
        
        #>

        $AllScheduledTasksProperties = @("Name","Status","Triggers","NextRunTime","LastRunTime","LastRunResult","Author","Created")
        $AllScheduledTasksUDTableSplatParams = @{
            Headers         = $AllScheduledTasksProperties
            Properties      = $AllScheduledTasksProperties
            PageSize        = 20
        }
        New-UDGrid @AllScheduledTasksUDTableSplatParams -Endpoint {
            $PUDRSSyncHT = $global:PUDRSSyncHT

            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]

            $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $SchTsksInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetScheduledTasksFunc
                
                $AllScheduledTasks = Get-ScheduledTasks
    
                [pscustomobject]@{
                    AllScheduledTasks   = $AllScheduledTasks
                }
            }
            
            $Session:AllScheduledTasksStatic = foreach ($obj in $SchTsksInfo.AllScheduledTasks) {
                [array]$TriggersPrepA = @($obj.ScheduledTask.Triggers | Where-Object {$_})
                if ($TriggersPrepA.Count -gt 0) {
                    $TriggersPrep = $($($TriggersPrepA | Get-Member).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}
                    $Triggers = $($($TriggersPrepA -match "Trigger") -replace "MSFT_Task") -replace "Trigger"
                }
                else {
                    $Triggers = $null
                }

                # LastRunResult Translation
                # From: https://en.wikipedia.org/wiki/Windows_Task_Scheduler
                $LastRunResult = switch ($obj.ScheduledTaskInfo.LastTaskResult) {
                    {$('{0:X}' -f $_) -eq '0'}          { "The operation completed successfully." }
                    {$('{0:X}' -f $_) -eq '1'}          { "Incorrect function called or unknown function called." }
                    {$('{0:X}' -f $_) -eq '2'}          { "File not found." }
                    {$('{0:X}' -f $_) -eq '10'}         { "The environment is incorrect." }
                    {$('{0:X}' -f $_) -eq '41300'}      { "Task is ready to run at its next scheduled time." }
                    {$('{0:X}' -f $_) -eq '41301'}      { "The task is currently running." }
                    {$('{0:X}' -f $_) -eq '41302'}      { "The task has been disabled." }
                    {$('{0:X}' -f $_) -eq '41303'}      { "The task has not yet run." }
                    {$('{0:X}' -f $_) -eq '41304'}      { "There are no more runs scheduled for this task." }
                    {$('{0:X}' -f $_) -eq '41305'}      { "One or more of the properties that are needed to run this task have not been set." }
                    {$('{0:X}' -f $_) -eq '41306'}      { "The last run of the task was terminated by the user." }
                    {$('{0:X}' -f $_) -eq '41307'}      { "Either the task has no triggers or the existing triggers are disabled or not set." }
                    {$('{0:X}' -f $_) -eq '41308'}      { "Event triggers do not have set run times." }
                    {$('{0:X}' -f $_) -eq '80010002'}   { "Call was canceled by the message filter." }
                    {$('{0:X}' -f $_) -eq '80041309'}   { "A task's trigger is not found." }
                    {$('{0:X}' -f $_) -eq '8004130A'}   { "One or more of the properties required to run this task have not been set." }
                    {$('{0:X}' -f $_) -eq '8004130B'}   { "There is no running instance of the task." }
                    {$('{0:X}' -f $_) -eq '8004130C'}   { "The Task Scheduler service is not installed on this computer." }
                    {$('{0:X}' -f $_) -eq '8004130D'}   { "The task object could not be opened." }
                    {$('{0:X}' -f $_) -eq '8004130E'}   { "The object is either an invalid task object or is not a task object." }
                    {$('{0:X}' -f $_) -eq '8004130F'}   { "No account information could be found in the Task Scheduler security database for the task indicated." }
                    {$('{0:X}' -f $_) -eq '80041310'}   { "Unable to establish existence of the account specified." }
                    {$('{0:X}' -f $_) -eq '80041311'}   { "Corruption was detected in the Task Scheduler security database." }
                    {$('{0:X}' -f $_) -eq '80041312'}   { "Task Scheduler security services are available only on Windows NT." }
                    {$('{0:X}' -f $_) -eq '80041313'}   { "The task object version is either unsupported or invalid." }
                    {$('{0:X}' -f $_) -eq '80041314'}   { "The task has been configured with an unsupported combination of account settings and run time options." }
                    {$('{0:X}' -f $_) -eq '80041315'}   { "The Task Scheduler Service is not running." }
                    {$('{0:X}' -f $_) -eq '80041316'}   { "The task XML contains an unexpected node." }
                    {$('{0:X}' -f $_) -eq '80041317'}   { "The task XML contains an element or attribute from an unexpected namespace." }
                    {$('{0:X}' -f $_) -eq '80041318'}   { "The task XML contains a value which is incorrectly formatted or out of range." }
                    {$('{0:X}' -f $_) -eq '80041319'}   { "The task XML is missing a required element or attribute." }
                    {$('{0:X}' -f $_) -eq '8004131A'}   { "The task XML is malformed." }
                    {$('{0:X}' -f $_) -eq '0004131B'}   { "The task is registered, but not all specified triggers will start the task." }
                    {$('{0:X}' -f $_) -eq '0004131C'}   { "The task is registered, but may fail to start. Batch logon privilege needs to be enabled for the task principal." }
                    {$('{0:X}' -f $_) -eq '8004131D'}   { "The task XML contains too many nodes of the same type." }
                    {$('{0:X}' -f $_) -eq '8004131E'}   { "The task cannot be started after the trigger end boundary." }
                    {$('{0:X}' -f $_) -eq '8004131F'}   { "An instance of this task is already running." }
                    {$('{0:X}' -f $_) -eq '80041320'}   { "The task will not run because the user is not logged on." }
                    {$('{0:X}' -f $_) -eq '80041321'}   { "The task image is corrupt or has been tampered with." }
                    {$('{0:X}' -f $_) -eq '80041322'}   { "The Task Scheduler service is not available." }
                    {$('{0:X}' -f $_) -eq '80041323'}   { "The Task Scheduler service is too busy to handle your request. Please try again later." }
                    {$('{0:X}' -f $_) -eq '80041324'}   { "The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition." }
                    {$('{0:X}' -f $_) -eq '00041325'}   { "The Task Scheduler service has asked the task to run." }
                    {$('{0:X}' -f $_) -eq '80041326'}   { "The task is disabled." }
                    {$('{0:X}' -f $_) -eq '80041327'}   { "The task has properties that are not compatible with earlier versions of Windows." }
                    {$('{0:X}' -f $_) -eq '80041328'}   { "The task settings do not allow the task to start on demand." }
                    {$('{0:X}' -f $_) -eq 'C000013A'}   { "The application terminated as a result of a CTRL+C." }
                    {$('{0:X}' -f $_) -eq 'C0000142'}   { "The application failed to initialize properly." }
                    Default                             { $null }
                }

                [pscustomobject]@{
                    Name            = $obj.ScheduledTask.TaskName
                    Status          = $obj.ScheduledTask.status
                    Triggers        = $Triggers
                    NextRunTime     = if ($obj.ScheduledTaskInfo.NextRunTime) {Get-Date $obj.ScheduledTaskInfo.NextRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                    LastRunTime     = if ($obj.ScheduledTaskInfo.LastRunTime) {Get-Date $obj.ScheduledTaskInfo.LastRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                    LastRunResult   = $LastRunResult
                    Author          = $obj.ScheduledTask.Author
                    Created         = if ($obj.ScheduledTask.Date) {Get-Date $obj.ScheduledTask.Date -Format MM-dd-yy_hh:mm:sstt} else {$null}
                }
            }
            $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
            
            $Session:AllScheduledTasksStatic | Out-UDGridData
        }

        # Live Data Element Example

        # Remove the Loading  Indicator
        $null = $Session:ScheduledTasksPageLoadingTracker.Add("FinishedLoading")

        #endregion >> Controls
    }
}
$Page = New-UDPage -Url "/ScheduledTasks/:RemoteHost" -Endpoint $ScheduledTasksPageContent
$null = $Pages.Add($Page)
