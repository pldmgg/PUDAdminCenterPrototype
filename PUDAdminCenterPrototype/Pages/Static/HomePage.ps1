#region >> Create Home Page

$HomePageContent = {
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Define some Cache: variables that we'll be using in a lot of different contexts
    $Cache:ThisModuleFunctionsStringArray = $ThisModuleFunctionsStringArray = $(Get-Module PUDAdminCenterPrototype).Invoke({$FunctionsForSBUse})

    $Cache:DynamicPages = $DynamicPages = @(
        "PSRemotingCreds"
        "ToolSelect"
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

    # Load PUDAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

    #region >> Loading Indicator

    New-UDRow -Columns {
        New-UDColumn -Endpoint {
            $Cache:RHostRefreshAlreadyRan = $False
            $Session:HomePageLoadingTracker = $False
            $Session:SearchRemoteHosts = $False
        }
        New-UDHeading -Text "Remote Hosts" -Size 4
    }

    New-UDRow -Columns {
        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
            if (!$Session:HomePageLoadingTracker) {
                New-UDHeading -Text "Loading...Please wait..." -Size 5
                New-UDPreloader -Size small
            }
        }
    }

    #endregion >> Loading Indicator

    #region >> HomePage Main Content

    New-UDRow -Endpoint {
        New-UDColumn -Endpoint {
            New-UDHeading -Text "General Network Scan" -Size 5
            New-UDElement -Id "ScanNetwork" -Tag div -EndPoint {
                if ($Session:ScanNetwork) {
                    New-UDHeading -Text "Scanning Network for RemoteHosts...Please wait..." -Size 6
                    New-UDPreloader -Size small
                }
            }
        }
    }
    New-UDRow -Endpoint {
        New-UDColumn -Endpoint {
            New-UDButton -Text "Scan Network" -OnClick {
                $Session:ScanNetwork = $True
                Sync-UDElement -Id "ScanNetwork"

                [System.Collections.ArrayList]$ScanRemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
                # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
                # the user to specify individual/range of hosts/devices that they want to manage.
                #$ScanRemoteHostListPrep = $ScanRemoteHostListPrep[0..20]
                if ($PSVersionTable.PSEdition -eq "Core") {
                    [System.Collections.ArrayList]$ScanRemoteHostListPrep = $ScanRemoteHostListPrep | foreach {$_ -replace "CN=",""}
                }

                # Filter Out the Remote Hosts that we can't resolve
                [System.Collections.ArrayList]$ScanRemoteHostList = @()

                $null = Clear-DnsClientCache
                foreach ($HName in $ScanRemoteHostListPrep) {
                    try {
                        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

                        if ($ScanRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                            $null = $ScanRemoteHostList.Add($RemoteHostNetworkInfo)
                        }
                    }
                    catch {
                        continue
                    }
                }

                $PUDRSSyncHT.RemoteHostList = $ScanRemoteHostList

                # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                foreach ($RHost in $ScanRemoteHostList) {
                    $Key = $RHost.HostName + "Info"
                    if ($PUDRSSyncHT.Keys -notcontains $Key) {
                        $Value = @{
                            NetworkInfo                 = $RHost
                            CredHT                      = $null
                            ServerInventoryStatic       = $null
                            RelevantNetworkInterfaces   = $null
                            LiveDataRSInfo              = $null
                            LiveDataTracker             = @{Current = $null; Previous = $null}
                        }
                        foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                            $DynPageHT = @{
                                LiveDataRSInfo      = $null
                                LiveDataTracker     = @{Current = $null; Previous = $null}
                            }
                            $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                        }
                        $PUDRSSyncHT.Add($Key,$Value)
                    }
                }

                $Session:ScanNetwork = $False
                Sync-UDElement -Id "ScanNetwork"

                # Refresh the Main Content
                Sync-UDElement -Id "MainContent"
            }
        }
    }

    # RemoteHost / Device Search
    New-UDRow -Endpoint {
        New-UDColumn -Endpoint {
            New-UDHeading -Text "Find Specific Remote Hosts" -Size 5
            New-UDElement -Id "SearchRemoteHosts" -Tag div -EndPoint {
                if ($Session:SearchRemoteHosts) {
                    New-UDHeading -Text "Searching for RemoteHosts...Please wait..." -Size 6
                    New-UDPreloader -Size small
                }
            }
        }

        New-UDColumn -Size 12 -Endpoint {
            New-UDRow -Endpoint {
                New-UDColumn -Size 5 -Endpoint {
                    New-UDTextbox -Id "HostNameOrFQDN" -Label "HostName_Or_FQDN" -Placeholder "Enter a HostName/FQDN, or comma-separated HostNames/FQDNs"
                }
                New-UDColumn -Size 5 -Endpoint {
                    New-UDTextbox -Id "IPAddress" -Label "IPAddress" -Placeholder "Enter an IP, comma-separated IPs, a range of IPs using a '-', or a range of IPs using CIDR"
                }
                New-UDColumn -Size 2 -Endpoint {
                    New-UDButton -Text "Search" -OnClick {
                        $Session:SearchRemoteHosts = $True
                        Sync-UDElement -Id "SearchRemoteHosts"

                        $HostNameTextBox = Get-UDElement -Id "HostNameOrFQDN"
                        $IPTextBox = Get-UDElement -Id "IPAddress"

                        $HostNames = $HostNameTextBox.Attributes['value']
                        $IPAddresses = $IPTextBox.Attributes['value']

                        [System.Collections.ArrayList]$RemoteHostListPrep = @()

                        if ($HostNames) {
                            if ($HostNames -match [regex]::Escape(',')) {
                                $HostNames -split [regex]::Escape(',') | foreach {
                                    if (![System.String]::IsNullOrWhiteSpace($_)) {
                                        $null = $RemoteHostListPrep.Add($_.Trim())
                                    }
                                }
                            }
                            else {
                                $null = $RemoteHostListPrep.Add($HostNames.Trim())
                            }
                        }

                        if ($IPAddresses) {
                            # Do some basic validation. Make sure no unexpected characters are present.
                            $UnexpectedCharsCheck = $([char[]]$IPAddresses -notmatch "[\s]|,|-|\/|[0-9]") | Where-Object {$_ -ne '.'}
                            if ($UnexpectedCharsCheck.Count -gt 0) {
                                $Session:SearchRemoteHosts = $False
                                Sync-UDElement -Id "SearchRemoteHosts"
                                $Msg = "The following invalid characters were found in the 'IPAddress' field:`n$($UnexpectedCharsCheck -join ', ')"
                                Show-UDToast -Message $Msg -Position 'topRight' -Title "BadChars" -Duration 10000
                                Write-Error $Msg
                                return
                            }

                            if (!$($IPAddresses -match [regex]::Escape(',')) -and !$($IPAddresses -match [regex]::Escape('-')) -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                $null = $RemoteHostListPrep.Add($IPAddresses.Trim())
                            }
                            if ($IPAddresses -match [regex]::Escape(',')) {
                                $ArrayOfRanges = $IPAddresses -split [regex]::Escape(',') | foreach {
                                    if (![System.String]::IsNullOrWhiteSpace($_)) {
                                        $_.Trim()
                                    }
                                }

                                if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) {
                                    foreach ($IPRange in $ArrayOfRanges) {
                                        if ($IPRange -match [regex]::Escape('-')) {
                                            $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                            $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]

                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                                Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                continue
                                            }

                                            Get-IPRange -start $StartIP -end $EndIP | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                        if ($IPRange -match [regex]::Escape('/')) {
                                            $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                            $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]

                                            Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                    }
                                }
                                if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                    foreach ($IPRange in $ArrayOfRanges) {
                                        $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                        $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]

                                        if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                            Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                        }
                                        if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                            Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                        }
                                        if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                            continue
                                        }

                                        Get-IPRange -start $StartIP -end $EndIP | foreach {
                                            $null = $RemoteHostListPrep.Add($_)
                                        }
                                    }
                                }
                                if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                    foreach ($IPRange in $ArrayOfRanges) {
                                        $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                        $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]

                                        Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                            $null = $RemoteHostListPrep.Add($_)
                                        }
                                    }
                                }
                                if (!$($IPAddresses -match [regex]::Escape('/')) -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                    $IPAddresses -split [regex]::Escape(',') | foreach {
                                        if (!$(TestIsValidIPAddress -IPAddress $_)) {
                                            Show-UDToast -Message "$_ is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadIP" -Duration 5000
                                        }
                                        else {
                                            $null = $RemoteHostListPrep.Add($_.Trim())
                                        }
                                    }
                                }
                            }
                            if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) { 
                                Write-Error "You are either missing a comma between two or more separate IP Ranges, or your notation is incorrect. Please try again."
                                $global:FunctionResult = "1"
                                return
                            }
                            if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]

                                if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                    Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                }
                                if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                    Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                }
                                if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                    continue
                                }

                                Get-IPRange -start $StartIP -end $EndIP | foreach {
                                    $null = $RemoteHostListPrep.Add($_)
                                }
                                
                            }
                            if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]

                                Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                    $null = $RemoteHostListPrep.Add($_)
                                }
                            }
                        }

                        # Filter Out the Remote Hosts that we can't resolve via DNS
                        [System.Collections.ArrayList]$RemoteHostList = @()

                        $null = Clear-DnsClientCache
                        foreach ($HNameOrIP in $RemoteHostListPrep) {
                            try {
                                $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HNameOrIP -ErrorAction Stop

                                $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                            }
                            catch {
                                Show-UDToast -Message "Unable to resolve $HNameOrIP" -Position 'topRight' -Title "CheckDNS" -Duration 5000
                                continue
                            }
                        }
                        $PUDRSSyncHT.RemoteHostList = $RemoteHostList

                        # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                        foreach ($RHost in $RemoteHostList) {
                            if ($PUDRSSyncHT.Keys -notcontains "$($RHost.HostName)Info") {
                                $Key = $RHost.HostName + "Info"
                                $Value = @{
                                    NetworkInfo                 = $RHost
                                    CredHT                      = $null
                                    ServerInventoryStatic       = $null
                                    RelevantNetworkInterfaces   = $null
                                    LiveDataRSInfo              = $null
                                    LiveDataTracker             = @{Current = $null; Previous = $null}
                                }
                                foreach ($DynPage in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    $DynPageHT = @{
                                        LiveDataRSInfo      = $null
                                        LiveDataTracker     = @{Current = $null; Previous = $null}
                                    }
                                    $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                                }
                                $PUDRSSyncHT.Add($Key,$Value)
                            }
                        }

                        $Session:SearchRemoteHosts = $True
                        Sync-UDElement -Id "SearchRemoteHosts"

                        # Refresh the Main Content
                        Sync-UDElement -Id "MainContent"
                    }
                }
            }
        }
    }

    <#
    New-UDRow -Endpoint {
        New-UDColumn -Endpoint {
            New-UDHeading -Text "Sampling of Available Remote Hosts" -Size 5
        }
    }
    #>

    New-UDElement -Id "MainContent" -Tag div -EndPoint {
        New-UDRow -Endpoint {
            New-UDColumn -Size 12 -Endpoint {
                $RHostUDTableEndpoint = {
                    $PUDRSSyncHT = $global:PUDRSSyncHT

                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

                    $RHost = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RHostName}

                    $RHostTableData = @{}
                    $RHostTableData.Add("HostName",$RHost.HostName.ToUpper())
                    $RHostTableData.Add("FQDN",$RHost.FQDN)

                    # Guess Operating System
                    if ($RHost.HostName -eq $env:ComputerName) {
                        $OSGuess = $(Get-CimInstance Win32_OperatingSystem).Caption
                    }
                    else {
                        $NmapOSResult = nmap -O $RHost.IPAddressList[0]
                        if ($NmapOSResult -match "OS details:") {
                            $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "OS details:"}) -replace "OS details: ",""
                            $OSGuess = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0].Trim()} else {$OSGuessPrep.Trim()}
                        }
                        if ($NmapOSResult -match "Aggressive OS guesses:") {
                            $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "Aggressive OS guesses:"}) -replace "Aggressive OS guesses: ",""
                            $OSGuessPrep = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0]} else {$OSGuessPrep}
                            $OSGuess = $($OSGuessPrep -replace "[\s]\([0-9]+%\)","").Trim()
                        }
                        if (!$OSGuess) {
                            $OSGuess = $null
                        }
                    }
                    $RHostTableData.Add("OS_Guess",$OSGuess)

                    $IPAddressListAsString = @($RHost.IPAddressList) -join ", "
                    $RHostTableData.Add("IPAddress",$IPAddressListAsString)

                    # Check Ping
                    try {
                        $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                            $RHost.IPAddressList[0],1000
                        ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId

                        $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                        $RHostTableData.Add("PingStatus",$PingStatus)
                    }
                    catch {
                        $RHostTableData.Add("PingStatus","Unavailable")
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
                            $RHostTableData.Add("WSMan","Available")

                            [System.Collections.ArrayList]$WSManPorts = @()
                            if ($WSMan5985Available) {
                                $null = $WSManPorts.Add("5985")
                            }
                            if ($WSMan5986Available) {
                                $null = $WSManPorts.Add("5986")
                            }

                            $WSManPortsString = $WSManPorts -join ', '
                            $RHostTableData.Add("WSManPorts",$WSManPortsString)
                        }
                    }
                    catch {
                        $RHostTableData.Add("WSMan","Unavailable")
                    }

                    # Check SSH
                    try {
                        $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22

                        if ($TestSSHResult.Open) {
                            $RHostTableData.Add("SSH","Available")
                        }
                        else {
                            $RHostTableData.Add("SSH","Unavailable")
                        }
                    }
                    catch {
                        $RHostTableData.Add("SSH","Unavailable")
                    }

                    $RHostTableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))

                    if ($RHostTableData.WSMan -eq "Available" -or $RHostTableData.SSH -eq "Available") {
                        # We are within an -Endpoint, so $Session: variables should be available
                        #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
                        if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                            $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                        }
                        else {
                            $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                        }
                    }
                    else {
                        $RHostTableData.Add("ManageLink","Unavailable")
                    }

                    $RHostTableData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))

                    if ($PUDRSSyncHT."$($RHost.HostName)Info".Keys -contains "RHostTableData") {
                        $PUDRSSyncHT."$($RHost.HostName)Info".RHostTableData = $RHostTableData
                    }
                    else {
                        $PUDRSSyncHT."$($RHost.HostName)Info".Add("RHostTableData",$RHostTableData)
                    }
                    
                    [pscustomobject]$RHostTableData | Out-UDTableData -Property @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
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

                    $ResultProperties = @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
                    $RHostUDTableSplatParams = @{
                        Title           = $RHost.HostName.ToUpper()
                        Headers         = $ResultProperties
                        #AutoRefresh     = $True 
                        #RefreshInterval = 15
                        Endpoint        = $RHostUDTableEndpoint
                    }
                    New-UDTable @RHostUDTableSplatParams

                    $RHostCounter++

                    if ($RHostCounter -ge $($PUDRSSyncHT.RemoteHostList.Count-1)) {
                        New-UDColumn -Endpoint {
                            $Session:HomePageLoadingTracker = $True
                            $Session:SearchRemoteHosts = $False
                            Sync-UDElement -Id "SearchRemoteHosts"
                        }
                    }
                }

                # This hidden column refreshes the RemoteHostList so that when the HomePage is reloaded, it only displays
                # host/devices that can be resolved. This is so that if PUDAdminCenter is used to shutdown/restart a Remote Host,
                # the list of hosts on the HomePage is accurate 
                New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                    $PUDRSSyncHT = $global:PUDRSSyncHT

                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

                    if ($Cache:HomeFinishedLoading -and !$Cache:RHostRefreshAlreadyRan) {
                        $null = Clear-DnsClientCache
                        foreach ($IPAddr in $PUDRSSyncHT.RemoteHostList.IPAddressList) {
                            try {
                                $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $IPAddr -ErrorAction Stop

                                # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
                                # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
                                if (!$RemoteHostNetworkInfo.HostName) {
                                    $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                                    $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                                    $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                                    $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                                    $RemoteHostNetworkInfo.Domain = 'Unknown'
                                }

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
            }
        }
    }

    #endregion >> HomePage Main Content
}
# IMPORTANT NOTE: Anytime New-UDPage is used with parameter set '-Name -Content', it appears in the hamburger menu
# This is REQUIRED for the HomePage, otherwise http://localhost won't load (in otherwords, you can't use the
# parameter set '-Url -Endpoint' for the HomePage).
# Also, it is important that the HomePage comes first in the $Pages ArrayList
$HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
$null = $Pages.Insert(0,$HomePage)