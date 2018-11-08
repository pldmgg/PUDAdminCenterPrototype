function TestSSH {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$OSGuess = "Windows",

        [Parameter(Mandatory=$True)]
        [pscustomobject]$RemoteHostNetworkInfo, # This must be a pscustomobject with properties HostName, FQDN, Domain, IPAddressList, and PingSuccess

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <RemoteHostName>\<User>
        [string]$LocalUserName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string]$DomainUserName,

        [Parameter(Mandatory=$False)]
        [string]$LocalPassword,

        [Parameter(Mandatory=$False)]
        [string]$DomainPassword,

        [Parameter(Mandatory=$False)]
        [string]$PublicCertPath,

        [Parameter(Mandatory=$False)]
        $OutputTracker
    )
    

    if ($OSGuess -eq "Windows") {
        if ($LocalUserName) {
            $FullUserName = $LocalUserName
        }
        if ($DomainUserName) {
            $FullUserName = $DomainUserName
        }

        if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
            $HostNameValue = @(
                $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
            )[0]
        }
        else {
            $HostNameValue = $RemoteHostNetworkInfo.FQDN
        }

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
            $HostNameValue
            '-UserName'
            $FullUserName
        )
        if ($PublicCertPath) {
            $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
            $null = $PwshInvCmdStringArray.Add("'$PublicCertPath'")
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

        if ($OutputTracker) {
            if ($OutputTracker.Keys -contains "PwshCmdString") {
                $OutputTracker.PwshCmdString = $PwshCmdString
            }
            else {
                $OutputTracker.Add("PwshCmdString",$PwshCmdString)
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

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
            }
            return
        }

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
            }
            else {
                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
            }
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
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                        $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                    }
                    else {
                        $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                    }
                }
                return
            }

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
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
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                }
            }
            
            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
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
                    if ($OutputTracker) {
                        if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepA") {
                            $PUDRSSyncHT.JsonOutputPrepA = $JsonOutputPrep
                        }
                        else {
                            $PUDRSSyncHT.Add("JsonOutputPrepA",$JsonOutputPrep)
                        }
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
            if ($LocalPassword) {
                $null = Send-AwaitCommand $LocalPassword
            }
            if ($DomainPassword) {
                $null = Send-AwaitCommand $DomainPassword
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
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepB") {
                        $PUDRSSyncHT.JsonOutputPrepB = $JsonOutputPrep
                    }
                    else {
                        $PUDRSSyncHT.Add("JsonOutputPrepB",$JsonOutputPrep)
                    }
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

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepC") {
                    $PUDRSSyncHT.JsonOutputPrepC = $JsonOutputPrep
                }
                else {
                    $PUDRSSyncHT.Add("JsonOutputPrepC",$JsonOutputPrep)
                }
            }

            $FinalJson = $JsonOutputPrep | foreach {if (![System.String]::IsNullOrWhiteSpace($_)) {$_.Trim()}}

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "FinalJson") {
                    $PUDRSSyncHT.FinalJson = $FinalJson
                }
                else {
                    $PUDRSSyncHT.Add("FinalJson",$FinalJson)
                }
            }

            try {
                $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
                $script:SSHCheckAsJson = $SSHCheckAsJson
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

    if ($OSGuess -eq "Linux" -or $TrySSHExe) {
        if ($LocalUserName) {
            $FullUserName = $($LocalUserName -split "\\")[-1]
        }
        if ($DomainUserName) {
            $DomainNameShort = $($DomainUserName -split "\\")[0]
            $FullUserName = $($DomainUserName -split "\\")[-1]
        }

        $HostNameValue = $RHostIP = @(
            $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
        )[0]

        # This is what we're going for:
        # $test = ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"

        [System.Collections.ArrayList]$SSHCmdStringArray = @(
            'ssh'
        )
        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
            $null = $SSHCmdStringArray.Add("-i")
            $null = $SSHCmdStringArray.Add("'" + $PublicCertPath + "'")
        }
        $null = $SSHCmdStringArray.Add("-t")
        if ($LocalUserName -and $LocalPassword) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$RHostIP")
        }
        if ($DomainUserName -and $DomainPassword) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$RHostIP")
        }
        $null = $SSHCmdStringArray.Add("`"echo 'ConnectionSuccessful'`"")
        $SSHCmdString = $SSHCmdStringArray -join " "

        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "SSHCmdString") {
                $PUDRSSyncHT.SSHCmdString = $SSHCmdString
            }
            else {
                $PUDRSSyncHT.Add("SSHCmdString",$SSHCmdString)
            }
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
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
            }
            return
        }

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
            }
            else {
                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
            }
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
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                }
            }
            
            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($Domain_Password) {
                    $null = Send-AwaitCommand $DomainPassword
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
                    if ($OutputTracker) {
                        if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepA") {
                            $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                        }
                        else {
                            $PUDRSSyncHT.Add("SSHOutputPrepA",$SSHOutputPrep)
                        }
                    }

                    New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }
            }
        }
        elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
            if ($LocalPassword) {
                $null = Send-AwaitCommand $LocalPassword
            }
            if ($DomainPassword) {
                $null = Send-AwaitCommand $DomainPassword
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
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepB") {
                        $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                    }
                    else {
                        $PUDRSSyncHT.Add("SSHOutputPrepB",$SSHOutputPrep)
                    }
                }

                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                return
            }

            $script:SSHOutputPrep = $SSHOutputPrep
        }
    }
}

# SIG # Begin signature block
# MIIM3gYJKoZIhvcNAQcCoIIMzzCCDMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDwrH03GEnV3CEm0ArwxUxUeR
# B++gggpPMIIEKTCCAxGgAwIBAgITRAAAAALGGh0rrvpIiwAAAAAAAjANBgkqhkiG
# 9w0BAQsFADBAMRMwEQYKCZImiZPyLGQBGRYDbGFiMRUwEwYKCZImiZPyLGQBGRYF
# YWxwaGExEjAQBgNVBAMTCUFscGhhREMwMTAeFw0xODExMDYxNTQ2MjhaFw0yMDEx
# MDYxNTU2MjhaMEExEzARBgoJkiaJk/IsZAEZFgNsYWIxFTATBgoJkiaJk/IsZAEZ
# FgVhbHBoYTETMBEGA1UEAxMKQWxwaGFTdWJDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAJ0yJxQZZ7jXPnBuOefihL0ehpBF1zoZpcM30pWneQA/kk9w
# ByX9ISyKWTABstiIu8b2g6lKUjZBM8AOcLPSjl1ZMQkh+qaSQbJFVNeNYllGpjd1
# oOYvSPtr9iPpghVkAFWw9IdOgnd/4XDd4NqlddyR4Qb0g7v3+AMYrqhQCk2VzELp
# 215LEO9sy1EMy7+B29B6P43Rp7ljA9Wc4Hnl+onviFWcIxmIhd0yGdobSxOSDgv5
# SUBfwk+DW03Y9pmJJHCU9hXFFVsPnrfBEvicGrkYx0vA+/O+jh5otex4eR+Tt7eB
# 5VhrfdHKbEkZnBwrJOVz3rURZIu3BsDFSfwNd70CAwEAAaOCARkwggEVMBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRWBfwwFO+72Ebloy7rHmHnxX3k5DAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTq79v4G/Vf91c0y+vSJBWEI/vmDTA8BgNVHR8E
# NTAzMDGgL6AthitodHRwOi8vcGtpLmFscGhhLmxhYi9jZXJ0ZGF0YS9BbHBoYURD
# MDEuY3JsMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAoYraHR0cDovL3BraS5h
# bHBoYS5sYWIvY2VydGRhdGEvQWxwaGFEQzAxLmNydDANBgkqhkiG9w0BAQsFAAOC
# AQEAoE9hHZ0Y5M5tC15cnxVNJa/ILfwRmwCxzPyOAUrdBu4jbSHF2vRsKIJAXFs4
# +mwXqXpLYSUbXF5tfB86OKs2f9L7soln3BXJHj3eEs27htf7RJK1JjPtO8rs3pdn
# h7TbDO3nyjkTcywJioScFZUTdIsQj7TBm3HIQ+/ZSdIWMHlQnYV2kW13XqUZnLhv
# PRjy1NMBG1BAxUrc4bMi1X+mVxoYb/tiB59jakd95wi7ICi2H/07dXoDpi+kAQA1
# ki1/U+cuDhuH7Q8hegt64MlmKD01rO5HODVujuIG1+M5ZkGDeLNKksPHcSJ/DBSn
# KjZca16Sn9No2kLq1q9gD8X/wzCCBh4wggUGoAMCAQICE3AAAAAHhXSIXehTWisA
# AAAAAAcwDQYJKoZIhvcNAQELBQAwQTETMBEGCgmSJomT8ixkARkWA2xhYjEVMBMG
# CgmSJomT8ixkARkWBWFscGhhMRMwEQYDVQQDEwpBbHBoYVN1YkNBMB4XDTE4MTEw
# NzAzMTQyMFoXDTE5MTEwNzAzMTQyMFowTzETMBEGCgmSJomT8ixkARkWA2xhYjEV
# MBMGCgmSJomT8ixkARkWBWFscGhhMQ4wDAYDVQQDEwVVc2VyczERMA8GA1UEAxMI
# YWxwaGFkZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMUGwGv3p0
# prkDmSUQphU6UvIFQ57NxJFUOSmMZ7SY/nYNDy0iTN26eD0S5J8AQE8B/IGLHUno
# tKFl2AUcQ31hpaSLE1YkThR3WZ4SFUaBMUgKKLc/RQKqE0iNbAfh53N/nnGs6jyu
# 47kyuFRwWE2tZee6b5hh0dbT7YZnahLO7cLWErU4ikWWjEA98TcMK1gaNa5ThBn1
# +4bo9wuxjRKIGpkUJBP/1gq8qeSJnfNelZ34lD0EEirj7/YTzL5YkHMSXTuFMozw
# Av4lXUW/qZ1pAT9rKBalQETxBv9SuC31hU/2EiB4EYYqVFLHglFRogLd7nFZhqa/
# 2O+WdW2LsW9lAgMBAAGjggL/MIIC+zAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE
# FMy71rz8tJOXdsGvBt6SIVSKUlrkMB8GA1UdIwQYMBaAFFYF/DAU77vYRuWjLuse
# YefFfeTkMIH3BgNVHR8Ege8wgewwgemggeaggeOGgbJsZGFwOi8vL0NOPUFscGhh
# U3ViQ0EsQ049QWxwaGFTdWJDQSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vy
# dmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1hbHBoYSxEQz1s
# YWI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
# TERpc3RyaWJ1dGlvblBvaW50hixodHRwOi8vcGtpLmFscGhhLmxhYi9jZXJ0ZGF0
# YS9BbHBoYVN1YkNBLmNybDCB9AYIKwYBBQUHAQEEgecwgeQwgacGCCsGAQUFBzAC
# hoGabGRhcDovLy9DTj1BbHBoYVN1YkNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
# MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWFscGhh
# LERDPWxhYj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
# dGlvbkF1dGhvcml0eTA4BggrBgEFBQcwAoYsaHR0cDovL3BraS5hbHBoYS5sYWIv
# Y2VydGRhdGEvQWxwaGFTdWJDQS5jcnQwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGC
# NxUIhLycPIHG3hyBiYk0hLvpfobokGRgg9+kPoHDslgCAWQCAQIwHwYDVR0lBBgw
# FgYKKwYBBAGCNwoDDAYIKwYBBQUHAwMwKQYJKwYBBAGCNxUKBBwwGjAMBgorBgEE
# AYI3CgMMMAoGCCsGAQUFBwMDMC0GA1UdEQQmMCSgIgYKKwYBBAGCNxQCA6AUDBJh
# bHBoYWRldkBhbHBoYS5sYWIwDQYJKoZIhvcNAQELBQADggEBAIhV0GPEvq5KwIs+
# DTqLsqHcojMyJhJwrZkEim2XAJfNQFkiDrZzism7lOyXYJol6Bjz1txhos7P194+
# VyBdEZ/Q+r94hrq6SFgC2gCAReDZiy50Au/hTv958QNX/O0OFdIGBxavLqBrWbwu
# yH+RtE9E4LICSPPd0dM/5XE0xtqDMjZcl3pVkqgHpv3O3zgtsTW+FWr4b9lq3rCO
# HxsBGU1w7Eh0LLK8MLqioecr/4B1rPTJkcASXWMU5bllQgQvUmlKW0GIfhC9aM4J
# 04MeJOU1mHLjDcxwWpDD670AFmGRg/mMPxMywvY0HLUszWikcXNYxF1ph+LhlLI9
# f9R1qqkxggH5MIIB9QIBATBYMEExEzARBgoJkiaJk/IsZAEZFgNsYWIxFTATBgoJ
# kiaJk/IsZAEZFgVhbHBoYTETMBEGA1UEAxMKQWxwaGFTdWJDQQITcAAAAAeFdIhd
# 6FNaKwAAAAAABzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUq7mSF6PPWiFWB1LZYsVo3okna6gw
# DQYJKoZIhvcNAQEBBQAEggEATuuwKhY4ZAr+6l6lvvPivPa3zB2NzWqI33GG78p1
# HJB7Anmzn56P6jO22g17MWuFKWXfeG+vSgpPmRoF4ujLQvwMzwcnNsmhn+SSpnRR
# ZUTfry7UDmbuSe5+6B62uW8A6IFyg1XpliOOMpMoP1DBZfwh1is3u2aNDW+MbXvK
# EvJUYhMKGdBM7cGpkgYL7HXkCyq2EmMapEeSz7w6BOdX9tLUDTl7AGDGe9icpN9i
# lz/gChnJvXR+OKb3z1YmOAO/9V78uf3O0dKSUI3HCBL6SLlhXMmz6+6P+JOd5j1Q
# mypWCCKtNfXImsWw+NJZ2xsyt6eMwULoMA5FP/7uz8KILg==
# SIG # End signature block
