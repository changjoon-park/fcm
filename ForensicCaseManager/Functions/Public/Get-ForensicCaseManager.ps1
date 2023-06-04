function Get-ForensicCaseManager {
    [Alias("fcm")]
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ParameterSetName = "Container",
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $Container,

        [Parameter(ParameterSetName = "Local")]
        [switch]
        $Local,

        [Parameter(ParameterSetName = "ImportCase")]
        [string]
        $ImportCase,

        # [Parameter(Position = 1,
        #     ParameterSetName = "Artifact")]
        [Parameter(Position = 1)]
        [ValidateSet("MFT", "UsnJrnl", "RecycleBin", "Prefetch", "Lnk", "JumpList", "ThumbCache", "IconCache",
                    "FileHistory", "Chrome", "Edge", "iExplorer", "RemoteAccess", "SRU(App)", "SRU(Network)", 
                    "WindowsTimeline", "Amcache", "UserAccount", "UserAssist", "USB(Registry)", "USB(EventLog)",
                    "ShimCache", "BAM", "NetworkInfo", "SystemInfo", "AutoRun", "MRU", "ShellBags", "WLAN", 
                    "LogonEvent")]
        [string[]]
        $Artifact,

        # [Parameter(Position = 1,
        #     ParameterSetName = "Category")]
        [Parameter(Position = 1)]
        [ValidateSet("All", "System Information", "Application Execution", "File and Folder Opening",
                    "Deleted Items and File Existence", "Browser Activity", "Cloud Storage", "Account Usage",
                    "Network Activity", "External Device And USB Usage")]
        [string[]]
        $Category,

        [Parameter()]
        [string]
        $Out = $env:TEMP
    )
    
    begin {
        ## Prepare to Work
        $SCRIPT_NAME = "Parser\main.py"
        $ROOT_DIRECTORY_NAME = "_fcm"

        if ($Artifact -and $Category) {
            Write-Host ""
            Write-Warning -Message "Select only one of the two options: [Artifact] / [Category]"
            Write-Host ""
            $ErrorFlag = $true
            return
        }

        if ($ImportCase) {
            if (Test-Path -LiteralPath $ImportCase) {
                $ImportCaseName = (Get-Item -LiteralPath $ImportCase).BaseName
    
                if ($ImportCaseName -eq $ROOT_DIRECTORY_NAME) {
                    $ImportCasePath = $ImportCase
                }
                else {
                    $ImportCasePath = Get-ChildItem -LiteralPath $ImportCase | Where-Object { $_.Name -eq $ROOT_DIRECTORY_NAME }
    
                    if (!$ImportCasePath) {
                        Write-Host ""
                        Write-Warning -Message ("Invalid Forensic Case Directory: [{0}]" -f $ImportCase)
                        Write-Host ""
                        $ErrorFlag = $true
                        return
                    }
                }
            }
            else {
                Write-Host ""
                Write-Warning -Message ("Path Not Found: [{0}]" -f $ImportCase)
                Write-Host ""
                $ErrorFlag = $true
                return
            }
        }

        $Script = Join-Path -Path $PSScriptRoot -ChildPath $SCRIPT_NAME
        $RootDirectory = Join-Path -Path $Out -ChildPath $ROOT_DIRECTORY_NAME
        $CaseNumber = 0
        $Containers = New-Object -TypeName System.Collections.ArrayList
        
        if ($Category -eq "All") {
            $Category = @(
                "System Information", "Network Activity", "Account Usage", "Application Execution", 
                "File and Folder Opening", "Deleted Items and File Existence",
                "Browser Activity", "External Device And USB Usage"
            )
        }
    }
    process {
        if ($ErrorFlag) {
            return
        }

        if ($ImportCase) {
            Write-Host ""
            Write-Host "Begin to Import Forensic Case: " -ForegroundColor DarkBlue -NoNewline
            Write-Host $ImportCasePath -BackgroundColor DarkCyan -ForegroundColor DarkBlue -NoNewline
            Write-Host ""
        }
        else {
            Write-Host ""
            Write-Host "Begin to Process Forensic Container: " -ForegroundColor DarkBlue -NoNewline
    
            if ($Local) {
                Write-Host "Local Container" -BackgroundColor DarkCyan -ForegroundColor DarkBlue -NoNewline
                Write-Host ""
                
                if ($Artifact) {
                    $output = & python.exe $Script --local -a ($Artifact -join ",") -o $Out
                    $Comment = $Artifact
                }
                elseif ($Category) {
                    $output = & python.exe $Script --local -y ($Category -join ",") -o $Out
                    $Comment = $Category
                }
            }
            else {
                Write-Host $Container -BackgroundColor DarkBlue -ForegroundColor Cyan

                $null = $Containers.Add($Container)

                if ($Artifact) {
                    $output = & python.exe $Script -c $Container -a ($Artifact -join ",") -o $Out
                    $Comment = $Artifact
                }
                elseif ($Category) {
                    $output = & python.exe $Script -c $Container -y ($Category -join ",") -o $Out
                    $Comment = $Category
                }
            }
    
            Write-Host ""
            if ($output) {
                Write-Host " * Processing Success: " -ForegroundColor Blue -NoNewline
            }
            else {
                Write-Host " * Processing Failed: " -ForegroundColor Red -NoNewline
            }
    
            Write-Host $Comment
            Write-Host ""
        }
    }
    end {
        if ($ErrorFlag) {
            return
        }

        if ($ImportCasePath) {
            $ForensicCases = Get-ChildItem -LiteralPath $ImportCasePath | Sort-Object -Property "CreationTime" -Descending
        }
        else {
            $ForensicCases = Get-ChildItem -LiteralPath $RootDirectory | Sort-Object -Property "CreationTime" -Descending
        }

        foreach ($case in $ForensicCases) {
            $CaseItems = Get-ChildItem -LiteralPath $case.FullName -File *.json
            $CaseInformation = Get-Content -LiteralPath ($CaseItems | Where-Object { $_.Name.StartsWith("case") }) | ConvertFrom-Json
            $LastSession = ($CaseItems | Where-Object { $_.Name.StartsWith("session") } | Sort-Object -Property "Name" -Descending)[0]
            $SourceContainer = $CaseInformation.source

            if ($ImportCasePath) {
                $CaseData = Get-CaseData -Path $LastSession.FullName -SourceContainer $SourceContainer
                
                $ForensicCase = [PSCustomObject] @{
                    "Number" = $CaseNumber
                    "Label" = $CaseInformation.case_label
                    "ComputerName" = $CaseInformation.computer_name
                    "Owner" = $CaseInformation.registered_owner
                    "Data" = $CaseData
                    "SourceContainer" = $SourceContainer
                }

                $CaseNumber++
        
                Write-Output $ForensicCase
            }
            elseif ($Local) {
                if ($SourceContainer -eq "Local") {
                    $CaseData = Get-CaseData -Path $LastSession.FullName -SourceContainer $SourceContainer
    
                    $ForensicCase = [PSCustomObject] @{
                        "Number" = $CaseNumber
                        "Label" = $CaseInformation.case_label
                        "ComputerName" = $CaseInformation.computer_name
                        "Owner" = $CaseInformation.registered_owner
                        "Data" = $CaseData
                        "SourceContainer" = $SourceContainer
                    }
    
                    $CaseNumber++
        
                    Write-Output $ForensicCase
                }
            }
            else {
                if ($Containers -contains $SourceContainer) {
                    $CaseData = Get-CaseData -Path $LastSession.FullName -SourceContainer $SourceContainer

                    $ForensicCase = [PSCustomObject] @{
                        "Number" = $CaseNumber
                        "Label" = $CaseInformation.case_label
                        "ComputerName" = $CaseInformation.computer_name
                        "Owner" = $CaseInformation.registered_owner
                        "Data" = $CaseData
                        "SourceContainer" = $SourceContainer
                    }

                    $CaseNumber++
        
                    Write-Output $ForensicCase
                }
            }
        }
    }
}

function Get-CaseData {
    param (
        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $SourceContainer
    )

    $Session = Get-Content -LiteralPath $Path | ConvertFrom-Json

    $CATEGORY_SYSTEM_INFORMATION = "System Information"
    $CATEGORY_APPLICATION_EXECUTION = "Application Execution"
    $CATEGORY_FILE_FOLDER_OPENING = "File and Folder Opening"
    $CATEGORY_DELETED_ITEMS_FILE_EXISTENCE = "Deleted Items and File Existence"
    $CATEGORY_BROWSER_ACTIVITY = "Browser Activity"
    $CATEGORY_CLOUD_STORAGE = "Cloud Storage"
    $CATEGORY_ACCOUNT_USAGE = "Account Usage"
    $CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION = "Network Activity"
    $CATEGORY_EXTERNAL_DEVICE_USB_USAGE = "External Device And USB Usage"
    
    $ForensicArtifact = New-Object -TypeName PSCustomObject
    $NetworkActivity = New-Object -TypeName PSCustomObject
    $AccountUsage = New-Object -TypeName PSCustomObject
    $ApplicationExecution = New-Object -TypeName PSCustomObject
    $FileFolderOpening = New-Object -TypeName PSCustomObject
    $BrowserActivity = New-Object -TypeName PSCustomObject
    $DeletedItemsAndFileExistence = New-Object -TypeName PSCustomObject
    $ExternalDeviceAndUsbUsage = New-Object -TypeName PSCustomObject

    $SruNetwork = New-Object -TypeName PSCustomObject
    $Amcache = New-Object -TypeName PSCustomObject
    $Chrome = New-Object -TypeName PSCustomObject
    $Edge = New-Object -TypeName PSCustomObject
    $iExplorer = New-Object -TypeName PSCustomObject

    Add-Member -InputObject $NetworkActivity -MemberType NoteProperty -Name "SRU" -Value $SruNetwork
    Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "AmCache" -Value $Amcache
    Add-Member -InputObject $BrowserActivity -MemberType NoteProperty -Name "Chrome" -Value $Chrome
    Add-Member -InputObject $BrowserActivity -MemberType NoteProperty -Name "Edge" -Value $Edge
    Add-Member -InputObject $BrowserActivity -MemberType NoteProperty -Name "iExplorer" -Value $iExplorer

    Add-Member -InputObject $SruNetwork -MemberType ScriptMethod -Name "ToString" -Value {
        $str = New-Object -TypeName System.Collections.ArrayList
        if ($this.NetworkConnectivity) {
            $null = $str.Add("NetworkConnectivity")
        }
        if ($this.NetworkData) {
            $null = $str.Add("NetworkData")
        }
        return ($str -join ", ")
    } -Force

    Add-Member -InputObject $Amcache -MemberType ScriptMethod -Name "ToString" -Value {
        $str = New-Object -TypeName System.Collections.ArrayList
        if ($this.Applications) {
            $null = $str.Add("Applications")
        }
        if ($this.ApplicationFiles) {
            $null = $str.Add("ApplicationFiles")
        }
        return ($str -join ", ")
    } -Force

    Add-Member -InputObject $Chrome -MemberType ScriptMethod -Name "ToString" -Value {
        $str = New-Object -TypeName System.Collections.ArrayList
        if ($this.VisitHistory) {
            $substr = "Visit: {0}" -f $this.VisitHistory.Count
            $null = $str.Add($substr)
        }
        if ($this.KeywordSearchTerms) {
            $substr = "KeywordSearch: {0}" -f $this.KeywordSearchTerms.Count
            $null = $str.Add($substr)
        }
        if ($this.Downloads) {
            $substr = "Downloads: {0}" -f $this.Downloads.Count
            $null = $str.Add($substr)
        }
        return ($str -join ", ")
    } -Force

    Add-Member -InputObject $Edge -MemberType ScriptMethod -Name "ToString" -Value {
        $str = New-Object -TypeName System.Collections.ArrayList
        if ($this.VisitHistory) {
            $substr = "Visit: {0}" -f $this.VisitHistory.Count
            $null = $str.Add($substr)
        }
        if ($this.KeywordSearchTerms) {
            $substr = "KeywordSearch: {0}" -f $this.KeywordSearchTerms.Count
            $null = $str.Add($substr)
        }
        if ($this.Downloads) {
            $substr = "Downloads: {0}" -f $this.Downloads.Count
            $null = $str.Add($substr)
        }
        return ($str -join ", ")
    } -Force

    Add-Member -InputObject $iExplorer -MemberType ScriptMethod -Name "ToString" -Value {
        $str = New-Object -TypeName System.Collections.ArrayList
        if ($this.VisitHistory) {
            $substr = "Visit: {0}" -f $this.VisitHistory.Count
            $null = $str.Add($substr)
        }
        return ($str -join ", ")
    } -Force

    ## Let's Begin to Work !

    foreach ($entry in $Session) {
        $Results = Get-Content -LiteralPath $entry.result | ConvertFrom-Json

        if ($entry.category -eq $CATEGORY_SYSTEM_INFORMATION) {
            switch ($entry.record) {
                "system_info" {
                    $SystemInfo =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "OS" = $record.product
                                "Edition" = $record.edition_id
                                "Release" = $record.release_id
                                "ComputerName" = $record.hostname
                                "InstallDate" = $record.install_date
                                "LastShutdownTime" = $record.shutdown_time
                                "RegisteredOwner" = $record.registered_owner
                                "ProductKey" = $record.product_key
                                "ProductId" = $record.product_id
                                "SystemRoot" = $record.system_root
                                "PathName" = $record.path_name
                                "Architecture" = $record.architecture
                                "TimeZone" = $record.timezone
                                "CodePage" = $record.codepage
                                "ResultDataFile" = $entry.result
                                "SourceContainer" = $SourceContainer
                            }

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                $str = "{0}(Installed: {1})" -f $this.OS, $this.InstallDate
                                return $str
                            } -Force
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "SystemInformation" -Value $SystemInfo
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION) {
            switch ($entry.record) {
                "network_history" {
                    $NetworkHistory =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "TimeCreated" = $record.created
                                "TimeLastConnected" = $record.last_connected
                                "ProfileName" = $record.profile_name
                                "ProfileGuid" = $record.profile_guid
                                "Description" = $record.description
                                "FirstNetwork" = $record.first_network
                                "DefaultGatewayMAC" = $record.default_gateway_mac
                                "Signature" = $record.signature
                                "SourceContainer" = $SourceContainer
                            }

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                $str = "{0}[{1}]" -f $this.ProfileName, $this.ProfileGuid
                                return $str
                            } -Force
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $NetworkActivity -MemberType NoteProperty -Name "NetworkHistory" -Value $NetworkHistory
                }
                "network_interface" {
                    $NetworkInterface =
                        foreach ($record in $Results) {
                            $IpAddr = $record.ipaddr
                            $DhcpIpAddr = $record.dhcp_ipaddr

                            if ($IpAddr) {
                                $IpAddress = $IpAddr
                            }
                            elseif ($DhcpIpAddr) {
                                $IpAddress = "{0} (DHCP)" -f $DhcpIpAddr
                            }
                            else {
                                continue
                            }

                            $obj = [PScustomObject] @{
                                "IpAddress" = $IpAddress
                                "LeaseObtainedTime" = $record.lease_obtained_time
                                "LeaseTerminatedTime" = $record.lease_terminates_time
                                "SourceContainer" = $SourceContainer
                            }

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.IpAddress
                            } -Force
        
                            Write-Output $obj
                        }

                    # Add-Member -InputObject $NetworkInterface -MemberType ScriptMethod -Name "ToString" -Value {
                    #     return ($this.IpAddress -join ", ")
                    # } -Force

                    Add-Member -InputObject $NetworkActivity -MemberType NoteProperty -Name "NetworkInterface" -Value $NetworkInterface
                }
                "wlan_event" {
                    $Index = 0
                    $RecordName = "WLAN"
                    $WlanEvent =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "EventTime" = $record.ts
                                "Task" = $record.task
                                "EventId" = $record.event_id
                                "EventRecordId" = $record.event_record_id
                                "InterfaceGuid" = $record.interface_guid
                                "InterfaceDescription" = $record.interface_description
                                "ConncetionMode" = $record.connection_mode
                                "ProfileName" = $record.profile_name
                                "SSID" = $record.ssid
                                "FailureReason" = $record.failure_reason
                                "ReasonCode" = $record.reason_code
                                "BSSType" = $record.bsstype
                                "PHYType" = $record.phytype
                                "AuthenticationAlgorithm" = $record.authentication_algorithm
                                "CipherAlgorithm" = $record.cipher_algorithm
                                "ConnectionId" = $record.connection_id
                                "Channel" = $record.channel
                                "Provider" = $record.provider
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "EventTime", "Task", "EventId", "SSID", "InterfaceDescription"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.SSID
                            } -Force
        
                            $Index++

                            Write-Output $obj
                        }
                        
                    Add-Member -InputObject $NetworkActivity -MemberType NoteProperty -Name $RecordName -Value $WlanEvent
                }
                "sru_network_connectivity" {
                    $SruNetworkConnectivity =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "RecordTime" = $record.ts
                                "InterfaceLuid" = $record.interface_luid
                                "ConnectStartTime" = $record.connect_start_time
                                "ConnectedTime" = $record.connected_time
                                "L2ProfileId" = $record.l2_profile_id
                                "L2ProfileFlags" = $record.l2_profile_flags
                                "SourceContainer" = $SourceContainer
                            }

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.InterfaceLuid
                            } -Force
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $SruNetwork -MemberType NoteProperty -Name "NetworkConnectivity" -Value $SruNetworkConnectivity
                }
                "sru_network_data" {
                    $SruNetworkData =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "RecordTime" = $record.ts
                                "Application" = $record.app
                                "User" = $record.user
                                "InterfaceLuid" = $record.interface_luid
                                "BytesSent" = $record.bytes_sent
                                "BytesRecieved" = $record.bytes_recvd
                                "L2ProfileId" = $record.l2_profile_id
                                "L2ProfileFlags" = $record.l2_profile_flags
                                "SourceContainer" = $SourceContainer
                            }

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.Application
                            } -Force
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $SruNetwork -MemberType NoteProperty -Name "NetworkData" -Value $SruNetworkData
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_ACCOUNT_USAGE) {
            switch ($entry.record) {
                "user_account" {
                    $Index = 0
                    $UserAccount =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "UserName" = $record.username
                                "RID" = $record.rid
                                "Created" = $record.creation
                                "LastLogin" = $record.lastlogin
                                "Logins" = $record.logins
                                "FailedLogins" = $record.failedlogins
                                "SID" = $record.sid
                                "Home" = $record.home
                                "LM" = $record.lm
                                "NTLM" = $record.ntlm
                                "ResultDataFile" = $entry.result
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "UserName", "RID", "Created", "LastLogin"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.UserName
                            } -Force
    
                            $Index++

                            Write-Output $obj
                        }
                        
                    Add-Member -InputObject $AccountUsage -MemberType NoteProperty -Name "UserAccount" -Value $UserAccount
                }
                "logon_event" {
                    $Index = 0
                    $LogonEvent =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "EventTime" = $record.ts
                                "Task" = $record.task
                                "EventId" = $record.event_id
                                "RecordNumber" = $record.event_record_id
                                "SubjectUserSid" = $record.subject_user_sid
                                "SubjectUserName" = $record.subject_user_name
                                "SubjectDomainName" = $record.subject_domain_name
                                "SubjectLogonId" = $record.subject_logon_id
                                "TargetUserSid" = $record.target_user_sid
                                "TargetUserName" = $record.target_user_name
                                "TargetDomainName" = $record.target_domain_name
                                "TargetServerName" = $record.target_server_name
                                "TargetInfo" = $record.target_info
                                "TargetLogonId" = $record.target_logon_id
                                "LogonType" = $record.logon_type
                                "WorkstationName" = $record.workstation_name
                                "IpAddress" = $record.ip_address
                                "IpPort" = $record.ip_port
                                "Channel" = $record.channel
                                "Provider" = $record.provider
                                "ResultDataFile" = $entry.result
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "EventTime", "Task", "SubjectUserName", "TargetUserName", "LogonType"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.TargetUserName
                            } -Force

                            $ProgressPercentCalc = ((($Index + 1) / $Results.count) * 100)

                            Write-Progress -Activity "LogonEvent" -Status "$ProgressPercentCalc % Completed" -PercentComplete $ProgressPercentCalc

                            $Index++
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $LogonEvent -MemberType ScriptMethod -Name ShowGraph -Value {
                        $SCRIPT_NAME = "Parser\util\graph\logon_event.py"
                        $Script = Join-Path -Path $PSScriptRoot -ChildPath $SCRIPT_NAME

                        & python.exe $Script -d $this.ResultDataFile[0]
                    }
        
                    Add-Member -InputObject $AccountUsage -MemberType NoteProperty -Name "LogonEvent" -Value $LogonEvent
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_APPLICATION_EXECUTION) {
            if ($entry.artifact -eq "Amcache") {
                switch ($entry.record) {
                    "amcache_applications" {
                        $Index = 0
                        $AmCacheApplications =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "InstallDate" = $record.install_date
                                    "ProgramName" = $record.name
                                    "Type" = $record.type
                                    "Publisher" = $record.publisher
                                    "UninstallString" = $record.uninstall_string
                                    "RootDirPath" = $record.root_dir_path
                                    "ProgramId" = $record.program_id
                                    "ProgramInstanceId" = $record.program_instance_id
                                    "MsiPackageCode" = $record.msi_package_code
                                    "MsiProductCode" = $record.msi_product_code
                                    "LastModified" = $record.mtime_regf
                                    "InstallDateArpLastModified" = $record.install_date_arp_last_modified
                                    "InstallDateFromLinkFile" = $record.install_date_from_link_file
                                    "OsVersionAtInstallTime" = $record.os_version_at_install_time
                                    "LanguageCode" = $record.language_code
                                    "PackageFullName" = $record.package_full_name
                                    "ManifestPath" = $record.manifest_path
                                    "RegistryKeyPath" = $record.registry_key_path
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "InstallDate", "ProgramName", "Type", "Publisher", "UninstallString", "RootDirPath"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                                
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers
                                
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }

                        Add-Member -InputObject $AmCache -MemberType NoteProperty -Name "Applications" -Value $AmCacheApplications
                    }
                    "amcache_application_files" {
                        $Index = 0
                        $AmCacheApplicationFiles =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "LastModified" = $record.mtime_regf
                                    "ProgramName" = $record.name
                                    "Size" = $record.size
                                    "Publisher" = $record.publisher
                                    "ProductName" = $record.product_name
                                    "ProductVersion" = $record.product_version
                                    "BinFileVersion" = $record.bin_file_version
                                    "BinProductVersion" = $record.bin_product_version
                                    "Version" = $record.version
                                    "ProgramId" = $record.program_id
                                    "Path" = $record.path
                                    "HashPath" = $record.hash_path
                                    "LinkDate" = $record.link_date
                                    "Digests" = $record.digests
                                    "Language" = $record.language
                                    "IsPeFile" = $record.is_pefile
                                    "IsOsComponent" = $record.is_oscomponent
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "LastModified", "ProgramName", "Size", "Publisher", "ProductName", "Version", "Path"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                                
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
                        Add-Member -InputObject $AmCache -MemberType NoteProperty -Name "ApplicationFiles" -Value $AmCacheApplicationFiles
                    }
                }
            }
            else {
                switch ($entry.record) {
                    "prefetch" {
                        $Index = 0
                        $Prefetch =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "LastExecuted" = $record.ts
                                    "ProgramName" = $record.filename
                                    "RunCount" = $record.runcount
                                    "LinkedFiles" = $record.linkedfiles
                                    "PreviousRuns" = $record.previousruns
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force

                                $Index++
            
                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "Prefetch" -Value $Prefetch
                    }
                    "userassist" {
                        $UserAssist =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "LastExecuted" = $record.ts
                                    "ProgramName" = $record.path
                                    "RunCount" = $record.number_of_executions
                                    "FocusCount" = $record.application_focus_count
                                    "FocusDuration" = $record.application_focus_duration
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force
            
                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "UserAssist" -Value $UserAssist
                    }
                    "shimcache" {
                        $ShimCache =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "LastModified" = $record.last_modified
                                    "ProgramName" = $record.path
                                    "Index" = $record.index
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force
            
                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "ShimCache" -Value $ShimCache                    
                    }
                    "bam" {
                        $BAM =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "LastExecuted" = $record.ts
                                    "ProgramName" = $record.path
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.ProgramName
                                } -Force
            
                                Write-Output $obj
                            }    
    
                        Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "BAM" -Value $BAM                    
                    }
                    "sru_application" {
                        $SruApplication =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "RecordTime" = $record.ts
                                    "Application" = $record.app
                                    "User" = $record.user
                                    "ForegroundCycleTime" = $record.foreground_cycle_time
                                    "BackgroundCycleTime" = $record.background_cycle_time
                                    "FaceTime" = $record.face_time
                                    "ForegroundContextSwitches" = $record.foreground_context_switches
                                    "BackgroundContextSwitches" = $record.background_context_switches
                                    "ForegroundBytesRead" = $record.foreground_bytes_read
                                    "ForegroundBytesWritten" = $record.foreground_bytes_written
                                    "ForegroundCountsReadOperation" = $record.foreground_num_read_operations
                                    "ForegroundCountsWrtieOperation" = $record.foreground_num_write_operations
                                    "ForegroundCountsFlush" = $record.foreground_number_of_flushes
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Application
                                } -Force
            
                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $ApplicationExecution -MemberType NoteProperty -Name "SRU" -Value $SruApplication                    
                    }
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_FILE_FOLDER_OPENING) {
            switch ($entry.record) {
                "shellbags" {
                    $ShellBags =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Path" = $record.path
                                "TimeCreated" = $record.creation_time
                                "TimeModified" = $record.modification_time
                                "TimeAccessed" = $record.access_time
                                "RegHivePath" = $record.regf_hive_path
                                "RegKeyPath" = $record.regf_key_path
                                "Size" = $record.filesize
                                "SourceContainer" = $SourceContainer
                            }
        
                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.Path
                            } -Force
        
                            Write-Output $obj
                        }
        
                    Add-Member -InputObject $FileFolderOpening -MemberType NoteProperty -Name "ShellBags" -Value $ShellBags
                }
                "file_history" {
                    $Index = 0
                    $FileHistory =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "AccessTime" = $record.ts
                                "FileName" = $record.file_name
                                "Extension" = $record.file_ext
                                "VisitCount" = $record.visit_count
                                "Browser" = $record.browser
                                "Path" = $record.path
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "AccessTime", "FileName", "Extension", "VisitCount", "Path"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.FileName
                            } -Force
        
                            $Index++

                            Write-Output $obj
                        }

                    Add-Member -InputObject $FileFolderOpening -MemberType NoteProperty -Name "FileHistory" -Value $FileHistory
                }
                "jumplist" {
                    $Index = 0
                    $JumpList =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "LastOpened" = $record.last_opened
                                "FileName" = $record.file_name
                                "Extension" = $record.file_ext
                                "Size" = $record.size
                                "VolumeLabel" = $record.volume_label
                                "VolumeSerialNumber" = $record.volume_serial_number
                                "Path" = $record.path
                                # "TargetCreated" = $record.target_created
                                # "TargetModified" = $record.target_modified
                                # "TargetAccessed" = $record.target_accessed
                                "DriveType" = $record.drive_type
                                "AppId" = $record.app_id
                                "AppName" = $record.app_name
                                "AccessCount" = $record.access_count
                                "EntryId" = $record.entry_id
                                "MachineId" = $record.machine_id
                                "MacAddress" = $record.mac_address
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "LastOpened", "FileName", "Extension", "VolumeLabel", "VolumeSerialNumber", "Path"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.FileName
                            } -Force
        
                            $Index++

                            Write-Output $obj
                        }

                    Add-Member -InputObject $FileFolderOpening -MemberType NoteProperty -Name "JumpList" -Value $JumpList
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_BROWSER_ACTIVITY) {
            if ($entry.artifact -eq "Chrome") {
                switch ($entry.record) {
                    "chrome_history" {
                        $Index = 0
                        $VisitHistory =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "VisitTime" = $record.ts
                                    "Title" = $record.title
                                    "VisitType" = $record.visit_type
                                    "VisitCount" = $record.visit_count
                                    "ID" = $record.id
                                    "Hidden" = $record.hidden
                                    "URL" = $record.url
                                    "FromURL" = $record.from_url
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "VisitTime", "Title", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers
                                
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    if ($this.Title) {
                                        return $this.Title
                                    }
                                } -Force

                                $ProgressPercentCalc = ((($Index + 1) / $Results.count) * 100)

                                Write-Progress -Activity "ChromHistory" -Status "$ProgressPercentCalc % Completed" -PercentComplete $ProgressPercentCalc
    
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "VisitHistory" -Value $VisitHistory
                    }
                    "chrome_downloads" {
                        $Index = 0
                        $Downloads =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "DownloadTime" = $record.ts_start
                                    "FileName" = $record.file_name
                                    "Extension" = $record.file_extension
                                    "ReceivedBytes" = $record.received_bytes
                                    "DownloadPath" = $record.download_path
                                    "DownloadURL" = $record.download_url
                                    "DownloadChainURL" = $record.download_chain_url  
                                    "ReferenceURL" = $record.reference_url
                                    "ID" = $record.id
                                    "MIMEType" = $record.mime_type
                                    "State" = $record.state
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "DownloadTime", "FileName", "Extension", "ReceivedBytes", "DownloadURL", "ReferenceURL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.FileName
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "Downloads" -Value $Downloads
                    }
                    "chrome_keyword_search_terms" {
                        $Index = 0
                        $KeywordSearchTerms =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "LastVisitTime" = $record.ts
                                    "Term" = $record.term
                                    "Title" = $record.title
                                    "SearchEngine" = $record.search_engine
                                    "URL" = $record.url
                                    "Id" = $record.id
                                    "VisitCount" = $record.visit_count
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "LastVisitTime", "Term", "Title", "SearchEngine", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers
                                
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Term
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "KeywordSearchTerms" -Value $KeywordSearchTerms
                    }
                    "chrome_autofill" {
                        $Index = 0
                        $AutoFill =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeCreated" = $record.ts_created
                                    "Value" = $record.value
                                    "Count" = $record.count
                                    "Name" = $record.name
                                    "TimeLastUsed" = $record.ts_last_used
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }
    
                                $defaultDisplaySet         = "Idx", "TimeCreated", "Value", "Count", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Value
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "AutoFill" -Value $AutoFill
                    }
                    "chrome_login_data" {
                        $Index = 0
                        $LoginData =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeCreated" = $record.ts_created
                                    "UserName" = $record.username_value
                                    "UsernameElement" = $record.username_element
                                    "Password" = $record.password_value
                                    "PasswordElement" = $record.password_element
                                    "OriginURL" = $record.origin_url
                                    "ActionURL" = $record.action_url
                                    "SignonRealm" = $record.signon_realm
                                    "TimeLastUsed" = $record.ts_last_used
                                    "TimePasswordModified" = $record.ts_password_modified
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "TimeCreated", "UserName", "OriginURL", "TimeLastUsed", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    if ($this.UserName) {
                                        return $this.UserName
                                    }
                                    else {
                                        return $this.OriginURL
                                    }
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "LoginData" -Value $LoginData
                    }
                    "chrome_bookmarks" {
                        $Index = 0
                        $Bookmarks =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeAdded" = $record.ts_added
                                    "Name" = $record.name
                                    "BookmarkType" = $record.bookmark_type
                                    "GUID" = $record.guid
                                    "ID" = $record.id
                                    "URL" = $record.url
                                    "Path" = $record.path
                                    "LastVisitedTime" = $record.last_visited_desktop
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "TimeAdded", "Name", "BookmarkType", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Name
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Chrome -MemberType NoteProperty -Name "Bookmarks" -Value $Bookmarks
                    }
                }
            }
            elseif ($entry.artifact -eq "Edge") {
                switch ($entry.record) {
                    "edge_history" {
                        $Index = 0
                        $VisitHistory =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "VisitTime" = $record.ts
                                    "Title" = $record.title
                                    "VisitType" = $record.visit_type
                                    "VisitCount" = $record.visit_count
                                    "ID" = $record.id
                                    "Hidden" = $record.hidden
                                    "URL" = $record.url
                                    "FromURL" = $record.from_url
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "VisitTime", "Title", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers
                                
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    if ($this.Title) {
                                        return $this.Title
                                    }
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "VisitHistory" -Value $VisitHistory
                    }
                    "edge_downloads" {
                        $Index = 0
                        $Downloads =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "DownloadTime" = $record.ts_start
                                    "FileName" = $record.file_name
                                    "Extension" = $record.file_extension
                                    "ReceivedBytes" = $record.received_bytes
                                    "DownloadPath" = $record.download_path
                                    "DownloadURL" = $record.download_url
                                    "DownloadChainURL" = $record.download_chain_url  
                                    "ReferenceURL" = $record.reference_url
                                    "ID" = $record.id
                                    "MIMEType" = $record.mime_type
                                    "State" = $record.state
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "DownloadTime", "FileName", "Extension", "ReceivedBytes", "DownloadPath", "DownloadURL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.FileName
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "Downloads" -Value $Downloads
                    }
                    "edge_keyword_search_terms" {
                        $Index = 0
                        $KeywordSearchTerms =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "LastVisitTime" = $record.ts
                                    "Term" = $record.term
                                    "Title" = $record.title
                                    "SearchEngine" = $record.search_engine
                                    "URL" = $record.url
                                    "Id" = $record.id
                                    "VisitCount" = $record.visit_count
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "LastVisitTime", "Term", "Title", "SearchEngine", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers
                                
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Term
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "KeywordSearchTerms" -Value $KeywordSearchTerms
                    }
                    "edge_autofill" {
                        $Index = 0
                        $AutoFill =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeCreated" = $record.ts_created
                                    "Value" = $record.value
                                    "Count" = $record.count
                                    "Name" = $record.name
                                    "TimeLastUsed" = $record.ts_last_used
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }
    
                                $defaultDisplaySet         = "Idx", "TimeCreated", "Value", "Count", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Value
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "AutoFill" -Value $AutoFill
                    }
                    "edge_login_data" {
                        $Index = 0
                        $LoginData =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeCreated" = $record.ts_created
                                    "UserName" = $record.username_value
                                    "UsernameElement" = $record.username_element
                                    "Password" = $record.password_value
                                    "PasswordElement" = $record.password_element
                                    "OriginURL" = $record.origin_url
                                    "ActionURL" = $record.action_url
                                    "SignonRealm" = $record.signon_realm
                                    "TimeLastUsed" = $record.ts_last_used
                                    "TimePasswordModified" = $record.ts_password_modified
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "TimeCreated", "UserName", "OriginURL", "TimeLastUsed", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    if ($this.UserName) {
                                        return $this.UserName
                                    }
                                    else {
                                        return $this.OriginURL
                                    }
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "LoginData" -Value $LoginData
                    }
                    "edge_bookmarks" {
                        $Index = 0
                        $Bookmarks =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "TimeAdded" = $record.ts_added
                                    "Name" = $record.name
                                    "BookmarkType" = $record.bookmark_type
                                    "GUID" = $record.guid
                                    "ID" = $record.id
                                    "URL" = $record.url
                                    "Path" = $record.path
                                    "LastVisitedTime" = $record.last_visited_desktop
                                    "Browser" = $record.browser_type
                                    "SourceContainer" = $SourceContainer
                                }

                                $defaultDisplaySet         = "Idx", "TimeAdded", "Name", "BookmarkType", "URL", "Browser"
                                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                                $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
            
                                Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Name
                                } -Force
            
                                $Index++

                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $Edge -MemberType NoteProperty -Name "Bookmarks" -Value $Bookmarks
                    }
                }
            }
            elseif ($entry.artifact -eq "iExplorer") {
                switch ($entry.record) {
                    "ie_history" {
                        $Index = 0
                        $VisitHistory =
                            foreach ($record in $Results) {
                                $obj = [PScustomObject] @{
                                    "Idx" = $Index
                                    "VisitTime" = $record.ts
                                    "Title" = $record.title
                                    "URL" = $record.url
                                    "Browser" = $record.browser
                                    "SourceContainer" = $SourceContainer
                                }
            
                                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                    return $this.Title
                                } -Force
            
                                $Index++
                                
                                Write-Output $obj
                            }
    
                        Add-Member -InputObject $iExplorer -MemberType NoteProperty -Name "VisitHistory" -Value $VisitHistory
                    }
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_DELETED_ITEMS_FILE_EXISTENCE) {
            switch ($entry.record) {
                "recyclebin" {
                    $Index = 0
                    $RecycleBin =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "DeleteTime" = $record.ts
                                "Name" = $record.filename
                                "Path" = $record.path
                                "Size" = $record.filesize
                                "SourceContainer" = $SourceContainer
                            }
        
                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.Name
                            } -Force

                            $Index++
        
                            Write-Output $obj
                        }
        
                    Add-Member -InputObject $DeletedItemsAndFileExistence -MemberType NoteProperty -Name "RecycleBin" -Value $RecycleBin
                }
            }
        }
        elseif ($entry.category -eq $CATEGORY_EXTERNAL_DEVICE_USB_USAGE) {
            switch ($entry.record) {
                "usbstor" {
                    $Index = 0
                    $UsbStor =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "Product" = $record.product
                                "Version" = $record.version
                                "Vendor" = $record.vendor
                                "FriendlyName" = $record.friendlyname
                                "SerialNumber" = $record.serial
                                "ContainerID" = $record.containerid
                                "DeviceType" = $record.device_type
                                "FirstInsertTime" = $record.first_insert
                                "FirstInstallTime" = $record.first_install
                                "LastInsertTime" = $record.last_insert
                                "LastRemovalTime" = $record.last_removal
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "FriendlyName", "SerialNumber", "FirstInstallTime", "FirstInsertTime", "LastInsertTime", "LastRemovalTime"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
        
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                return $this.Product
                            } -Force
        
                            $Index++
        
                            Write-Output $obj
                        }

                    Add-Member -InputObject $ExternalDeviceAndUsbUsage -MemberType NoteProperty -Name "UsbStor" -Value $UsbStor
                }
                "usb_event" {
                    $Index = 0
                    $UsbEevnt =
                        foreach ($record in $Results) {
                            $obj = [PScustomObject] @{
                                "Idx" = $Index
                                "EventTime" = $record.ts
                                "Task" = $record.task
                                "EventID" = $record.event_id
                                "EventRecordID" = $record.event_record_id
                                "CapcaityGB" = $record.capacity_gb
                                "Manufacturer" = $record.manufacturer
                                "Model" = $record.model
                                "Revision" = $record.revision
                                "SerialNumber" = $record.serialnumber
                                "ParentID" = $record.parent_id
                                "Channel" = $record.channel
                                "Provider" = $record.provider
                                "SourceContainer" = $SourceContainer
                            }

                            $defaultDisplaySet         = "Idx", "EventTime", "Task", "EventId", "CapcaityGB", "Model", "SerialNumber"
                            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet", [string[]] $defaultDisplaySet)
                            $PSStandardMembers         = [System.Management.Automation.PSMemberInfo[]] @($defaultDisplayPropertySet)
                            
                            Add-Member -InputObject $obj MemberSet PSStandardMembers $PSStandardMembers

                            Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                                $str = "{0} {1} {2} ({3})" -f $this.Manufacturer, $this.Model, $this.Revision, $this.SerialNumber
                                return $str
                            } -Force
        
                            $Index++

                            Write-Output $obj
                        }

                    Add-Member -InputObject $ExternalDeviceAndUsbUsage -MemberType NoteProperty -Name "UsbEvent" -Value $UsbEevnt
                }
            }
        }
    }
    

    ## Wrap Up !

    if ([string]::IsNullOrEmpty($SruNetwork)) {
        $NetworkActivity.PSObject.properties.Remove("SRU")
    }
    if ([string]::IsNullOrEmpty($Amcache)) {
        $ApplicationExecution.PSObject.properties.Remove("Amcache")
    }
    if ([string]::IsNullOrEmpty($Chrome)) {
        $BrowserActivity.PSObject.properties.Remove("Chrome")
    }
    if ([string]::IsNullOrEmpty($Edge)) {
        $BrowserActivity.PSObject.properties.Remove("Edge")
    }
    if ([string]::IsNullOrEmpty($iExplorer)) {
        $BrowserActivity.PSObject.properties.Remove("iExplorer")
    }

    if (!([string]::IsNullOrEmpty($NetworkActivity))) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "NetworkActivity" -Value $NetworkActivity

        Add-Member -InputObject $NetworkActivity -MemberType ScriptMethod -Name "ToString" -Value {
            if ($this.NetworkInterface) {
                $str = $this.NetworkInterface.ToString()
            }
            else {
                $str = New-Object -TypeName System.Collections.ArrayList
                if ($this.SRU) {
                    $null = $str.Add("SRU(Network)")
                }
                if ($this.WLAN) {
                    $null = $str.Add("WLAN")
                }
                if ($this.NetworkInterface) {
                    $null = $str.Add("NetworkInterface")
                }
                if ($this.NetworkHistory) {
                    $null = $str.Add("NetworkHistory")
                }
                $str = $str -join ", "
            }
            return $str
        } -Force
    }
    if (![string]::IsNullOrEmpty($AccountUsage)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "AccountUsage" -Value $AccountUsage

        Add-Member -InputObject $AccountUsage -MemberType ScriptMethod -Name "ToString" -Value {
            if ($this.UserAccount) {
                $str = New-Object -TypeName System.Collections.ArrayList
                $ExcludeList = ("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", 
                                "systemprofile", "LocalService", "NetworkService")
                foreach ($entry in $this.UserAccount) {
                    if ($entry.Home) {
                        if ($entry.Home.contains("ServiceProfiles")) {
                            continue
                        }
                    }
                    if ($entry.UserName -in $ExcludeList) {
                        continue
                    }
                    $name = "{0}({1})" -f $entry.UserName, $entry.RID
                    $null = $str.Add($name)
                }
                $str = $str | Select-Object -Unique
                return ($str -join " / ")
            }
            else {
                $str = New-Object -TypeName System.Collections.ArrayList
                if ($this.LogonEvent) {
                    $null = $str.Add("LogonEvent")
                }
                return ($str -join ", ")
            }
        } -Force
    }
    if (![string]::IsNullOrEmpty($ApplicationExecution)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "ApplicationExecution" -Value $ApplicationExecution

        Add-Member -InputObject $ApplicationExecution -MemberType ScriptMethod -Name "ToString" -Value {
            $str = New-Object -TypeName System.Collections.ArrayList
            if ($this.Prefetch) {
                $null = $str.Add("Prefetch")
            }
            if ($this.UserAssist) {
                $null = $str.Add("UserAssist")
            }
            if ($this.Amcache) {
                $null = $str.Add("AmCache")
            }
            if ($this.ShimCache) {
                $null = $str.Add("ShimCache")
            }
            if ($this.BAM) {
                $null = $str.Add("BAM")
            }
            if ($this.SRU) {
                $null = $str.Add("SRU(App)")
            }
            return ($str -join ", ")
        } -Force
    }
    if (![string]::IsNullOrEmpty($FileFolderOpening)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "FileFolderOpening" -Value $FileFolderOpening

        Add-Member -InputObject $FileFolderOpening -MemberType ScriptMethod -Name "GetTimeline" -Value {
            $Records =
                foreach ($record in $this.FileHistory) {
                    Add-Member -InputObject $record -MemberType ScriptMethod -Name ToString -Value {
                        return "FileHistory"
                    } -Force

                    $obj = [PScustomObject] @{
                        "Time" = $record.AccessTime
                        "FileName" = $record.FileName
                        "Extension" = $record.Extension
                        "Path" = $record.Path
                        "Artifact" = $record
                    }

                    Write-Output $obj
                }
            $Records +=
                foreach ($record in $this.JumpList) {
                    Add-Member -InputObject $record -MemberType ScriptMethod -Name ToString -Value {
                        return "JumpList"
                    } -Force

                    $obj = [PScustomObject] @{
                        "Time" = $record.LastOpened
                        "FileName" = $record.FileName
                        "Extension" = $record.Extension
                        "Path" = $record.Path
                        "Artifact" = $record
                    }

                    Write-Output $obj
                }
            $Records = $Records | Sort-Object -Property "Time" -Descending

            $Index = 0
            $Timeline +=
                foreach ($record in $Records) {
                    $obj = [PScustomObject] @{
                        "Index" = $Index
                        "Time" = $record.Time
                        "FileName" = $record.FileName
                        "Extension" = $record.Extension
                        "Path" = $record.Path
                        "Artifact" = $record.Artifact
                    }

                    Write-Output $obj

                    $Index++
                }
                
                Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
                    return $this.Path
                } -Force

            return $Timeline
        }

        Add-Member -InputObject $FileFolderOpening -MemberType ScriptMethod -Name "ToString" -Value {
            $str = New-Object -TypeName System.Collections.ArrayList
            if ($this.ShellBags) {
                $null = $str.Add("ShellBags")
            }
            if ($this.FileHistory) {
                $null = $str.Add("FileHistory")
            }
            if ($this.JumpList) {
                $null = $str.Add("JumpList")
            }
            return ($str -join ", ")
        } -Force
    }
    if (![string]::IsNullOrEmpty($BrowserActivity)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "BrowserActivity" -Value $BrowserActivity

        Add-Member -InputObject $BrowserActivity -MemberType ScriptMethod -Name "ToString" -Value {
            $str = New-Object -TypeName System.Collections.ArrayList
            if ($this.Chrome) {
                $null = $str.Add("Chrome")
            }
            if ($this.Edge) {
                $null = $str.Add("Edge")
            }
            if ($this.iExplorer) {
                $null = $str.Add("iExplorer")
            }
            return ($str -join ", ")
        } -Force
    }
    if (![string]::IsNullOrEmpty($DeletedItemsAndFileExistence)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "DeletedItems/FileExistence" -Value $DeletedItemsAndFileExistence
        
        Add-Member -InputObject $DeletedItemsAndFileExistence -MemberType ScriptMethod -Name "ToString" -Value {
            $str = New-Object -TypeName System.Collections.ArrayList
            if ($this.RecycleBin) {
                $null = $str.Add("RecycleBin")
            }
            return ($str -join ", ")
        } -Force
    }
    if (![string]::IsNullOrEmpty($ExternalDeviceAndUsbUsage)) {
        Add-Member -InputObject $ForensicArtifact -MemberType NoteProperty -Name "ExternalDevice/UsbUsage" -Value $ExternalDeviceAndUsbUsage

        Add-Member -InputObject $ExternalDeviceAndUsbUsage -MemberType ScriptMethod -Name "ToString" -Value {
            $str = New-Object -TypeName System.Collections.ArrayList
            if ($this.UsbStor) {
                $null = $str.Add("UsbStor")
            }
            if ($this.UsbEvent) {
                $null = $str.Add("UsbEvent")
            }
            return ($str -join ", ")
        } -Force
    }


    Add-Member -InputObject $ForensicArtifact -MemberType ScriptMethod -Name "ToString" -Value {
        return "{Forensic Artifacts}"
    } -Force

    return $ForensicArtifact
}
