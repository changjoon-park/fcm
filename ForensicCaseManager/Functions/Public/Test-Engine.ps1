function Test-Engine {
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
        $Category
    )
    
    begin {
        ## Prepare to Work
        $Platform = $PSVersionTable.Platform

        if ($Platform -eq "Unix") {
            $SCRIPT_NAME = "Parser/main.py"
        }
        else {
            $SCRIPT_NAME = "Parser\main.py"
        }    

        if ($Artifact -and $Category) {
            Write-Host ""
            Write-Warning -Message "Select only one of the two options: [Artifact] / [Category]"
            Write-Host ""
            $ErrorFlag = $true
            return
        }

        $Script = Join-Path -Path $PSScriptRoot -ChildPath $SCRIPT_NAME
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

        Write-Host ""
        Write-Host "Begin to Process Forensic Container: " -ForegroundColor DarkBlue -NoNewline
    
        if ($Local) {
            Write-Host "Local Container" -BackgroundColor DarkCyan -ForegroundColor DarkBlue -NoNewline
            Write-Host ""
                
            if ($Artifact) {
                $output = & python $Script --local -a ($Artifact -join ",")
                $Comment = $Artifact
            }
            elseif ($Category) {
                $output = & python $Script --local -y ($Category -join ",")
                $Comment = $Category
            }
        }
        else {
            Write-Host $Container -BackgroundColor DarkBlue -ForegroundColor Cyan

            $null = $Containers.Add($Container)

            if ($Artifact) {
                $output = & python $Script -c $Container -a ($Artifact -join ",")
                $Comment = $Artifact
            }
            elseif ($Category) {
                $output = & python $Script -c $Container -y ($Category -join ",")
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
    end {
        if ($ErrorFlag) {
            return
        }
    }
}
