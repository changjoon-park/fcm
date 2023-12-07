function Test-Engine {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $CaseName,

        [Parameter(Mandatory = $true)]
        [string[]]
        $Container,

        [ValidateSet("MFT", "UsnJrnl", "RecycleBin", "Prefetch", "Lnk", "JumpList", "ThumbCache", "IconCache",
            "FileHistory", "Chrome", "Edge", "iExplorer", "RemoteAccess", "SRU(App)", "SRU(Network)", 
            "WindowsTimeline", "Amcache", "UserAccount", "UserAssist", "USB(Registry)", "USB(EventLog)",
            "ShimCache", "BAM", "NetworkInfo", "SystemInfo", "AutoRun", "MRU", "ShellBags", "WLAN", 
            "LogonEvent")]
        [string[]]
        $Artifact,

        [ValidateSet("All", "System Information", "Application Execution", "File and Folder Opening",
            "Deleted Items and File Existence", "Browser Activity", "Cloud Storage", "Account Usage",
            "Network Activity", "External Device And USB Usage")]
        [string[]]
        $Category,

        [Parameter()]
        [string]
        $Out
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
        $null = $Containers.Add($Container)

        if ($Artifact) {
            & python.exe $Script -n $CaseName -c $Container -a ($Artifact -join ",") -o $Out
        }
        elseif ($Category) {
            & python.exe $Script -n $CaseName-c $Container -y ($Category -join ",") -o $Out
        }
    }
}
