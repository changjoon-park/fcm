# Arrays holding valid artifacts and categories
$Global:ValidArtifacts = @(
    "All", "MFT", "UsnJrnl", "RecycleBin", "Prefetch", "Lnk", "JumpList", "ThumbCache", "IconCache",
    "FileHistory", "Chrome", "Edge", "iExplorer", "RemoteAccess", "SRU(App)", "SRU(Network)", 
    "WindowsTimeline", "Amcache", "UserAccount", "UserAssist", "USB(Registry)", "USB(EventLog)",
    "ShimCache", "BAM", "NetworkInfo", "SystemInfo", "AutoRun", "MRU", "ShellBags", "WLAN", "LogonEvent"
)

$Global:ValidCategories = @(
    "System Information", "Network Activity", "Account Usage", "Application Execution", 
    "File and Folder Opening", "Deleted Items and File Existence", "Browser Activity", "External Device And USB Usage"
)

function Add-DynamicParam {
    param (
        [string]$Name,
        [System.Collections.ObjectModel.Collection[System.Attribute]]$Attributes,
        [string]$ParameterSetName,
        [int]$Position
    )

    $paramAttribute = New-Object System.Management.Automation.ParameterAttribute
    $paramAttribute.ParameterSetName = $ParameterSetName
    $paramAttribute.Position = $Position

    $Attributes.Add($paramAttribute)

    $dynamicParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
        $Name, [string[]], $Attributes)
    
    $runtimeParameters.Add($Name, $dynamicParam)
}

function Get-CategoryNumber {
    param (
        [string]$CategoryName
    )

    switch ($CategoryName) {
        "Application Execution" { return 1 }
        "File and Folder Opening" { return 2 }
        "Deleted Items and File Existence" { return 3 }
        "Browser Activity" { return 4 }
        "Cloud Storage" { return 5 }
        "Account Usage" { return 6 }
        "Network Activity and Physical Location" { return 7 }
        "System Information" { return 8 }
        "External Device And USB Usage" { return 9 }
        Default { return 0 }
    }
}

function Test-Engine {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Case
    )

    dynamicparam {
        $runtimeParameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Artifact parameter
        $artifactAttributes = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $artifactAttributes.Add((New-Object System.Management.Automation.ValidateSetAttribute($Global:ValidArtifacts)))

        # Add Artifact Dynamic Parameter at position 1
        Add-DynamicParam -Name 'Artifact' -Attributes $artifactAttributes -ParameterSetName 'ArtifactSet' -Position 1

        # Category parameter
        $categoryAttributes = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $categoryAttributes.Add((New-Object System.Management.Automation.ValidateSetAttribute($Global:ValidCategories)))

        # Add Category Dynamic Parameter at position 2
        Add-DynamicParam -Name 'Category' -Attributes $categoryAttributes -ParameterSetName 'CategorySet' -Position 2

        return $runtimeParameters
    }

    begin {
        $artifact = $PSBoundParameters['Artifact']
        $category = $PSBoundParameters['Category']

        if ($artifact -and $category) {
            Write-Warning -Message "Select only one of the two options: [Artifact] / [Category]"
            return
        }

        # Determine the appropriate Python executable based on the operating system
        $Python = if ($PSVersionTable.Platform -eq "Unix") { "python3" } else { "python.exe" }
        $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Parser/main.py"
    }

    process {
        $Arguments = @("-c", $Case)
        if ($PSBoundParameters.ContainsKey('Artifact')) {
            $processedArtifacts = if ('All' -in $Artifact) {
                $Global:ValidArtifacts.Where({ $_ -ne 'All' }).ForEach({ $_.ToLower() })
            } else {
                $Artifact.ForEach({ $_.ToLower() })
            }
            $Arguments += "-a", ($processedArtifacts -join ",")
        }
        
        if ($PSBoundParameters.ContainsKey('Category')) {
            $processedCategories = if ('All' -in $Category) {
                $Global:ValidCategories
            } else {
                $Category.ForEach({ Get-CategoryNumber $_ })
            }
            $Arguments += "-t", ($processedCategories -join ",")
        }

        if ($PSVersionTable.Platform -eq "Unix") {
            & $Python $ScriptPath $Arguments
        } else {
            & cmd /c "$Python $ScriptPath $Arguments"
        }
    }
}