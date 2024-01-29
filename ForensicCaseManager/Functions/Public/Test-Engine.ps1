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

function Get-CatetoryNumber {
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
        $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $validateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($Global:ValidArtifacts)
        $attributeCollection.Add($validateSetAttribute)
        $artifactParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
            'Artifact', [string[]], $attributeCollection)
        $artifactParam.Attributes.Add((New-Object System.Management.Automation.ParameterAttribute -Property @{
            ParameterSetName = 'ArtifactSet'
        }))
        $runtimeParameters.Add('Artifact', $artifactParam)

        # Category parameter
        $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $validateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($Global:ValidCategories)
        $attributeCollection.Add($validateSetAttribute)
        $categoryParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
            'Category', [string[]], $attributeCollection)
        $categoryParam.Attributes.Add((New-Object System.Management.Automation.ParameterAttribute -Property @{
            ParameterSetName = 'CategorySet'
        }))
        $runtimeParameters.Add('Category', $categoryParam)

        return $runtimeParameters
    }

    begin {
        $artifact = $PSBoundParameters['Artifact']
        $category = $PSBoundParameters['Category']

        if ($artifact -and $category) {
            Write-Warning -Message "Select only one of the two options: [Artifact] / [Category]"
            return
        }

        # Determine the system platform
        $platform = $PSVersionTable.Platform

        # Determine the appropriate Python executable based on the operating system
        $Python = if ($PSVersionTable.Platform -eq "Unix") { "python3" } else { "python.exe" }
    }

    process {
        # Define the script path
        $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Parser\main.py"

        # Handle 'All' selection for artifacts and categories
        $processedArtifacts = if ($artifact -contains "All") {
            $Global:ValidArtifacts | Where-Object { $_ -ne "All" }
        } else {
            $artifact | ForEach-Object { $_.ToLower() }
        }

        $processedCategories = if ($category -contains "All") {
            $Global:ValidCategories
        } else {
            $category | ForEach-Object { Get-CatetoryNumber $_ }
        }

        # Construct and execute the command
        $PythonCommand = "$Python $ScriptPath -c $Case"
        if ($processedArtifacts) {
            $PythonCommand += " -a " + ($processedArtifacts -join ",")
        } elseif ($processedCategories) {
            $PythonCommand += " -t " + ($processedCategories -join ",")
        }

        # Execute the command based on the platform
        if ($platform -eq "Unix") {
            & $PythonCommand
        } else {
            & cmd /c $PythonCommand
        }
    }
}