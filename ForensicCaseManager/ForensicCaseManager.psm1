# Import PowerShell modules from the Modules directory, considering potential version subdirectories
$ModuleDirectories = Get-ChildItem -Path "$PSScriptRoot\Modules\" -Directory

foreach ($moduleDir in $ModuleDirectories) {
    $versionDirectories = Get-ChildItem -Path $moduleDir.FullName -Directory -ErrorAction SilentlyContinue
    $ModuleManifest = $null

    if ($versionDirectories -and $versionDirectories.Count -gt 0) {
        # Assuming the version directories follow a 'major.minor.patch' naming convention
        $latestVersionDir = $versionDirectories | Sort-Object { [Version] $_.Name } -Descending | Select-Object -First 1
        if ($latestVersionDir) {
            $ModuleManifest = Join-Path -Path $latestVersionDir.FullName -ChildPath "$($moduleDir.Name).psd1"
        }
    } else {
        # If there are no version directories, assume the module manifest is directly under the module directory
        $ModuleManifest = Join-Path -Path $moduleDir.FullName -ChildPath "$($moduleDir.Name).psd1"
    }

    # Import the module manifest if it exists
    if ($ModuleManifest -and (Test-Path -Path $ModuleManifest)) {
        Import-Module -Name $ModuleManifest -Force
        Write-Verbose "Imported $($moduleDir.Name) module."
    }
}

## Import Scripts
# Import public and private function scripts
$Public  = @( Get-ChildItem -Path "$PSScriptRoot/Functions/Public/" -Recurse -Filter *.ps1 )
$Private = @( Get-ChildItem -Path "$PSScriptRoot/Functions/Private/" -Recurse -Filter *.ps1 )

@($Public + $Private) | ForEach-Object {
    try {
        . $_.FullName
        Write-Verbose "Imported $($_.Name) script."
    } 
    catch {
        Write-Error "Failed to import function $($_.FullName): $_"
    }
}
