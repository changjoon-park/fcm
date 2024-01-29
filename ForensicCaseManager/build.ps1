# ForensicCaseManager(FCM)
# Dependencies: dissect 3.9

# Function to get the configuration path based on the platform
function Get-ConfigPath {
    if ($PSVersionTable.Platform -eq "Unix") {
        return Join-Path -Path $env:HOME -ChildPath ".fcm/config.json"
    } else {
        return Join-Path -Path $env:USERPROFILE -ChildPath ".fcm/config.json"
    }
}

# Function to initialize or update the configuration file
function Initialize-ConfigFile {
    param (
        [string]$ConfigPath,
        [string]$Platform
    )

    $json = @{ platform = $Platform } | ConvertTo-Json

    if (Test-Path -Path $ConfigPath) {
        $json | Set-Content -Path $ConfigPath
    } else {
        New-Item -Path $ConfigPath -ItemType File -Force
        $json | Set-Content -Path $ConfigPath
    }
}

# Function to create a Python virtual environment
function Create-VirtualEnv {
    param (
        [string]$VirtualEnvDirectory
    )

    Write-Host ">>> Creating a Virtual Environment for ForensicCaseManager(FCM)" -ForegroundColor DarkBlue

    try {
        & $Python -m venv $VirtualEnvDirectory
    } catch {
        Write-Warning "Failed to create Python Virtualenv."
        return $false
    }

    return $true
}

# Function to activate the Python virtual environment
function Activate-VirtualEnv {
    param (
        [string]$VirtualEnvDirectory
    )

    $VirtualEnvScript = Get-ChildItem -Path $VirtualEnvDirectory -Recurse |
                        Where-Object { $_.Name -eq "activate.ps1" }

    try {
        & $VirtualEnvScript.FullName
    } catch {
        Write-Warning "Failed to enter Python Virtualenv."
        return $false
    }

    return $true
}

# Function to install required dependencies
function Install-Dependencies {
    param (
        [string]$RequirementsPath
    )

    $Packages = & $pip freeze

    if (-not $Packages) {
        Write-Warning "Dependencies are required. Installing.."
        & $pip install -r $RequirementsPath
    }
}

# Function to output virtual environment information
function Get-VirtualEnvInfo {
    param (
        [string]$VirtualEnvDirectory
    )

    $Packages = & $pip freeze
    $PackageInfo = $Packages | ForEach-Object {
        $parts = $_.Split("==")
        [PSCustomObject] @{
            "Name"    = $parts[0]
            "Version" = $parts[1]
        }
    }

    return [PSCustomObject] @{
        "Path"     = $VirtualEnvDirectory
        "Packages" = $PackageInfo
    }
}

# Main script execution starts here
$ConfigPath = Get-ConfigPath
$Python = if ($PSVersionTable.Platform -eq "Unix") { "python3" } else { "python.exe" }
$pip = if ($PSVersionTable.Platform -eq "Unix") { "pip3" } else { "pip.exe" }

Initialize-ConfigFile -ConfigPath $ConfigPath -Platform $PSVersionTable.Platform

$VirtualEnvDirectory = Join-Path -Path $PSScriptRoot -ChildPath ".venv"

if (-not (Test-Path -Path $VirtualEnvDirectory -PathType Container)) {
    if (-not (Create-VirtualEnv -VirtualEnvDirectory $VirtualEnvDirectory)) { return }
}

if (-not (Activate-VirtualEnv -VirtualEnvDirectory $VirtualEnvDirectory)) { return }

$RequirementsPath = Join-Path -Path $PSScriptRoot -ChildPath "requirements.txt"
Install-Dependencies -RequirementsPath $RequirementsPath

$venvInfo = Get-VirtualEnvInfo -VirtualEnvDirectory $VirtualEnvDirectory
Write-Output $venvInfo

