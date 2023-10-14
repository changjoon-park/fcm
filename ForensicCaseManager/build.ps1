# ForensicCaseManager(FCM)
# Dependencies: dissect 3.9

# User Platform Check
$Platform = $PSVersionTable.Platform

if ($Platform -eq "Unix") {
    $ConfigPath = "$env:HOME/.fcm/config.json"
}
else {
    $ConfigPath = "$env:USERPROFILE\.fcm\config.json"
}

$json = @{
    platform = $Platform
} | ConvertTo-Json

if (Test-Path -Path $ConfigPath) {
    $json | Set-Content -Path $ConfigPath
}
else {
    New-Item -Path $ConfigPath -ItemType File -Force
    $json | Set-Content -Path $ConfigPath
}

# Create Virtual Environment
if (-not (Test-Path -Path $PSScriptRoot\.venv -PathType Container)) {
    Write-Host ""
    Write-Host ">>> Creating a Virtual Environment for ForensicCaseManager(FCM)" -ForegroundColor DarkBlue

    try {
        if ($Platform -eq "Unix") {
            python3 -m venv $PSScriptRoot/.venv
        }
        else {
            python.exe -m venv $PSScriptRoot\.venv
        }
    }
    catch {
        Write-Warning "Failed to create Python Virtualenv."
        return
    }
}

# Activate Virtual Environment
try {
    if ($Platform -eq "Unix") {
        & $PSScriptRoot/.venv/bin/activate.ps1
    }
    else {
        & $PSScriptRoot\.venv\Scripts\activate.ps1
    }
}
catch {
    Write-Host ""
    Write-Warning "Failed to enter Python Virtualenv."
    return
}

# Check if Dependencies are installed
$Packages = pip freeze
if (-not $Packages) {
    Write-Host ""
    Write-Warning "Dependencies are required. Installing.."
    Write-Host ""

    if ($Platform -eq "Unix") {
        pip install -r $PSScriptRoot/requirements.txt
    }
    else {
        pip install -r $PSScriptRoot\requirements.txt
    }
}

# Set Virtalenv Information Object
$Packages = pip freeze
$PackageInfo = foreach ($package in $Packages) {
    $obj = [PSCustomObject] @{
        "Name"    = $package.split("==")[0]
        "Version" = $package.split("==")[1]
    }
    Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
        return $this.Name
    } -Force

    Write-Output $obj
}

# Out Virtualenv Information Object
if ($Platform -eq "Unix") {
    $venv = [PSCustomObject] @{
        "Path"     = "$PSScriptRoot/.venv"
        "Packages" = $PackageInfo
    }
}
else {
    $venv = [PSCustomObject] @{
        "Path"     = "$PSScriptRoot\.venv"
        "Packages" = $PackageInfo
    }
}

Write-Output $venv

