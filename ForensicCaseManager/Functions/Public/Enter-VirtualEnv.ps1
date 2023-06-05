function Enter-Virtualenv {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $InstallDependency
    )

    $FunctionsDir = Split-Path -Path $PSScriptRoot
    $BuildScript = Get-ChildItem -Path (Split-Path -Path $FunctionsDir) `
                        | Where-Object { $_.Name -eq "build.ps1" }

    if ($InstallDependency) {
        & $BuildScript.FullName -InstallDependency
    }
    else {
        & $BuildScript.FullName
    }
}