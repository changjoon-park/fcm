function Enter-VirtualEnv {
    $FunctionsDir = Split-Path -Path $PSScriptRoot
    $BuildScript = Get-ChildItem -Path (Split-Path -Path $FunctionsDir) `
                        | Where-Object { $_.Name -eq "build.ps1" }
    & $BuildScript.FullName
}
