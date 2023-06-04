## Import Modules
foreach ($resource in (Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath .\Lib) -Recurse -File -Filter *.dll)) {
    Add-Type -Path $resource.FullName
}

## Import Scripts
$Public  = @( Get-ChildItem -Path "$PSScriptRoot\Functions\Public\" -Recurse -Filter *.ps1 )
$Private = @( Get-ChildItem -Path "$PSScriptRoot\Functions\Private\*.ps1" )

@($Public + $Private) | ForEach-Object {
    try {
        . $_.FullName
    } 
    catch {
        Write-Error -Message "Failed to import function $($_.FullName): $_"
    }
}