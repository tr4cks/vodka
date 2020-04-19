function New-LibFromDll {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if (-Not ($_ | Test-Path)) {
                throw "File does not exist"
            }
            if (-Not ($_ | Test-Path -PathType Leaf)) {
                throw "Argument must be a file"
            }
            $true
        })]
        [String]
        $LibraryPath
    )

    function Begin([String[]]$lines) {
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match "ordinal +hint +RVA +name") {
                return $i
            }
        }
        return -1
    }

    # Parsing of exports
    $lines = (dumpbin.exe /NOLOGO /EXPORTS $LibraryPath) | Out-String -Stream
    $begin = Begin($lines)
    if ($begin -eq -1 -or $begin + 2 -ge $lines.Length) {
        throw "File format does not correspond to what is expected"
    }
    $begin += 2
    $exports = @()
    for ($i = $begin; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match " +(?<ordinal>\d+) +[0-9a-fA-F]+ +[0-9a-fA-F]+ +(?<name>.+)") {
            $exports += @{
                ordinal = $Matches.ordinal
                name = $Matches.name
            }
        } else {
            break
        }
    }

    $libraryDirectoryName = (Get-Item -Path $LibraryPath).DirectoryName
    $libraryBaseName = (Get-Item -Path $LibraryPath).BaseName
    $defPath = Join-Path -Path $libraryDirectoryName -ChildPath "$libraryBaseName.def"
    $libPath = Join-Path -Path $libraryDirectoryName -ChildPath "$libraryBaseName.lib"

    # Creating .def and .lib files
    "LIBRARY   $($libraryBaseName.ToUpper())" | Out-File -FilePath $defPath
    "EXPORTS" | Out-File -FilePath $defPath -Append
    $exports | ForEach-Object {
        "   $($_.name)   @$($_.ordinal)"
    } | Out-File -FilePath $defPath -Append
    lib.exe /NOLOGO "/DEF:$defPath" "/OUT:$libPath"
}

Export-ModuleMember -Function New-LibFromDll
