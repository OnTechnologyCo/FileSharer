param([string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('FileSharerSecurity-' + [Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$exe = Join-Path $OutputDirectory 'DownloadSecurity.exe'
& $compiler /nologo /target:exe /main:DownloadSecurity /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll /r:System.Web.dll /r:System.Security.dll "/out:$exe" (Join-Path $root 'FileSharer.cs') (Join-Path $PSScriptRoot 'DownloadSecurity.cs')
if ($LASTEXITCODE -ne 0) { throw 'Security harness compile failed.' }
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldSystemTemp = $env:SYSTEMTEMP
try {
    # ZipCache and logs are isolated from any running installation.
    $env:TEMP = $OutputDirectory
    $env:TMP = $OutputDirectory
    $env:SYSTEMTEMP = $OutputDirectory
    & $exe
    if ($LASTEXITCODE -ne 0) { throw 'Download security regression failed.' }
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    $env:SYSTEMTEMP = $oldSystemTemp
}
