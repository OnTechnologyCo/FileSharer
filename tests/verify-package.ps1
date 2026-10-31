param([string]$Dist = (Join-Path (Split-Path $PSScriptRoot -Parent) 'dist'))
$ErrorActionPreference = 'Stop'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('FileSharerPackage-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp | Out-Null
function Extract-Resource($Assembly, $Name, $Path) {
    $source = $Assembly.GetManifestResourceStream($Name)
    if (-not $source) { throw "Missing resource $Name" }
    $target = [IO.File]::Create($Path)
    try { $source.CopyTo($target) } finally { $source.Dispose(); $target.Dispose() }
}
function Assert-Same($A, $B) {
    if ((Get-FileHash $A).Hash -ne (Get-FileHash $B).Hash) { throw "Embedded artifact mismatch: $A" }
}
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldSystemTemp = $env:SYSTEMTEMP
try {
    $setup = [Reflection.Assembly]::LoadFile((Join-Path $Dist 'FileSharer_Setup.exe'))
    $appPath = Join-Path $temp 'FileSharer.exe'
    Extract-Resource $setup 'FileSharer.exe' $appPath
    Assert-Same $appPath (Join-Path $Dist 'FileSharer.exe')
    $app = [Reflection.Assembly]::LoadFile($appPath)
    $gzipPath = Join-Path $temp 'helper.gz'
    Extract-Resource $app 'tsproxy.exe.gz' $gzipPath
    $inputStream = [IO.File]::OpenRead($gzipPath)
    $gzip = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
    $helper = Join-Path $temp 'tsproxy.exe'
    $output = [IO.File]::Create($helper)
    try { $gzip.CopyTo($output) } finally { $output.Dispose(); $gzip.Dispose(); $inputStream.Dispose() }
    Assert-Same $helper (Join-Path $Dist 'tsproxy.exe')
    $info = & go.exe version -m $helper
    if ($LASTEXITCODE -ne 0 -or $info[0] -notmatch '\bgo1\.26\.10$') { throw 'Embedded Go version mismatch' }
    Write-Output $info[0]
    Write-Output 'PASS: installer -> application -> Go helper hashes match'

    # Exercise the production extraction path with a same-size stale cache, without launching it.
    $env:TEMP = $temp
    $env:TMP = $temp
    $env:SYSTEMTEMP = $temp
    if (-not ([IO.Path]::GetTempPath()).StartsWith($temp)) { throw 'Cannot isolate temporary path' }
    $cache = Join-Path $temp 'FileSharerTs'
    New-Item -ItemType Directory $cache | Out-Null
    $cachedHelper = Join-Path $cache 'tsproxy.exe'
    $bytes = [IO.File]::ReadAllBytes($helper)
    $bytes[0] = $bytes[0] -bxor 1
    [IO.File]::WriteAllBytes($cachedHelper, $bytes)
    $extract = $app.GetType('LocalFileSharer.TailscaleTunnel').GetMethod('ExtractProxy', [Reflection.BindingFlags]'NonPublic,Static')
    $extracted = $extract.Invoke($null, @())
    if (-not $extracted -or -not $extracted.StartsWith($temp)) { throw 'Extraction failed or escaped fixture' }
    Assert-Same $extracted $helper
    Write-Output 'PASS: same-size stale helper replaced by embedded patched helper'
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    $env:SYSTEMTEMP = $oldSystemTemp
    Remove-Item -LiteralPath $temp -Force -Recurse -ErrorAction SilentlyContinue
}
