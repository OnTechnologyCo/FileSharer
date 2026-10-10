param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $compiler)) {
    throw 'The .NET Framework 4.x C# compiler was not found.'
}
$goCommand = Get-Command go.exe -ErrorAction Stop
$outDir = [System.IO.Path]::GetFullPath($OutputDirectory)
if ($outDir.TrimEnd('\') -eq $root.TrimEnd('\')) {
    throw 'Choose an output directory other than the project root.'
}
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$helper = Join-Path $outDir 'tsproxy.exe'
Push-Location (Join-Path $root 'tsproxy')
try {
    & $goCommand.Source build -mod=readonly -trimpath -ldflags '-s -w' -o $helper .
    if ($LASTEXITCODE -ne 0) { throw 'The Go helper build failed.' }
} finally {
    Pop-Location
}

$compressedHelper = Join-Path $outDir 'tsproxy.exe.gz'
$inputStream = [System.IO.File]::OpenRead($helper)
try {
    $outputStream = [System.IO.File]::Create($compressedHelper)
    try {
        $gzip = [System.IO.Compression.GZipStream]::new(
            $outputStream, [System.IO.Compression.CompressionMode]::Compress
        )
        try { $inputStream.CopyTo($gzip) } finally { $gzip.Dispose() }
    } finally { $outputStream.Dispose() }
} finally { $inputStream.Dispose() }

$icon = Join-Path $root 'filesharer.ico'
$application = Join-Path $outDir 'FileSharer.exe'
$appArgs = @(
    '/nologo', '/target:winexe', '/codepage:65001',
    '/r:System.IO.Compression.dll', '/r:System.IO.Compression.FileSystem.dll',
    '/r:System.Web.dll', '/r:System.Security.dll',
    ('/win32icon:' + $icon),
    ('/resource:' + $compressedHelper + ',tsproxy.exe.gz'),
    ('/out:' + $application), (Join-Path $root 'FileSharer.cs')
)
& $compiler @appArgs
if ($LASTEXITCODE -ne 0) { throw 'The application build failed.' }

$installer = Join-Path $outDir 'FileSharer_Setup.exe'
$setupArgs = @(
    '/nologo', '/target:winexe', '/codepage:65001',
    '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll',
    ('/win32icon:' + $icon),
    ('/resource:' + $application + ',FileSharer.exe'),
    ('/resource:' + $icon + ',filesharer.ico'),
    ('/resource:' + (Join-Path $root 'filesharer_128.png') + ',filesharer_128.png'),
    ('/out:' + $installer), (Join-Path $root 'Setup.cs')
)
& $compiler @setupArgs
if ($LASTEXITCODE -ne 0) { throw 'The installer build failed.' }
Write-Output ('Build complete: ' + $outDir)
