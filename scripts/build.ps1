param([string]$Go = 'go', [string]$Architecture = 'arm64')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$versionSource = Get-Content -LiteralPath (Join-Path $projectRoot 'internal/app/config.go') -Raw
$releaseVersion = [regex]::Match($versionSource, 'const version = "([^"]+)"').Groups[1].Value
if (-not $releaseVersion) { throw 'Version missing' }
Push-Location $projectRoot
try {
  & $Go test ./...
  if ($LASTEXITCODE) { throw 'Tests failed' }
  & $Go vet ./...
  if ($LASTEXITCODE) { throw 'Vet failed' }
  New-Item -ItemType Directory -Force -Path bin | Out-Null
  $oldOS = $env:GOOS; $oldArch = $env:GOARCH; $oldCGO = $env:CGO_ENABLED
  try {
    $env:GOOS = 'linux'; $env:GOARCH = $Architecture; $env:CGO_ENABLED = '0'
    & $Go build -trimpath -buildvcs=false -ldflags='-s -w' -o "bin/linknest-linux-$Architecture" ./cmd/linknest
    if ($LASTEXITCODE) { throw 'Build failed' }
  } finally { $env:GOOS = $oldOS; $env:GOARCH = $oldArch; $env:CGO_ENABLED = $oldCGO }
  Write-Output "LinkNest $releaseVersion binary: $projectRoot/bin/linknest-linux-$Architecture"
} finally { Pop-Location }
