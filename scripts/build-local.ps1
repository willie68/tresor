Param(
    [string]$OutputDir = "bin",
    [string]$BinaryName = "tresor.exe"
)

$ErrorActionPreference = "Stop"

# Match goreleaser: WinFSP/cgofuse is used via the pure-Go (!cgo) Windows backend.
$env:CGO_ENABLED = "0"

Write-Host "==> Running go mod tidy"
go mod tidy

Write-Host "==> Running tests"
go test ./...

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$target = Join-Path $OutputDir $BinaryName
Write-Host "==> Building $target"
go build -tags nocgo -o $target ./cmd/tresor

Write-Host "Build complete: $target"
