param(
    [string]$Name = "优悠密评百宝箱",
    [string]$Version = "2.0.3"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "未找到虚拟环境 Python：$Python"
}

Write-Host "== 1/3 使用 PyInstaller 构建免安装目录 =="
& $Python -m PyInstaller --noconfirm --clean --windowed `
    --name $Name `
    --icon "cryptotoolbox\assets\app_icon.ico" `
    --add-data "cryptotoolbox/assets;cryptotoolbox/assets" `
    --collect-submodules cryptotoolbox `
    --collect-submodules gmalg `
    --collect-submodules tongsuopy `
    --version-file "version_info.txt" `
    --distpath "dist" --workpath "build/pyinstaller" `
    --log-level WARN "run.py"

$AppDir = Join-Path $Root "dist\$Name"
if (-not (Test-Path (Join-Path $AppDir "$Name.exe"))) {
    throw "构建失败：未生成 $AppDir\$Name.exe"
}
Copy-Item "scripts\使用说明.txt" (Join-Path $AppDir "使用说明.txt") -Force

Write-Host "== 2/3 冒烟测试（离屏打开全部页面）=="
$env:QT_QPA_PLATFORM = "offscreen"
$env:QT_QPA_FONTDIR = "$env:SystemRoot\Fonts"
$proc = Start-Process -FilePath (Join-Path $AppDir "$Name.exe") -ArgumentList "--smoke-test" -PassThru
if (-not $proc.WaitForExit(120000)) {
    $proc.Kill()
    throw "冒烟测试超时"
}
if ($proc.ExitCode -ne 0) {
    throw "冒烟测试失败，退出码：$($proc.ExitCode)"
}

Write-Host "== 3/3 打包 ZIP 与校验值 =="
$Zip = Join-Path $Root "dist\$($Name)_v$($Version)_免安装.zip"
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path (Join-Path $AppDir "*") -DestinationPath $Zip -CompressionLevel Optimal

$Hash = (Get-FileHash $Zip -Algorithm SHA256).Hash
$SizeMB = [math]::Round((Get-Item $Zip).Length / 1MB, 1)
"$Hash  $([IO.Path]::GetFileName($Zip))" | Set-Content "$Zip.sha256" -Encoding utf8

Write-Host ""
Write-Host "完成："
Write-Host "  目录：$AppDir"
Write-Host "  压缩包：$Zip（$SizeMB MB）"
Write-Host "  SHA256：$Hash"
