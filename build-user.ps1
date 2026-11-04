# Builds the DevilTalk user programs (the separate crate in user\hello).
# Run this before cargo run. Outputs: hello.bin and badwrite.bin (flat binaries)
# and hello_seg.elf (an ELF with separate code, constant and data segments).
$root = $PSScriptRoot
$crate = Join-Path $root "user\hello"
$target = Join-Path $root "x86_64-deviltalk.json"
$built = Join-Path $crate "target\x86_64-deviltalk\release\hello"

Push-Location $root
$sysroot = (rustc --print sysroot).Trim()
Pop-Location
$bin = Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-msvc\bin"
$objcopy = Join-Path $bin "llvm-objcopy.exe"
$nm = Join-Path $bin "llvm-nm.exe"
$readobj = Join-Path $bin "llvm-readobj.exe"
if (-not (Test-Path $objcopy)) {
    Write-Host "llvm-objcopy.exe not found in $bin"
    Write-Host "Try: rustup component add llvm-tools-preview"
    return
}

function Build-One($name, $features, $ldName, $makeBin) {
    $ld = Join-Path $crate $ldName
    $env:RUSTFLAGS = "-C relocation-model=pic -C link-arg=-T$ld"
    $cargoArgs = @("build", "--release", "-Z", "build-std=core,compiler_builtins", "-Z", "build-std-features=compiler-builtins-mem", "-Z", "json-target-spec", "--target", $target)
    if ($features) { $cargoArgs += @("--features", $features) }
    Push-Location $crate
    & cargo @cargoArgs
    $code = $LASTEXITCODE
    Pop-Location
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Write-Host "BUILD FAILED for $name (cargo exit code $code)"
        return $false
    }
    $elf = Join-Path $crate "$name.elf"
    Copy-Item $built $elf -Force
    $nmOut = & $nm $elf | Select-String " _start$"
    Write-Host ("_start: " + $nmOut)
    if ($makeBin) {
        $out = Join-Path $crate "$name.bin"
        & $objcopy -O binary $elf $out
        $len = (Get-Item $out).Length
        Write-Host "$name.bin: $len bytes (limit 4096)"
        if ($len -eq 0 -or $len -gt 4096) {
            Write-Host "PROBLEM: $name.bin has an unusable size"
            return $false
        }
    } else {
        $len = (Get-Item $elf).Length
        Write-Host "$name.elf: $len bytes"
        & $readobj --program-headers $elf | Select-String "Type:|Flags|VirtualAddress:|MemSize:" | Out-Host
    }
    return $true
}

$ok1 = Build-One "hello" $null "link.ld" $true
$ok2 = Build-One "badwrite" "bad" "link.ld" $true
$ok3 = Build-One "hello_seg" $null "link-elf.ld" $false
if ($ok1 -eq $true -and $ok2 -eq $true -and $ok3 -eq $true) {
    Write-Host "All three programs built."
} else {
    Write-Host "At least one program failed. Send me the output above."
}
