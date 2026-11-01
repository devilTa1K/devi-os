# Verifies the DevilTalk audit stream the kernel writes to COM1 (serial.log).
# Live lines (DT1) are the trusted record. Re-export lines (DT1R) are what the
# kernel claims NOW; any difference from the live record is tampering.
param([string]$Path = "serial.log")

function HexToBytes([string]$hex) {
    $b = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) {
        $b[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16)
    }
    return ,$b
}
function BytesToHex([byte[]]$b) {
    return (($b | ForEach-Object { $_.ToString("x2") }) -join "")
}

if (-not (Test-Path $Path)) { "No $Path yet. Run the OS first."; return }

# QEMU may still have the file open, so open it shared.
$fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
$sr = New-Object IO.StreamReader($fs)
$text = $sr.ReadToEnd()
$sr.Close()

$sha = [Security.Cryptography.SHA256]::Create()
$anchor = @{}
$lastLive = -1
$live = 0; $reexp = 0; $problems = 0

foreach ($line in ($text -split "`n")) {
    $p = $line.Trim() -split ' '
    if ($p.Count -ne 8) { continue }
    if ($p[0] -ne 'DT1' -and $p[0] -ne 'DT1R') { continue }
    if ($p[6].Length -ne 64 -or $p[7].Length -ne 64) { continue }   # partial line

    $seq = [int64]$p[1]; $tick = [int64]$p[2]
    $kind = [byte]$p[3]; $thread = [byte]$p[4]; $arg = [int64]$p[5]
    $prev = $p[6]; $hash = $p[7]

    $buf = [byte[]]((HexToBytes $prev) + [BitConverter]::GetBytes($seq) + [BitConverter]::GetBytes($tick) + @($kind, $thread) + [BitConverter]::GetBytes($arg))
    $calc = BytesToHex ($sha.ComputeHash($buf))
    if ($calc -ne $hash) {
        "PROBLEM #$seq ($($p[0])): hash does not match its own fields (entry was edited)"
        $problems++
    }

    $key = [string]$seq
    $prevKey = [string]($seq - 1)
    if ($p[0] -eq 'DT1') {
        $live++
        if ($seq -ne $lastLive + 1) {
            "PROBLEM #$seq (live): gap in the stream, expected #$($lastLive + 1) (lines were lost)"
            $problems++
        }
        if ($anchor.ContainsKey($prevKey) -and $anchor[$prevKey] -ne $prev) {
            "PROBLEM #$seq (live): does not chain to the earlier entry the kernel reported"
            $problems++
        }
        $anchor[$key] = $hash
        $lastLive = $seq
    } else {
        $reexp++
        if ($anchor.ContainsKey($key)) {
            if ($anchor[$key] -ne $hash) {
                "PROBLEM #$seq (re-export): REWRITTEN, differs from what the kernel reported live"
                $problems++
            }
        } else {
            "NOTE #$seq (re-export): never seen live, cannot check against an anchor"
        }
    }
}

"live entries: $live   re-exported: $reexp   problems: $problems"
if ($problems -eq 0 -and $reexp -gt 0) { "OK: everything the kernel re-exports matches what it reported live." }
if ($reexp -eq 0) { "No re-export yet. Type export in the DevilTalk shell, then run this again." }
