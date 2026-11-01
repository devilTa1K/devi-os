# Explains the DevilTalk audit stream (serial.log) in plain language.
# Rule-based: no network, no API key, same answer every time.
# The thread names below match this demo build; edit them for your own apps.
param([string]$Path = "serial.log")

$names = @{
    0 = "The console shell"; 1 = "App A (prints)"; 2 = "App B (no capabilities)";
    3 = "App C"; 4 = "App D"; 5 = "App E (file reader)"; 6 = "App F"; 7 = "App G";
    8 = "App H"; 9 = "App I"; 10 = "App J (log reader)"; 11 = "App K (bad pointers)"; 12 = "App L (no audit capability)"
}

function Who($t) {
    $k = [int]$t
    if ($names.ContainsKey($k)) { return $names[$k] }
    return "Thread $k"
}
function CallName($n) {
    switch ([int]$n) { 1 { "PRINT" } 2 { "NETWORK" } 3 { "FILES" } 5 { "AUDIT_READ" } default { "unknown call $n" } }
}
function CapList($bits) {
    $b = [int64]$bits
    $l = @()
    if ($b -band 1) { $l += "PRINT" }
    if ($b -band 2) { $l += "NETWORK" }
    if ($b -band 4) { $l += "FILES" }
    if ($b -band 8) { $l += "SECRET" }
    if ($b -band 16) { $l += "AUDIT_READ" }
    if ($l.Count -eq 0) { return "no capabilities" }
    return ($l -join ", ")
}
function FilterList($bits) {
    $b = [int64]$bits
    $l = @()
    if ($b -band 2) { $l += "PRINT" }
    if ($b -band 4) { $l += "NETWORK" }
    if ($b -band 8) { $l += "FILES" }
    if ($b -band 16) { $l += "SANDBOX" }
    if ($l.Count -eq 0) { return "nothing" }
    return ($l -join ", ")
}
function KillText($who, $cause) {
    switch ([int]$cause) {
        13 { return "$who ran a privileged instruction it may not use (general protection fault) and was killed." }
        14 { return "$who touched memory it may not access (page fault) and was killed." }
        15 { return "$who tried to run code from a data page (NX violation) and was killed." }
        16 { return "$who tried to overwrite its own read-only code (write violation) and was killed." }
        17 { return "$who called a syscall outside its filter and was killed." }
        default { return "$who was killed (cause code $cause)." }
    }
}
$threadCaps = @{ 0 = 4 }   # the console shell starts with FILES (assumed from the OS design)
$lastFilter = @{}

function DenySentence($e) {
    $who = Who $e.Thread
    $call = CallName $e.Arg
    $held = 0
    if ($threadCaps.ContainsKey([int]$e.Thread)) { $held = [int64]$threadCaps[[int]$e.Thread] }
    $needBit = 0
    if ([int]$e.Arg -eq 1) { $needBit = 1 } elseif ([int]$e.Arg -eq 2) { $needBit = 2 } elseif ([int]$e.Arg -eq 3) { $needBit = 4 } elseif ([int]$e.Arg -eq 5) { $needBit = 16 }
    if ($needBit -ne 0 -and ($held -band $needBit)) {
        return "$who asked for the $call service but was refused. It already holds $call, so the file it asked for needs another capability (most likely SECRET); the log does not say which file."
    }
    return "$who asked for the $call service without holding that capability and was refused."
}

function SandboxSentence($e) {
    $who = Who $e.Thread
    $t = [int]$e.Thread
    if ($lastFilter.ContainsKey($t) -and $lastFilter[$t] -eq $e.Arg) {
        return "$who asked to change its syscall filter again, but nothing changed: a filter can only shrink, never grow."
    }
    $lastFilter[$t] = $e.Arg
    return "$who narrowed its own syscall filter. It may now only call: $(FilterList $e.Arg). This cannot be undone."
}

function PtrText($a) {
    $v = [uint64]$a
    $hex = '0x{0:x}' -f $v
    if ($v -eq 0xb8000) { return "$hex, the kernel's screen buffer" }
    if ($v -ge 0x555500000000 -and $v -lt 0x555600000000) { return "$hex, user memory but outside this app's own buffer" }
    if ($v -ge [uint64]'18446744073709551360') { return "$hex, at the very top of memory, so pointer plus length would overflow" }
    return $hex
}

function Sentence($e) {
    $who = Who $e.Thread
    switch ($e.Kind) {
        1 { return "The kernel booted and started the audit log." }
        2 { $threadCaps[[int]$e.Thread] = [int64]$e.Arg; return "$who was started in user mode (ring 3) with: $(CapList $e.Arg)." }
        3 { return DenySentence $e }
        4 { return KillText $who $e.Arg }
        5 { return "The SECRET capability was granted to the console shell." }
        6 { return "The SECRET capability was revoked from the console shell." }
        7 { return SandboxSentence $e }
        8 { return "A wrong passphrase was typed at the console (failure number $($e.Arg))." }
        9 { return "$who read the secret file." }
        10 { return "$who passed a pointer the kernel refused (it pointed outside the thread's own buffer). Nothing was written. Pointer: $(PtrText $e.Arg)." }
        default { return "Unknown event type $($e.Kind)." }
    }
}

if (-not (Test-Path $Path)) { "No $Path yet. Run the OS first."; return }

$fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
$sr = New-Object IO.StreamReader($fs)
$raw = $sr.ReadToEnd()
$sr.Close()

$seen = @{}
$entries = @()
foreach ($line in ($raw -split "`n")) {
    $p = $line.Trim() -split ' '
    if ($p.Count -ne 8 -or $p[0] -ne 'DT1') { continue }
    if ($p[6].Length -ne 64 -or $p[7].Length -ne 64) { continue }
    $seq = [int64]$p[1]
    if ($seen.ContainsKey($seq)) { continue }
    $seen[$seq] = $true
    $entries += [pscustomobject]@{ Seq = $seq; Tick = [int64]$p[2]; Kind = [int]$p[3]; Thread = [int]$p[4]; Arg = [uint64]$p[5] }
}

# Integrity first: an explanation of a tampered log is not trustworthy.
$bad = 0
$verifier = Join-Path $PSScriptRoot "verify-audit.ps1"
if (Test-Path $verifier) {
    $v = & $verifier -Path $Path
    $bad = @($v | Where-Object { $_ -like 'PROBLEM*' }).Count
}
if ($bad -gt 0) {
    "WARNING: verify-audit.ps1 found $bad problem(s) in this log."
    "Treat the explanation below as unreliable until you know why."
    ""
} else {
    "Integrity check: no problems found by verify-audit.ps1."
    ""
}

if ($entries.Count -eq 0) { "No audit entries yet."; return }

$missing = @()
$firstSeq = $entries[0].Seq
$lastSeq = $entries[$entries.Count - 1].Seq
for ($s = $firstSeq; $s -le $lastSeq; $s++) {
    if (-not $seen.ContainsKey([int64]$s)) { $missing += $s }
}
if ($missing.Count -gt 0) {
    "WARNING: these entries are missing from the stream and are NOT explained below: #" + ($missing -join ", #")
    ""
}

"== Timeline =="
foreach ($e in $entries) {
    $secs = [math]::Round($e.Tick / 18.2)
    $line2 = Sentence $e
    "#{0:000} [{1,4}s] {2}" -f $e.Seq, $secs, $line2
}

$kills = @($entries | Where-Object { $_.Kind -eq 4 })
$denials = @($entries | Where-Object { $_.Kind -eq 3 })
$authf = @($entries | Where-Object { $_.Kind -eq 8 })
$grants = @($entries | Where-Object { $_.Kind -eq 5 })

""
"== Summary =="
"Entries read: $($entries.Count)"
"Threads killed: $($kills.Count)"
"Refused calls logged: $($denials.Count) (sampled: first per thread and call, then every 512th)"
"Wrong passphrases: $($authf.Count)"

""
"== Notable =="
$any = $false
foreach ($k in $kills) {
    $any = $true
    "- " + (KillText (Who $k.Thread) $k.Arg)
}
$sandboxed = @($entries | Where-Object { $_.Kind -eq 7 } | ForEach-Object { $_.Thread })
foreach ($k in $kills) {
    if ($k.Arg -eq 17 -and ($sandboxed -contains $k.Thread)) {
        "- " + (Who $k.Thread) + " restricted itself, then broke its own restriction. The kernel killed it even though its capabilities may have allowed the call."
    }
}
foreach ($g in ($denials | Group-Object Thread)) {
    $calls = @($g.Group | ForEach-Object { $_.Arg } | Sort-Object -Unique)
    if ($calls.Count -ge 3) {
        $any = $true
        "- " + (Who ([int]$g.Name)) + " was refused $($calls.Count) different services. That looks like probing for something it can use."
    }
}
if ($authf.Count -ge 3) {
    $any = $true
    "- $($authf.Count) wrong passphrases at the console. That could be someone guessing."
}
foreach ($g in $grants) {
    $any = $true
    "- SECRET was granted at entry #$($g.Seq), after a correct passphrase."
}
$reads = @($entries | Where-Object { $_.Kind -eq 9 })
foreach ($r in $reads) {
    $any = $true
    "- " + (Who $r.Thread) + " read the secret file (entry #" + $r.Seq + ")."
}
$bp = @($entries | Where-Object { $_.Kind -eq 10 })
foreach ($g in ($bp | Group-Object Thread)) {
    $any = $true
    "- " + (Who ([int]$g.Name)) + " passed " + $g.Count + " pointers the kernel refused. A refused pointer is never written to."
}
if (-not $any) { "- Nothing unusual in this log." }







""
"== Limits of this explanation =="
"- Refused calls are sampled, so the real number is far higher than the number listed."
"- Only reads of the secret file are logged, not reads of other files."
"- A refused FILES call does not say which file was requested."
"- Names such as App A are demo labels in this script, not read from the log."
"- This is a rule-based summary of the log. It cannot tell an attack from a bug."










