# Linux memory: limescan and limebuild

`limescan memory.mem` now prints one actionable recommendation. It automatically
checks ISFs under `lime/symbols` for an exact banner match, then prints a `limebuild`
command. Override that location with `--symbols-dir PATH`. Without a local match,
it consults `isf-catalog.json.gz`: a compressed list of 10,988 upstream ISF names,
about 76 KB, containing no symbol data. Known entries get a GitHub page and direct
download link pinned to the recorded upstream commit. Download only the selected
ISF yourself. A catalog entry confirms the filename existed at that commit, not
that its banner matches your dump; `limebuild` verifies that after downloading.

The normal workflow is:

```bash
limescan memory.mem
# Copy the exact command printed by limescan, for example:
limebuild memory.mem --isf ./downloaded-kernel.json.xz
# limebuild prints the Volatility command to run next.
```

`limebuild --isf` no longer requires `-o`: it installs the selected ISF under
`lime/symbols/linux` and prints its Volatility command. Matching installed files
are reused; different existing files are not overwritten. Explicit `-o` keeps
the original exclusive-write behavior. `--vmlinux` still requires `-o`.

No full repository clone is needed. Refresh the small catalog explicitly with:

```bash
python3 /mnt/d/tools/lime/catalog.py
```
Without a local match, recognized Ubuntu banners produce a specific ISF filename,
GitHub link, and `limebuild --isf ...` command to run after downloading it.
This is an offline recommendation: remote availability and compatibility are not
claimed until the downloaded ISF is validated. Unknown distributions get a banner
and repository search direction without an invented package filename.

Use `--verbose` to see every banner variant, or `--json` for the complete report
including the selected recommendation. Ranking prefers an intact Ubuntu suffix
and timestamp; only matching against an actual ISF confirms exact banner equality.

## Fast investigation without symbols: limefast

`limefast` is a native C++17 scanner for Linux/WSL, compiled with `-O3` using
the installed g++ (or clang++). The Python launcher compiles only on the first
run or after source changes, then replaces itself with the native executable.
There are no pip packages, symbol downloads, Go builds, or kernel packages needed.
The compiled binary is `lime/bin/limefast`; `lime/native.cpp` is its source.

It maps the input read-only and validates all LiME ranges before scanning.
This avoids allocating a multi-gigabyte Python buffer or collecting results in RAM.
The OS still reads pages from disk; mmap does not make disk I/O free. A cold scan
can be much slower than a repeat scan served by the OS cache. Large files require
a 64-bit environment. Do not modify/truncate the evidence while it is mapped.

Run immediately (no alias installation needed):

```bash
/mnt/d/tools/limefast /mnt/d/tryhard/evidence.mem --help
```

For short commands in the current shell:

```bash
alias limefast='python3 /mnt/d/tools/lime/fast.py'
```

Suggested workflow for a challenge with multiple investigation questions:

```bash
# Save broad clues once; an existing output is never overwritten.
limefast evidence.mem --kind all --limit 0 -o triage.tsv

# Search the much smaller report when a question arrives.
rg -i 'username|hostname|wget|curl|/home/|/tmp/' triage.tsv

# Focused searches of the original dump, including bytes outside printable strings.
limefast evidence.mem --find 'suspect-name' --find 'example.com' --limit 0 -o focused.tsv

# Separate filters when the broad report is noisy.
limefast evidence.mem --kind commands --limit 0 -o commands.tsv
limefast evidence.mem --kind urls --limit 0 -o urls.tsv
limefast evidence.mem --kind flags --limit 0 -o flags.tsv

# Read the neighborhood of a hit without scanning 4 GB again.
# Replace the example offset with file_offset from your report.
limefast evidence.mem --read 0xbe74411f --length 512

# Dispatcher also supported:
python3 /mnt/d/tools/tools.py lime fast evidence.mem --kind paths
```

Default limit is 1000 rows for an interactive preview. It stops early and explicitly
prints `STOPPED AT LIMIT (partial scan)`. Always use `--limit 0` for full coverage.
Progress statistics go to stderr; rows go to stdout or `--output`. Output is TSV:
file offset, physical address (LiME only), category, context file offset, escaped text.
Nonprintable bytes become `\xNN` and backslashes become `\\`, so output cannot inject
terminal escape sequences. `--read` uses **file offsets**, not physical addresses.

`--find` searches exact case-sensitive byte strings (not regex), including matches
outside printable runs. Repeated terms are searched separately within each range;
their results are not globally sorted or deduplicated. Searches never cross LiME
range boundaries. UTF-16 decoding is not implemented.

Category modes inspect ASCII printable runs at least 4 bytes long. They inspect
8192-byte windows with 512-byte overlap and emit the first matching clue per window;
`all` prioritizes flag-like text, then other categories. Long runs and repeated memory
copies may produce duplicate rows. This is deliberately a **triage report**, not an
exhaustive artifact database. Use specific categories or `--find` for follow-up.
Flag-like braces and words such as `history` may be ordinary program text.
Context defaults to 120 bytes before/after a hit; increase with `--context` (max 4096).

What this can help answer: visible URL/domain, path, command text, configuration
values, kernel banner, and plaintext flag clues. Corroborate each clue with nearby
data and other evidence. A string alone cannot prove execution, ownership, or time.
This does not recover a process list, associate sockets with PIDs, reconstruct virtual
address spaces, extract fragmented files, or replace Volatility's kernel plugins.
For those questions, a matching ISF may still be necessary. A previously built exact
ISF can be imported with `limebuild --isf`; rebuilding is unnecessary.

Tests: `python3 -m unittest discover -s tests -p 'test_limefast.py' -v` in WSL/Linux.
Exit status: 0 successful operation (including zero hits or an explicit row limit),
1 invalid arguments/input/output. Coverage and the partial-scan marker are on stderr.

### Local measurement

On the available WSL machine, `/mnt/d/tryhard/evidence.mem` (4,229,558,206 bytes,
254 LiME ranges) took 36.994 seconds for a complete literal `Linux` search and
47.830 seconds for complete `--kind all` triage, including TSV output. A repeat
literal search took 42.160 seconds; this run did not show a cache speedup. These are
observed end-to-end scans through `/mnt/d`, not controlled cold-cache benchmarks
or guarantees for another disk. Compilation took about 1 second in the test suite.

The generated `lime/evidence-triage.tsv` contains 88,321 heuristic rows in
41,072,206 bytes. Reading/counting that report with Python on Windows took
0.558 seconds. These are candidate clues, not 88,321 confirmed artifacts.
The report contains extracted evidence and should be kept with the challenge files.

`limescan` checks LiME v1 ranges (including truncation and overlap), scans complete
Linux banners without loading the entire dump into RAM, and reports symbol readiness.
Raw files can also be scanned, but finding a banner does not prove a valid physical dump.
Multiple banners are reported because stale kernel strings can exist in memory.

`limebuild` creates Volatility 3 ISF symbols using dwarf2json, or imports an existing
ISF. It checks required type data and exact banner matching before writing output.
It never modifies the dump, replaces existing output, or patches a mismatched banner.
Banner matching is necessary but does not guarantee every Volatility plugin works.

```bash
# Activate new aliases in the current shell without changing shell configuration:
alias limescan='python3 /mnt/d/tools/lime/scanner.py'
alias limebuild='python3 /mnt/d/tools/lime/builder.py'
# For persistent aliases, run the existing installer and source ~/.bashrc.

limescan /mnt/d/tryhard/evidence.mem
limescan memory.mem --json
limescan memory.mem --isf symbols/linux/kernel.json.xz
limebuild memory.mem --vmlinux /path/to/vmlinux --dwarf2json /path/to/dwarf2json -o symbols/linux/kernel.json.xz
limebuild memory.mem --isf /path/to/existing.json.xz -o symbols/linux/kernel.json.xz
vol -s ./symbols -f memory.mem linux.pslist.PsList

# Unified dispatcher:
python3 /mnt/d/tools/tools.py lime scan memory.mem
python3 /mnt/d/tools/tools.py lime build --help
```

Scanning and importing use only Python's standard library. Building requires the
matching uncompressed debug kernel ELF (vmlinux with DWARF types), and dwarf2json.
An optional `--system-map` must come from that same kernel build.
A banner alone, kernel headers, a stripped kernel, or a System.map alone cannot
reconstruct the necessary type information. Obtain the exact distribution debug
kernel package, extract it, and supply its vmlinux. Package availability is not
checked automatically. The scanner recommends looking for a prebuilt ISF first;
the suggested filename is not a claim that it is available online.

Build dwarf2json in Linux/WSL with Go as documented upstream:

```bash
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json
go build
```

Exit codes: 0 success; 1 invalid input/build failure; scanner 2 no complete banner.
ISF validation loads JSON into RAM; dwarf2json may require at least 8 GB for large kernels.
No downloads or installation happen implicitly.

References:
- https://github.com/volatilityfoundation/dwarf2json
- https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h
