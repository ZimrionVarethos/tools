#!/usr/bin/env python3
"""
Unified DFIR Forensic Toolkit Master Runner
Central entrypoint for all forensics modules (Global, AD1, PCAP, DMP, IMG)
"""
import sys
import os

# Ensure tools directory is on sys.path
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

# Ensure UTF-8 output on Windows terminal
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import argparse
from core.banner import print_banner, print_ad1_banner
from rich.console import Console

console = Console(force_terminal=True, legacy_windows=False)


def handle_ad1_command(ad1_args):
    """Dispatch AD1 module subcommands."""
    if not ad1_args:
        print_ad1_help()
        return

    sub = ad1_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = ad1_args[1:]

    if sub in ["history", "browser_history", "ad1history"]:
        from ad1.history import main as history_main
        history_main(remaining)
    elif sub in ["amcache", "ad1amcache"]:
        from ad1.amcache import main as amcache_main
        amcache_main(remaining)
    elif sub in ["ntuser", "ad1ntuser"]:
        from ad1.ntuser import main as ntuser_main
        ntuser_main(remaining)
    elif sub in ["recent", "ad1recent"]:
        from ad1.recent import main as recent_main
        recent_main(remaining)
    elif sub in ["extensions", "extension", "ad1extensions", "ad1extension"]:
        from ad1.extensions import main as ext_main
        ext_main(remaining)
    elif sub in ["scan", "ad1scan"]:
        from ad1.scan import main as scan_main
        scan_main(remaining)
    elif sub in ["scandetail", "ad1scandetail", "userfiles"]:
        from ad1.scandetail import main as scandetail_main
        scandetail_main(remaining)
    elif sub in ["dpapi", "ad1dpapi", "decrypt"]:
        from ad1.dpapi_decrypt import main as dpapi_main
        dpapi_main(remaining)
    elif sub in ["-h", "--help", "help"]:
        print_ad1_help()
    else:
        if sub.endswith(".ad1") or os.path.exists(ad1_args[0]):
            from ad1.history import main as history_main
            history_main(ad1_args)
        else:
            console.print(f"[bold red]Unknown AD1 subcommand:[/bold red] {ad1_args[0]}")
            print_ad1_help()


def handle_pcap_command(pcap_args):
    """Dispatch PCAP module subcommands."""
    if not pcap_args:
        print_pcap_help()
        return

    sub = pcap_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = pcap_args[1:]

    if sub in ["first", "pcapfirst", "first_look", "overview", "triage", "macro"]:
        from pcap.first_look import main as first_main
        first_main(remaining)
    elif sub in ["tree", "pcaptree", "hierarchy", "streams"]:
        from pcap.tree import main as tree_main
        tree_main(remaining)
    elif sub in ["file", "files", "pcapfile", "carve", "export"]:
        from pcap.file_carver import main as file_main
        file_main(remaining)
    elif sub in ["stream", "follow", "pcapstream", "pcapcat"]:
        from pcap.stream_follower import main as stream_main
        stream_main(remaining)
    elif sub in ["scanstream", "pcapscanstream", "scan_stream", "streamscan"]:
        from pcap.scan_stream import main as scan_stream_main
        scan_stream_main(remaining)
    elif sub in ["scan", "pcapscan", "hunter"]:
        from pcap.scanner import main as scan_main
        scan_main(remaining)
    elif sub in ["payload", "pcappayload", "extractor", "dns", "icmp"]:
        from pcap.payload_extractor import main as payload_main
        payload_main(remaining)
    elif sub in ["portpayload", "pcapportpayload", "port", "ports"]:
        from pcap.port_payload import main as port_payload_main
        port_payload_main(remaining)
    elif sub in ["endpoint", "endpoints", "pcapendpoint", "url", "urls", "c2"]:
        from pcap.endpoint import main as endpoint_main
        endpoint_main(remaining)
    elif sub in ["-h", "--help", "help"]:
        print_pcap_help()
    else:
        if sub.endswith((".pcap", ".pcapng", ".cap")) or os.path.exists(pcap_args[0]):
            from pcap.scanner import main as scan_main
            scan_main(pcap_args)
        else:
            console.print(f"[bold red]Unknown PCAP subcommand:[/bold red] {pcap_args[0]}")
            print_pcap_help()


def handle_dmp_command(dmp_args):
    """Dispatch DMP memory dump subcommands."""
    if not dmp_args:
        print_dmp_help()
        return

    sub = dmp_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = dmp_args[1:]

    if sub in ["scan", "dmpscan", "hunter", "triage"]:
        from dmp.scanner import main as dmp_main
        dmp_main(remaining)
    elif sub in ["dump", "dmpdump", "carve", "extract"]:
        from dmp.dumper import main as dumper_main
        dumper_main(remaining)
    elif sub in ["peb", "dmppeb", "env"]:
        from dmp.scanner import main as dmp_main
        dmp_main(remaining + ["--peb"])
    elif sub in ["modules", "dmpmodules", "lm"]:
        from dmp.scanner import main as dmp_main
        dmp_main(remaining + ["--modules"])
    elif sub in ["flags", "flag", "dmpflags"]:
        from dmp.scanner import main as dmp_main
        dmp_main(remaining + ["--flags-only"])
    elif sub in ["memcarve", "limecarve"]:
        import subprocess
        mc_bin = "/mnt/d/tools/bin/memcarve"
        subprocess.run([mc_bin if os.path.exists(mc_bin) else "memcarve"] + remaining)
        return
    elif sub in ["volrust", "vol-rs", "vol_rs"]:
        import subprocess
        vol_bin = "/mnt/d/tools/bin/vol-rs"
        if os.path.exists(vol_bin):
            subprocess.run([vol_bin] + remaining)
        else:
            subprocess.run(["vol-rs"] + remaining)
        return
    elif sub in ["-h", "--help", "help"]:
        print_dmp_help()
    else:
        if sub.endswith((".dmp", ".raw", ".bin")) or os.path.exists(dmp_args[0]):
            from dmp.scanner import main as dmp_main
            dmp_main(dmp_args)
        else:
            console.print(f"[bold red]Unknown DMP subcommand:[/bold red] {dmp_args[0]}")
            print_dmp_help()


def handle_exe_command(exe_args):
    """Dispatch EXE binary doctor and repair subcommands."""
    if not exe_args:
        print_exe_help()
        return

    sub = exe_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = exe_args[1:]

    if sub in ["fix", "exefix", "repair", "realign"]:
        from exe.fixer import main as exe_main
        exe_main(remaining)
    elif sub in ["diagnose", "check", "doctor", "health"]:
        from exe.fixer import main as exe_main
        exe_main(["--diagnose"] + remaining)
    elif sub in ["unmap", "unpack"]:
        from exe.fixer import main as exe_main
        exe_main(["--unmap"] + remaining)
    elif sub in ["-h", "--help", "help"]:
        print_exe_help()
    else:
        from exe.fixer import main as exe_main
        exe_main(exe_args)


def handle_stego_command(stego_args):
    """Dispatch Steganography module subcommands."""
    if not stego_args:
        print_stego_help()
        return

    sub = stego_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = stego_args[1:]

    if sub in ["scan", "stegoscan", "inspector"]:
        from stego.scanner import main as scan_main
        scan_main(remaining)
    elif sub in ["diff", "stegodiff", "compare", "shift"]:
        from stego.differ import main as diff_main
        diff_main(remaining)
    elif sub in ["crack", "stegocrack", "steghide", "outguess"]:
        from stego.cracker import main as crack_main
        crack_main(remaining)
    elif sub in ["audio", "stegoaudio", "spectrogram", "wav"]:
        from stego.audio import main as audio_main
        audio_main(remaining)
    elif sub in ["-h", "--help", "help"]:
        print_stego_help()
    else:
        if os.path.exists(stego_args[0]):
            from stego.scanner import main as scan_main
            scan_main(stego_args)
        else:
            console.print(f"[bold red]Unknown Stego subcommand:[/bold red] {stego_args[0]}")
            print_stego_help()


def handle_assembly_command(asm_args):
    """Dispatch Assembly & Reverse Engineering suite subcommands."""
    if not asm_args:
        print_assembly_help()
        return

    sub = asm_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = asm_args[1:]

    if sub in ["ghidra", "ghidraanalyze", "cli", "bridge"]:
        from assembly.ghidra.analyzer import main as ghidra_main
        ghidra_main(remaining)
    elif sub in ["exe", "exefix", "pe"]:
        from assembly.exe.fixer import main as exe_main
        exe_main(remaining)
    elif sub in ["doctor", "exedoctor"]:
        from assembly.exe.fixer import main as exe_main
        exe_main(["--diagnose"] + remaining)
    elif sub in ["guide", "ghidraguide", "wuguide"]:
        from assembly.exe.ghidraguide import main as guide_main
        guide_main(remaining)
    elif sub in ["elf", "elffix", "elfdoctor"]:
        from assembly.elf.inspector import main as elf_main
        elf_main(remaining)
    elif sub in ["binary", "disasm", "shellcode", "raw"]:
        from assembly.binary.disasm import main as disasm_main
        disasm_main(remaining)
    elif sub in ["-h", "--help", "help"]:
        print_assembly_help()
    else:
        console.print(f"[bold red]Unknown Assembly subcommand:[/bold red] {asm_args[0]}")
        print_assembly_help()


def handle_core_command(core_args):
    """Dispatch Core and Rust high-performance subcommands."""
    if not core_args or core_args[0] in ["-h", "--help", "help"]:
        print_core_help()
        return

    sub = core_args[0].lower()
    if sub.endswith(".py"):
        sub = sub[:-3]

    remaining = core_args[1:]

    if sub in ["globalscan", "gscan"]:
        from core.globalscan import main as globalscan_main
        globalscan_main(remaining)
    elif sub in ["globalscan2", "gscan2"]:
        import subprocess
        gs2_bin = "/mnt/d/tools/bin/globalscan2"
        subprocess.run([gs2_bin if os.path.exists(gs2_bin) else "globalscan2"] + remaining)
    elif sub in ["strings2", "s2"]:
        import subprocess
        s2_bin = "/mnt/d/tools/bin/strings2"
        subprocess.run([s2_bin if os.path.exists(s2_bin) else "strings2"] + remaining)
    elif sub in ["binwalk2", "bw2"]:
        import subprocess
        bw2_bin = "/mnt/d/tools/bin/binwalk2"
        subprocess.run([bw2_bin if os.path.exists(bw2_bin) else "binwalk2"] + remaining)
    elif sub in ["memcarve", "limecarve"]:
        import subprocess
        mc_bin = "/mnt/d/tools/bin/memcarve"
        subprocess.run([mc_bin if os.path.exists(mc_bin) else "memcarve"] + remaining)
    elif sub in ["volrust", "vol-rs", "vol_rs"]:
        import subprocess
        vol_bin = "/mnt/d/tools/bin/vol-rs"
        subprocess.run([vol_bin if os.path.exists(vol_bin) else "vol-rs"] + remaining)
    elif sub in ["-h", "--help", "help"]:
        print_core_help()
    else:
        if os.path.exists(core_args[0]):
            import subprocess
            gs2_bin = "/mnt/d/tools/bin/globalscan2"
            subprocess.run([gs2_bin if os.path.exists(gs2_bin) else "globalscan2"] + core_args)
        else:
            console.print(f"[bold red]Unknown Core subcommand:[/bold red] {core_args[0]}")
            print_core_help()


def print_pcap_help():
    print_banner("PCAP NETWORK FORENSICS (pcap)", "Packet Capture, Stream Carving & Protocol Analyzer")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools pcap <command> <capture.pcap> [options]
  <shorthand_command> <capture.pcap> [options]

[bold cyan]Available PCAP Commands:[/bold cyan]
  [green]endpoint[/green]   Otomatis scan semua stream untuk C2, Flag, Seed, Exfil, Fake Telemetry & multi-base decode
  [green]first[/green]      Instant macro triage dashboard (metadata, protocol hierarchy, port classification, top talkers)
  [green]tree[/green]       Visual protocol hierarchy tree, conversations matrix, & TCP/UDP streams
  [green]file[/green]       Carve & reconstruct transferred files (PE, ELF, ZIP, PDF, images, etc.)
  [green]stream[/green]     Interactive Wireshark-style follow stream & raw hex dump (Client Cyan, Server Green)
  [green]scan[/green]       Threat & flag hunter (C2 beacons, reverse shells, high-entropy ciphertexts)
  [green]scanstream[/green] Deep stream & payload inspector with automated XOR brute-force (0x01..0xFF)
  [green]payload[/green]    Packet payload extractor (DNS tunneling, ICMP ping data, TCP/UDP raw)
  [green]portpayload[/green] Port manipulation covert channel decoder (Port-to-ASCII, IP.ID & TTL covert)

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]pcapendpoint <file.pcap>[/bold yellow]               Scan otomatis semua stream untuk C2, Flag, Seed & Exfil
  [bold yellow]pcapendpoint <file.pcap> -s 49[/bold yellow]          Follow percakapan request-response stream #49
  [bold yellow]pcapendpoint <file.pcap> --all[/bold yellow]          Tampilkan seluruh endpoint termasuk telemetri OS normal
  [bold yellow]pcapfirst <file.pcap>[/bold yellow]                  Macro triage dashboard (metadata, protocols, top talkers)
  [bold yellow]pcaptree <file.pcap>[/bold yellow]                   Display protocol tree & IP conversation endpoints
  [bold yellow]pcapfile <file.pcap> -o ./out/[/bold yellow]         Carve & save all reconstructed files to folder
  [bold yellow]pcapstream <file.pcap> -s 2[/bold yellow]            Follow TCP stream index 2 in color-coded mode
  [bold yellow]pcapstream <file.pcap> -s 2 --hex[/bold yellow]      Follow stream in side-by-side Hex/ASCII dump
  [bold yellow]pcapscan <file.pcap>[/bold yellow]                   Scan all streams for CTF flags & C2 beacons
  [bold yellow]pcapscanstream <file.pcap>[/bold yellow]             Deep stream scanner with auto XOR brute-force & entropy
  [bold yellow]pcappayload <file.pcap> --dns[/bold yellow]          Extract DNS tunneling subdomains & auto-decode
  [bold yellow]pcappayload <file.pcap> --icmp -c[/bold yellow]      Reassemble ICMP ping data sequence
  [bold yellow]pcapportpayload <file.pcap>[/bold yellow]          Decode port covert channels & TTL / IP.ID covert data

[bold cyan]Examples:[/bold cyan]
  pcapendpoint wire.pcap
  pcapendpoint wire.pcap -s 51
  pcapfirst traffic.pcapng
  pcappayload exfil.pcap --dns --domain evil.corp
  pcapportpayload covert.pcap --port-ascii
""")


def print_dmp_help():
    print_banner("MEMORY FORENSICS SUITE (dmp / lime / rust)", "Minidump, LiME Raw RAM, Multi-Page Carver & Volatility Rust")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools dmp <command> <memory.dmp/.raw> [options]
  <shorthand_command> <memory.dmp/.raw> [options]

[bold cyan]Available Memory Commands:[/bold cyan]
  [green]memcarve[/green]   Universal Raw Memory Carver (Rust ⚡) for DEX, ELF, PE, ZIP with LIFO reverse page detection
  [green]volrust[/green]    High-performance Volatility 3 port in Rust (vol-rs) - 20x to 500x faster
  [green]scan[/green]       Full automated Windows memory triage (PEB info, loaded modules, CTF flag hunter)
  [green]peb[/green]        Process Environment Block (!peb): cmdline, env vars, working directory
  [green]modules[/green]    Loaded Executables and DLLs Matrix (lm / lmvm)
  [green]dump[/green]       Carve and dump embedded memory streams & main executable to disk
  [green]flags[/green]      Fast memory scan for plaintext, UTF-16, & Base64 CTF flag patterns

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]memcarve scan <mem.raw> DEX "api/v1"[/bold yellow]       Carve DEX binary containing string with LIFO reverse-page assembler
  [bold yellow]memcarve scan <mem.raw> -a "keyword"[/bold yellow]       Scan all 15 header signatures in dictionary containing keyword
  [bold yellow]memcarve dict[/bold yellow]                             List all supported file formats & magic headers
  [bold yellow]volrust -f <mem.raw> windows.pslist[/bold yellow]       Execute Volatility plugin via ultra-fast Rust engine
  [bold yellow]dmpscan <memory.dmp>[/bold yellow]                      Comprehensive Windows memory triage & flag hunt
  [bold yellow]dmpscan <memory.dmp> --flags-only[/bold yellow]         Quick display of captured flag matches
  [bold yellow]dmpdump <memory.dmp> --main -o out.exe[/bold yellow]   Dump main executable reconstructed from memory
  [bold yellow]dmppeb <memory.dmp>[/bold yellow]                       Extract command line, process path & env vars
  [bold yellow]dmpmodules <memory.dmp>[/bold yellow]                   List all loaded DLLs, base addresses & sizes

[bold cyan]Examples:[/bold cyan]
  memcarve scan chall.raw DEX "api/v1" --extract ./out
  volrust -f memory.raw windows.malfind
  dmpdump lsass.dmp -i 0x7ff62fbd0000 -o dumped.exe
""")


def print_lime_help():
    print_banner("LINUX LiME MEMORY FORENSICS (lime)", "Kernel Banner Scanner, Volatility Symbol Builder & Native Triage")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools lime <command> <memory.lime/.raw> [options]
  <shorthand_command> <memory.lime/.raw> [options]

[bold cyan]Available LiME Commands:[/bold cyan]
  [green]scan[/green]       Scan Linux kernel release banner, architecture & matching ISF symbol recommendation
  [green]build[/green]      Automated download & compilation of Volatility 3 matching symbol tables
  [green]fast[/green]       Native symbol-free Linux memory triage (pslist, modules, network, creds)

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]limescan <memory.lime>[/bold yellow]                   Identify kernel banner (e.g. 5.15.0-generic) & arch
  [bold yellow]limebuild <memory.lime>[/bold yellow]                  Download vmlinux/dwarf & generate .json.xz symbol table
  [bold yellow]limefast <memory.lime>[/bold yellow]                   Perform symbol-free process and memory inspection

[bold cyan]Examples:[/bold cyan]
  limescan memory.lime
  limebuild memory.lime -o ./symbols/
  limefast memory.lime --pslist
""")


def print_ad1_help():
    print_ad1_banner()
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools ad1 <command> <evidence.ad1> [options]
  <shorthand_command> <evidence.ad1> [options]

[bold cyan]Available AD1 Commands:[/bold cyan]
  [green]history[/green]     Extract browser history (Chrome, Edge, Firefox, Brave) + DPAPI bundle
  [green]dpapi[/green]       Automated offline DPAPI MasterKey recovery & Chromium login decryption
  [green]amcache[/green]     Analyze Amcache.hve (Program execution artifacts, paths, SHA1 hashes)
  [green]ntuser[/green]      Analyze NTUSER.DAT (UserAssist ROT13, TypedPaths, RunMRU, RecentDocs)
  [green]recent[/green]      Analyze recent activity (.lnk shortcut files & Windows JumpLists)
  [green]extensions[/green]  Triage browser extensions, orphan storage & LevelDB C2 strings
  [green]scan[/green]        Interactive visual folder tree with sensitive file highlighting & flags
  [green]scandetail[/green]  Zero-noise user documents, notes & photos hunter (excludes AppData)

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]ad1history <file.ad1>[/bold yellow]              Extract all browser history databases
  [bold yellow]ad1dpapi <file.ad1> -p <pass>[/bold yellow]       Decrypt saved passwords using user password
  [bold yellow]ad1amcache <file.ad1>[/bold yellow]              Parse Amcache execution artifacts
  [bold yellow]ad1ntuser <file.ad1>[/bold yellow]               Parse UserAssist & TypedPaths from registry
  [bold yellow]ad1recent <file.ad1>[/bold yellow]               Inspect LNK files & target paths
  [bold yellow]ad1scan <file.ad1>[/bold yellow]                 Scan directory tree & flag sensitive files
  [bold yellow]ad1scandetail <file.ad1> -u <user>[/bold yellow] Locate user documents & photos

[bold cyan]Examples:[/bold cyan]
  tools ad1 history evidence.ad1
  ad1dpapi evidence.ad1 -p "Password123!"
  ad1scan evidence.ad1
""")


def print_stego_help():
    print_banner("STEGANOGRAPHY SUITE (stego)", "Custom Chunks, Spatial Shift, Password Cracker & Audio FFT")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools stego <command> <file> [options]
  <shorthand_command> <file> [options]

[bold cyan]Available Stego Commands:[/bold cyan]
  [green]scan[/green]       PNG custom chunks, IHDR height repair, trailing overlays past IEND/FFD9
  [green]diff[/green]       2-image spatial shift auto-bruteforce (dx, dy) & residual delta decoder
  [green]crack[/green]      Automated password cracker for Steghide (blank & wordlist) and OutGuess
  [green]audio[/green]      High-resolution FFT frequency spectrogram visualizer & WAV LSB extractor

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]stegoscan <image.png>[/bold yellow]            Inspect chunk headers & custom chunks (raCh, etc.)
  [bold yellow]stegoscan <image.png> --fix-height[/bold yellow] Auto-repair PNG IHDR height mismatch (CRC)
  [bold yellow]stegoscan <image.jpg> --carve ./out/[/bold yellow] Carve trailing overlay & embedded ZIP/PE
  [bold yellow]stegodiff <img1> <img2>[/bold yellow]          Auto-align 2 images & decode residual deltas
  [bold yellow]stegocrack <secret.jpg>[/bold yellow]         Extract Steghide with blank / common passwords
  [bold yellow]stegocrack <secret.jpg> -w <dict>[/bold yellow] Dictionary attack with wordlist (e.g. rockyou)
  [bold yellow]stegoaudio <sound.wav>[/bold yellow]          Generate spectrogram PNG to see Morse/visual text

[bold cyan]Examples:[/bold cyan]
  stegoscan scan_042_preview.png
  stegodiff preview.png reference.png
  stegocrack secret.jpg -w /usr/share/wordlists/rockyou.txt
  stegoaudio recording.wav -o ./spectrogram.png
""")


def print_assembly_help():
    print_banner("ASSEMBLY & REVERSE ENGINEERING (assembly)", "Ghidra Companion, PE Doctor, ELF Doctor & Disassembler")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools assembly <command> [options]
  <shorthand_command> [options]

[bold cyan]Available Assembly Submodules:[/bold cyan]
  [green]ghidra[/green]     Interactive live 2-way companion to Ghidra GUI (ghidraanalyze / ghidracli)
  [green]exe[/green]        Windows PE binary doctor, memory dump realigner, unmapper (exefix / exedoctor)
  [green]elf[/green]        Linux ELF header inspector, stripped symbol detector, UPX check (elfdoctor)
  [green]binary[/green]     Multi-arch raw shellcode disassembler x64/x86/ARM (disasm / shellcode)

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]ghidraanalyze status[/bold yellow]          Check active Ghidra bridge connection
  [bold yellow]ghidraanalyze current[/bold yellow]         Decompile & reconstruct clean C at cursor position
  [bold yellow]ghidraanalyze goto <addr>[/bold yellow]     Navigate Ghidra GUI window to address
  [bold yellow]ghidraanalyze callers <addr>[/bold yellow]  Display function call tree
  [bold yellow]ghidraanalyze rename <addr> <name>[/bold yellow] Rename function/variable directly from CLI
  [bold yellow]exefix <dumped.exe> -o <out>[/bold yellow] Realign memory-dumped PE for clean Ghidra decompilation
  [bold yellow]exedoctor <file.exe>[/bold yellow]          Diagnose PE header integrity and sections
  [bold yellow]ghidraguide <file.exe>[/bold yellow]        Generate Ghidra reversing blueprint & analysis checklist
  [bold yellow]elfdoctor <binary.elf>[/bold yellow]        Inspect Linux ELF header, arch, stripped symbols & UPX
  [bold yellow]disasm <payload.bin> -a x64[/bold yellow]   Disassemble raw shellcode with PEB/API detection

[bold cyan]Examples:[/bold cyan]
  ghidraanalyze current
  exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe
  elfdoctor malware.elf
  disasm shellcode.bin -a x64
""")


def print_exe_help():
    print_assembly_help()


def handle_cipher_command(cipher_args):
    """Dispatch Cipher and Cryptography commands."""
    if not cipher_args or cipher_args[0] in ["-h", "--help", "help"]:
        print_cipher_help()
        return
    sub = cipher_args[0].lower()
    if sub in ["hunt", "cryptohunt", "keyhunt", "keyfind", "keyscan", "cryptoparse"]:
        from cipher.cryptohunt import main as hunt_main
        hunt_main(cipher_args[1:])
        return
    from cipher.checker import main as cipher_main
    cipher_main(cipher_args)


def print_cipher_help():
    print_banner("CRYPTOGRAPHY & CIPHER IDENTIFIER (cipher)", "Payload Entropy Profiler, Key Harvester & Decryptor Templates")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools cipher [options]
  ciphercheck [options]
  cryptohunt <file> [options]

[bold cyan]Available Tools & Script Templates:[/bold cyan]
  [green]ciphercheck[/green]     Auto-identify encoding, cipher type (AES, DES, RC4, ChaCha20, RSA), entropy & auto-XOR
  [green]cryptohunt[/green]      Automated Key (32B/16B), Nonce (12B/8B), Crypto Constants & Struct Harvester
  [green]T_aes.py[/green]        AES-128/192/256 Decryptor & Encryptor (ECB, CBC, CTR, GCM, auto-IV)
  [green]T_chacha20.py[/green]   ChaCha20 & Salsa20 Stream Cipher Toolkit
  [green]T_xor.py[/green]        Single-byte brute force, repeating key & 32-bit rolling seed XOR
  [green]T_rc4.py[/green]        RC4 / ARC4 Stream Cipher Toolkit
  [green]T_rsa.py[/green]        RSA Decryptor (Wiener, Fermat, FactorDB)
  [green]T_classical.py[/green]  Caesar (ROT1-25), Vigenere, Atbash, Railfence solver

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]ciphercheck[/bold yellow]                           Interactive mode (paste cipher string directly)
  [bold yellow]ciphercheck -t "<string>"[/bold yellow]             Direct inline ciphertext inspection
  [bold yellow]ciphercheck -i <file.txt>[/bold yellow]             Read and analyze ciphertext from file
  [bold yellow]cryptohunt <binary.elf>[/bold yellow]               Scan 32B/16B keys & auto-detect paired {Nonce, Key}
  [bold yellow]cryptohunt <mem.lime> --near flag.txt[/bold yellow]  Targeted key hunt in proximity of keyword/address
  [bold yellow]cryptohunt <file> --test-decrypt <ct>[/bold yellow]  Auto-test candidate keys against ChaCha20/AES/RC4

[bold cyan]Examples:[/bold cyan]
  ciphercheck -t "Jy87cmlfKFs/I1x6Q15F..."
  cryptohunt elf_51767488.bin --pair --test-decrypt "KEVt/ztn..." --prefix "GEMASTIK"
  cryptohunt memory.lime --near "expand 32-byte k" --range 65536
""")


def print_core_help():
    print_banner("UNIVERSAL & RUST CORE SUITE (core / rust)", "Zero-Copy SIMD Memory Mapping & Parallel Forensic Engines")
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools core <command> [file] [options]
  tools rust <command> [file] [options]
  <shorthand_command> [file] [options]

[bold cyan]Available Tools:[/bold cyan]
  [green]globalscan2[/green] Universal Rust file scanner, CTF flag hunter, entropy & XOR brute-force (100x faster)
  [green]strings2[/green]    Ultra-fast strings extractor (ASCII & UTF-16LE), regex search & context lines (-C)
  [green]binwalk2[/green]    Zero-copy SIMD firmware & embedded binary signature carver (-e -o <dir>)
  [green]memcarve[/green]    Universal Raw Memory Carver with LIFO reverse-page allocation assembler
  [green]volrust[/green]     High-performance Volatility 3 port in Rust (vol-rs) - 20x to 500x faster
  [green]globalscan[/green]  Original Python universal scanner (flag regex, keyword, metadata, auto-decoders)

[bold cyan]Direct Shorthand Commands:[/bold cyan]
  [bold yellow]globalscan2 <file>[/bold yellow]               Scan flags, hashes, entropy & XOR brute-force
  [bold yellow]globalscan2 <file> --flags-only[/bold yellow]  Fast display of discovered CTF flags
  [bold yellow]strings2 <file> -s "pattern"[/bold yellow]     Search ASCII/UTF-16LE strings with context lines
  [bold yellow]strings2 <file> -r "api/v[0-9]"[/bold yellow]  Search strings with regular expression
  [bold yellow]binwalk2 <file> -e -o ./out[/bold yellow]       Carve embedded files & signatures with SIMD speed
  [bold yellow]memcarve scan <file> DEX "api"[/bold yellow]   Carve DEX containing keyword with reverse order support
  [bold yellow]memcarve scan <file> -a "flag"[/bold yellow]   Scan all 15 header signatures containing flag
  [bold yellow]memcarve dict[/bold yellow]                    Display all supported file signatures & headers
  [bold yellow]volrust -f <mem.raw> pslist[/bold yellow]      Run Volatility plugin with instant Rust execution

[bold cyan]Examples:[/bold cyan]
  globalscan2 cute.DMP
  strings2 -s "api/v1" wire.pcap -C 2
  binwalk2 firmware.bin -e -o ./carved
  memcarve scan chall.raw DEX "api/v1" --extract ./out
""")


def print_global_help():
    print_banner(
        tool_name="ADVANCED DFIR FORENSICS SUITE (tools)",
        sub_title="Modular Digital Forensics & Incident Response Platform"
    )
    console.print("""
[bold cyan]Syntax & Usage:[/bold cyan]
  tools <module> <command> [options]
  <shorthand_command> [options]

[bold cyan]Forensic Modules:[/bold cyan]
  [bold yellow]core / rust[/bold yellow] Universal High-Speed Rust Tools (Globalscan2, Strings2, Binwalk2, Memcarve, Volrust)
  [bold yellow]pcap[/bold yellow]        Network Packet Capture (.pcap, .pcapng) forensics & C2 Threat Hunter
  [bold yellow]dmp[/bold yellow]         Windows Memory Dump (.dmp, .raw) & Memcarve Rust Suite
  [bold yellow]lime[/bold yellow]        Linux LiME Memory Forensics, Banner Scanner & Symbol Builder
  [bold yellow]assembly[/bold yellow]    Reverse Engineering & Binary Suite (Ghidra, PE Doctor, ELF, Shellcode)
  [bold yellow]cipher[/bold yellow]      Cryptography & Obfuscation Analysis (Cipher Identifier, Keyhunt, Decryptors)
  [bold yellow]stego[/bold yellow]       Steganography Suite (Custom Chunks, Spatial Differential, Cracker, Audio)
  [bold yellow]ad1[/bold yellow]         AccessData Logical Image (.ad1) forensics & Browser History

[bold cyan]Shorthand Direct Commands by Category:[/bold cyan]

[bold bright_magenta]⚡ Universal & Rust High-Performance Suite:[/bold bright_magenta]
  [green]globalscan2 <file>[/green]            Port Rust super cepat: scan flags, hashes, metadata & XOR brute-force
  [green]strings2 <file> -s <str>[/green]       Carving string ASCII/UTF-16LE ultra-cepat dengan regex & context lines
  [green]binwalk2 <file> -e -o <dir>[/green]   Zero-copy SIMD firmware & binary signature carver
  [green]memcarve scan <raw> DEX <q>[/green]   Universal memory carver dengan LIFO reverse-page allocation assembler
  [green]volrust -f <raw> <plugin>[/green]     Porting resmi Volatility 3 berbasis Rust (20x s/d 500x lebih cepat)

[bold bright_magenta]🌐 PCAP Network Forensics & C2 Hunter (pcap/):[/bold bright_magenta]
  [green]pcapendpoint <file.pcap>[/green]        Scan otomatis seluruh stream untuk C2, Flag, Seed, Exfil & Telemetri Palsu
  [green]pcapendpoint <file.pcap> -s <ID>[/green] Follow percakapan request-response dua arah pada stream tertentu
  [green]pcapfirst <file.pcap>[/green]           Macro triage dashboard: metadata, hierarki protokol, port & top talkers
  [green]pcaptree <file.pcap>[/green]            Visualisasi protocol hierarchy tree & IP conversation matrix
  [green]pcapfile <file.pcap> -o <dir>[/green]   Rekonstruksi & carve file yang ditransfer lewat traffic jaringan
  [green]pcapstream <file.pcap> -s <ID>[/green]  Wireshark-style follow stream dua arah (Client Cyan, Server Hijau)
  [green]pcapscan <file.pcap>[/green]            Threat & flag hunter (C2 patterns, high-entropy ciphertext)
  [green]pcapscanstream <file.pcap>[/green]      Deep stream scanner dengan automated XOR brute-force & entropy
  [green]pcappayload <file.pcap> --dns[/green]   Ekstraksi DNS tunneling subdomains & auto-decode
  [green]pcappayload <file.pcap> --icmp[/green]  Rekonstruksi data urutan ping ICMP exfiltration
  [green]pcapportpayload <file.pcap>[/green]     Covert channel decoder via manipulasi port / IP.ID / TTL

[bold bright_magenta]🧠 Memory Forensics (Windows, Linux, Android) (dmp/, lime/):[/bold bright_magenta]
  [green]dmpscan <memory.dmp>[/green]            Triage otomatis memori Windows: PEB, modul ter-load & flag hunter
  [green]dmpdump <memory.dmp> --main[/green]    Carve & dump main executable atau blok memori via base address
  [green]dmppeb <memory.dmp>[/green]             Ekstraksi PEB (Command line, environment variables, working dir)
  [green]dmpmodules <memory.dmp>[/green]         Daftar loaded executables & DLLs (setara lm / lmvm WinDbg)
  [green]dmpflags <memory.dmp>[/green]           Quick hunt flag pattern di memori virtual committed
  [green]limescan <memory.lime>[/green]          Scan kernel release banner, arsitektur & rekomendasi simbol
  [green]limebuild <memory.lime>[/green]         Download & compile otomatis matching symbol tables Volatility 3
  [green]limefast <memory.lime>[/green]          Triage instan memori Linux tanpa simbol (.json & tabel proses)

[bold bright_magenta]🛠️ Assembly & Reverse Engineering Suite (assembly/):[/bold bright_magenta]
  [green]ghidraanalyze current[/green]          Jembatan live interaktif ke Ghidra GUI Windows (decompile di cursor)
  [green]exefix <dumped.exe> -o <out>[/green]  Realign section header PE dump memori untuk decompilasi Ghidra bersih
  [green]exedoctor <file.exe>[/green]           Diagnosa PE header integrity, sections, dan checksum
  [green]ghidraguide <file.exe>[/green]         Blueprint analisis biner & checklist navigasi Ghidra
  [green]elfdoctor <binary.elf>[/green]         Diagnosa biner Linux ELF: header, 32/64-bit, stripped symbols, UPX
  [green]disasm <payload.bin> -a x64[/green]   Multi-arch raw shellcode disassembler dengan deteksi PEB / API

[bold bright_magenta]🔐 Cryptography & Obfuscation Analysis (cipher/):[/bold bright_magenta]
  [green]ciphercheck[/green]                    Interactive mode: identifikasi jenis cipher, encoding, dan entropy
  [green]ciphercheck -t "<string>"[/green]      Inspeksi cepat string ciphertext langsung di terminal
  [green]cryptohunt <file>[/green]              Auto-harvest Key 32B/16B, Nonce, dan konstanta kriptografi
  [green]python3 .../cipher/T_*.py[/green]      Template script siap pakai (AES, ChaCha20, RC4, RSA, XOR, Classical)

[bold bright_magenta]🖼️ Steganography & Artifact Triage (stego/):[/bold bright_magenta]
  [green]stegoscan <image.png>[/green]           Diagnosa chunk kustom PNG, fix height IHDR & carve trailing overlay
  [green]stegodiff <img1> <img2>[/green]         Auto-bruteforce shift 2D (dx, dy) & decode residual arithmetic delta
  [green]stegocrack <secret.jpg>[/green]        Automated Steghide & OutGuess cracker (blank & wordlist)
  [green]stegoaudio <sound.wav>[/green]         Visualisasi spektrogram FFT resolusi tinggi & WAV LSB extractor

[bold bright_magenta]📂 AccessData AD1 Forensics (ad1/):[/bold bright_magenta]
  [green]ad1history <file.ad1>[/green]          Ekstraksi database browser (Chrome, Edge, Firefox, Brave) + DPAPI bundle
  [green]ad1dpapi <file.ad1> -p <pwd>[/green]   Dekripsi offline password Chromium via DPAPI MasterKey
  [green]ad1amcache <file.ad1>[/green]          Analisis artefak eksekusi program Amcache.hve
  [green]ad1ntuser <file.ad1>[/green]           Analisis registry user: UserAssist ROT13, TypedPaths, RunMRU
  [green]ad1recent <file.ad1>[/green]           Analisis file shortcut LNK & Windows JumpLists
  [green]ad1extensions <file.ad1>[/green]       Triage ekstensi browser, orphan storage & LevelDB C2 strings
  [green]ad1scan <file.ad1>[/green]             Visual folder tree & penandaan file sensitif
  [green]ad1scandetail <file.ad1>[/green]       Pencarian dokumen pengguna, notes, dan foto tanpa noise

[bold cyan]Help Commands per Module:[/bold cyan]
  tools --help              Bantuan umum seluruh toolkit
  tools core --help         Bantuan modul universal & engine Rust (globalscan2, strings2, memcarve, binwalk2)
  tools pcap --help         Bantuan modul network & PCAP
  tools dmp --help          Bantuan modul memory dump & memcarve
  tools lime --help         Bantuan modul LiME Linux RAM
  tools assembly --help     Bantuan modul reverse engineering & Ghidra
  tools cipher --help       Bantuan modul kriptografi & template decrypter
  tools stego --help        Bantuan modul steganografi
  tools ad1 --help          Bantuan modul image forensik AD1
""")


def main():
    raw_args = sys.argv[1:]

    if not raw_args or raw_args[0] in ["-h", "--help", "help"]:
        print_global_help()
        return

    first_arg = raw_args[0].lower()

    if first_arg in ['limescan', 'limebuild', 'limefast', 'lime']:
        if first_arg == 'lime':
            if len(raw_args) < 2 or raw_args[1] in ['-h', '--help', 'help']:
                print_lime_help()
                return
            if raw_args[1] not in ['scan', 'build', 'fast']:
                console.print(f"[bold red]Unknown LiME command:[/bold red] {raw_args[1]}")
                print_lime_help()
                return
            action, remaining = raw_args[1], raw_args[2:]
        else:
            action, remaining = first_arg[4:], raw_args[1:]
        
        from lime.scanner import main as lime_scan
        from lime.builder import main as lime_build
        from lime.fast import main as lime_fast
        sys.exit({'scan': lime_scan, 'build': lime_build, 'fast': lime_fast}[action](remaining))

    # Handle shorthand aliases
    if first_arg in ["pcapfirst", "pcapfirst.py"]:
        from pcap.first_look import main as first_main
        first_main(raw_args[1:])
        return
    elif first_arg in ["pcaptree", "pcaptree.py"]:
        from pcap.tree import main as tree_main
        tree_main(raw_args[1:])
        return
    elif first_arg in ["pcapfile", "pcapfile.py"]:
        from pcap.file_carver import main as file_main
        file_main(raw_args[1:])
        return
    elif first_arg in ["pcapstream", "pcapstream.py", "pcapcat", "pcapfollow"]:
        from pcap.stream_follower import main as stream_main
        stream_main(raw_args[1:])
        return
    elif first_arg in ["pcapscan", "pcapscan.py"]:
        from pcap.scanner import main as scan_main
        scan_main(raw_args[1:])
        return
    elif first_arg in ["pcapscanstream", "pcapscanstream.py"]:
        from pcap.scan_stream import main as scan_stream_main
        scan_stream_main(raw_args[1:])
        return
    elif first_arg in ["pcappayload", "pcappayload.py", "pcappld"]:
        from pcap.payload_extractor import main as payload_main
        payload_main(raw_args[1:])
        return
    elif first_arg in ["pcapportpayload", "pcapportpayload.py", "pcapport", "portpayload"]:
        from pcap.port_payload import main as port_payload_main
        port_payload_main(raw_args[1:])
        return
    elif first_arg in ["pcapendpoint", "pcapendpoint.py", "pcapend", "pcapurl", "pcapurls"]:
        from pcap.endpoint import main as endpoint_main
        endpoint_main(raw_args[1:])
        return
    elif first_arg in ["strings2"]:
        import subprocess
        s2_bin = "/mnt/d/tools/bin/strings2"
        subprocess.run([s2_bin if os.path.exists(s2_bin) else "strings2"] + raw_args[1:])
        return
    elif first_arg in ["binwalk2"]:
        import subprocess
        bw2_bin = "/mnt/d/tools/bin/binwalk2"
        subprocess.run([bw2_bin if os.path.exists(bw2_bin) else "binwalk2"] + raw_args[1:])
        return
    elif first_arg in ["memcarve"]:
        import subprocess
        mc_bin = "/mnt/d/tools/bin/memcarve"
        subprocess.run([mc_bin if os.path.exists(mc_bin) else "memcarve"] + raw_args[1:])
        return
    elif first_arg in ["dmpscan", "dmpscan.py"]:
        from dmp.scanner import main as dmp_main
        dmp_main(raw_args[1:])
        return
    elif first_arg in ["dmppeb", "dmppeb.py"]:
        from dmp.scanner import main as dmp_main
        dmp_main(raw_args[1:] + ["--peb"])
        return
    elif first_arg in ["dmpmodules", "dmpmodules.py"]:
        from dmp.scanner import main as dmp_main
        dmp_main(raw_args[1:] + ["--modules"])
        return
    elif first_arg in ["dmpflags", "dmpflags.py"]:
        from dmp.scanner import main as dmp_main
        dmp_main(raw_args[1:] + ["--flags-only"])
        return
    elif first_arg in ["dmpdump", "dmpdump.py"]:
        from dmp.dumper import main as dumper_main
        dumper_main(raw_args[1:])
        return
    elif first_arg in ["volrust", "vol-rs", "vol_rs"]:
        import subprocess
        vol_bin = "/mnt/d/tools/bin/vol-rs"
        subprocess.run([vol_bin if os.path.exists(vol_bin) else "vol-rs"] + raw_args[1:])
        return
    elif first_arg in ["elfdoctor", "elfdoctor.py", "elffix", "elfinspect"]:
        from assembly.elf.inspector import main as elf_main
        elf_main(raw_args[1:])
        return
    elif first_arg in ["ghidraguide", "ghidraguide.py", "wuguide"]:
        from assembly.exe.ghidraguide import main as guide_main
        guide_main(raw_args[1:])
        return
    elif first_arg in ["disasm", "shellcode", "blobscan"]:
        from assembly.binary.disasm import main as disasm_main
        disasm_main(raw_args[1:])
        return
    elif first_arg in ["ad1history", "ad1history.py"]:
        from ad1.history import main as history_main
        history_main(raw_args[1:])
        return
    elif first_arg in ["ad1amcache", "ad1amcache.py"]:
        from ad1.amcache import main as amcache_main
        amcache_main(raw_args[1:])
        return
    elif first_arg in ["ad1ntuser", "ad1ntuser.py"]:
        from ad1.ntuser import main as ntuser_main
        ntuser_main(raw_args[1:])
        return
    elif first_arg in ["ad1recent", "ad1recent.py"]:
        from ad1.recent import main as recent_main
        recent_main(raw_args[1:])
        return
    elif first_arg in ["ad1extensions", "ad1extensions.py", "ad1extension", "ad1extension.py"]:
        from ad1.extensions import main as ext_main
        ext_main(raw_args[1:])
        return
    elif first_arg in ["ad1scan", "ad1scan.py"]:
        from ad1.scan import main as scan_main
        scan_main(raw_args[1:])
        return
    elif first_arg in ["ad1scandetail", "ad1scandetail.py", "ad1detail", "ad1detail.py"]:
        from ad1.scandetail import main as scandetail_main
        scandetail_main(raw_args[1:])
        return
    elif first_arg in ["ad1dpapi", "ad1dpapi.py", "ad1decrypt", "ad1decrypt.py"]:
        from ad1.dpapi_decrypt import main as dpapi_main
        dpapi_main(raw_args[1:])
        return
    elif first_arg in ["globalscan", "globalscan.py", "gscan"]:
        from core.globalscan import main as globalscan_main
        filtered_args = []
        for a in raw_args[1:]:
            if a == "-file": filtered_args.append("-f")
            else: filtered_args.append(a)
        globalscan_main(filtered_args)
        return
    elif first_arg in ["globalscan2", "gscan2"]:
        import subprocess
        gs2_bin = "/mnt/d/tools/bin/globalscan2"
        if os.path.exists(gs2_bin):
            subprocess.run([gs2_bin] + raw_args[1:])
        else:
            subprocess.run(["globalscan2"] + raw_args[1:])
        return
    elif first_arg in ["exefix", "exefix.py", "exedoctor", "exefixed", "exe"]:
        handle_exe_command(raw_args[1:])
        return
    elif first_arg in ["stegoscan", "stegoscan.py", "stegscan"]:
        from stego.scanner import main as stego_scan_main
        stego_scan_main(raw_args[1:])
        return
    elif first_arg in ["stegodiff", "stegodiff.py", "stegdiff"]:
        from stego.differ import main as stego_diff_main
        stego_diff_main(raw_args[1:])
        return
    elif first_arg in ["stegocrack", "stegocrack.py", "stegcrack"]:
        from stego.cracker import main as stego_crack_main
        stego_crack_main(raw_args[1:])
        return
    elif first_arg in ["stegoaudio", "stegoaudio.py", "stegaudio"]:
        from stego.audio import main as stego_audio_main
        stego_audio_main(raw_args[1:])
        return
    elif first_arg in ["cryptohunt", "cryptohunt.py", "keyhunt", "keyhunt.py", "keyfind", "cryptoparse"]:
        from cipher.cryptohunt import main as hunt_main
        hunt_main(raw_args[1:])
        return
    elif first_arg in ["ciphercheck", "ciphercheck.py", "cipher", "crypto"]:
        handle_cipher_command(raw_args[1:])
        return
    elif first_arg in ["ad1cli", "ad1cli.py"]:
        handle_ad1_command(raw_args[1:])
        return
    elif first_arg in ["ghidraanalyze", "ghidraanalyze.py", "ghidra", "ghidracli", "ghidrabridge"]:
        from assembly.ghidra.analyzer import main as ghidra_main
        ghidra_main(raw_args[1:])
        return

    # Handle module routing
    if first_arg == "ad1":
        handle_ad1_command(raw_args[1:])
    elif first_arg == "pcap":
        handle_pcap_command(raw_args[1:])
    elif first_arg == "dmp":
        handle_dmp_command(raw_args[1:])
    elif first_arg in ["exe", "pe"]:
        handle_exe_command(raw_args[1:])
    elif first_arg in ["assembly", "asm"]:
        handle_assembly_command(raw_args[1:])
    elif first_arg in ["stego", "steg"]:
        handle_stego_command(raw_args[1:])
    elif first_arg in ["cipher", "crypto"]:
        handle_cipher_command(raw_args[1:])
    elif first_arg in ["core", "rust"]:
        handle_core_command(raw_args[1:])
    elif first_arg == "globalscan":
        from core.globalscan import main as globalscan_main
        globalscan_main(raw_args[1:])
    elif first_arg == "img":
        print_banner("FORENSIC MODULE: " + first_arg.upper())
        console.print(f"[bold yellow][i] Module '{first_arg}' is registered on roadmap and ready for artifact engine integration.[/bold yellow]")
    else:
        # Check direct file extensions
        if first_arg.endswith(".ad1"):
            from ad1.history import main as history_main
            history_main(raw_args)
        elif first_arg.endswith((".pcap", ".pcapng", ".cap")):
            from pcap.scanner import main as scan_main
            scan_main(raw_args)
        elif first_arg.endswith((".dmp", ".raw")):
            from dmp.scanner import main as dmp_main
            dmp_main(raw_args)
        elif os.path.exists(raw_args[0]):
            from core.globalscan import main as globalscan_main
            globalscan_main(raw_args)
        else:
            console.print(f"[bold red]Unknown module or command:[/bold red] {raw_args[0]}")
            print_global_help()


if __name__ == "__main__":
    main()
