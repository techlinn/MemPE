<p align="center">
  <img src="assets/banner.png" alt="MemPE banner" width="550">
</p>

<p align="center">
  <b>Pull every EXE and DLL out of a running Windows process and get back PE files your tools can actually open.</b>
</p>

<p align="center">
  <a href="https://github.com/techlinn/MemPE/actions/workflows/ci.yml"><img src="https://github.com/techlinn/MemPE/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/techlinn/MemPE/releases/latest"><img src="https://img.shields.io/github/v/release/techlinn/MemPE" alt="Latest release"></a>
  <a href="https://github.com/techlinn/MemPE/releases"><img src="https://img.shields.io/github/downloads/techlinn/MemPE/total" alt="Downloads"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20x86%20%7C%20x64-blue" alt="Windows x86 and x64">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/techlinn/MemPE" alt="MIT license"></a>
</p>

<p align="center">
  <a href="https://github.com/techlinn/MemPE/releases/latest">Download</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#supported-packers">Packers</a> ·
  <a href="#limitations">Limitations</a>
</p>

---

Packers can hide a program on disk all they want. The moment it runs, the real thing has to be sitting in memory, and that's where mempe grabs it.

It takes every module in the process, lays each one back out the way a file on disk expects, rebuilds the imports, and writes PE files that IDA, Ghidra or your favorite debugger will open without complaining. If it knows the packer, it goes a step further and hands you the original program back.

Here it is on a UPX-packed crackme that's sitting at its password prompt:

```text
> mempe.exe -p 28884

TARGET
  Name       upx_packed_binary.exe
  Arch       x64

OUTPUT
  Main       .\mempe\upx_packed_binary.exe
  Entry      0x00002700 (.text, unwind-covered)
  Packer     UPX 5.30, restored headers, entry point, imports, relocations, resources, debug directory (CodeView entry)
  Lost       debug entries the packer erased
  DLLs       29

DONE  Analysis-ready memory images
```

`UPX0` and `UPX1` are gone. What comes out is the program as it was compiled, with its real entry point and import table. The `Lost` line is mempe being upfront: UPX deleted those debug entries when it packed the file, so nobody can bring them back.

## What you get

- Every EXE and DLL in an x86 or x64 process, rebuilt from its in-memory layout into a normal PE file
- Imports put back together, even when the packer trashed the import table
- PEs that were mapped by hand or stashed in random memory, the kind the module list never shows you
- Packers undone when mempe knows them (see [the table](#supported-packers))
- A report that tells you what it couldn't recover, so a broken dump never passes itself off as a good one

## How it works

```mermaid
flowchart TB
    process(["Running process"]) --> capture["Snapshot memory and<br/>find every PE in it"]
    capture --> known{"Known packer?"}
    known -- yes --> module["Packer module puts<br/>the original back"]
    known -- no --> repair["Headers repaired<br/>from memory evidence"]
    module --> rebuild["Rebuild layout, imports<br/>and directories"]
    repair --> rebuild
    rebuild --> output(["PE files + report"])

    classDef endpoint fill:#2f81f71a,stroke:#2f81f7,stroke-width:2px
    classDef step fill:#8b949e1a,stroke:#8b949e,stroke-width:1px
    classDef decision fill:#d299221a,stroke:#d29922,stroke-width:2px
    classDef packer fill:#3fb9501a,stroke:#3fb950,stroke-width:2px
    class process,output endpoint
    class capture,repair,rebuild step
    class known decision
    class module packer
    linkStyle default stroke:#8b949e,stroke-width:2px
```

mempe snapshots the process, finds every module plus any PE hiding in non-image memory, and checks each one against its packer modules. A packer it knows gets undone properly. Anything else is repaired from what the memory shows. Either way, the image is rebuilt into file layout, its imports are recovered, and you get a PE file plus a report.

## Supported packers

| Packer | Status | Notes |
|---|---|---|
| UPX | Supported | 3.91 to 5.3.0, x86 and x64, EXEs and DLLs, tampered and modified copies too |
| VMProtect | Planned | Protector with code virtualization |
| Themida / WinLicense | Planned | Protector with code virtualization |
| Code Virtualizer | Planned | Virtualizer from the makers of Themida |
| Enigma Protector | Planned | Protector |
| Obsidium | Planned | Protector |
| ASProtect | Planned | Protector |
| Armadillo | Planned | Protector, including its debug-blocker child process |
| PELock | Planned | Protector |
| Safengine Shielden | Planned | Protector with code virtualization |
| EXECryptor | Planned | Protector with code morphing |
| MPRESS | Planned | Compressor |
| ASPack | Planned | Compressor |
| PECompact | Planned | Compressor |
| Petite | Planned | Compressor |
| FSG | Planned | Compressor |
| MEW | Planned | Compressor |
| nPack / NsPack | Planned | Compressors |
| kkrunchy | Planned | Compressor from the demoscene |
| WinUpack | Planned | Compressor |
| MoleBox | Planned | Virtual file system packer |
| Anything else | Generic dump | Still dumped and rebuilt with imports recovered, just without packer-specific cleanup |

Anything missing? [Open an issue](https://github.com/techlinn/MemPE/issues) and I'll add it.

Each packer lives in its own file under [`src/pe/packers/`](src/pe/packers), so adding one doesn't touch the rest of the tool.

## Usage

Grab `mempe-windows-x86_64.zip` from the [latest release](https://github.com/techlinn/MemPE/releases/latest). It's one exe with nothing to install, and it dumps 32-bit and 64-bit processes alike.

Dump a running process by PID (hex works too, like `0x1078`):

```text
mempe.exe -p 4216
```

Or have mempe wait for a program to launch and grab it once it has settled:

```text
mempe.exe -w target.exe
```

| Option | What it does |
|---|---|
| `-e`, `--entry-point <rva>` | You already found the OEP? Tell mempe and it uses that |
| `--only <name or base>` | Only write the images you care about. Everything is still captured, so imports resolve the same |
| `--raw-regions` | Also save executable memory with no PE in it, like shellcode |
| `-h`, `--help` | Shows the help |

Everything lands in a `mempe` folder in the current directory.

To build it yourself, you need Windows 10 or later and stable Rust:

```text
cargo build --release
```

> [!CAUTION]
> mempe dumps a process that's already running, so whatever you're dumping has to run first. If it's malware, do this in a VM.

## Limitations

- Let the program unpack itself before you dump it. Go too early and you'll get the packed bytes back, though mempe will warn you when a section looks like it was never decrypted.
- Only x86 and x64 Windows PE files are supported.
- mempe needs permission to read the target. Elevated targets need an elevated terminal, and protected processes can still say no.
- Heavy API hashing or custom loaders can leave some imports unresolved. mempe counts those instead of dropping them quietly.
- Dumps are for static analysis. Getting one to run again can take some manual work.

## When to reach for something else

mempe is about getting clean files out of a process. If you want to sweep processes for injected or modified code, [pe-sieve](https://github.com/hasherezade/pe-sieve) and [hollows_hunter](https://github.com/hasherezade/hollows_hunter) are built for exactly that. If you're already stepping through a target in [x64dbg](https://github.com/x64dbg/x64dbg), its built-in [Scylla](https://github.com/NtQuery/Scylla) is the quickest way to fix imports by hand at the point you stopped.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The main image and all known DLLs were rebuilt |
| `1` | Invalid arguments, cancelled output, or output setup failed |
| `2` | The target could not be queried, captured, or written |
| `3` | Some output was written, but the main image or one or more DLLs failed |

## Issues and contributing

Hit a bug, a dump that came out wrong, or a packer mempe should know about? [Open an issue](https://github.com/techlinn/MemPE/issues) and I'll take a look. If you're reporting a bad dump, the console output helps a lot, and so does the packer or protector the target was built with.

Pull requests are welcome too. A new packer is a good place to start, since each one lives in its own file under [`src/pe/packers/`](src/pe/packers).

MIT licensed. See [LICENSE](LICENSE).
