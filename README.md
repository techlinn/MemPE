<p align="center">
  <img src="assets/banner.png" alt="MemPE banner" width="550">
</p>

# mempe

mempe dumps Windows executables and DLLs from a running process, then rebuilds each image into a file that regular PE tools can parse. It also checks non-image memory for manually mapped and embedded PEs.

Use it for reverse engineering and unpacking. mempe is a dumper, not a malware scanner, and its output is meant for analysis rather than execution.

## What it does

- Dumps PE32 and PE32+ images from x86 and x64 processes
- Accepts a PID or waits for a new process with a given name
- Checks distributed executable and writable-image page samples for stability before a watched dump
- Finds loader-mapped modules and page-aligned PEs in executable non-image memory
- Carves embedded PEs out of captured images and out of readable non-image memory, including executable memory such as a shellcode loader's buffer, and including drivers and .NET assemblies loaded from a byte array
- Converts in-memory sections back to a normal file layout
- Adds observed section access flags and recovers nonzero runtime data beyond damaged section bounds
- Recovers imports from the existing descriptor table, from delay-load directory 13, from trusted IAT ranges, and from direct x86/x64 call sites
- Counts delay-load slots the program has declared but not called yet, so an unresolved slot is reported rather than quietly missing
- Handles named exports, ordinal exports, forwarded exports, and common API-set forwarders
- Merges damaged headers with validated structural evidence from the original file, but only when the memory is still backed by that file
- Recalculates derived optional-header sizes and the PE checksum from the final rebuilt bytes
- Accepts a validated manual entry-point RVA for unpacked main images
- Clears directories that no longer point to valid data and removes broken x64 unwind entries
- Reports what it observed about the entry point and about sections it may not have captured in a decrypted state
- Zero-fills unreadable pages and reports them in the final summary
- Orders warnings so the ones that mean the dump may be wrong come before the cosmetic ones
- Reports how much memory the PE scans had to leave unread, so an empty carve result is distinguishable from an incomplete one

## Usage

Dump a running process by PID:

```text
mempe.exe -p 4216
```

Hexadecimal PIDs work too:

```text
mempe.exe -p 0x1078
```

Wait for a new process with a specific file name:

```text
mempe.exe -w target.exe
```

Watch mode ignores matching processes that are already running. Once a new one appears, mempe waits briefly for its executable mappings to settle before dumping it.

Set a known entry-point RVA for the main image:

```text
mempe.exe -p 4216 --entry-point 0x31A20
```

The value is an RVA, not a virtual address. mempe rejects it unless it lies inside a captured executable section.

Also write the raw bytes of executable memory that held no complete PE:

```text
mempe.exe -p 4216 --raw-regions
```

This is off by default because it can add a lot of files. Use it when you are looking for headerless payloads or shellcode that the PE carver will not pick up. Each committed range of such an allocation is written twice: the untouched bytes as `.raw`, and a `.txt` next to it recording the load address, allocation base, committed size, page protection and whether the region was executable, so you can point a disassembler at the right address. No header is invented for those bytes.

Write only the images you care about:

```text
mempe.exe -p 4216 --only explorer.exe
mempe.exe -p 4216 --only 0x00007FF611EA0000
```

Every image is still captured and indexed, so imports resolve exactly as they would in a full dump; only the files written are filtered. Dumping explorer writes 389 files by default and one with `--only`.

Show the built-in help:

```text
mempe.exe -h
```

## How a dump is rebuilt

Reading the code in execution order is the fastest way to understand it. There are four stages.

**1. Capture** (`src/memory.rs`)

Working-set page state is measured first, in `measure_image_pages`, before anything else touches the process. This ordering matters: taking a PSS snapshot marks every page copy-on-write, which destroys the private-page signal mempe uses later to tell decrypted memory from memory that was never written.

`AddressSpace::acquire` then takes a `PSS_CAPTURE_VA_CLONE` snapshot, falling back to a plain live read if that fails. `list_regions` walks the address space, `group_images` collects regions into images by allocation base, and `read_image` copies each image's committed regions into a buffer, zero-filling anything unreadable and recording what protections each region actually had. `find_hidden_images` looks for page-aligned PE headers inside executable non-image allocations, and `read_allocations` picks up the committed, readable ranges of non-image memory so the carver can search them later.

**2. Rebuild** (`src/pe/rebuild/`, one image at a time)

`resolve_source_bytes` decides which bytes to work from. It parses the captured headers; if `e_lfanew` is unusable, `parse_memory_image` brute-force scans for an NT signature before giving up. Only if that fails does mempe read the original file from disk and splice its headers on, and only when the memory at that base is still image-backed and the mapped file still matches the name the loader reported. Either way, `recover_section_headers` then repairs the section table from the region evidence gathered during capture. That last step does most of the work for packed images, whose section headers often claim a raw size of zero.

`build_output_buffer` lays out the file, `write_core_header_fields` fixes the fields that describe the new layout, and `write_sections` copies each section from its memory offset to its file offset, renaming any section whose name is unreadable.

`apply_repairs` then clears data directories that no longer point into the rebuilt file, drops x64 unwind entries that fail validation, repoints debug entries at the new layout, and clears the dynamic-base flag on images that have no relocations.

`resolve_imports` builds an import plan. It prefers the existing descriptor table; failing that it looks for an intact descriptor array the packer left behind, then for trusted IAT ranges. It always additionally walks delay-load directory 13 and any `call`/`jmp`/`mov` instruction that references a data slot. Anything recovered is written into an appended `.mempe` section.

`finalize_output` applies the entry point, recomputes derived header sizes and the checksum, and reparses the finished bytes with an independent PE parser as a self-check. If that reparse fails, the image is reported as a failure rather than written.

**3. Carve** (`src/pe/carve.rs`)

Every captured image, every executable non-image allocation that held no page-aligned PE, and every other readable non-image allocation is scanned for embedded PEs. A candidate has to survive a full disk-image parse before it is written, and its length comes from its own section table and certificate directory, so signed payloads come out byte-exact.

**4. Write** (`src/output.rs`, `src/dump.rs`)

`dump.rs` turns rebuilt images, carved payloads, and raw regions into output files and accumulates the summary counters. `output.rs` writes them and handles name collisions.

## Output

Dumped files are written to a `mempe` folder in the current directory. The main image keeps the target's file name. DLLs use their module or embedded export name when one is available; unnamed images fall back to their base address. A payload carved out of an image is named after that image, one carved out of loose memory after the address it was found at, and raw regions after their base address and size.

If `mempe` already contains files, mempe asks whether to overwrite matching names, rename new files, or cancel. When standard input is redirected, name conflicts are renamed automatically.

The console summary shows what was rebuilt and calls out anything that may affect the dump, including unreadable pages, repaired headers, skipped import pointers, invalid directories, and modules that could not be rebuilt.

Two lines describe what mempe observed rather than what it changed. The entry line says whether the entry point falls inside surviving unwind data, which ordinary compiler output almost always has and hand-written stubs usually do not. The layout line counts sections that were seen writable and executable at the same time. Neither is a verdict; both are observations that happen to differ between normal binaries and transformed ones.

mempe also warns when an executable section is high-entropy but shows no sign of having been written since the image was mapped. That combination usually means the section was still encrypted when the snapshot was taken, so the copy in the dump is not real code. The warning is about mempe's own output, not about the target.

A separate warning covers the more extreme case: an executable section that is entirely zero in the dump. That means the section was never populated at capture time, so the file contains nothing real for it. Dumping a packed target too early is the usual cause, and re-running after the program has settled normally fixes it.

## Building

mempe requires Windows 10 or later. Build it with the stable Rust toolchain:

```text
cargo build --release
```

The executable will be written to:

```text
target\release\mempe.exe
```

Run the tests and lints with:

```text
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Permissions

mempe needs permission to open and read the target process. An elevated target may require an elevated terminal. Windows protected processes can still deny access.

## Limitations

- Import recovery depends on the IAT and on the exports available in the captured process. Packed files, custom loaders, API hashing, and unusual thunk layouts may leave imports unresolved.
- A delay-load slot that has never been called still points at its own stub, so its target cannot be recovered. mempe counts those slots and reports them separately rather than dropping them silently.
- Hidden images are found by looking for page-aligned PE headers. A complete PE stored at any other offset is still carved, but headerless payloads and raw shellcode are only written with `--raw-regions`, and then as plain bytes with no reconstructed header, alongside a sidecar recording where they were mapped.
- Import recovery through a `mov r64,[rip+disp32]` requires a neighbouring pointer slot resolving into the same module, because a lone cached pointer to an API is not a link-time dependency. Pointers reached through `call` or `jmp` are accepted without that check. Runtime dispatch tables, such as the `gdi32.dll` thunks into `gdi32full.dll`, are still recorded as imports: they are real pointers to real exports, and separating them from genuine imports would need a hardcoded list of Windows shim relationships.
- If module enumeration is denied, mempe still dumps. Image names then come from mapped files rather than the loader, the main image is identified by its mapped path, and the degraded mode is reported.
- Capture stops at 4096 images or 4 GiB of image data. Hitting either truncates the dump and reports the number of images skipped instead of failing; the main image is always captured.
- Unreadable memory is replaced with zeroes. The warning count tells you how much data was lost.
- The entropy warning fires on any section that is resident and was never written after loading, whatever its type. A section that was never faulted in at all is reported by the separate all-zero warning, and a `.pdata` section holding something other than a runtime-function table is reported by a third.
- The embedded-PE scan stops after 256 MiB of committed non-image memory, and the hidden-image scan after 1 GiB. Anything past either limit is left unread and the amount is reported, so an empty carve result can be told apart from a truncated one.
- The "written after load" signal behind the entropy warning is only reliable on the first dump of a process. Taking a snapshot appears to disturb it, so a second dump of the same PID can report more never-written sections than the first.
- If the main image has been unmapped from the target, mempe dumps every other module and reports the missing main image rather than failing outright. The result is a partial dump and exit code 3.
- A structurally valid PE is useful for static analysis, but it may still need manual work before it can run.
- Only x86 and x64 Windows PE images are supported.

<div align="center">
<h2>Exit Codes</h2>
  <table>
    <thead>
      <tr>
        <th>Code</th>
        <th>Meaning</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>0</code></td>
        <td align="left">The main image and all known DLLs were rebuilt</td>
      </tr>
      <tr>
        <td><code>1</code></td>
        <td align="left">Invalid arguments, cancelled output, or output setup failed</td>
      </tr>
      <tr>
        <td><code>2</code></td>
        <td align="left">The target could not be queried, captured, or written</td>
      </tr>
      <tr>
        <td><code>3</code></td>
        <td align="left">Some output was written, but the main image or one or more DLLs failed</td>
      </tr>
    </tbody>
  </table>
</div>

<div align="center">
  <h2>License</h2>
  <p>MIT</p>
</div>
