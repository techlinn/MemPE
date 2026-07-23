<p align="center">
  <img src="assets/banner.png" alt="MemPE banner" width="550">
</p>

# mempe

mempe dumps Windows executables and DLLs from a running process, then rebuilds each image into a file that regular PE tools can parse. It also checks executable non-image memory for manually mapped PEs.

Use it for reverse engineering and unpacking. mempe is a dumper, not a malware scanner, and its output is meant for analysis rather than execution.

## What it does

- Dumps PE32 and PE32+ images from x86 and x64 processes
- Accepts a PID or waits for a new process with a given name
- Checks distributed executable and writable-image page samples for stability before a watched dump
- Finds loader-mapped modules and page-aligned PEs in executable non-image memory
- Converts in-memory sections back to a normal file layout
- Adds observed section access flags and recovers nonzero runtime data beyond damaged section bounds
- Recovers imports by matching IAT entries and direct x86/x64 IAT call sites against exports from captured modules
- Handles named exports, ordinal exports, forwarded exports, and common API-set forwarders
- Merges damaged headers with validated structural evidence from the original file when available
- Recalculates derived optional-header sizes from the final rebuilt section table
- Accepts a validated manual entry-point RVA for unpacked main images
- Clears directories that no longer point to valid data and removes broken x64 unwind entries
- Zero-fills unreadable pages and reports them in the final summary

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

Show the built-in help:

```text
mempe.exe -h
```

## Output

Dumped files are written to a `mempe` folder in the current directory. The main image keeps the target's file name. DLLs use their module or embedded export name when one is available; unnamed images fall back to their base address.

If `mempe` already contains files, mempe asks whether to overwrite matching names, rename new files, or cancel. When standard input is redirected, name conflicts are renamed automatically.

The console summary shows what was rebuilt and calls out anything that may affect the dump, including unreadable pages, repaired headers, skipped import pointers, invalid directories, and modules that could not be rebuilt.

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

- Import recovery is based on the IAT and the exports available in the captured process. Packed files, custom loaders, API hashing, and unusual thunk layouts may leave imports unresolved.
- Hidden images are found by looking for page-aligned PE headers inside executable non-image allocations. Headerless payloads and raw shellcode are not dumped.
- Unreadable memory is replaced with zeroes. The warning count tells you how much data was lost.
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
