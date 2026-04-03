# PEB Module Walker — PoC

Retrieves a loaded DLL's base address by walking the **Process Environment Block** (PEB) directly, without calling `GetModuleHandleA`. **This technique is well-known** and already widely used in malware and offensive tooling, this is **just my own implementation of it**, built from scratch to learn how PE export tables work.

This is the first step of my WinAPI-free resolution chain:

```
PEB walk → DllBase
         → export table walk → hash match → function address → man finds happiness
```

---

## How it works

Every Windows process has a PEB at `gs:[0x60]` (x64). The PEB holds a `PEB_LDR_DATA` structure which contains three doubly-linked lists of all modules loaded in the current process. We walk `InMemoryOrderModuleList` and compare each entry's `BaseDllName` against the target.

No `GetModuleHandleA`, no `LoadLibraryA`, no imported WinAPI involved.

---

## Files

```
.
├── peb_walk_x64.c      # PoC - lists all loaded modules, resolves kernel32.dll, cross-checks with GetModuleHandleA
└── README.md
```
---

## Example output

```
=== loaded modules ===
[dbg] peb_walk.c:64:list_modules() walking InMemoryOrderModuleList
  base: 0000000000000000  |  C:\path\to\your.exe
  base: 0000000000000000  |  C:\Windows\SYSTEM32\ntdll.dll
  base: 0000000000000000  |  C:\Windows\System32\KERNEL32.DLL
  base: 0000000000000000  |  C:\Windows\System32\KERNELBASE.dll
  ...

[dbg] peb_walk.c:xx:main() searching for 'kernel32.dll' via PEB walk
[ok] base address (PEB walk)         : 0000000000000000
[ok] base address (GetModuleHandleA) : 0000000000000000
[ok] match -- addresses are identical
```

---

## Notes

- Lists only modules loaded in the **current process** - not system-wide.
- The search is case-insensitive (`_wcsicmp`) to handle casing differences like `KERNEL32.DLL` vs `kernel32.dll`.
- `winternl.h` only partially exposes `LDR_DATA_TABLE_ENTRY` - the struct is redefined in full to access `DllBase`, `FullDllName`, and `BaseDllName`.

---

## Disclaimer

This is a proof of concept for educational and research purposes only.  
Use responsibly and in accordance with applicable laws.
