# PE Export Hash Resolver — PoC

Resolves Windows API function addresses by **hashing export names** instead of calling `GetProcAddress` directly.  
**This technique is well-known** and already widely used in malware and offensive tooling, this is **just my own implementation of it**, built from scratch to learn how PE export tables work.

---

## How it works

1. Load the target DLL (or grab it if already mapped)
2. Walk the PE export table (`IMAGE_EXPORT_DIRECTORY`)
3. Hash each exported function name
4. Compare against the pre-computed target hash
5. Return the resolved address

No string comparison, no plaintext API name left in the binary.

---

## Files

```
.
├── PocGetFCTAdressByHash.c      # PoC — resolves VirtualAlloc from kernel32.dll and cross-checks with GetProcAddress
└── README.md
```

---

## Usage

### 1. Implement your hash function

Replace the stub in `main.c` with your own:

```c
unsigned long my_hash(const char* string, int seed)
{
    // your implementation here
    return 0;
}
```

### 2. Pre-compute the target hash

```c
unsigned long hash = my_hash("VirtualAlloc", YOUR_SEED);
```

### 3. Resolve the function

```c
PVOID addr = GetFCTAdressByHash("kernel32.dll", hash);
```

---

## Build

```bash
# MinGW
gcc main.c -o poc.exe -lkernel32

# MSVC
cl main.c /link kernel32.lib
```

Requires Windows. The export table walk is pure PE parsing — `GetModuleHandleA` / `LoadLibraryA` are only used for the PoC wrapper.

---

## Example output

```
[dbg] hash of 'VirtualAlloc' : 0x????????????????
[dbg] lib: 'kernel32.dll', target hash: '0x????????????????'
[ok] kernel32.dll already loaded
[ok] function found : VirtualAlloc                    ordinal:  XX  address: 0x????????????????
[ok] address (hash)   : 0x????????????????
[ok] address (WinAPI) : 0x????????????????
[ok] match -- addresses are identical
```

---

## Notes

- The export table walk is **read-only**.
- Forwarded exports (e.g. `ntdll -> kernel32`) are not handled in this PoC. 
- Ordinal-only exports (no name) are skipped — nothing to hash.(i use the NumberOfNames() fonction to iterate into the PE)
- Keep your seed private if you are using this for obfuscation.

---

## Disclaimer

This is a proof of concept for educational and research purposes only.  
Use responsibly and in accordance with applicable laws.
