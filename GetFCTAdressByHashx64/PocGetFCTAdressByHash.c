#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#define ok(msg, ...)   printf("\033[32m[ok]\033[0m "    msg "\n" __VA_OPT__(,) __VA_ARGS__)
#define info(msg, ...) printf("\033[33m[info]\033[0m "  msg "\n" __VA_OPT__(,) __VA_ARGS__)
#define err(msg, ...)  printf("\033[31m[error]\033[0m " msg "\n" __VA_OPT__(,) __VA_ARGS__)
#define dbg(msg, ...)  printf("\033[90m[dbg] %s:%d:%s()\033[0m " msg "\n", __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__)


/*
 * TODO: Replace with your own hash function.
 *
 * Requirements:
 *   - Deterministic for a given (string, seed) pair
 *   - Low collision rate across typical Win32 export names
 *   - Returns an unsigned long
 *
 * The seed lets you vary the hash space between projects / builds.
 */

unsigned long my_hash(const char* string, int seed)
{
    // your implementation here
    (void)string;
    (void)seed;
    return 0;
}


unsigned long* GetFCTAdressByHash(char* lib, unsigned long target_hash)
{
    dbg("lib: '%s', target hash: '0x%016lx'", lib, target_hash);

    /*--------------------[Load the DLL]--------------------*/
    void* module = GetModuleHandleA(lib);

    if (module) {
        ok("%s already loaded", lib);} 
    else {
        module = LoadLibraryA(lib);
        if (!module) {
            err("failed to load %s", lib);
            return NULL;
        }
        ok("%s loaded", lib);}
    dbg("module base: %p", module);

    /*--------------------[Validate DOS header]--------------------*/
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        err("invalid e_magic (0x%04hx), not a valid PE", dos_header->e_magic);
        return NULL;}
    dbg("e_magic OK (0x%04hx), e_lfanew = 0x%08x", dos_header->e_magic, dos_header->e_lfanew);

    /*--------------------[Walk the export table]--------------------*/
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(
        (BYTE*)module + dos_header->e_lfanew);

    IMAGE_DATA_DIRECTORY export_entry =
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    IMAGE_EXPORT_DIRECTORY* export_table = (IMAGE_EXPORT_DIRECTORY*)(
        (BYTE*)module + export_entry.VirtualAddress);

    PDWORD name_rvas    = (PDWORD)((BYTE*)module + export_table->AddressOfNames);
    PDWORD func_rvas    = (PDWORD)((BYTE*)module + export_table->AddressOfFunctions);
    WORD*  ordinals     = (WORD*) ((BYTE*)module + export_table->AddressOfNameOrdinals);

    dbg("%lu exported functions to scan", export_table->NumberOfNames);

    /*--------------------[Compare hashes]--------------------*/
    for (DWORD i = 0; i < export_table->NumberOfNames; i++) {

        char*         name    = (char*)((BYTE*)module + name_rvas[i]);
        WORD          ordinal = ordinals[i];
        void*         addr    = (PVOID)((BYTE*)module + func_rvas[ordinal]);
        unsigned long hash    = my_hash(name, YOUR_SEED);

        if (hash == target_hash) {
            ok("function found : %-40s ordinal: %4u  address: %p", name, ordinal, addr);
            return addr;
        }
    }

    err("no function matched the hash in %s", lib);
    return NULL;
}


int main(void)
{
    // PoC: resolve VirtualAlloc from kernel32.dll
    const char* target_name = "VirtualAlloc";
    const char* dll         = "kernel32.dll";

    // Pre-compute this hash offline or at startup — never pass the raw string at runtime
    unsigned long hash = my_hash(target_name, YOUR_SEED);
    dbg("hash of '%s' : 0x%016lx", target_name, hash);

    PVOID addr_hash = GetFCTAdressByHash((char*)dll, hash);

    if (!addr_hash) {
        err("function not found");
        getchar();
        return EXIT_FAILURE;
    }

    ok("address (hash)   : %p", addr_hash);

    /*--------------------[Cross-check with GetProcAddress]--------------------*/
    PVOID addr_winapi = (PVOID)GetProcAddress(GetModuleHandleA(dll), target_name);

    if (!addr_winapi) {
        err("GetProcAddress failed");
        getchar();
        return EXIT_FAILURE;
    }

    ok("address (WinAPI) : %p", addr_winapi);

    if (addr_hash == addr_winapi) {
        ok("match -- addresses are identical");
    } else {
        err("mismatch -- hash: %p  /  WinAPI: %p", addr_hash, addr_winapi);
    }

    getchar();
    return EXIT_SUCCESS;
}
