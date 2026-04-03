#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <wchar.h>

#define ok(msg, ...)   printf("\033[32m[ok]\033[0m "    msg "\n" __VA_OPT__(,) __VA_ARGS__)
#define err(msg, ...)  printf("\033[31m[error]\033[0m " msg "\n" __VA_OPT__(,) __VA_ARGS__)
#define dbg(msg, ...)  printf("\033[90m[dbg] %s:%d:%s()\033[0m " msg "\n", __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__)

/*
 * Windows only partially exposes LDR_DATA_TABLE_ENTRY in winternl.h.
 * We redefine it fully to access DllBase, FullDllName, and BaseDllName.
 */
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

/*
 * Walk the PEB InMemoryOrderModuleList and return the base address
 * of the module whose BaseDllName matches `target` (case-insensitive).
 * Returns NULL if not found.
 *
 * This reimplements what GetModuleHandleA does internally,
 * without calling any WinAPI.
 */
PVOID get_module_base(const wchar_t* target)
{
    PEB*          peb   = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr   = peb->Ldr;
    LIST_ENTRY*   head  = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY*   entry = head->Flink;

    while (entry != head) {
        MY_LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(
            entry,
            MY_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        if (mod->BaseDllName.Buffer &&
            _wcsicmp(mod->BaseDllName.Buffer, target) == 0)
        {
            return mod->DllBase;
        }

        entry = entry->Flink;
    }

    return NULL;
}

// Print every module loaded in the current process (base address + full path) 
void list_modules(void)
{
    PEB*          peb   = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr   = peb->Ldr;
    LIST_ENTRY*   head  = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY*   entry = head->Flink;

    dbg("walking InMemoryOrderModuleList");

    while (entry != head) {
        MY_LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(
            entry,
            MY_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        printf("  base: %p  |  %S\n",
            mod->DllBase,
            mod->FullDllName.Buffer
        );

        entry = entry->Flink;
    }
}

int main(void)
{
    const wchar_t* target = L"kernel32.dll";

    printf("=== loaded modules ===\n");
    list_modules();
    printf("\n");

    /*--------------------[PEB walk]--------------------*/
    dbg("searching for '%S' via PEB walk", target);
    PVOID addr_peb = get_module_base(target);

    if (!addr_peb) {
        err("'%S' not found in PEB module list", target);
        getchar();
        return 1;
    }
    ok("base address (PEB walk)         : %p", addr_peb);

    /*--------------------[Cross-check with GetModuleHandleA]--------------------*/
    PVOID addr_winapi = (PVOID)GetModuleHandleA("kernel32.dll");

    if (!addr_winapi) {
        err("GetModuleHandleA failed");
        getchar();
        return 1;
    }
    ok("base address (GetModuleHandleA) : %p", addr_winapi);

    /*--------------------[Compare]--------------------*/
    if (addr_peb == addr_winapi)
        ok("match -- addresses are identical");
    else
        err("mismatch -- PEB: %p  /  WinAPI: %p", addr_peb, addr_winapi);

    getchar();
    return 0;
}
