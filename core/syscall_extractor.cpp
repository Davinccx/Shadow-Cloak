#include <windows.h>
#include <stdio.h>


typedef struct _SYSCALL_INFO {
	DWORD SyscallNumber;
	const char* FunctionName;
	PVOID FunctionAddress;
} SYSCALL_INFO, * PSYSCALL_INFO;


void PrintBytes(unsigned char* data, int length) {

	for(int i = 0; i < length; i++) {
		printf("%02X ", data[i]);
	}

	printf("\n");

}

DWORD GetSyscallNumber(PVOID functionAddress) {
	unsigned char* bytes = (unsigned char*)functionAddress;

    /*
    * Patrón típico de syscall en x64:
    *
    * 4C 8B D1             mov r10, rcx
    * B8 XX 00 00 00       mov eax, XX  <- XX es el syscall number
    * F6 04 25 08 03 FE 7F 01  test byte ptr [...]
    * 75 03                jne ...
    * 0F 05                syscall
    * C3                   ret
    *
    * Nos interesa el byte en posición [4] que es el syscall number
    */

    // Verificar patrón: mov r10, rcx (4C 8B D1)
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
        // Verificar: mov eax, XX (B8 XX 00 00 00)
        if (bytes[3] == 0xB8) {
            // El syscall number está en bytes[4]
            DWORD syscallNumber = *(DWORD*)(bytes + 4);
            // Solo nos interesa el byte bajo (el número real)
            return syscallNumber & 0xFF;
        }
    }

    // Patrón alternativo en algunas versiones:
    // B8 XX 00 00 00       mov eax, XX
    if (bytes[0] == 0xB8) {
        DWORD syscallNumber = *(DWORD*)(bytes + 1);
        return syscallNumber & 0xFF;
    }

    return (DWORD)-1;  // No encontrado

}

BOOL ExtractSyscall(const char* functionName, PSYSCALL_INFO pInfo) {
    // Obtener handle de ntdll.dll (siempre está cargada)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Failed to get ntdll.dll handle\n");
        return FALSE;
    }

    // Obtener dirección de la función
    FARPROC funcProc = GetProcAddress(hNtdll, functionName);
    PVOID functionAddr = (PVOID)funcProc;
    if (functionAddr == NULL) {
        printf("[-] Function not found: %s\n", functionName);
        return FALSE;
    }

    // Extraer el syscall number
    DWORD syscallNum = GetSyscallNumber(functionAddr);
    if (syscallNum == (DWORD)-1) {
        printf("[-] Failed to extract syscall number from: %s\n", functionName);
        return FALSE;
    }

    // Rellenar estructura
    pInfo->FunctionName = functionName;
    pInfo->FunctionAddress = functionAddr;
    pInfo->SyscallNumber = syscallNum;

    return TRUE;
}

int main() {
    printf("========================================\n");
    printf("  Syscall Number Extractor v1.0\n");
    printf("========================================\n\n");

    // Obtener versión de Windows
    OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

    // Note: GetVersionEx está deprecated pero funciona para este propósito
#pragma warning(push)
#pragma warning(disable: 4996)
    GetVersionExW(&osvi);
#pragma warning(pop)

    printf("[*] Windows Version: %lu.%lu (Build %lu)\n\n",
        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    // Lista de funciones que nos interesan
    const char* functions[] = {
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtProtectVirtualMemory",
        "NtQuerySystemInformation",
        "NtQueryVirtualMemory",
        "NtReadVirtualMemory",
        "NtClose",
        "NtOpenProcessToken",
        "NtDuplicateObject",
        "NtWaitForSingleObject"
    };

    int numFunctions = sizeof(functions) / sizeof(functions[0]);

    printf("[*] Extracting syscall numbers for %d functions:\n\n", numFunctions);
    printf("%-35s %-15s %-20s\n", "Function", "Syscall #", "Address");
    printf("%-35s %-15s %-20s\n", "--------", "---------", "-------");

    SYSCALL_INFO info;
    int successCount = 0;

    for (int i = 0; i < numFunctions; i++) {
        if (ExtractSyscall(functions[i], &info)) {
            printf("%-35s 0x%04X (%-3d)  0x%p\n",
                info.FunctionName,
                info.SyscallNumber,
                info.SyscallNumber,
                info.FunctionAddress);
            successCount++;
        }
    }

    printf("\n[+] Successfully extracted %d/%d syscall numbers\n", successCount, numFunctions);

    // Generar código C para usar
    printf("\n========================================\n");
    printf("  Generated C Code\n");
    printf("========================================\n\n");

    printf("// Syscall numbers for this Windows version\n");
    printf("// Build: %lu\n", osvi.dwBuildNumber);
    printf("#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)\n\n");

    for (int i = 0; i < numFunctions; i++) {
        if (ExtractSyscall(functions[i], &info)) {
            printf("#define SYSCALL_%-25s 0x%04X\n",
                info.FunctionName + 2,  // Skip "Nt" prefix
                info.SyscallNumber);
        }
    }

    printf("\n");

    // Mostrar ejemplo de uso
    printf("\n========================================\n");
    printf("  Example Assembly Stub\n");
    printf("========================================\n\n");

    if (ExtractSyscall("NtOpenProcess", &info)) {
        printf("; NtOpenProcess syscall stub\n");
        printf("NtOpenProcess:\n");
        printf("    mov r10, rcx\n");
        printf("    mov eax, 0x%02X       ; Syscall number\n", info.SyscallNumber);
        printf("    syscall\n");
        printf("    ret\n\n");
    }

    // Mostrar los bytes reales de la función
    printf("\n========================================\n");
    printf("  Raw Function Bytes (First 20)\n");
    printf("========================================\n\n");

    for (int i = 0; i < numFunctions && i < 3; i++) {  // Solo primeras 3 para no saturar
        if (ExtractSyscall(functions[i], &info)) {
            printf("%s:\n", info.FunctionName);
            printf("  ");
            PrintBytes((unsigned char*)info.FunctionAddress, 20);
            printf("\n");
        }
    }

    printf("\n[*] Done! You can now use these syscall numbers in your code.\n");
    printf("[*] Note: These numbers are specific to this Windows build.\n");

    return 0;
}