#pragma once
#ifndef SYSCALLS_INLINE_H
#define SYSCALLS_INLINE_H

#include <windows.h>
#include <stdio.h>

// NTSTATUS type and macros
typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Object Attributes structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// Client ID structure
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// PS_ATTRIBUTE structure
typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// Initialize OBJECT_ATTRIBUTES macro
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// Syscall numbers for Windows 11 Build 26100
#define SYSCALL_NtOpenProcess               0x26
#define SYSCALL_NtAllocateVirtualMemory     0x18
#define SYSCALL_NtWriteVirtualMemory        0x3A
#define SYSCALL_NtCreateThreadEx            0xC9
#define SYSCALL_NtProtectVirtualMemory      0x50
#define SYSCALL_NtClose                     0x0F
#define SYSCALL_NtWaitForSingleObject       0x04

// Syscall stub generator
// Creates syscall stub in executable memory
PVOID GenerateSyscallStub(DWORD syscallNumber) {
    /*
     * Generated stub bytes (x64):
     * mov r10, rcx     ; 4C 8B D1
     * mov eax, XX      ; B8 XX 00 00 00
     * syscall          ; 0F 05
     * ret              ; C3
     */

    unsigned char stubTemplate[] = {
        0x4C, 0x8B, 0xD1,                           // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,              // mov eax, syscall_number (placeholder)
        0x0F, 0x05,                                 // syscall
        0xC3                                        // ret
    };

    // Allocate executable memory for stub
    PVOID stubMemory = VirtualAlloc(
        NULL,
        sizeof(stubTemplate),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (stubMemory == NULL) {
        return NULL;
    }

    // Copy template to memory
    memcpy(stubMemory, stubTemplate, sizeof(stubTemplate));

    // Patch syscall number at offset 4 (after B8)
    *(DWORD*)((unsigned char*)stubMemory + 4) = syscallNumber;

    return stubMemory;
}

// Function pointer types for syscalls
typedef NTSTATUS(*pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(*pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(*pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(*pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(*pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(*pNtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(*pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

// Global function pointers (initialized once)
static pNtOpenProcess g_NtOpenProcess = NULL;
static pNtAllocateVirtualMemory g_NtAllocateVirtualMemory = NULL;
static pNtWriteVirtualMemory g_NtWriteVirtualMemory = NULL;
static pNtCreateThreadEx g_NtCreateThreadEx = NULL;
static pNtProtectVirtualMemory g_NtProtectVirtualMemory = NULL;
static pNtClose g_NtClose = NULL;
static pNtWaitForSingleObject g_NtWaitForSingleObject = NULL;

// Initialize all syscall stubs
BOOL InitializeSyscalls() {
    g_NtOpenProcess = (pNtOpenProcess)GenerateSyscallStub(SYSCALL_NtOpenProcess);
    if (!g_NtOpenProcess) return FALSE;

    g_NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GenerateSyscallStub(SYSCALL_NtAllocateVirtualMemory);
    if (!g_NtAllocateVirtualMemory) return FALSE;

    g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GenerateSyscallStub(SYSCALL_NtWriteVirtualMemory);
    if (!g_NtWriteVirtualMemory) return FALSE;

    g_NtCreateThreadEx = (pNtCreateThreadEx)GenerateSyscallStub(SYSCALL_NtCreateThreadEx);
    if (!g_NtCreateThreadEx) return FALSE;

    g_NtProtectVirtualMemory = (pNtProtectVirtualMemory)GenerateSyscallStub(SYSCALL_NtProtectVirtualMemory);
    if (!g_NtProtectVirtualMemory) return FALSE;

    g_NtClose = (pNtClose)GenerateSyscallStub(SYSCALL_NtClose);
    if (!g_NtClose) return FALSE;

    g_NtWaitForSingleObject = (pNtWaitForSingleObject)GenerateSyscallStub(SYSCALL_NtWaitForSingleObject);
    if (!g_NtWaitForSingleObject) return FALSE;

    return TRUE;
}

// Wrapper functions (easier to use)
inline NTSTATUS SysNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    if (!g_NtOpenProcess) return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
    return g_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

inline NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!g_NtAllocateVirtualMemory) return (NTSTATUS)0xC0000001;
    return g_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

inline NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    if (!g_NtWriteVirtualMemory) return (NTSTATUS)0xC0000001;
    return g_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

inline NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
) {
    if (!g_NtCreateThreadEx) return (NTSTATUS)0xC0000001;
    return g_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);
}

inline NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    if (!g_NtProtectVirtualMemory) return (NTSTATUS)0xC0000001;
    return g_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

inline NTSTATUS SysNtClose(HANDLE Handle) {
    if (!g_NtClose) return (NTSTATUS)0xC0000001;
    return g_NtClose(Handle);
}

inline NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
) {
    if (!g_NtWaitForSingleObject) return (NTSTATUS)0xC0000001;
    return g_NtWaitForSingleObject(Handle, Alertable, Timeout);
}

#endif // SYSCALLS_INLINE_H