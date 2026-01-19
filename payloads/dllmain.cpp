// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"
#include <windows.h>
#include <stdio.h>

// DllMain is called when the DLL is loaded
// This is where your payload code goes
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        // DLL is being loaded into a process
        // This is where your code executes

        // Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications
        // (performance optimization)
        DisableThreadLibraryCalls(hModule);

        // Pop a message box to show we're injected
        MessageBoxA(
            NULL,
            "DLL successfully injected!\nYour code is now running in the target process.",
            "Injection Successful",
            MB_OK | MB_ICONINFORMATION
        );

        // You could do anything here:
        // - Spawn a reverse shell
        // - Hook functions
        // - Dump memory
        // - Keylog
        // - Take screenshots
        // - Etc.

        // For now, just the message box to prove it worked

        break;

    case DLL_THREAD_ATTACH:
        // A new thread is being created (we disabled these notifications)
        break;

    case DLL_THREAD_DETACH:
        // A thread is exiting (we disabled these notifications)
        break;

    case DLL_PROCESS_DETACH:
        // DLL is being unloaded
        // Cleanup code would go here
        break;
    }

    return TRUE;  // Return TRUE to indicate successful initialization
}