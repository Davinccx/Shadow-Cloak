# ShadowCloak 🕶️

Framework de inyección de DLLs usando syscalls directas para Windows. Proyecto educativo para entender técnicas de evasión de EDRs.

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://www.microsoft.com/windows)
[![x64](https://img.shields.io/badge/arch-x64-green.svg)](https://en.wikipedia.org/wiki/X86-64)

## ⚠️ Aviso Legal

Este proyecto es **únicamente con fines educativos**. Lo he desarrollado para:
- Aprender sobre Windows internals y syscalls
- Entender cómo funcionan las técnicas de evasión de malware
- Practicar para certificaciones de Red Team (OSCP, CRTO)

**NO está pensado para usos maliciosos**. Si lo usas, hazlo solo en:
- ✅ Tus propios equipos y laboratorios
- ✅ CTFs y plataformas como HackTheBox
- ✅ Pentesting con autorización por escrito

Cualquier uso ilegal es responsabilidad tuya. Yo no me hago responsable de cómo uses esto.

---

## ¿Qué es esto?

Es un inyector de DLLs pero que bypasea los hooks que ponen los EDRs (Crowdstrike, Defender ATP, etc).

La mayoría de inyectores usan las APIs normales de Windows:
```
Tu código → OpenProcess() → kernel32.dll → ntdll.dll [EDR aquí 🎣] → Kernel
```

Este proyecto hace syscalls directas:
```
Tu código → Syscall directo → Kernel [EDR bypaseado]
```

La idea la saqué de analizar malware de APTs y quería implementarlo yo mismo para entenderlo bien.

---

## Características

- **Syscalls directas**: No usa APIs normales, va directo al kernel
- **Sin Assembly files**: Genera el código en memoria en runtime (más sencillo)
- **Funciona en cualquier Windows**: Extrae los números de syscall automáticamente
- **Comentado**: Todo el código tiene explicaciones para que se entienda

Las syscalls que implementé:
- `NtOpenProcess` (0x26) - Abre el proceso objetivo
- `NtAllocateVirtualMemory` (0x18) - Reserva memoria en el proceso
- `NtWriteVirtualMemory` (0x3A) - Escribe la ruta de la DLL
- `NtCreateThreadEx` (0xC9) - Crea el thread remoto
- `NtWaitForSingleObject` (0x04) - Espera a que termine
- `NtClose` (0x0F) - Limpia los handles

---

## Cómo funciona

Los EDRs modernos "hookean" las funciones de `ntdll.dll` para ver qué hace cada proceso. Es efectivo contra la mayoría de malware.

Pero si haces la syscall TÚ MISMO, no pasa por esos hooks. Es como llamar directo al kernel sin intermediarios.

El truco está en generar este código en memoria:
```asm
mov r10, rcx      ; Guardar primer argumento
mov eax, 0x26     ; Número de syscall (NtOpenProcess)
syscall           ; Llamada directa
ret
```

Y luego llamarlo como si fuera una función normal. Así de simple (bueno, no tan simple, pero funciona).

---

## Instalación

Necesitas:
- Windows 10 u 11 (x64)
- MinGW o Visual Studio

---

## Uso

Es bastante directo:

```bash
# 1. Abre un proceso (ej: notepad)
start notepad.exe

# 2. Inyecta la DLL
bin/injector.exe notepad.exe bin/payload.dll
```

Deberías ver algo así:
```
[*] Inicializando syscalls directas...
[+] Syscalls inicializadas

[*] PASO 1: Abriendo proceso con NtOpenProcess...
[+] Proceso abierto mediante syscall
[+] Hooks de EDR bypaseados

[*] PASO 2: Reservando memoria con NtAllocateVirtualMemory...
[+] Memoria reservada mediante syscall

...

✓ INYECCIÓN EXITOSA
```

Si todo va bien, la DLL se ejecutará dentro de notepad sin que el EDR se entere.

---
## ¿Esto realmente funciona?

Sí. Lo he probado en:
- Windows 10 (varias builds)
- Windows 11 (build 26100)
- Con Defender activado

Defender no lo detecta porque no pasa por los hooks. Obviamente si añades un payload malicioso real, Defender lo detectará por otros métodos (firmas, comportamiento, etc).

Pero la técnica de inyección en sí bypasea los hooks de userland completamente.

---

## Limitaciones

No es perfecto. Estas cosas todavía pueden detectarlo:
- Callbacks del kernel (si el EDR tiene driver en kernel mode)
- Memory scanning (si escanean la memoria buscando stubs de syscalls)
- Stack walking (si verifican desde dónde viene la syscall)
- Análisis comportamental (si ven patrones raros)

Pero para aprender y para bypasear EDRs básicos, funciona de sobra.

---
