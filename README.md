Project Structure for ShadowCloak
Alright, here's how I'm organizing this thing. Might change later but this makes sense for now.
ShadowCloak/
│
├── README.md                          # Main readme (you're looking at it)
│
├── process_injection/                 # All the injection techniques
│   ├── dll_injection/
│   │   ├── injector.cpp              # Classic DLL injection via CreateRemoteThread
│   │   ├── payload.dll               # Sample DLL to inject
│   │   └── README.md                 # How it works, usage, detection notes
│   │
│   ├── process_hollowing/
│   │   ├── hollow.cpp                # Unmaps and replaces process memory
│   │   ├── target_process.exe        # Legitimate process to hollow out
│   │   └── README.md
│   │
│   ├── thread_hijacking/
│   │   ├── hijack.cpp                # Suspend thread, modify context, resume
│   │   └── README.md
│   │
│   └── reflective_dll/               # TODO - when I figure this out properly
│       └── README.md
│
├── syscalls/                         # Direct and indirect syscall implementations
│   ├── direct_syscalls/
│   │   ├── syscalls.asm              # Assembly stubs for syscalls
│   │   ├── syscalls.h                # Header with syscall numbers
│   │   ├── direct_inject.cpp         # Example using direct syscalls
│   │   └── README.md
│   │
│   ├── indirect_syscalls/            # TODO - more research needed
│   │   └── README.md
│   │
│   └── utils/
│       ├── get_syscall_numbers.py    # Helper to extract syscall numbers
│       └── parse_ntdll.py            # Parse ntdll for function addresses
│
├── amsi_bypass/
│   ├── memory_patch/
│   │   ├── amsi_patch.cpp            # Patches AmsiScanBuffer in memory
│   │   ├── amsi_patch.ps1            # PowerShell version
│   │   └── README.md
│   │
│   ├── context_patch/
│   │   ├── context_bypass.cpp        # Patches AMSI context structure
│   │   └── README.md
│   │
│   └── force_fail/
│       ├── force_fail.ps1            # Forces AMSI to always return clean
│       └── README.md
│
├── etw_bypass/
│   ├── etw_patch.cpp                 # Patches EtwEventWrite
│   ├── provider_disable.cpp          # Disables specific ETW providers
│   └── README.md
│
├── unhooking/
│   ├── full_unhook.cpp               # Reads fresh ntdll from disk
│   ├── selective_unhook.cpp          # Only unhooks specific functions
│   ├── manual_map.cpp                # Manually map clean ntdll
│   └── README.md
│
├── loaders/                          # Various shellcode loaders
│   ├── basic_loader.cpp              # Simple VirtualAlloc + memcpy + execute
│   ├── encrypted_loader.cpp          # XOR encrypted payload
│   ├── staged_loader.cpp             # Downloads and executes stage2
│   └── README.md
│
├── crypters/                         # Payload encryption tools
│   ├── xor_crypter.py               # Basic XOR encryption
│   ├── aes_crypter.py               # AES-256 encryption
│   ├── rc4_crypter.py               # RC4 encryption
│   └── README.md
│
├── utils/                            # Helper scripts and tools
│   ├── process_scanner.cpp           # Find processes to inject into
│   ├── dll_check.cpp                 # Check what DLLs are hooked
│   ├── detect_sandbox.cpp            # Basic sandbox detection
│   └── edr_check.ps1                 # Check what EDR is running
│
├── docs/
│   ├── detection_notes.md            # What gets detected by which EDR
│   ├── mitre_mapping.md              # Full MITRE ATT&CK mapping
│   ├── techniques_explained.md       # Detailed explanations
│   ├── build_guide.md                # How to build everything
│   └── testing_methodology.md        # How I test these techniques
│
├── examples/                         # Working examples and demos
│   ├── calc_shellcode.bin           # Classic calc.exe shellcode
│   ├── reverse_shell.bin            # Simple reverse shell
│   └── demo_payloads/
│
└── tests/                           # Test scripts (someday...)
    └── run_tests.py
Notes to myself

Keep each technique in its own folder with a good README explaining how it works
Add comments in the code - future me will thank current me
Test everything in a VM before pushing (obviously)
Document which Windows versions each technique works on
Keep track of what EDRs detect what - this is constantly changing
Maybe add a wiki later if this gets bigger
Consider adding automated testing against known EDR products (if I can get access)

Build order (for new people)
Start simple, work your way up:

Basic loaders - understand how shellcode execution works
Process injection - learn the different techniques
Syscalls - understand how to bypass userland hooks
AMSI/ETW - specific bypasses for monitoring
Unhooking - more advanced evasion

Don't try to build everything at once, you'll just confuse yourself (learned this the hard way).
Dependencies
Most stuff just needs:

Windows 10/11 (tested on both)
Visual Studio 2019 or newer
Python 3.x for the helper scripts
Administrator privileges for most techniques

Some techniques need specific libraries:

OpenSSL for AES crypter
Capstone for the disassembly stuff (planned)

Testing environment
I'm testing all this on:

Windows 10 22H2 (VM)
Windows 11 23H2 (VM)
With and without various EDRs enabled (when possible)

Obviously don't test this on production systems or machines you care about. Use VMs.
