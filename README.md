# ShadowCloak

A collection of Windows evasion techniques I've been playing around with for bypassing EDR and AV solutions. Started this as a way to document what I was learning about how modern security products work and how attackers get around them.

Most of this stuff is based on publicly available research and techniques that red teamers have been using for years - nothing groundbreaking here, just my implementations and notes.

## What's in here

Right now I've got a few different categories:

**Process Injection** - The classics: DLL injection, process hollowing, thread hijacking. Pretty much what every offensive tool uses at some point.

**Direct Syscalls** - Bypassing userland hooks by going straight to the kernel. Turns out a lot of EDRs just hook ntdll.dll and call it a day.

**AMSI Bypass** - Because PowerShell is still useful and Microsoft's AMSI is annoying. A couple different approaches depending on what you need.

**ETW Patching** - Disabling Event Tracing for Windows so your actions don't get logged as much.

**Unhooking** - Restoring original function bytes when you find hooks in your process.

Each folder has its own README with more details on how the technique works and what it's trying to accomplish.

## Building

You'll need Visual Studio 2019+ for the C/C++ stuff. Some techniques use inline assembly so make sure that's enabled.

```
git clone https://github.com/Davinccx/ShadowCloak
cd ShadowCloak
```

For individual techniques, navigate to their folder and build with:
```
cl /EHsc technique_name.cpp
```

Or just open the .sln files in Visual Studio.

## Usage

**Disclaimer first**: This is for educational purposes and authorized testing only. Don't be stupid with this. Seriously.

Most tools here are standalone executables or DLLs you can load. Check the specific technique's README for usage examples.

Basic example for the shellcode loader:
```
loader.exe payload.bin
```

## Why I made this

Honestly? I wanted to understand how these evasion techniques actually work under the hood. You can read about them all day but until you implement them yourself and see what works (and what doesn't), it doesn't really click.

Also useful for my own red team engagements where I need to customize payloads to get past specific defenses.

## Detection notes

I'm trying to document which EDR products detect which techniques, but this changes constantly as vendors update their products. What works today might not work tomorrow.

Generally speaking:
- Basic process injection = detected by pretty much everything now
- Direct syscalls = more stealthy but some EDRs are catching on
- AMSI bypasses = hit or miss, depends on the method
- Unhooking = can trigger behavioral alerts

Check the `docs/detection_notes.md` file for more specific info (when I get around to writing it properly).

## MITRE ATT&CK Mapping

Since everyone wants to see this now:
- T1055 - Process Injection
- T1106 - Native API
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1140 - Deobfuscate/Decode Files or Information

## TODO

Things I want to add when I have time:
- [ ] More injection techniques (APC queue, thread pool injection)
- [ ] Indirect syscalls implementation
- [ ] Better obfuscation for the loaders
- [ ] Heaven's Gate for WoW64 processes
- [ ] More comprehensive testing against different EDRs
- [ ] Actually finish the documentation

## Resources

Stuff that helped me learn this:
- Maldev Academy - seriously good resource
- ReWolf's blog on syscalls
- Red Team Notes by @spotheplanet
- MalwareTech's old blog posts
- Various GitHub repos from other researchers

## Contributing

If you want to add techniques or fix bugs, PRs are welcome. Just try to keep the code readable and add some explanation of what you're doing.

## License

MIT - do whatever you want with it, just don't blame me if something breaks or you get caught.

---

Made this because I was tired of copy-pasting code from 10 different repos. Now it's all in one place and at least I understand how it works.
