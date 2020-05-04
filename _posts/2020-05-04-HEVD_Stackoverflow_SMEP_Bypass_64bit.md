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

Again, just following along with Abatchy's blog, we can find the first gadget (actually the 2nd in our code) by locating a gadget that allows us to place a value into `cr4` easily and then takes a `ret` soon after. Luckily for us, this gadget exists inside of `nt!HvlEndSystemInterrupt`. 

We can find it in WinDBG with the following:
```

## Conclusion
