---
layout: single
title: "Fuzzing Like A Caveman 4: Snapshot/Code Coverage Fuzzer!"
date: 2020-06-13
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fuzzing
  - C
---

## Introduction
I'm addicted to fuzzing. That's it. 

Last time we blogged, we had a dumb fuzzer that would test an intentionally vulnerable program that would perform some checks on a file and if the input file passed a check, it would progress to the next check, and if the input passed all checks the program would segfault. We discovered the importance of **code coverage** and how it can help reduce exponentially rare occurences during fuzzing into linearly rare occurences. Let's get right into how we improved our dumb fuzzer!

## Performance
First things first, our dumb fuzzer was slow as hell. If you remember, we were averaging about 1,500 fuzz cases per second with our dumb fuzzer. During my testing, AFL in QEMU mode (simulating not having source code available for compilation instrumentation) was hovering around 1,000 fuzz cases per second. This makes sense, since AFL does way more than our dumb fuzzer, especially in QEMU mode where we are emulating a CPU and providing code coverage.

Our target binary (-> [HERE](https://gist.github.com/h0mbre/db209b70eb614aa811ce3b98ad38262d) <-) would do the following: 
+ extract the bytes from a file on disk into a buffer
+ perform 3 checks on the buffer to see if the indexes that were checked matched hardcoded values
+ segfaulted if all checks were passed, exit if one of the checks failed

Our dumb fuzzer would do the following:
+ extract bytes from a valid jpeg on disk into a byte buffer
+ mutate 2% of the bytes in the buffer by random byte overwriting
+ write the mutated file to disk
+ feed the mutated file to the target binary by executing a `fork()` and `execvp()` each fuzzing iteration

As you can see, this is a lot of file system interactions and syscalls. Let's use `strace` on our vulnerable binary and see what syscalls the binary makes (for this post, I've hardcoded the `.jpeg` file into the vulnerable binary so that we don't have to use command line arguments for ease of testing):
```
execve("/usr/bin/vuln", ["vuln"], 0x7ffe284810a0 /* 52 vars */) = 0
brk(NULL)                               = 0x55664f046000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=88784, ...}) = 0
mmap(NULL, 88784, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f0793d2e000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\260\34\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=2030544, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0793d2c000
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f079372c000
mprotect(0x7f0793913000, 2097152, PROT_NONE) = 0
mmap(0x7f0793b13000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f0793b13000
mmap(0x7f0793b19000, 15072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f0793b19000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f0793d2d500) = 0
mprotect(0x7f0793b13000, 16384, PROT_READ) = 0
mprotect(0x55664dd97000, 4096, PROT_READ) = 0
mprotect(0x7f0793d44000, 4096, PROT_READ) = 0
munmap(0x7f0793d2e000, 88784)           = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
brk(NULL)                               = 0x55664f046000
brk(0x55664f067000)                     = 0x55664f067000
write(1, "[>] Analyzing file: Canon_40D.jp"..., 35[>] Analyzing file: Canon_40D.jpg.
) = 35
openat(AT_FDCWD, "Canon_40D.jpg", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=7958, ...}) = 0
fstat(3, {st_mode=S_IFREG|0644, st_size=7958, ...}) = 0
lseek(3, 4096, SEEK_SET)                = 4096
read(3, "\v\260\v\310\v\341\v\371\f\22\f*\fC\f\\\fu\f\216\f\247\f\300\f\331\f\363\r\r\r&"..., 3862) = 3862
lseek(3, 0, SEEK_SET)                   = 0
write(1, "[>] Canon_40D.jpg is 7958 bytes."..., 33[>] Canon_40D.jpg is 7958 bytes.
) = 33
read(3, "\377\330\377\340\0\20JFIF\0\1\1\1\0H\0H\0\0\377\341\t\254Exif\0\0II"..., 4096) = 4096
read(3, "\v\260\v\310\v\341\v\371\f\22\f*\fC\f\\\fu\f\216\f\247\f\300\f\331\f\363\r\r\r&"..., 4096) = 3862
close(3)                                = 0
write(1, "[>] Check 1 no.: 2626\n", 22[>] Check 1 no.: 2626
) = 22
write(1, "[>] Check 2 no.: 3979\n", 22[>] Check 2 no.: 3979
) = 22
write(1, "[>] Check 3 no.: 5331\n", 22[>] Check 3 no.: 5331
) = 22
write(1, "[>] Check 1 failed.\n", 20[>] Check 1 failed.
)   = 20
write(1, "[>] Char was 00.\n", 17[>] Char was 00.
)      = 17
exit_group(-1)                          = ?
+++ exited with 255 +++
```

You can see that during the process of the target binary, we run plenty of code before we even open the input file. Looking through the strace output, we don't even open the input file until we've run the following syscalls: 
```
execve
brk
access
access
openat
fstat
mmap
close
access
openat
read
opeant
read
fstat
mmap
mmap
mprotect
mmap
mmap
arch_prctl
mprotect
mprotect
mprotect
munmap
fstat
brk
brk
write
```
After all of those syscalls, we **finally** open the file from the disk to read in the bytes with this line from the `strace` output:
```
openat(AT_FDCWD, "Canon_40D.jpg", O_RDONLY) = 3
```

So keep in mind, we run these syscalls **every single** fuzz iteration with our dumb fuzzer. Our dumb fuzzer (-> [HERE](https://gist.github.com/h0mbre/0873edec8346122fc7dc5a1a03f0d2f1) <-) would open a write a file to disk every iteration, and the vulnerable binary would run all of the start up syscalls and finally read in the file from disk every iteration. So thats a couple dozen syscalls and **two** file system interactions every single fuzzing iteration. No wonder our dumb fuzzer was so slow. 

## Implementing a Rudimentary Snapshot Mechanism

