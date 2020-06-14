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

So keep in mind, we run these syscalls **every single** fuzz iteration with our dumb fuzzer. Our dumb fuzzer (-> [HERE](https://gist.github.com/h0mbre/0873edec8346122fc7dc5a1a03f0d2f1) <-) would write a file to disk every iteration, and spawn an instance of the target program with `fork() + execvp()`. The vulnerable binary would run all of the start up syscalls and finally read in the file from disk every iteration. So thats a couple dozen syscalls and **two** file system interactions every single fuzzing iteration. No wonder our dumb fuzzer was so slow. 

## Rudimentary Snapshot Mechanism
I started to think about how we could save time when fuzzing such a simple target binary and thought if I could just figure out how to take a snapshot of the program's memory *after* it had already read the file off of disk and had stored the contents in its heap, I could just save that process state and manually insert a new fuzzcase in the place of the bytes that the target had read in and then have the program run until it reaches an `exit()` call. Once the target hits the exit call, I would rewind the program state to what it was when I captured the snapshot and insert a new fuzz case and then do it all over again.

You can see how this would improve performance. We would skip all of the target binary startup overhead and we would completely bypass all file system interactions. A huge difference would be we would only make **one** call to `fork()` which is an expensive syscall. For 100,000 fuzzing iterations let's say, we'd go from 200,000 filesystem interactions (one for the dumb fuzzer to create a `mutated.jpeg` on disk, one for the target to read the `mutated.jpeg`) and 100,000 `fork()` calls to 0 file system interactions and only the initial `fork()`.

In summary, our fuzzing process should look like this:
1. Start target binary, but break on first instruction before anything runs
2. Set breakpoints on a 'start' and 'end' location (start will be **after** the program reads in bytes from the file on disk, end will be the address of `exit()`)
3. Run the program until it hits the 'start' breakpoint
4. Collect all writable memory sections of the process in a buffer
5. Capture all register states
6. Insert our fuzzcase into the heap overwriting the bytes that the program read in from file on disk
7. Resume target binary until it reaches 'end' breakpoint
8. Rewind process state to where it was at 'start' 
9. Repeat from step 6

We are only doing steps 1-5 only once, so this routine doesn't need to be very fast. Steps 6-9 are where the fuzzer will spend 99% of its time so we need this to be fast.

## Writing a Simple Debugger with Ptrace
In order to implement our snapshot mechanism, we'll need to use the very intuitive, albeit apparently slow and restrictive, `ptrace()` interface. When I was getting started writing the debugger portion of the fuzzer a couple weeks ago, I leaned heavily on this [blog post](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1) by [Eli Bendersky](https://twitter.com/elibendersky) which is a great introduction to `ptrace()` and shows you how to create a simple debugger. 

### Breakpoints 
The debugger portion of our code doesn't really need much functionality, it really only needs to be able to insert breakpoints and remove breakpoints. The way that you use `ptrace()` to set and remove breakpoints is to overwrite a single-byte instruction at at an address with the `int3` opcode `\xCC`. However, if you just overwrite the value there while setting a breakpoint, it will be impossible to remove the breakpoint because you won't know what value was held there originally and so you won't know what to overwrite `\xCC` with. 

To begin using `ptrace()`, we spawn a second process with `fork()`.
```c
pid_t child_pid = fork();
if (child_pid == 0) {
    //we're the child process here
    execute_debugee(debugee);
}
```

So first thing's first, we need a way to grab the one-byte value at an address before we insert our breakpoint. For the fuzzer, I developed a header file and source file I called `ptrace_helpers` to help ease the development process of using `ptrace()`. To grab the value, we'll grab the 64-bit value at the address but only care about the byte all the way to the right. (I'm using the type `long long unsigned` because that's how register values are defined in `<sys/user.h>` and I wanted to keep everything the same).

```c
long long unsigned get_value(pid_t child_pid, long long unsigned address) {
    
    errno = 0;
    long long unsigned value = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, 0);
    if (value == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }

    return value;	
}
```

So this function will use the `PTRACE_PEEKTEXT` argument to read the value located at `address` in the child process (`child_pid`) which is our target. So now that we have this value, we can save it off and insert our breakpoint with the following code:

```c
void set_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {

    errno = 0;
    long long unsigned breakpoint = (original_value & 0xFFFFFFFFFFFFFF00 | 0xCC);
    int ptrace_result = ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)breakpoint);
    if (ptrace_result == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}
```

You can see that this function will take our original value that we gathered with the previous function and performs two bitwise operations to keep the first 7 bytes intact but then replace the last byte with `\xCC`. Notice that we are now using `PTRACE_POKETEXT`. One of the frustrating features of the `ptrace()` interface is that we can only read and write 8 bytes at a time!

So now that we can set breakpoints, the last function we need to implement is one to remove breakpoints, which would entail overwriting the `int3` with the original byte value. 
```c
void revert_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {

    errno = 0;
    int ptrace_result = ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)original_value);
    if (ptrace_result == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}
```

Again, using `PTRACE_POKETEXT`, we can overwrite the `\xCC` with the original byte value. So now we have the ability to set and remove breakpoints. Let's now learn how we can utilize `ptrace` and the `/proc` pseudo files to create a snapshot of our target!

### Snapshotting with Ptrace and /Proc
Another cool feature of `ptrace()` is the ability to capture register states in a debuggee process. 
