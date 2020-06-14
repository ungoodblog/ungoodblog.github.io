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
Last time we blogged, we had a dumb fuzzer that would test an intentionally vulnerable program that would perform some checks on a file and if the input file passed a check, it would progress to the next check, and if the input passed all checks the program would segfault. We discovered the importance of **code coverage** and how it can help reduce exponentially rare occurences during fuzzing into linearly rare occurences. Let's get right into how we improved our dumb fuzzer!

Big thanks to @gamozolabs for all of his content that got me hooked on the topic.

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

Now we need to have the child process volunteer to be 'traced' by the parent process. This is done with the `PTRACE_TRACEME` argument, which we'll use inside our `execute_debugee` function:
```c
// request via PTRACE_TRACEME that the parent trace the child
long ptrace_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
if (ptrace_result == -1) {
    fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
    perror("ptrace");
    exit(errno);
}
```

The rest of the function doesn't involve `ptrace` but I'll go ahead and show it here because there is an important function to forcibly disable ASLR in the debuggee process. This is crucial as we'll be leverage breakpoints at static addresses that **cannot** change process to process. We disable ASLR by calling `personality()` with `ADDR_NO_RANDOMIZE`. Separately, we'll route `stdout` and `stderr` to `/dev/null` so that we don't muddy our terminal with the target binary's output.
```c
// disable ASLR
int personality_result = personality(ADDR_NO_RANDOMIZE);
if (personality_result == -1) {
    fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
    perror("personality");
    exit(errno);
}
 
// dup both stdout and stderr and send them to /dev/null
int fd = open("/dev/null", O_WRONLY);
dup2(fd, 1);
dup2(fd, 2);
close(fd);
 
// exec our debugee program, NULL terminated to avoid Sentinel compilation
// warning. this replaces the fork() clone of the parent with the 
// debugee process 
int execl_result = execl(debugee, debugee, NULL);
if (execl_result == -1) {
    fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
    perror("execl");
    exit(errno);
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

Again, using `PTRACE_POKETEXT`, we can overwrite the `\xCC` with the original byte value. So now we have the ability to set and remove breakpoints. 

Lastly, we'll need a way to resume execution in the debuggee. This can be accomplished by utilizing the `PTRACE_CONT` argument in `ptrace()` as follows:
```c
void resume_execution(pid_t child_pid) {

    int ptrace_result = ptrace(PTRACE_CONT, child_pid, 0, 0);
    if (ptrace_result == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}
```
An important thing to note is, if we hit a breakpoint at address `0x000000000000000`, `rip` will actually be at `0x0000000000000001`. So after reverting our overwritten instruction to its previous value, we'll also need to subtract 1 from `rip` before resuming execution, we'll learn how to do this via `ptrace` in the next section.

Let's now learn how we can utilize `ptrace` and the `/proc` pseudo files to create a snapshot of our target!

### Snapshotting with ptrace and /proc

### Register States
Another cool feature of `ptrace()` is the ability to capture and set register states in a debuggee process. We can do both of those things respectively with the helper functions I placed in `ptrace_helpers.c`:
```c
// retrieve register states
struct user_regs_struct get_regs(pid_t child_pid, struct user_regs_struct registers) {                                                                                                 
    int ptrace_result = ptrace(PTRACE_GETREGS, child_pid, 0, &registers);                                                                              
    if (ptrace_result == -1) {                                                                              
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);                                                                         
        perror("ptrace");                                                                              
        exit(errno);                                                                              
    }

    return registers;                                                                              
}
```
```c
// set register states
void set_regs(pid_t child_pid, struct user_regs_struct registers) {

    int ptrace_result = ptrace(PTRACE_SETREGS, child_pid, 0, &registers);
    if (ptrace_result == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}
```

The `struct user_regs_struct` is defined in `<sys/user.h>`. You can see we use `PTRACE_GETREGS` and `PTRACE_SETREGS` respectively to retrieve register data and set register data. So with these two functions, we'll be able to create a `struct user_regs_struct` of snapshot register values when we are sitting at our 'start' breakpoint and when we reach our 'end' breakpoint, we'll be able to revert the register states (most imporantly `rip`) to what they were when snapshotted. 

### Snapshotting Writable Memory Sections with /proc
Now that we have a way to capture register states, we'll need a way to capture writable memory states for our snapshot. I did this by interacting with the `/proc` pseudo files. I used GDB to break on the first function that peforms a check in `vuln`, importantly this function is after `vuln` reads the `jpeg` off disk and will serve as our 'start' breakpoint. Once we break here in GDB, we can `cat` the `/proc/$pid/maps` file to get a look at how memory is mapped in the process (keep in mind GDB also forces ASLR off using the same method we did in our debugger). We can see the output here grepping for writable sections (ie, sections that could be clobbered during our fuzzcase run):
```
h0mbre@pwn:~/fuzzing/dragonfly_dir$ cat /proc/12011/maps | grep rw
555555756000-555555757000 rw-p 00002000 08:01 786686                     /home/h0mbre/fuzzing/dragonfly_dir/vuln
555555757000-555555778000 rw-p 00000000 00:00 0                          [heap]
7ffff7dcf000-7ffff7dd1000 rw-p 001eb000 08:01 1055012                    /lib/x86_64-linux-gnu/libc-2.27.so
7ffff7dd1000-7ffff7dd5000 rw-p 00000000 00:00 0 
7ffff7fe0000-7ffff7fe2000 rw-p 00000000 00:00 0 
7ffff7ffd000-7ffff7ffe000 rw-p 00028000 08:01 1054984                    /lib/x86_64-linux-gnu/ld-2.27.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

So that's seven distinct sections of memory. You'll notice that the `heap` is one of the sections. It is important to realize that our fuzzcase will be inserted into the heap, but the address in the heap that stores the fuzzcase will not be the same in our fuzzer as it is in GDB. This is likely due to some sort of environment variable difference between the two debuggers I think. If we look in GDB when we break on `check_one()` in `vuln`, we see that `rax` is a pointer to the beginning of our input, in this case the `Canon_40D.jpg`. 
```
$rax   : 0x00005555557588b0  →  0x464a1000e0ffd8ff
```

That pointer, `0x00005555557588b0`, is located in the heap. So all I had to do to find out where that pointer was in our debugger/fuzzer, was just break at the same point and use `ptrace()` to retrieve the `rax` value.

I would break on `check_one` and then open `/proc/$pid/maps` to get the offsets within the program that contain writable memory sections, and then I would open `/proc/$pid/mem` and read from those offsets into a buffer to store the writable memory. This code was stored in a source file called `snapshot.c` which contained some definitions and functions to both capture snapshots and restore them. For this part, capturing writable memory, I used the following definitions and function:
```c
unsigned char* create_snapshot(pid_t child_pid) {
 
    struct SNAPSHOT_MEMORY read_memory = {
        {
            // maps_offset
            0x555555756000,
            0x7ffff7dcf000,
            0x7ffff7dd1000,
            0x7ffff7fe0000,
            0x7ffff7ffd000,
            0x7ffff7ffe000,
            0x7ffffffde000
        },
        {
            // snapshot_buf_offset
            0x0,
            0xFFF,
            0x2FFF,
            0x6FFF,
            0x8FFF,
            0x9FFF,
            0xAFFF
        },
        {
            // rdwr length
            0x1000,
            0x2000,
            0x4000,
            0x2000,
            0x1000,
            0x1000,
            0x21000
        }
    };  
 
    unsigned char* snapshot_buf = (unsigned char*)malloc(0x2C000);
 
    // this is just /proc/$pid/mem
    char proc_mem[0x20] = { 0 };
    sprintf(proc_mem, "/proc/%d/mem", child_pid);
 
    // open /proc/$pid/mem for reading
    // hardcoded offsets are from typical /proc/$pid/maps at main()
    int mem_fd = open(proc_mem, O_RDONLY);
    if (mem_fd == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("open");
        exit(errno);
    }
 
    // this loop will:
    //  -- go to an offset within /proc/$pid/mem via lseek()
    //  -- read x-pages of memory from that offset into the snapshot buffer
    //  -- adjust the snapshot buffer offset so nothing is overwritten in it
    int lseek_result, bytes_read;
    for (int i = 0; i < 7; i++) {
        //printf("dragonfly> Reading from offset: %d\n", i+1);
        lseek_result = lseek(mem_fd, read_memory.maps_offset[i], SEEK_SET);
        if (lseek_result == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("lseek");
            exit(errno);
        }
 
        bytes_read = read(mem_fd,
            (unsigned char*)(snapshot_buf + read_memory.snapshot_buf_offset[i]),
            read_memory.rdwr_length[i]);
        if (bytes_read == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("read");
            exit(errno);
        }
    }
 
    close(mem_fd);
    return snapshot_buf;
}
```

You can see that I hardcoded all the offsets and the lengths of the sections. Keep in mind, this doesn't need to be fast. We're only capturing a snapshot once, so it's ok to interact with the file system. So we'll loop through these 7 offsets and lengths and write them all into a buffer called `snapshot_buf` which will be stored in our fuzzer's heap. So now we have both the register states and the memory states of our process as it begins `check_one` (our 'start' breakpoint). 

Let's now figure out how to restore the snapshot when we reach our 'end' breakpoint.

### Restoring Snapshot
To restore the process memory state, we could just write to `/proc/$pid/mem` the same way we read from it; however, this portion needs to be fast since we are doing this every fuzzing iteration now. Iteracting with the file system every fuzzing iteration will slow us down big time. Luckily, since Linux kernel version 3.2, there is support for a much faster, process-to-process, memory reading/writing API that we can leverage called [`process_vm_writev()`](https://linux.die.net/man/2/process_vm_writev). Since this process works directly with another process and doesn't traverse the kernel and doesn't involve the file system, it will greatly increase our write speeds.

It's kind of confusing looking at first but the man page example is really all you need to understand how it works, I've opted to just hardcode all of the offsets since this fuzzer is simply a POC. and we can restore the writable memory as follows:
```c
void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid) {
 
    ssize_t bytes_written = 0;
    // we're writing *from* 7 different offsets within snapshot_buf
    struct iovec local[7];
    // we're writing *to* 7 separate sections of writable memory here
    struct iovec remote[7];
 
    // this struct is the local buffer we want to write from into the 
    // struct that is 'remote' (ie, the child process where we'll overwrite
    // all of the non-heap writable memory sections that we parsed from 
    // proc/$pid/memory)
    local[0].iov_base = snapshot_buf;
    local[0].iov_len = 0x1000;
    local[1].iov_base = (unsigned char*)(snapshot_buf + 0xFFF);
    local[1].iov_len = 0x2000;
    local[2].iov_base = (unsigned char*)(snapshot_buf + 0x2FFF);
    local[2].iov_len = 0x4000;
    local[3].iov_base = (unsigned char*)(snapshot_buf + 0x6FFF);
    local[3].iov_len = 0x2000;
    local[4].iov_base = (unsigned char*)(snapshot_buf + 0x8FFF);
    local[4].iov_len = 0x1000;
    local[5].iov_base = (unsigned char*)(snapshot_buf + 0x9FFF);
    local[5].iov_len = 0x1000;
    local[6].iov_base = (unsigned char*)(snapshot_buf + 0xAFFF);
    local[6].iov_len = 0x21000;
 
    // just hardcoding the base addresses that are writable memory
    // that we gleaned from /proc/pid/maps and their lengths
    remote[0].iov_base = (void*)0x555555756000;
    remote[0].iov_len = 0x1000;
    remote[1].iov_base = (void*)0x7ffff7dcf000;
    remote[1].iov_len = 0x2000;
    remote[2].iov_base = (void*)0x7ffff7dd1000;
    remote[2].iov_len = 0x4000;
    remote[3].iov_base = (void*)0x7ffff7fe0000;
    remote[3].iov_len = 0x2000;
    remote[4].iov_base = (void*)0x7ffff7ffd000;
    remote[4].iov_len = 0x1000;
    remote[5].iov_base = (void*)0x7ffff7ffe000;
    remote[5].iov_len = 0x1000;
    remote[6].iov_base = (void*)0x7ffffffde000;
    remote[6].iov_len = 0x21000;
 
    bytes_written = process_vm_writev(child_pid, local, 7, remote, 7, 0);
    //printf("dragonfly> %ld bytes written\n", bytes_written);
}
```

So for 7 different writable sections, we'll write into the debuggee process at the offsets defined in `/proc/$pid/maps` from our `snapshot_buf` that has the pristine snapshot data. AND IT WILL BE FAST!

So now that we have the ability to restore the writable memory, we'll only need to restore the register states now and we'll be able to complete our rudimentary snapshot mechanism. That is easy using our `ptrace_helpers` defined functions and you can see the two function calls within the fuzzing loop as follows: 
```c
// restore writable memory from /proc/$pid/maps to its state at Start
restore_snapshot(snapshot_buf, child_pid);

// restore registers to their state at Start
set_regs(child_pid, snapshot_registers);
```

So that's how our snapshot process works and in my testing, we achieved about a 20-30x speed-up over the dumb fuzzer!

## Making our Dumb Fuzzer Smart
At this point, we still have a dumb fuzzer (albeit much faster now). We need to be able to track code coverage. A very simple way to do this would be to place a breakpoint at every 'basic block' between `check_one` and `exit` so that if we reach new code, a breakpoint will be reached and we can `do_something()` there. 

This is exactly what I did except for simplicity sake, I just placed 'dynamic' (code coverage) breakpoints at the entry points to `check_two` and `check_three`. When a 'dynamic' breakpoint is reached, we save the input that reached the code into an array of `char` pointers called the 'corpus' and we can now start mutating those saved inputs instead of just our 'prototype' input of `Canon_40D.jpg`. 

So our code coverage feedback mechanism will work like this:
1. Mutate prototype input and insert the fuzzcase into the heap
2. Resume debuggee
3. If 'dynamic breakpoint' reached, save input into corpus
4. If corpus > 0, randomly pick an input from the corpus or the prototype and repeat from step 1

We also have to remove the dynamic breakpoint so that we stop breaking on it. Good thing we already know how to do this well!

As you may remember from the last post, code coverage is crucial to our ability to crash this test binary `vuln` as it performs 3 byte comparisons that all must pass before it crashes. We determined mathematically last post that our chances of passing the first check is about **1 in 13 thousand** and our chances of passing the first two checks is about **1 in 170 million**. Because we're saving input off that passes `check_one` and mutating it further, we can reduce the probability of passing `check_two` down to something close to the **1 in 13 thousand** figure. This also applies to inputs that then pass `check_two` and we can therefore reach and pass `check_three` with ease. 

## Running The Fuzzer
The first stage of our fuzzer, which collects snapshot data and sets 'dynamic breakpoints' for code coverage, completes very quickly even though its not meant to be fast. This is because all the values are hardcoded since our target is extremely simple. In a complex multi-threaded target we would need some way to script the discovery of dynamic breakpoint addresses via Ghidra or `objdump` or something and we'd need to have that script write a configuration file for our fuzzer, but that's far off. For now, for a POC, this works fine. 

```
h0mbre@pwn:~/fuzzing/dragonfly_dir$ ./dragonfly 

dragonfly> debuggee pid: 12156
dragonfly> setting 'start/end' breakpoints:

   start-> 0x555555554b41
   end  -> 0x5555555548c0

dragonfly> set dynamic breakpoints: 

           0x555555554b7d
           0x555555554bb9

dragonfly> collecting snapshot data
dragonfly> snapshot collection complete
dragonfly> press any key to start fuzzing!
```

You can see that the fuzzer helpfully displays the 'start' and 'end' breakpoints as well as lists the 'dynamic breakpoints' for us so that we can check to see that they are correct before fuzzing. The fuzzer pauses and waits for us to press any key to start fuzzing. We can also see that the snapshot data collection has completed successfully so now we are broken on 'start' and have all the data we need to start fuzzing.

Once we press enter, we get a statistics output that shows us how the fuzzing is going:
```
dragonfly> stats (target:vuln, pid:12156)

fc/s       : 41720
crashes    : 5
iterations : 0.3m
coverage   : 2/2 (%100.00)
```

As you can see, it found both 'dynamic breakpoints' almost instantly and is currently running about 41k fuzzing iterations per second of CPU time (about 20-30x faster in wall time than our dumb fuzzer).

Most importantly, you can see that we were able to crash the binary 5 times already in just 300k iterations! We could've never done this with our previous fuzzer.

**vv CLICK THIS TO WATCH IT IN ACTION vv**

[![asciicast](https://asciinema.org/a/WJEXrsznf1GY3FLxAAf7TsNBi.png)](https://asciinema.org/a/WJEXrsznf1GY3FLxAAf7TsNBi)

## Conclusion
One of the biggest takeaways for me from doing this was just how much more performance you can squeeze out of a fuzzer if you just customize it for your target. Using out of the box frameworks like AFL is great and they are incredibly impressive tools, I hope this fuzzer will one day grow into something comparable. We were able to run about 20-30x faster than AFL for this really simple target and were able to crash it almost instantly with just a little bit of reverse engineering and customization. I thought this was really neat and instructive. In the future, when I adapt this fuzzer for a real target, I should be able to outperform frameworks again. 

## Ideas for Improvment
Where to begin? We have a lot of areas where we can improve but some immediate improvements that can be made are:
+ optimize performance by refactoring code, changing location of global variables
+ enabling the dynamic configuration of the fuzzer via a config file that can be created via a Python script
+ implementing more mutation methods
+ implementing more code coverage mechanisms
+ developing the fuzzer so that many instances can run in parallel and share discovered inputs/coverage data

Perhaps we will see these improvements in a subsequent post and the results of fuzzing a real target with the same general approach. Until then!

## Code
All of the code for this blogpost can be found here: https://github.com/h0mbre/Fuzzing/tree/master/Caveman4
