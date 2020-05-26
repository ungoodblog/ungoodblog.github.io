---
layout: single
title: "Fuzzing Like A Caveman 3: Understanding Why Code Coverage Matters, Maybe?"
date: 2020-05-26
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fuzzing
  - exif
  - parsing
  - C
---

## Introduction
In this episode of 'Fuzzing like a Caveman', we'll be continuing on our by noob for noobs fuzzing journey and trying to wrap our little baby fuzzing brains around the concept of code coverage and why its so important. As far as I know, code coverage is, at a high-level, the attempt made by fuzzers to track/increase how much of the target application's code is reached by the fuzzer's inputs. The idea being that the more code your fuzzer inputs reach, the greater the attack surface, the more comprehensive your testing is, and other big brain stuff that I don't understand yet. 

I've been working on my pwn skills, but taking short breaks for sanity to write some C and watch some @gamazolabs streams. @gamazolabs broke down the importance of code coverage during one of these streams, and I cannot for the life of me track down the clip, but I remembered it vaguely enough to set up some test cases just for my own testing to demonstrate why "dumb" fuzzers are so disadvantaged compared to code-coverage-guided fuzzers. Get ready for some (probably incorrect 🤣) 8th grade probability theory. By the end of this blog post, we should be able to at least understand, broadly, how state of the art fuzzers worked in 1990. 

## Our Fuzzer
We have this beautiful, error free, perfectly written, single-threaded jpeg mutation fuzzer that we've ported to C from our previous blog posts and tweaked a bit for the purposes of our experiments here. 
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h> 
#include <fcntl.h>

int crashes = 0;

struct ORIGINAL_FILE {
    char * data;
    size_t length;
};

struct ORIGINAL_FILE get_data(char* fuzz_target) {

    FILE *fileptr;
    char *clone_data;
    long filelen;

    // open file in binary read mode
    // jump to end of file, get length
    // reset pointer to beginning of file
    fileptr = fopen(fuzz_target, "rb");
    if (fileptr == NULL) {
        printf("[!] Unable to open fuzz target, exiting...\n");
        exit(1);
    }
    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);

    // cast malloc as char ptr
    // ptr offset * sizeof char = data in .jpeg
    clone_data = (char *)malloc(filelen * sizeof(char));

    // get length for struct returned
    size_t length = filelen * sizeof(char);

    // read in the data
    fread(clone_data, filelen, 1, fileptr);
    fclose(fileptr);

    struct ORIGINAL_FILE original_file;
    original_file.data = clone_data;
    original_file.length = length;

    return original_file;
}

void create_new(struct ORIGINAL_FILE original_file, size_t mutations) {

    //
    //----------------MUTATE THE BITS-------------------------
    //
    int* picked_indexes = (int*)malloc(sizeof(int)*mutations);
    for (int i = 0; i < (int)mutations; i++) {
        picked_indexes[i] = rand() % original_file.length;
    }

    char * mutated_data = (char*)malloc(original_file.length);
    memcpy(mutated_data, original_file.data, original_file.length);

    for (int i = 0; i < (int)mutations; i++) {
        char current = mutated_data[picked_indexes[i]];

        // figure out what bit to flip in this 'decimal' byte
        int rand_byte = rand() % 256;
        
        mutated_data[picked_indexes[i]] = (char)rand_byte;
    }

    //
    //---------WRITING THE MUTATED BITS TO NEW FILE-----------
    //
    FILE *fileptr;
    fileptr = fopen("mutated.jpeg", "wb");
    if (fileptr == NULL) {
        printf("[!] Unable to open mutated.jpeg, exiting...\n");
        exit(1);
    }
    // buffer to be written from,
    // size in bytes of elements,
    // how many elements,
    // where to stream the output to :)
    fwrite(mutated_data, 1, original_file.length, fileptr);
    fclose(fileptr);
    free(mutated_data);
    free(picked_indexes);
}

void exif(int iteration) {
    
    //fileptr = popen("exiv2 pr -v mutated.jpeg >/dev/null 2>&1", "r");
    char* file = "vuln";
    char* argv[3];
    argv[0] = "vuln";
    argv[1] = "mutated.jpeg";
    argv[2] = NULL;
    pid_t child_pid;
    int child_status;

    child_pid = fork();
    if (child_pid == 0) {
        
        // this means we're the child process
        int fd = open("/dev/null", O_WRONLY);

        // dup both stdout and stderr and send them to /dev/null
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        

        execvp(file, argv);
        // shouldn't return, if it does, we have an error with the command
        printf("[!] Unknown command for execvp, exiting...\n");
        exit(1);
    }
    else {
        // this is run by the parent process
        do {
            pid_t tpid = waitpid(child_pid, &child_status, WUNTRACED |
             WCONTINUED);
            if (tpid == -1) {
                printf("[!] Waitpid failed!\n");
                perror("waitpid");
            }
            if (WIFEXITED(child_status)) {
                //printf("WIFEXITED: Exit Status: %d\n", WEXITSTATUS(child_status));
            } else if (WIFSIGNALED(child_status)) {
                crashes++;
                int exit_status = WTERMSIG(child_status);
                printf("\r[>] Crashes: %d", crashes);
                fflush(stdout);
                char command[50];
                sprintf(command, "cp mutated.jpeg ccrashes/%d.%d", iteration, 
                exit_status);
                system(command);
            } else if (WIFSTOPPED(child_status)) {
                printf("WIFSTOPPED: Exit Status: %d\n", WSTOPSIG(child_status));
            } else if (WIFCONTINUED(child_status)) {
                printf("WIFCONTINUED: Exit Status: Continued.\n");
            }
        } while (!WIFEXITED(child_status) && !WIFSIGNALED(child_status));
    }
}

int main(int argc, char** argv) {

    if (argc < 3) {
        printf("Usage: ./cfuzz <valid jpeg> <num of fuzz iterations>\n");
        printf("Usage: ./cfuzz Canon_40D.jpg 10000\n");
        exit(1);
    }

    // get our random seed
    srand((unsigned)time(NULL));

    char* fuzz_target = argv[1];
    struct ORIGINAL_FILE original_file = get_data(fuzz_target);
    printf("[>] Size of file: %ld bytes.\n", original_file.length);
    size_t mutations = (original_file.length - 4) * .02;
    printf("[>] Flipping up to %ld bytes.\n", mutations);

    int iterations = atoi(argv[2]);
    printf("[>] Fuzzing for %d iterations...\n", iterations);
    for (int i = 0; i < iterations; i++) {
        create_new(original_file, mutations);
        exif(i);
    }
    
    printf("\n[>] Fuzzing completed, exiting...\n");
    return 0;
}
```

Not going to spend a lot of time on the fuzzer's features (what features?) here, but some important things about the fuzzer code:
+ it takes a file as input and copies the bytes from the file into a buffer
+ it calculates the length of the buffer in bytes, and then mutates 2% of the bytes by randomly overwriting them with arbitrary bytes
+ the function responsible for the mutation, `create_new`, doesn't keep track of what byte indexes were mutated so theoretically, the same index could be chosen for mutation multiple times, so really, the fuzzer mutates **up to** 2% of the bytes. 

### Small Detour, I Apologize 
We only have one mutation method here to keep things super simple, in doing so, I actually learned something really useful that I hadn't clearly thought out previously. In a previous post I wondered, embarrassingly, aloud and in print, how much different random bit flipping was from random byte overwriting (flipping?). Well, it turns out, they are super different. Let's take a minute to see how. 

Let's say we're mutating an array of bytes called `bytes`. We're mutating index 5. `bytes[5]` == `\x41` `(65 in decimal)` in the unmutated, pristine original file. If we *only* bit flip, we are super limited in how much we can mutate this byte. 65 is `01000001` in binary. Let's just go through at see how much it changes from arbitrarily flipping one bit:
+ Flipping first bit: `11000001` = 193,
+ Flipping second bit: `00000001` = 1,
+ Flipping third bit: `01100001` = 97,
+ Flipping fourth bit: `01010001` = 81,
+ Flipping fifth bit: `01001001` = 73,
+ Flipping sixth bit: `01000101` = 69,
+ Flipping seventh bit: `01000011` = 67, and
+ Flipping eighth bit: `010000001` = 64.

As you can see, we're locked in to a severely limited amount of possibilities. 

## Vulnerable Program
I wrote a simple cartoonish program to demonstrate how hard it can be for "dumb" fuzzers to find bugs. Imagine a target a application that has several decision trees in the disassembly map view of the binary. The application performs 2-3 checks on the input to see if it meets certain criteria before passing the input to some sort of vulnerable function. Here is what I mean:

![](/assets/images/AWE/tree.PNG)

Our program does this exact thing, it retrieves the bytes of an input file and checks the bytes at an index 1/3rd of the file length, 1/2 of the file length, and 2/3 of the file length to see if the bytes in those positions match some hardcoded values (arbitrary). If all the checks are passed, the application copies the byte buffer into a small buffer causing a segfault to simulate a vulnerable function. Here is our program:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct ORIGINAL_FILE {
    char * data;
    size_t length;
};

struct ORIGINAL_FILE get_bytes(char* fileName) {

    FILE *filePtr;
    char* buffer;
    long fileLen;

    filePtr = fopen(fileName, "rb");
    if (!filePtr) {
        printf("[>] Unable to open %s\n", fileName);
        exit(-1);
    }
    
    if (fseek(filePtr, 0, SEEK_END)) {
        printf("[>] fseek() failed, wtf?\n");
        exit(-1);
    }

    fileLen = ftell(filePtr);
    if (fileLen == -1) {
        printf("[>] ftell() failed, wtf?\n");
        exit(-1);
    }

    errno = 0;
    rewind(filePtr);
    if (errno) {
        printf("[>] rewind() failed, wtf?\n");
        exit(-1);
    }

    long trueSize = fileLen * sizeof(char);
    printf("[>] %s is %ld bytes.\n", fileName, trueSize);
    buffer = (char *)malloc(fileLen * sizeof(char));
    fread(buffer, fileLen, 1, filePtr);
    fclose(filePtr);

    struct ORIGINAL_FILE original_file;
    original_file.data = buffer;
    original_file.length = trueSize;

    return original_file;
}

void check_one(char* buffer, int check) {

    if (buffer[check] == '\x6c') {
        return;
    }
    else {
        printf("[>] Check 1 failed.\n");
        exit(-1);
    }
}

void check_two(char* buffer, int check) {

    if (buffer[check] == '\x57') {
        return;
    }
    else {
        printf("[>] Check 2 failed.\n");
        exit(-1);
    }
}

void check_three(char* buffer, int check) {

    if (buffer[check] == '\x21') {
        return;
    }
    else {
        printf("[>] Check 3 failed.\n");
        exit(-1);
    }
}

void vuln(char* buffer, size_t length) {

    printf("[>] Passed all checks!\n");
    char vulnBuff[20];

    memcpy(vulnBuff, buffer, length);

}

int main(int argc, char *argv[]) {
    
    if (argc < 2 || argc > 2) {
        printf("[>] Usage: vuln example.txt\n");
        exit(-1);
    }

    char *filename = argv[1];
    printf("[>] Analyzing file: %s.\n", filename);

    struct ORIGINAL_FILE original_file = get_bytes(filename);

    int checkNum1 = (int)(original_file.length * .33);
    printf("[>] Check 1 no.: %d\n", checkNum1);

    int checkNum2 = (int)(original_file.length * .5);
    printf("[>] Check 2 no.: %d\n", checkNum2);

    int checkNum3 = (int)(original_file.length * .67);
    printf("[>] Check 3 no.: %d\n", checkNum3);

    check_one(original_file.data, checkNum1);
    check_two(original_file.data, checkNum2);
    check_three(original_file.data, checkNum3);
    
    vuln(original_file.data, original_file.length);
    

    return 0;
}
```

Our sample file, which we'll mutate and feed to this vulnerable application is still the same file from the previous posts, the `Canon_40D.jpg` file with exif data.
```
h0mbre@pwn:~/fuzzing$ file Canon_40D.jpg 
Canon_40D.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=11, manufacturer=Canon, model=Canon EOS 40D, orientation=upper-left, xresolution=166, yresolution=174, resolutionunit=2, software=GIMP 2.4.5, datetime=2008:07:31 10:38:11, GPS-Data], baseline, precision 8, 100x68, frames 3
h0mbre@pwn:~/fuzzing$ ls -lah Canon_40D.jpg 
-rw-r--r-- 1 h0mbre h0mbre 7.8K May 25 06:21 Canon_40D.jpg
```

The file is 7958 bytes long. Let's feed it to the vulnerable program and see what indexes are chosen for the checks:
```
h0mbre@pwn:~/fuzzing$ vuln Canon_40D.jpg 
[>] Analyzing file: Canon_40D.jpg.
[>] Canon_40D.jpg is 7958 bytes.
[>] Check 1 no.: 2626
[>] Check 2 no.: 3979
[>] Check 3 no.: 5331
[>] Check 1 failed.
```

So we can see that indexes `2626`, `3979`, and `5331` were chosen for testing and that the file failed the first check as the byte at that position wasn't `\x6c`. 

## Experiment 1: Passing Only One Check
Let's take away checks two and three and see how our dumb fuzzer performs against the binary when we only have to pass one check. 

I'll comment out checks two and three:
```
check_one(original_file.data, checkNum1);
//check_two(original_file.data, checkNum2);
//check_three(original_file.data, checkNum3);
    
vuln(original_file.data, original_file.length);
```

And so now, we'll take our unaltered jpeg, which naturally does not pass the first check, and have our fuzzer mutate it and send it to the vulnerable application hoping for crashes. Remember, that the fuzzer mutates up to 159 bytes of the 7958 bytes total each fuzzing iteration. If the fuzzer randomly inserts an `\x6c` into index `2626`, we will pass the first check and execution will pass to the vulnerable function and cause a crash. Let's run our dumb fuzzer 1 million times and see how many crashes we get. 
