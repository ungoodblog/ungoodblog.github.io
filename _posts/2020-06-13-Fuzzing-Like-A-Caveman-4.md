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
First things first, our dumb fuzzer was slow as hell. If you remember, we were averaging about 1,500 fuzz cases per second with our dumb fuzzer. During my testing, AFL in QEMU mode (simulating not having source code available for compilation instrumentation) was hovering around 1,000 fuzz cases per second. This makes sense, since AFL does way more than our dumb fuzzer, especially in QEMU mode where we are emulating a CPU architecture and providing code coverage.

Our target binary would do the following: 
+ extract the bytes from a file on disk into a buffer
+ perform 3 checks on the buffer to see if the indexes that were checked matched hardcoded values
+ segfaulted if all checks were passed, exit if one of the checks failed

Our dumb fuzzer would do the following:
+ extract bytes from a valid jpeg on disk into a byte buffer
+ mutate 2% of the bytes in the buffer by random byte overwriting
+ write the mutated file to disk
+ feed the mutated file to the target binary by executing a `fork()` and `execvp()` each fuzzing iteration

As you can see, this is a lot of file system interactions and syscalls. 
