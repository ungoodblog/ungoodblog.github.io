---
layout: single
title: "Fuzzing Like A Caveman 2: Improving Performance"
date: 2020-04-08
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fuzzing
  - exif
  - parsing
  - Python
  - jpeg
  - mutation
  - C++
---

## Introduction
In this episode of 'Fuzzing like a Caveman' we'll just be looking at improving the performance of our previous fuzzer. This means there won't be any wholesale changes, we're simply looking to improve upon what we already had in the previous post. This means we'll still end up walking away from this blogpost with a very basic mutation fuzzer (please let it be faster!!) and hopefully some more bugs on a different target. We won't really tinker with multi-threading or multi-processing in this post, we will save that for subsequent fuzzing posts. 

I feel the need to add a **DISCLAIMER** here that I am not a professional developer, far from it. I'm simply not experienced enough with programming at this point to recognize opportunities to improve performance the way a more seasoned programmer would. I'm going to use my crude skillset and my limited knowledge of programming to improve our previous fuzzer, that's it. The code produced will not be pretty, it will not be perfect, but it will be *better* than what we had in the previous post. It should also be mentioned that all testing was done on VMWare Workstation on an x86 Kali VM with 1 CPU and 1 Core. 

Let's take a moment to define 'better' in the context of this blog post as well. What I mean by 'better' here is that we can iterate through n fuzzing iterations faster, that's it. We'll take the time to completely rewrite the fuzzer, use a cool language, pick a hardened target, and employ more advanced fuzzing techniques at a later date. :)

***Obviously, if you haven't read the previous post you will be LOST!***

## Analyzing Our Fuzzer 
Our last fuzzer, quite plainly, worked! We found some bugs in our target. But we knew we left some optimizations on the table when we turned in our homework. Let's again look at the fuzzer from the last post (with minor changes for testing purposes):
```python
#!/usr/bin/env python3

import sys
import random
from pexpect import run
from pipes import quote

# read bytes from our valid JPEG and return them in a mutable bytearray 
def get_bytes(filename):

	f = open(filename, "rb").read()

	return bytearray(f)

def bit_flip(data):

	num_of_flips = int((len(data) - 4) * .01)

	indexes = range(4, (len(data) - 4))

	chosen_indexes = []

	# iterate selecting indexes until we've hit our num_of_flips number
	counter = 0
	while counter < num_of_flips:
		chosen_indexes.append(random.choice(indexes))
		counter += 1

	for x in chosen_indexes:
		current = data[x]
		current = (bin(current).replace("0b",""))
		current = "0" * (8 - len(current)) + current
		
		indexes = range(0,8)

		picked_index = random.choice(indexes)

		new_number = []

		# our new_number list now has all the digits, example: ['1', '0', '1', '0', '1', '0', '1', '0']
		for i in current:
			new_number.append(i)

		# if the number at our randomly selected index is a 1, make it a 0, and vice versa
		if new_number[picked_index] == "1":
			new_number[picked_index] = "0"
		else:
			new_number[picked_index] = "1"

		# create our new binary string of our bit-flipped number
		current = ''
		for i in new_number:
			current += i

		# convert that string to an integer
		current = int(current,2)

		# change the number in our byte array to our new number we just constructed
		data[x] = current

	return data

def magic(data):

	magic_vals = [
	(1, 255),
	(1, 255),
	(1, 127),
	(1, 0),
	(2, 255),
	(2, 0),
	(4, 255),
	(4, 0),
	(4, 128),
	(4, 64),
	(4, 127)
	]

	picked_magic = random.choice(magic_vals)

	length = len(data) - 8
	index = range(0, length)
	picked_index = random.choice(index)

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (1, )
	if picked_magic[0] == 1:
		if picked_magic[1] == 255:			# 0xFF
			data[picked_index] = 255
		elif picked_magic[1] == 127:		# 0x7F
			data[picked_index] = 127
		elif picked_magic[1] == 0:			# 0x00
			data[picked_index] = 0

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (2, )
	elif picked_magic[0] == 2:
		if picked_magic[1] == 255:			# 0xFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
		elif picked_magic[1] == 0:			# 0x0000
			data[picked_index] = 0
			data[picked_index + 1] = 0

	# here we are hardcoding all of the byte overwrites for all of the tuples that being (4, )
	elif picked_magic[0] == 4:
		if picked_magic[1] == 255:			# 0xFFFFFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		elif picked_magic[1] == 0:			# 0x00000000
			data[picked_index] = 0
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 128:		# 0x80000000
			data[picked_index] = 128
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 64:			# 0x40000000
			data[picked_index] = 64
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 127:		# 0x7FFFFFFF
			data[picked_index] = 127
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		
	return data

# create new jpg with mutated data
def create_new(data):

	f = open("mutated.jpg", "wb+")
	f.write(data)
	f.close()

def exif(counter,data):

    command = "exif mutated.jpg -verbose"

    out, returncode = run("sh -c " + quote(command), withexitstatus=1)

    if b"Segmentation" in out:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    #if counter % 100 == 0:
    #	print(counter, end="\r")

if len(sys.argv) < 2:
	print("Usage: JPEGfuzz.py <valid_jpg>")

else:
	filename = sys.argv[1]
	counter = 0
	while counter < 1000:
		data = get_bytes(filename)
		functions = [0, 1]
		picked_function = random.choice(functions)
		picked_function = 1
		if picked_function == 0:
			mutated = magic(data)
			create_new(mutated)
			exif(counter,mutated)
		else:
			mutated = bit_flip(data)
			create_new(mutated)
			exif(counter,mutated)

		counter += 1
```

You may notice a few changes. We've:
+ commented out the print statement for  the iterations counter every 100 iterations,
+ added print statements to notify us of any Segfaults,
+ hardcoded 1k iterations,
+ added this line: `picked_function = 1` temporarily so that we eliminate any randomness in our testing and we only stick to one mutation method (`bit_flip()`)

Let's run this version of our fuzzer with some profiling instrumentation and we can really analyze how much time we spend where in our program's execution. 

We can make use of the `cProfile` Python module and see where we spend our time during 1,000 fuzzing iterations. The program takes a filepath argument to a valid JPEG file if you remember, so our complete command line syntax will be: `python3 -m cProfile -s cumtime JPEGfuzzer.py ~/jpegs/Canon_40D.jpg`.

**It should also be noted that adding this `cProfile` instrumentation could slow down performance. I tested without it and for the iteration sizes we use in this post, it didn't seem to make a significant difference.**

After letting this run, we see our program output and we get to see where we spent the most time during execution. 
```
2476093 function calls (2474812 primitive calls) in 122.084 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     33/1    0.000    0.000  122.084  122.084 {built-in method builtins.exec}
        1    0.108    0.108  122.084  122.084 blog.py:3(<module>)
     1000    0.090    0.000  118.622    0.119 blog.py:140(exif)
     1000    0.080    0.000  118.452    0.118 run.py:7(run)
     5432  103.761    0.019  103.761    0.019 {built-in method time.sleep}
     1000    0.028    0.000  100.923    0.101 pty_spawn.py:316(close)
     1000    0.025    0.000  100.816    0.101 ptyprocess.py:387(close)
     1000    0.061    0.000    9.949    0.010 pty_spawn.py:36(__init__)
     1000    0.074    0.000    9.764    0.010 pty_spawn.py:239(_spawn)
     1000    0.041    0.000    8.682    0.009 pty_spawn.py:312(_spawnpty)
     1000    0.266    0.000    8.641    0.009 ptyprocess.py:178(spawn)
     1000    0.011    0.000    7.491    0.007 spawnbase.py:240(expect)
     1000    0.036    0.000    7.479    0.007 spawnbase.py:343(expect_list)
     1000    0.128    0.000    7.409    0.007 expect.py:91(expect_loop)
     6432    6.473    0.001    6.473    0.001 {built-in method posix.read}
     5432    0.089    0.000    3.818    0.001 pty_spawn.py:415(read_nonblocking)
     7348    0.029    0.000    3.162    0.000 utils.py:130(select_ignore_interrupts)
     7348    3.127    0.000    3.127    0.000 {built-in method select.select}
     1000    0.790    0.001    1.777    0.002 blog.py:15(bit_flip)
     1000    0.015    0.000    1.311    0.001 blog.py:134(create_new)
     1000    0.100    0.000    1.101    0.001 pty.py:79(fork)
     1000    1.000    0.001    1.000    0.001 {built-in method posix.forkpty}
-----SNIP-----
```
For this type of analysis, we don't really care about how many segfaults we had since we're not really tinkering much with the mutation methods or comparing different methods. Granted there will be some randomness here, as a crash would necessitate extra processing, but this will do for now. 

I snipped only the sections of code where we spent more than 1.0 seconds cumulatively. You can see we spent by far the most time in `blog.py:140(exif)`. A whopping 118 seconds out of 122 seconds total. Our `exif()` function seems to be a major problem in our performance. 

We can see that most of the time we spent underneath that function was directly related to the function, we see plenty of appeals to the `pty` module from our `pexpect` usage. Let's rewrite our function using `Popen` from the `subprocess` module and see if we can improve performance here!

Here is our redefined `exif()` function:
```python
def exif(counter,data):

    p = Popen(["exif", "mutated.jpg", "-verbose"], stdout=PIPE, stderr=PIPE)
    (out,err) = p.communicate()

    if p.returncode == -11:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    #if counter % 100 == 0:
    #	print(counter, end="\r")
 ```

Here is our performance report:
```
2065580 function calls (2065443 primitive calls) in 2.756 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000    2.756    2.756 {built-in method builtins.exec}
        1    0.038    0.038    2.756    2.756 subpro.py:3(<module>)
     1000    0.020    0.000    1.917    0.002 subpro.py:139(exif)
     1000    0.026    0.000    1.121    0.001 subprocess.py:681(__init__)
     1000    0.099    0.000    1.045    0.001 subprocess.py:1412(_execute_child)
 -----SNIP-----
 ```
 
 What a difference. This fuzzer, with the redefined `exif()` function performed the same amount of work in only 2 seconds!! That's insane! The old fuzzer: 122 seconds, new fuzzer: 2.7 seconds.
 
## Improving Further in Python
Let's try to continue improving our fuzzer all within Python. First, let's get a good benchmark for us to perform against. We'll get our optimized Python fuzzer to iterate through 50,000 fuzzing iterations and we'll use the `cProfile` module again to get some fine-grained statistics about where we spend our time. 
```
102981395 function calls (102981258 primitive calls) in 141.488 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000  141.488  141.488 {built-in method builtins.exec}
        1    1.724    1.724  141.488  141.488 subpro.py:3(<module>)
    50000    0.992    0.000  102.588    0.002 subpro.py:139(exif)
    50000    1.248    0.000   61.562    0.001 subprocess.py:681(__init__)
    50000    5.034    0.000   57.826    0.001 subprocess.py:1412(_execute_child)
    50000    0.437    0.000   39.586    0.001 subprocess.py:920(communicate)
    50000    2.527    0.000   39.064    0.001 subprocess.py:1662(_communicate)
   208254   37.508    0.000   37.508    0.000 {built-in method posix.read}
   158238    0.577    0.000   28.809    0.000 selectors.py:402(select)
   158238   28.131    0.000   28.131    0.000 {method 'poll' of 'select.poll' objects}
    50000   11.784    0.000   25.819    0.001 subpro.py:14(bit_flip)
  7950000    3.666    0.000   10.431    0.000 random.py:256(choice)
    50000    8.421    0.000    8.421    0.000 {built-in method _posixsubprocess.fork_exec}
    50000    0.162    0.000    7.358    0.000 subpro.py:133(create_new)
  7950000    4.096    0.000    6.130    0.000 random.py:224(_randbelow)
   203090    5.016    0.000    5.016    0.000 {built-in method io.open}
    50000    4.211    0.000    4.211    0.000 {method 'close' of '_io.BufferedRandom' objects}
    50000    1.643    0.000    4.194    0.000 os.py:617(get_exec_path)
    50000    1.733    0.000    3.356    0.000 subpro.py:8(get_bytes)
 35866791    2.635    0.000    2.635    0.000 {method 'append' of 'list' objects}
   100000    0.070    0.000    1.960    0.000 subprocess.py:1014(wait)
   100000    0.252    0.000    1.902    0.000 selectors.py:351(register)
   100000    0.444    0.000    1.890    0.000 subprocess.py:1621(_wait)
   100000    0.675    0.000    1.583    0.000 selectors.py:234(register)
   350000    0.432    0.000    1.501    0.000 subprocess.py:1471(<genexpr>)
 12074141    1.434    0.000    1.434    0.000 {method 'getrandbits' of '_random.Random' objects}
    50000    0.059    0.000    1.358    0.000 subprocess.py:1608(_try_wait)
    50000    1.299    0.000    1.299    0.000 {built-in method posix.waitpid}
   100000    0.488    0.000    1.058    0.000 os.py:674(__getitem__)
   100000    1.017    0.000    1.017    0.000 {method 'close' of '_io.BufferedReader' objects}
-----SNIP-----
```

50,000 iterations took us a grand total of 141 seconds, this is great performance compared to what we were dealing with. We previously took 122 seconds to do 1,000 iterations! Once again filtering on only time where we spent over 1.0 seconds, we see that we again spent most of our time in `exif()` but we also see some performance issues in `bit_flip()` as we spent 25 cumulative seconds there. Let's try to optimize that function a bit. 

Let's go ahead and repost what the old `bit_flip()` function looked like:
```python
def bit_flip(data):

	num_of_flips = int((len(data) - 4) * .01)

	indexes = range(4, (len(data) - 4))

	chosen_indexes = []

	# iterate selecting indexes until we've hit our num_of_flips number
	counter = 0
	while counter < num_of_flips:
		chosen_indexes.append(random.choice(indexes))
		counter += 1

	for x in chosen_indexes:
		current = data[x]
		current = (bin(current).replace("0b",""))
		current = "0" * (8 - len(current)) + current
		
		indexes = range(0,8)

		picked_index = random.choice(indexes)

		new_number = []

		# our new_number list now has all the digits, example: ['1', '0', '1', '0', '1', '0', '1', '0']
		for i in current:
			new_number.append(i)

		# if the number at our randomly selected index is a 1, make it a 0, and vice versa
		if new_number[picked_index] == "1":
			new_number[picked_index] = "0"
		else:
			new_number[picked_index] = "1"

		# create our new binary string of our bit-flipped number
		current = ''
		for i in new_number:
			current += i

		# convert that string to an integer
		current = int(current,2)

		# change the number in our byte array to our new number we just constructed
		data[x] = current

	return data
```

This function is admittedly a bit clumsy. We can simplify it greatly by utilizing better logic. I find this is often the case with programming in my limited experience, you can have all of the fancy esoteric programming knowledge you want, but if the logic behind your program is unsound, then the program's performance will suffer. 

Let's reduce the amount of type conversions we do, for instance ints to str or vice versa, and let's just get less code into our editor. We can accomplish what we want with a re-defined `bit_flip()` function as follows: 
```python
def bit_flip(data):

	length = len(data) - 4

	num_of_flips = int(length * .01)

	picked_indexes = []
	
	flip_array = [1,2,4,8,16,32,64,128]

	counter = 0
	while counter < num_of_flips:
		picked_indexes.append(random.choice(range(0,length)))
		counter += 1


	for x in picked_indexes:
		mask = random.choice(flip_array)
		data[x] = data[x] ^ mask

	return data
```

If we employ this new function and monitor the results, we get a performance grade of:
```
59376275 function calls (59376138 primitive calls) in 135.582 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000  135.582  135.582 {built-in method builtins.exec}
        1    1.940    1.940  135.582  135.582 subpro.py:3(<module>)
    50000    0.978    0.000  107.857    0.002 subpro.py:111(exif)
    50000    1.450    0.000   64.236    0.001 subprocess.py:681(__init__)
    50000    5.566    0.000   60.141    0.001 subprocess.py:1412(_execute_child)
    50000    0.534    0.000   42.259    0.001 subprocess.py:920(communicate)
    50000    2.827    0.000   41.637    0.001 subprocess.py:1662(_communicate)
   199549   38.249    0.000   38.249    0.000 {built-in method posix.read}
   149537    0.555    0.000   30.376    0.000 selectors.py:402(select)
   149537   29.722    0.000   29.722    0.000 {method 'poll' of 'select.poll' objects}
    50000    3.993    0.000   14.471    0.000 subpro.py:14(bit_flip)
  7950000    3.741    0.000   10.316    0.000 random.py:256(choice)
    50000    9.973    0.000    9.973    0.000 {built-in method _posixsubprocess.fork_exec}
    50000    0.163    0.000    7.034    0.000 subpro.py:105(create_new)
  7950000    3.987    0.000    5.952    0.000 random.py:224(_randbelow)
   202567    4.966    0.000    4.966    0.000 {built-in method io.open}
    50000    4.042    0.000    4.042    0.000 {method 'close' of '_io.BufferedRandom' objects}
    50000    1.539    0.000    3.828    0.000 os.py:617(get_exec_path)
    50000    1.843    0.000    3.607    0.000 subpro.py:8(get_bytes)
   100000    0.074    0.000    2.133    0.000 subprocess.py:1014(wait)
   100000    0.463    0.000    2.059    0.000 subprocess.py:1621(_wait)
   100000    0.274    0.000    2.046    0.000 selectors.py:351(register)
   100000    0.782    0.000    1.702    0.000 selectors.py:234(register)
    50000    0.055    0.000    1.507    0.000 subprocess.py:1608(_try_wait)
    50000    1.452    0.000    1.452    0.000 {built-in method posix.waitpid}
   350000    0.424    0.000    1.436    0.000 subprocess.py:1471(<genexpr>)
 12066317    1.339    0.000    1.339    0.000 {method 'getrandbits' of '_random.Random' objects}
   100000    0.466    0.000    1.048    0.000 os.py:674(__getitem__)
   100000    1.014    0.000    1.014    0.000 {method 'close' of '_io.BufferedReader' objects}
-----SNIP-----
```

As you can see from the metrics, we only spend 14 cumulative seconds in `bit_flip()` at this point! In our last go-round, we spent 25 seconds here, this is almost twice as fast at this point. We're doing a good job of optimizing in my opinion here. 

Now that we have our ideal Python benchmark (keep in mind there might be opportunities for multi-processing or multi-threading but let's save this idea for another time), let's go ahead and port our fuzzer to a new language, C++ and test the performance.

## New Fuzzer in C++
To get started, let's just go ahead and flat out run our newly optimized python fuzzer through 100,000 fuzzing iterations and see how long in total it takes. 
```
118749892 function calls (118749755 primitive calls) in 256.881 seconds
```

100k iterations in only 256 seconds! That destroys our previous fuzzer.

That will be our benchmark we try to beat in C++. Now, as unfamiliar as I am with the nuances of Python development, multiply that by 10 and you'll have my unfamiliarity with C++. This code might be laughable to some, but it's the best I could manage at the present moment and we can explain each function as it relates to our previous Python code. 

Let's go through, function by function, and describe their implementation. 

```cpp
//
// this function simply creates a stream by opening a file in binary mode;
// finds the end of file, creates a string 'data', resizes data to be the same
// size as the file moves the file pointer back to the beginning of the file;
// reads the data from the into the data string;
//
std::string get_bytes(std::string filename)
{
	std::ifstream fin(filename, std::ios::binary);

	if (fin.is_open())
	{
		fin.seekg(0, std::ios::end);
		std::string data;
		data.resize(fin.tellg());
		fin.seekg(0, std::ios::beg);
		fin.read(&data[0], data.size());

		return data;
	}

	else
	{
		std::cout << "Failed to open " << filename << ".\n";
		exit(1);
	}

}
```
This function, as my comment says, simply retrives a byte string from our target file, which in the case of our testing will still be `Canon_40D.jpg`. 

```cpp
//
// this will take 1% of the bytes from our valid jpeg and
// flip a random bit in the byte and return the altered string
//
std::string bit_flip(std::string data)
{
	
	int size = (data.length() - 4);
	int num_of_flips = (int)(size * .01);

	// get a vector full of 1% of random byte indexes
	std::vector<int> picked_indexes;
	for (int i = 0; i < num_of_flips; i++)
	{
		int picked_index = rand() % size;
		picked_indexes.push_back(picked_index);
	}

	// iterate through the data string at those indexes and flip a bit
	for (int i = 0; i < picked_indexes.size(); ++i)
	{
		int index = picked_indexes[i];
		char current = data.at(index);
		int decimal = ((int)current & 0xff);
		
		int bit_to_flip = rand() % 8;
		
		decimal ^= 1 << bit_to_flip;
		decimal &= 0xff;
		
		data[index] = (char)decimal;
	}

	return data;

}
```

This function is a direct equivalent of our `bit_flip()` function in our Python script. 

```cpp
//
// takes mutated string and creates new jpeg with it;
//
void create_new(std::string mutated)
{
	std::ofstream fout("mutated.jpg", std::ios::binary);

	if (fout.is_open())
	{
		fout.seekp(0, std::ios::beg);
		fout.write(&mutated[0], mutated.size());
	}
	else
	{
		std::cout << "Failed to create mutated.jpg" << ".\n";
		exit(1);
	}

}
```

This function will simply create a temporary `mutated.jpg` file, similar to our `create_new()` function that we had in the Python script. 

```cpp
//
// function to run a system command and store the output as a string;
// https://www.jeremymorgan.com/tutorials/c-programming/how-to-capture-the-output-of-a-linux-command-in-c/
//
std::string get_output(std::string cmd)
{
	std::string output;
	FILE * stream;
	char buffer[256];

	stream = popen(cmd.c_str(), "r");
	if (stream)
	{
		while (!feof(stream))
			if (fgets(buffer, 256, stream) != NULL) output.append(buffer);
				pclose(stream);
	}

	return output;

}

//
// we actually run our exiv2 command via the get_output() func;
// retrieve the output in the form of a string and then we can parse the string;
// we'll save all the outputs that result in a segfault or floating point except;
//
void exif(std::string mutated, int counter)
{
	std::string command = "exif mutated.jpg -verbose 2>&1";

	std::string output = get_output(command);

	std::string segfault = "Segmentation";
	std::string floating_point = "Floating";

	std::size_t pos1 = output.find(segfault);
	std::size_t pos2 = output.find(floating_point);

	if (pos1 != -1)
	{
		std::cout << "Segfault!\n";
		std::ostringstream oss;
		oss << "/root/cppcrashes/crash." << counter << ".jpg";
		std::string filename = oss.str();
		std::ofstream fout(filename, std::ios::binary);

		if (fout.is_open())
			{
				fout.seekp(0, std::ios::beg);
				fout.write(&mutated[0], mutated.size());
			}
		else
		{
			std::cout << "Failed to create " << filename << ".jpg" << ".\n";
			exit(1);
		}
	}
	else if (pos2 != -1)
	{
		std::cout << "Floating Point!\n";
		std::ostringstream oss;
		oss << "/root/cppcrashes/crash." << counter << ".jpg";
		std::string filename = oss.str();
		std::ofstream fout(filename, std::ios::binary);

		if (fout.is_open())
			{
				fout.seekp(0, std::ios::beg);
				fout.write(&mutated[0], mutated.size());
			}
		else
		{
			std::cout << "Failed to create " << filename << ".jpg" << ".\n";
			exit(1);
		}
	}
}
```

These two functions work together. `get_output` takes a C++ string as a parameter and will run that command on the operating system and capture the output. The function then returns the output as a string to the calling function `exif()`. 

`exif()` will take the output and look for `Segmentation fault` or `Floating point exception` errors and then if found, will write those bytes to a file and save them as a `crash.<counter>.jpg` file. Very similar to our Python fuzzer.

```cpp
//
// simply generates a vector of strings that are our 'magic' values;
//
std::vector<std::string> vector_gen()
{
	std::vector<std::string> magic;

	using namespace std::string_literals;

	magic.push_back("\xff");
	magic.push_back("\x7f");
	magic.push_back("\x00"s);
	magic.push_back("\xff\xff");
	magic.push_back("\x7f\xff");
	magic.push_back("\x00\x00"s);
	magic.push_back("\xff\xff\xff\xff");
	magic.push_back("\x80\x00\x00\x00"s);
	magic.push_back("\x40\x00\x00\x00"s);
	magic.push_back("\x7f\xff\xff\xff");

	return magic;
}

//
// randomly picks a magic value from the vector and overwrites that many bytes in the image;
//
std::string magic(std::string data, std::vector<std::string> magic)
{
	
	int vector_size = magic.size();
	int picked_magic_index = rand() % vector_size;
	std::string picked_magic = magic[picked_magic_index];
	int size = (data.length() - 4);
	int picked_data_index = rand() % size;
	data.replace(picked_data_index, magic[picked_magic_index].length(), magic[picked_magic_index]);

	return data;

}

//
// returns 0 or 1;
//
int func_pick()
{
	int result = rand() % 2;

	return result;
}
```

These functions are pretty similar to our Python implementation as well. `vector_gen()` pretty much just creates our vector of 'magic values' and then subsequent functions like `magic()` use the vector to randomly pick an index and then overwrite data in the valid jpeg with mutated data accordingly. 

`func_pick()` is very simple and just returns a `0` or a `1` so that our fuzzer can randomly `bit_flip()` or `magic()` mutate our valid jpeg. To keep things consistent, let's have our fuzzer only choose `bit_flip()` for the time being by adding a temporary line of `function = 1` to our program so that we match our Python testing. 

Here is our `main()` function which executes all of our code so far:
```cpp
int main(int argc, char** argv)
{

	if (argc < 3)
	{
		std::cout << "Usage: ./cppfuzz <valid jpeg> <number_of_fuzzing_iterations>\n";
		std::cout << "Usage: ./cppfuzz Canon_40D.jpg 10000\n";
		return 1;
	}

	// start timer
	auto start = std::chrono::high_resolution_clock::now();

	// initialize our random seed
	srand((unsigned)time(NULL));

	// generate our vector of magic numbers
	std::vector<std::string> magic_vector = vector_gen();

	std::string filename = argv[1];
	int iterations = atoi(argv[2]);

	int counter = 0;
	while (counter < iterations)
	{

		std::string data = get_bytes(filename);

		int function = func_pick();
		function = 1;
		if (function == 0)
		{
			// utilize the magic mutation method; create new jpg; send to exiv2
			std::string mutated = magic(data, magic_vector);
			create_new(mutated);
			exif(mutated,counter);
			counter++;
		}
		else
		{
			// utilize the bit flip mutation; create new jpg; send to exiv2
			std::string mutated = bit_flip(data);
			create_new(mutated);
			exif(mutated,counter);
			counter++;
		}
	}

	// stop timer and print execution time
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
	std::cout << "Execution Time: " << duration.count() << "ms\n";

	return 0;
}
```

We get a valid JPEG to mutate and a number of fuzzing iterations from the command line arguments. We then have some timing mechanisms in place with the `std::chrono` namespace to time how long our program takes to execute. 

We're kind of cheating here by only selecting `bit_flip()` type mutations, but that is what we did in Python as well so we want an 'Apples to Apples' comparison. 

Let's go ahead and run this for 100,000 iterations and compare it our Python fuzzer benchmark of 256 seconds.

Once we run our C++ fuzzer, we get a printed time spent in milleseconds of: `Execution Time: 172638ms` or 172 seconds.

So we comfortably destroyed our Python fuzzer with our new C++ fuzzer! This is so exciting. Let's go ahead and do some math here: 172/256 = 67%. So we're roughly 33% faster with our C++ implementation. (God I hope you aren't some 200 IQ math genius reading this and throwing up on your keyboard).

Let's take our optimized Python and C++ fuzzers and take on a new target!

## Selecting a New Victim
Looking at what comes pre-installed on Kali Linux since that's our operating environment, let's take a peek at `exiv2` which is found in `/usr/bin/exiv2`. 

```
root@kali:~# exiv2 -h
Usage: exiv2 [ options ] [ action ] file ...

Manipulate the Exif metadata of images.

Actions:
  ad | adjust   Adjust Exif timestamps by the given time. This action
                requires at least one of the -a, -Y, -O or -D options.
  pr | print    Print image metadata.
  rm | delete   Delete image metadata from the files.
  in | insert   Insert metadata from corresponding *.exv files.
                Use option -S to change the suffix of the input files.
  ex | extract  Extract metadata to *.exv, *.xmp and thumbnail image files.
  mv | rename   Rename files and/or set file timestamps according to the
                Exif create timestamp. The filename format can be set with
                -r format, timestamp options are controlled with -t and -T.
  mo | modify   Apply commands to modify (add, set, delete) the Exif and
                IPTC metadata of image files or set the JPEG comment.
                Requires option -c, -m or -M.
  fi | fixiso   Copy ISO setting from the Nikon Makernote to the regular
                Exif tag.
  fc | fixcom   Convert the UNICODE Exif user comment to UCS-2. Its current
                character encoding can be specified with the -n option.

Options:
   -h      Display this help and exit.
   -V      Show the program version and exit.
   -v      Be verbose during the program run.
   -q      Silence warnings and error messages during the program run (quiet).
   -Q lvl  Set log-level to d(ebug), i(nfo), w(arning), e(rror) or m(ute).
   -b      Show large binary values.
   -u      Show unknown tags.
   -g key  Only output info for this key (grep).
   -K key  Only output info for this key (exact match).
   -n enc  Charset to use to decode UNICODE Exif user comments.
   -k      Preserve file timestamps (keep).
   -t      Also set the file timestamp in 'rename' action (overrides -k).
   -T      Only set the file timestamp in 'rename' action, do not rename
           the file (overrides -k).
   -f      Do not prompt before overwriting existing files (force).
   -F      Do not prompt before renaming files (Force).
   -a time Time adjustment in the format [-]HH[:MM[:SS]]. This option
           is only used with the 'adjust' action.
   -Y yrs  Year adjustment with the 'adjust' action.
   -O mon  Month adjustment with the 'adjust' action.
   -D day  Day adjustment with the 'adjust' action.
   -p mode Print mode for the 'print' action. Possible modes are:
             s : print a summary of the Exif metadata (the default)
             a : print Exif, IPTC and XMP metadata (shortcut for -Pkyct)
             t : interpreted (translated) Exif data (-PEkyct)
             v : plain Exif data values (-PExgnycv)
             h : hexdump of the Exif data (-PExgnycsh)
             i : IPTC data values (-PIkyct)
             x : XMP properties (-PXkyct)
             c : JPEG comment
             p : list available previews
             S : print structure of image
             X : extract XMP from image
   -P flgs Print flags for fine control of tag lists ('print' action):
             E : include Exif tags in the list
             I : IPTC datasets
             X : XMP properties
             x : print a column with the tag number
             g : group name
             k : key
             l : tag label
             n : tag name
             y : type
             c : number of components (count)
             s : size in bytes
             v : plain data value
             t : interpreted (translated) data
             h : hexdump of the data
   -d tgt  Delete target(s) for the 'delete' action. Possible targets are:
             a : all supported metadata (the default)
             e : Exif section
             t : Exif thumbnail only
             i : IPTC data
             x : XMP packet
             c : JPEG comment
   -i tgt  Insert target(s) for the 'insert' action. Possible targets are
           the same as those for the -d option, plus a modifier:
             X : Insert metadata from an XMP sidecar file <file>.xmp
           Only JPEG thumbnails can be inserted, they need to be named
           <file>-thumb.jpg
   -e tgt  Extract target(s) for the 'extract' action. Possible targets
           are the same as those for the -d option, plus a target to extract
           preview images and a modifier to generate an XMP sidecar file:
             p[<n>[,<m> ...]] : Extract preview images.
             X : Extract metadata to an XMP sidecar file <file>.xmp
   -r fmt  Filename format for the 'rename' action. The format string
           follows strftime(3). The following keywords are supported:
             :basename:   - original filename without extension
             :dirname:    - name of the directory holding the original file
             :parentname: - name of parent directory
           Default filename format is %Y%m%d_%H%M%S.
   -c txt  JPEG comment string to set in the image.
   -m file Command file for the modify action. The format for commands is
           set|add|del <key> [[<type>] <value>].
   -M cmd  Command line for the modify action. The format for the
           commands is the same as that of the lines of a command file.
   -l dir  Location (directory) for files to be inserted from or extracted to.
   -S .suf Use suffix .suf for source files for insert command.
```

Looking at the help guidance, let's just go ahead and randomly take a crack at `pr` for `Print image metadata` and also `-v` for `Be verbose during the program run`. You can see from this help guidance that there is plenty of attack surface here for us explore but let's keep things simple for now.

Our command string now in our fuzzers will be something like `exiv2 pr -v mutated.jpg`. 

Let's go ahead and update our fuzzers and see if we can find some more bugs on a much harder target. It's worth mentioning that this target is currently supported, and not a trivial binary for us to find bugs on like our last target (an unsupported 7 year old project on Github). 

This target has already been fuzzed by much more advanced fuzzers, you can simply google for something like 'ASan exiv2' and get plenty of hits of fuzzers creating segfaults in the binary and forwarding the ASan output to the github repository as a bug. This is a significant step up from our last target. 

[exiv2 on Github](https://github.com/Exiv2/exiv2)

[exiv2 Website](https://www.exiv2.org/)

## Fuzzing Our New Target
Let's start off with our new and improved Python fuzzer and monitor it's performance over 50,000 iterations. Let's add some code that monitors for Floating point exceptions in addition to our Segmentation fault detection (Call it a hunch!). Our new `exif()` function will look like this: 
```python
def exif(counter,data):

    p = Popen(["exiv2", "pr", "-v", "mutated.jpg"], stdout=PIPE, stderr=PIPE)
    (out,err) = p.communicate()

    if p.returncode == -11:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    elif p.returncode == -8:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Floating Point!")
```

Looking at the output from `python3 -m cProfile -s cumtime subpro.py ~/jpegs/Canon_40D.jpg`:
```
75780446 function calls (75780309 primitive calls) in 213.595 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000  213.595  213.595 {built-in method builtins.exec}
        1    1.481    1.481  213.595  213.595 subpro.py:3(<module>)
    50000    0.818    0.000  187.205    0.004 subpro.py:111(exif)
    50000    0.543    0.000  143.499    0.003 subprocess.py:920(communicate)
    50000    6.773    0.000  142.873    0.003 subprocess.py:1662(_communicate)
  1641352    3.186    0.000  122.668    0.000 selectors.py:402(select)
  1641352  118.799    0.000  118.799    0.000 {method 'poll' of 'select.poll' objects}
    50000    1.220    0.000   42.888    0.001 subprocess.py:681(__init__)
    50000    4.400    0.000   39.364    0.001 subprocess.py:1412(_execute_child)
  1691919   25.759    0.000   25.759    0.000 {built-in method posix.read}
    50000    3.863    0.000   13.938    0.000 subpro.py:14(bit_flip)
  7950000    3.587    0.000    9.991    0.000 random.py:256(choice)
    50000    7.495    0.000    7.495    0.000 {built-in method _posixsubprocess.fork_exec}
    50000    0.148    0.000    7.081    0.000 subpro.py:105(create_new)
  7950000    3.884    0.000    5.764    0.000 random.py:224(_randbelow)
   200000    4.582    0.000    4.582    0.000 {built-in method io.open}
    50000    4.192    0.000    4.192    0.000 {method 'close' of '_io.BufferedRandom' objects}
    50000    1.339    0.000    3.612    0.000 os.py:617(get_exec_path)
    50000    1.641    0.000    3.309    0.000 subpro.py:8(get_bytes)
   100000    0.077    0.000    1.822    0.000 subprocess.py:1014(wait)
   100000    0.432    0.000    1.746    0.000 subprocess.py:1621(_wait)
   100000    0.256    0.000    1.735    0.000 selectors.py:351(register)
   100000    0.619    0.000    1.422    0.000 selectors.py:234(register)
   350000    0.380    0.000    1.402    0.000 subprocess.py:1471(<genexpr>)
 12066004    1.335    0.000    1.335    0.000 {method 'getrandbits' of '_random.Random' objects}
    50000    0.063    0.000    1.222    0.000 subprocess.py:1608(_try_wait)
    50000    1.160    0.000    1.160    0.000 {built-in method posix.waitpid}
   100000    0.519    0.000    1.143    0.000 os.py:674(__getitem__)
  1691352    0.902    0.000    1.097    0.000 selectors.py:66(__len__)
  7234121    1.023    0.000    1.023    0.000 {method 'append' of 'list' objects}
-----SNIP-----
```

It appears we took 213 seconds total and didn't really find any bugs, that's a shame, but could just be luck. Let's run our C++ fuzzer in the same exact circumstances and monitor the output.

Here we go, we get a similiar time but much improved:
```
root@kali:~# ./blogcpp ~/jpegs/Canon_40D.jpg 50000
Execution Time: 170829ms
```

That's a pretty significant improvement, 43 seconds. That's 20% off of our Python time. (Again, I apologize to math people.)

Let's keep our C++ fuzzer running for a bit and see if we find any bugs :).

## Bugs on Our New Target!
After maybe 10 seconds of running the fuzzer again, I got this terminal output:
```
root@kali:~# ./blogcpp ~/jpegs/Canon_40D.jpg 1000000
Floating Point!
```

It appears we have satisfied requirements for a Floating Point exception. We should have a nice jpg waiting for us in the `cppcrashes` directory. 
```
root@kali:~/cppcrashes# ls
crash.522.jpg
```

Let's confirm the bug by running `exiv2` against this sample:
```
root@kali:~/cppcrashes# exiv2 pr -v crash.522.jpg
File 1/1: crash.522.jpg
Error: Offset of directory Image, entry 0x011b is out of bounds: Offset = 0x080000ae; truncating the entry
Warning: Directory Image, entry 0x8825 has unknown Exif (TIFF) type 68; setting type size 1.
Warning: Directory Image, entry 0x8825 doesn't look like a sub-IFD.
File name       : crash.522.jpg
File size       : 7958 Bytes
MIME type       : image/jpeg
Image size      : 100 x 68
Camera make     : Aanon
Camera model    : Canon EOS 40D
Image timestamp : 2008:05:30 15:56:01
Image number    : 
Exposure time   : 1/160 s
Aperture        : F7.1
Floating point exception
```

We indeed found a new bug! This is super exciting. We should issue a bug report to the `exiv2` developers on Github.

## Conclusion
We first optimized our fuzzer in Python and then rewrote it in C++. We gained some massive performance advantages and even found some new bugs on a new harder target.

For some fun, let's compare our original fuzzer's performance for 50,000 iterations:
```
123052109 function calls (123001828 primitive calls) in 6243.939 seconds
```

As you can see, 6,243 seconds is significantly slower than our C++ fuzzer benchmark of 170 seconds.

## Addendum 15/May/2020
Just playing around with porting the C++ fuzzer to C and I made some modest improvements on my own. One of the logic changes I made was to collect the data from the original valid image only once and then copy that data into a newly allocated buffer each fuzzing iteration and then do the mutation operations on the newly allocated buffer. This C version of basically the same C++ fuzzer performed pretty well compared to the C++ fuzzer. Here is a comparison between the two for `200,000` iterations (you can ignore the crash findings as this fuzzer is extremely dumb and 100% random):
```
h0mbre:~$ time ./cppfuzz Canon_40D.jpg 200000
<snipped_results>

real    10m45.371s
user    7m14.561s
sys     3m10.529s

h0mbre:~$ time ./cfuzz Canon_40D.jpg 200000
<snipped_results>

real    10m7.686s
user    7m27.503s
sys     2m20.843s
```

So, over `200,000` iterations we end up saving about 35-40 seconds. This was pretty typical in my testing. So just by the few logic changes and using less C++-provided abstractions we saved a lot of `sys` time. We increased speed by about 5%. 

### Monitoring Child Process Exit Status
After completing the C translation, I went to Twitter to ask for suggestions about performance improvements. [@lcamtuf](https://twitter.com/lcamtuf), the creator of AFL, explained to me that I shouldn't be using `popen()` in my code as it spawns a shell and performs abysmally. Here is the code segment I asked for help on:
```c
void exif(int iteration) {
    
    FILE *fileptr;
    
    //fileptr = popen("exif_bin target.jpeg -verbose >/dev/null 2>&1", "r");
    fileptr = popen("exiv2 pr -v mutated.jpeg >/dev/null 2>&1", "r");

    int status = WEXITSTATUS(pclose(fileptr));
    switch(status) {
        case 253:
            break;
        case 0:
            break;
        case 1:
            break;
        default:
            crashes++;
            printf("\r[>] Crashes: %d", crashes);
            fflush(stdout);
            char command[50];
            sprintf(command, "cp mutated.jpeg ccrashes/crash.%d.%d",
             iteration,status);
            system(command);
            break;
    }
}
``` 
As you can see, we use `popen()`, run a shell-command, and then close the file pointer to the child process and return the exit-status for monitoring with the `WEXITSTATUS` macro. I was filtering out some exit codes that I didn't care about like `253`, `0`, and `1`, and was hoping to see some related to the floating point errors we already found with our C++ fuzzer or maybe even a segfault. `@lcamtuf` suggested that instead of `popen()`, I call `fork()` to spawn a child process, `execvp()` to have the child process execute a command, and then finally use `waitpid()` to await the child process termination and return the exit status. 

Since we don't have a proper shell in this syscall path, I had to also open a handle to `/dev/null` and call `dup2()` to route both `stdout` and `stderr` there as we don't care about the command output. I also used the `WTERMSIG` macro to retrieve the signal that terminated the child process in the event that the `WIFSIGNALED` macro returned true, which would indicate we got a segfault or floating point exception, etc. So now, our updated function looks like this:
```c
void exif(int iteration) {
    
    char* file = "exiv2";
    char* argv[4];
    argv[0] = "pr";
    argv[1] = "-v";
    argv[2] = "mutated.jpeg";
    argv[3] = NULL;
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
```

You can see that this drastically improves performance for our `200,000` iteration benchmark:
```
h0mbre:~$ time ./cfuzz2 Canon_40D.jpg 200000
<snipped_results>

real    8m30.371s
user    6m10.219s
sys     2m2.098s
```

### Summary of Results
+ C++ Fuzzer -- 310 iterations/sec
+ C Fuzzer -- 329 iterations/sec (**+ 6%**)
+ C Fuzzer 2.0 -- 392 iterations/sec (**+ 26%**)

Thanks to @lcamtuf and [@carste1n](https://twitter.com/carste1n) for the help. 

I've uploaded the code here: https://github.com/h0mbre/Fuzzing/tree/master/JPEGMutation
