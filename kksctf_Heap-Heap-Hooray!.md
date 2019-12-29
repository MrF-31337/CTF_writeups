We are given 3 files the binary, zip archive with libc and ld and bash script that runs the binary. 
First let's look at the binary in IDA:

<img src="image1.png" width=500 height=500>

Here is the code that simply reads a character and executes a command appropriate to it. But what v4 variable used for ?
Lets look deep into the function allocate_chunk:

<img src="image2.png">

The function allocate_chunk first reads id,after that it checks if ID bit of v4 is 0 and if it is it reads size and content and sets the chunks[id] to malloc(size).
So v4 is used to check if chunk is freed or used. If the ID bit is set to 0 it is freed and if it's not it is allocated.
Now let's look at the list_chunks_content:

<img src="image3.png">

Function prints all the chunks content with printf passing the chunk address as the first argument and here we have a format string vulnerability. We don't have an arbitary write here because format string isn't on the stack, but address v4 is. So we can overwrite v4 to get double free.
The glibc2.27 is used in this task, in this version tcache was added. When multiple threads are using heap the heap manager locks the heap while one thread is using it to avoid errors.So to make the allocations faster peaple made a tcache. A tcache or per thread cache is a bin that is own for each of threads unlike the other bins, so when u are using a tcache heap manager doesn't need to lock a heap and allocations go faster. But there is no security checks in tcache. Since glibc2.27 tcache is used by default, You can read more about tcache here https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache/.

Our strategy is pretty simple:
1.we leak the libc using format string vulnerabilitiy.
2.we create two chunks in second chunk is payload to overwrite the v4 with 0b111 (7).
3.free first chunk
4.overwrite the v4
5.free first chunk again
6.overwrite the v4 again
7.free first chunk again
8.allocate chunk with content p32(freegot) to overwrite the bk pointer to freeaddress in got table
9.allocate chunk with content "/bin/sh\x00"
10.allocate chunk with content p32(system)
11.free chunk with /bin/sh
