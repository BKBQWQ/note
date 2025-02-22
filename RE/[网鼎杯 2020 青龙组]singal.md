@[TOC]([网鼎杯 2020 青龙组]singal)
### 题目出处：[题目](https://www.nssctf.cn/problem/1232)
1. 进入到main函数，主函数的逻辑非常简单，一个copy函数将地址在 **&byte_403040** 处长度为456的数组付给v4，再调用一个vm_cpu函数，想必解题的关键就在vm_cpu函数：
![](https://img-blog.csdnimg.cn/direct/83e5406d11f44017a4fa93045879fea5.png#pic_center)
2. 观察vm_cpu函数的逻辑发现是一个取指令，然后执行相对应的函数，取指令的地址就在 **&byte_403040** 将该处的数组提取出来，再结合函数中对应的处理提取处指令（函数）的硬件码、长度、寄存器。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/aba5a9301aed4da8bf400e2982ce1c84.png#pic_center)
3. 分析完成vm_cpu函数后如下：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/6bde978b2b1a4136b2c74f158439cca7.png#pic_center)
4. 编写脚本直接输出cpu实际执行的指令(伪指令)：

```
opcode=[10,   
    4,  16,    
    8,   
    3, 5,
    1,   
    4,   32,   
    8, 
    5,   3,   
    1,    
    3,   2, 
    8,  
    11,   
    1,   
    12,   
    8, 
    4,   4,   
    1,    
    5,   
    3, 8,   
    3,  33,    
    1,  
    11, 
    8,  
    11,   
    1,    
    4,   9, 
    8,   
    3,  32,    
    1,   
    2, 81,   
    8,   
    4,   36,   
    1, 
   12,   
   8,  
   11,    
   1,   
   5, 2,   
   8,   
   2,   37,   
   1, 
    2,  54,   
    8,    
    4,  65, 
    1,   
    2,  32,    
    8,   
    5, 1,   
    1,   
    5,    3,   
    8, 
    2,  37,   
    1,    
    4,   9, 
    8,   
    3,  32,    
    1,   
    2, 65,   
    8,  
    12,    
    1,   
    7,  34,   
    7,  63,    
    7,  52, 
    7,  50,   
    7,  114,
    7,  51,  
    7,  24,   
    7,  167, 
    7,  49,  
    7,  241,  
    7,  40,  
    7,  132,    
    7,  193, 
    7,  30,  
    7,  122,
    114,200]
ip=0
print("mov reg_0,0")
print("mov reg_1,0")
print("mov reg_2,0")
print("mov reg_3,0")
print("mov reg_4,0")
while True:
    tmp=opcode[ip]
    if tmp>=114:
        break
 
    if tmp==1:
        print("(%d)"%(ip),end="")
        print("mov flag[reg_3 + 100],reg_0")
        print("inc reg_3")
        print("inc reg_1")
        ip+=1
    elif tmp==2:
        print("(%d)"%(ip),end="")
        print("reg_0 = %d + flag[reg_1]"%(opcode[ip + 1]))#为了避免来回繁琐的mov移动直接采取"="赋值，下同
        ip+=2
    elif tmp==3:
        print("(%d)"%(ip),end="")
        print("reg_0 = flag[reg_1] - %d"%(opcode[ip + 1]))
        ip+=2
    elif tmp==4:
        print("(%d)"%(ip),end="")
        print("reg_0 = %d ^ flag[reg_1]"%(opcode[ip + 1]))
        ip+=2
    elif tmp==5:
        print("(%d)"%(ip),end="")
        print("reg_0 = %d * flag[reg_1]"%(opcode[ip + 1]))
        ip+=2
    elif tmp==6:
        print("(%d)"%(ip),end="")
        ip+=1
    elif tmp==7:
        print("(%d)"%(ip),end="")
        print("cmp flag[reg_4 + 100],%d"%(opcode[ip + 1]))
        print("jnz exit")
        print("inc reg_4")
        ip+=2
    elif tmp==8:
        print("(%d)"%(ip),end="")
        print("mov flag[reg_2],reg_0")
        print("inc reg_2")
        ip+=1

    elif tmp==10:
        print("(%d)"%(ip),end="")
        print("read flag")
        ip+=1
    elif tmp==11:
        print("(%d)"%(ip),end="")
        print("reg_0 = flag[reg_1] - 1")
        ip+=1
    elif tmp==12:
        print("(%d)"%(ip),end="")
        print("reg_0 = flag[reg_1] + 1")
        ip+=1
```
5. 输出后的伪指令如下，结合分析：
mov reg_0,0
mov reg_1,0
mov reg_2,0
mov reg_3,0
mov reg_4,0
(0)read flag		读取输入的flag
每次reg_3寄存器加一都是一次对flag的操作，对输入的flag进行opration，然后放入到与flag相对偏移为100的位置
第一次：
(1)reg_0 = 16 ^ flag[reg_1]
(3)mov flag[reg_2],reg_0
inc reg_2
(4)reg_0 = flag[reg_1] - 5
(6)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第二次：
(7)reg_0 = 32 ^ flag[reg_1]
(9)mov flag[reg_2],reg_0
inc reg_2
(10)reg_0 = 3 * flag[reg_1]
(12)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第三次：
(13)reg_0 = flag[reg_1] - 2
(15)mov flag[reg_2],reg_0
inc reg_2
(16)reg_0 = flag[reg_1] - 1
(17)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第四次：
(18)reg_0 = flag[reg_1] + 1
(19)mov flag[reg_2],reg_0
inc reg_2
(20)reg_0 = 4 ^ flag[reg_1]
(22)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第五次：
(23)reg_0 = 3 * flag[reg_1]
(25)mov flag[reg_2],reg_0
inc reg_2
(26)reg_0 = flag[reg_1] - 33
(28)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第六次：
(29)reg_0 = flag[reg_1] - 1
(30)mov flag[reg_2],reg_0
inc reg_2
(31)reg_0 = flag[reg_1] - 1
(32)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第七次：
(33)reg_0 = 9 ^ flag[reg_1]
(35)mov flag[reg_2],reg_0
inc reg_2
(36)reg_0 = flag[reg_1] - 32
(38)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第八次：
(39)reg_0 = 81 + flag[reg_1]
(41)mov flag[reg_2],reg_0
inc reg_2
(42)reg_0 = 36 ^ flag[reg_1]
(44)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第九次：
(45)reg_0 = flag[reg_1] + 1
(46)mov flag[reg_2],reg_0
inc reg_2
(47)reg_0 = flag[reg_1] - 1
(48)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十次：
(49)reg_0 = 2 * flag[reg_1]
(51)mov flag[reg_2],reg_0
inc reg_2
(52)reg_0 = 37 + flag[reg_1]
(54)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十一次：
(55)reg_0 = 54 + flag[reg_1]
(57)mov flag[reg_2],reg_0
inc reg_2
(58)reg_0 = 65 ^ flag[reg_1]
(60)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十二次：
(61)reg_0 = 32 + flag[reg_1]
(63)mov flag[reg_2],reg_0
inc reg_2
(64)reg_0 = 1 * flag[reg_1]
(66)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十三次：
(67)reg_0 = 3 * flag[reg_1]
(69)mov flag[reg_2],reg_0
inc reg_2
(70)reg_0 = 37 + flag[reg_1]
(72)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十四次：
(73)reg_0 = 9 ^ flag[reg_1]
(75)mov flag[reg_2],reg_0
inc reg_2
(76)reg_0 = flag[reg_1] - 32
(78)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
第十五次：
(79)reg_0 = 65 + flag[reg_1]
(81)mov flag[reg_2],reg_0
inc reg_2
(82)reg_0 = flag[reg_1] + 1
(83)mov flag[reg_3 + 100],reg_0
inc reg_3
inc reg_1
接下来为比较操作，与提供的硬件opcode进行比较：
(84)cmp flag[reg_4 + 100],34
jnz exit
inc reg_4
(86)cmp flag[reg_4 + 100],63
jnz exit
inc reg_4
(88)cmp flag[reg_4 + 100],52
jnz exit
inc reg_4
(90)cmp flag[reg_4 + 100],50
jnz exit
inc reg_4
(92)cmp flag[reg_4 + 100],114
jnz exit
inc reg_4
(94)cmp flag[reg_4 + 100],51
jnz exit
inc reg_4
(96)cmp flag[reg_4 + 100],24
jnz exit
inc reg_4
(98)cmp flag[reg_4 + 100],167
jnz exit
inc reg_4
(100)cmp flag[reg_4 + 100],49
jnz exit
inc reg_4
(102)cmp flag[reg_4 + 100],241
jnz exit
inc reg_4
(104)cmp flag[reg_4 + 100],40
jnz exit
inc reg_4
(106)cmp flag[reg_4 + 100],132
jnz exit
inc reg_4
(108)cmp flag[reg_4 + 100],193
jnz exit
inc reg_4
(110)cmp flag[reg_4 + 100],30
jnz exit
inc reg_4
(112)cmp flag[reg_4 + 100],122
jnz exit
inc reg_4
6. 经过分析可以看出，前面对flag的操作共15次比较也是15次，read函数中也明确指出输入的flag长度为15：![](https://img-blog.csdnimg.cn/direct/b911c0ba5a5a446ab2b43cae34e68a1a.png#pic_center)
7. 提取出上面比较的数据(result)，根据每次的加密操作反写出逆向操作，逆向代码如下：

```
res=[34,63,52, 50,114,51,24,167,49,241,40,132,193,30,122,]
flag=[]
flag.append((res[0]+5)^16)
flag.append((res[1]//3)^32)
flag.append((res[2]+2+1))
flag.append((res[3]^4)-1)
flag.append((res[4]+33)//3)
flag.append((res[5]+1+1))
flag.append((res[6]+32)^9)
flag.append((res[7]^36)-81)
flag.append((res[8]))
flag.append((res[9]-37)//2)
flag.append((res[10]^65)-54)
flag.append((res[11]-32))
flag.append((res[12]-37)//3)
flag.append((res[13]+32)^9)
flag.append((res[14]-1-65))
for i in flag:
    print(chr(i&0xFF),end="")
#757515121f3d478
```
#### 最终flag{757515121f3d478}
### 总结本体和上一篇vm逆向类似，分析出指令的硬件编码后还原指令即可逆向出flag

