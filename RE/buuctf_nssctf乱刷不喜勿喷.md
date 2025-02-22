@[TOC](BUUCTF刷题集合)
### 1. [GUET-CTF2019]re

#### 题目地址[[GUET-CTF2019]re](https://buuoj.cn/challenges#%5BGUET-CTF2019%5Dre)
1. 发现upx壳，直接用工具脱壳。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/1c5e2cdf86724ed1a724510c01259d6b.png#pic_center)
2. 脱壳后利用ida打开，如下：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/f65fd9ea7e6b4b459d28d8349923c9ad.png#pic_center)
3. 其中仅有一个加密函数，sub_4009AE，进入查看：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/a42bb0325ac34dd58429ae760e93b44b.png#pic_center)
4. 这不是典型的Z3求解吗，不要太简单直接上脚本：

```
from z3 import *
a1=[0]*32
for i in range(32):
    a1[i]=BitVec("a1[%d]"%(i),32)
print(type(a1[1]))
s=Solver()
s.add(1629056 *a1[0] == 166163712)
s.add(6771600 * a1[1] == 731332800)
s.add(3682944 * a1[2] == 357245568)
s.add(10431000 * a1[3] == 1074393000)
s.add(3977328 * a1[4] == 489211344)
s.add(5138336 * a1[5] == 518971936)
# s.add(a1[6]==49)
s.add(7532250 * a1[7] == 406741500)
s.add(5551632 * a1[8] == 294236496)
s.add(3409728 * a1[9] == 177305856)
s.add(13013670 * a1[10] == 650683500)
s.add(6088797 * a1[11] == 298351053)
s.add(7884663 * a1[12] == 386348487)
s.add(8944053 * a1[13] == 438258597)
s.add(5198490 * a1[14] == 249527520)
s.add(4544518 * a1[15] == 445362764)
s.add(3645600 * a1[17] == 174988800)
s.add(10115280 * a1[16] == 981182160)
s.add(9667504 * a1[18] == 493042704)
s.add(5364450 * a1[19] == 257493600)
s.add(13464540 * a1[20] == 767478780)
s.add(5488432 * a1[21] == 312840624)
s.add(14479500 * a1[22] == 1404511500)
s.add(6451830 * a1[23] == 316139670)
s.add(6252576 * a1[24] == 619005024)
s.add(7763364 * a1[25] == 372641472)
s.add(7327320 * a1[26] == 373693320)
s.add(8741520 * a1[27] == 498266640)
s.add(8871876 * a1[28] == 452465676)
s.add(4086720 * a1[29] == 208422720)
s.add(9374400 * a1[30] == 515592000)
s.add(5759124 * a1[31] == 719890500)
print(s.check())
m=s.model()
flag=[]
for i in a1:
   print((m[i]),",",end="")
```
5. 观察输出发现，哎~，怎么少一个输出，a1[6]=None,这里应该是程序埋坑了，a1[6]的等式在程序中的其他位置，但是咱也没有时间找直接在0-9A-Za_z中间一个一个试：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/ca39a4a3c45c4cd0919e7a5241081dfe.png#pic_center)
6. 最后提交尝试出来a1[6]=49, **flag** =flag{e165421110ba03099a1c039337}
### 总结：身为ctfer得熟练使用Z3约束求解器来解题。
### 2. [2019红帽杯]easyRE
#### 题目地址：[[2019红帽杯]easyRE](https://buuoj.cn/challenges#%5B2019%E7%BA%A2%E5%B8%BD%E6%9D%AF%5DeasyRE)
1. ida打开文件进入main函数中：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/88a1ae861b7640e08c3ed99fbc5ed826.png#pic_center)
2. 观察第一部分为简单的异或操作，然后与前面的字符串进行对比cmp， **注意**要将前面三个字符串拼接起来，ida将其使用三个数组存放，实际上他们在内存中是连续的。脚本如下,注意中间存在两个（127）：

```
res="Iodl>Qnb(ocyy.id`3w}wek9{iy=~yL@EC"
print(len(res))
for i in range(36):
    print(chr(ord(res[i])^i),end="")
```
3. 得到的字符串如下：Info:The first four chars are 'flag',提示前四个字符为**flag**
4. 往后看有第二次输入，长度为39，而后进行了10次base加密，再与off_6cc090处的字符串进行比较。将其逆向输出后发现是一个网址**https://bbs.pediy.com/thread-254172.htm**，很显然这不是flag。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/2540c199cca04de88f6ac17016080137.png#pic_center)
5. 只能继续往后寻找，但是main函数以及分析完成，返回到start函数中，查看main函数后面的init函数(这里是我重命名之后的函数)：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/9bf6259343a744abb061d89ef78e1fd3.png#pic_center)
6. init函数里面发现调用了其他函数，直接使用表调用：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/0a491910d0ad43c88765b976af6fcd04.png#pic_center)
7. 进入off_6CBEE0这个段查看调用了哪些函数，找到与flag有关的函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/cd037871b6034a91a8fe191f70d248bd.png#pic_center)
8. 经过仔细对比发现sub_400D35函数很可疑，开始似乎对v1和v4数组进行了初始化，然后利用初始化后的数组对res(全局变量)进行异或，并且从异或的循环中发现V4的长度v4，接下来需要找到v4数组的值即可逆向出res：![](https://img-blog.csdnimg.cn/direct/dc46eea6af9a4f18b8c56d152189fe4d.png#pic_center)
9. 这里找出v4的值有两种方法,方法1：动态调试再if语句处打断点，程序运行到此处时从内存中提取。方法2：利用前文解出的 **前四个字符为flag**,再加上v4的长度恰好为4，可以利用res的前四个字符位于“flag”异或处v4，这里采用方法2代码如下，输出得到的key="&YA1"：
```
b=[0x40, 0x35, 0x20, 0x56]
flag="flag"
for i in range(4):
  print(chr(ord(flag[i])^b[i]),end="")
```
10. 利用key于res即可还原处flag，代码如下：

```
a=[0x40, 0x35, 0x20, 0x56, 0x5D, 0x18, 0x22, 0x45, 0x17, 0x2F, 
  0x24, 0x6E, 0x62, 0x3C, 0x27, 0x54, 0x48, 0x6C, 0x24, 0x6E, 
  0x72, 0x3C, 0x32, 0x45, 0x5B]
key="&YA1"
for i in range(len(a)):
  print(chr(ord(key[i%len(key)])^a[i]),end="")
#`flag{Act1ve_Defen5e_Test}
```
### 3. [HUBUCTF 2022 新生赛]Anger？Angr
### 题目地址：[HUBU不会就是湖北大专吧？](https://www.nssctf.cn/problem/2601)
1. 进去看逻辑，发现又是一道Z3约束求解的题，每个check里面时一个等式：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/9e13c5c8da3744ddac0678218cd62f27.png#pic_center)
2. 直接附上脚本：

```
from z3 import *
a1=[0]*32
for i in range(32):
    a1[i]=BitVec("a1[%d]"%(i),32)
s=Solver()
s.add(a1[10] <= 40 )
s.add( 24 * a1[30] % 84 == 12 )
s.add( a1[16] != 66)
s.add(a1[4] > 51 )
s.add( a1[15] > 90 )
s.add( a1[18] != 38)
s.add(a1[3] <= 107 )
s.add( 61 * a1[20] % 95 == 2 )
s.add( a1[27] != 67)
s.add(a1[29] <= 69 )
s.add( 39 * a1[18] % 57 == 27 )
s.add( a1[29] <= 90)
s.add(a1[21] > 42 )
s.add( a1[0] > 35 )
s.add( a1[7] != 74)
s.add(a1[19] <= 79 )
s.add( a1[15] > 74 )
s.add( a1[22] > 92)
s.add(a1[14] <= 89 )
s.add( a1[26] > 36 )
s.add( a1[24] != 95)
s.add(a1[22] > 53 )
s.add( a1[12] != 33 )
s.add( 29 * a1[6] % 33 == 24)
s.add(a1[16] != 71 )
s.add( 22 * a1[24] % 96 == 60 )
s.add( 41 * a1[26] % 31 == 27)
s.add(a1[25] != 102 )
s.add( 38 * a1[6] % 54 == 36 )
s.add( a1[18] != 95)
s.add(a1[4] > 52 )
s.add( 72 * a1[6] % 86 == 42 )
s.add( a1[11] <= 76)
s.add(a1[5] <= 109 )
s.add( a1[9] > 44 )
s.add( a1[8] > 77)
s.add(a1[28] != 107 )
s.add( (69 * a1[5] % 3)==0 )
s.add( a1[17] > 73)
s.add(a1[0] != 70 )
s.add( a1[13] > 72 )
s.add( a1[1] <= 108)
s.add(a1[14] != 97 )
s.add( a1[1] <= 90 )
s.add( 87 * a1[31] % 69 == 45)
s.add(a1[11] <= 99 )
s.add( a1[24] != 107 )
s.add( a1[26] <= 111)
s.add(a1[0] > 36 )
s.add( a1[3] <= 65 )
s.add( a1[2] > 41)
s.add(a1[23] != 84 )
s.add( a1[16] != 101 )
s.add( a1[13] <= 99)
s.add(a1[19] > 33 )
s.add( a1[25] <= 122 )
s.add( a1[28] != 67)
s.add(86 * a1[17] % 74 == 64 )
s.add( a1[10] != 87 )
s.add( a1[30] <= 108)
s.add(a1[8] != 87 )
s.add( 46 * a1[12] % 26 == 20 )
s.add( 50 * a1[9] % 52 == 22)
s.add(a1[8] > 47 )
s.add( a1[21] <= 100 )
s.add( a1[11] > 34)
s.add(a1[27] != 127 )
s.add( a1[21] > 42 )
s.add( 5 * a1[10] % 32 == 20)
s.add(a1[19] != 91 )
s.add( a1[12] <= 107 )
s.add( a1[29] != 124)
s.add(57 * a1[13] % 13 == 2 )
s.add( a1[27] <= 100 )
s.add( 61 * a1[22] % 67 == 66)
s.add(a1[7] <= 118 )
s.add( a1[1] != 64 )
s.add( a1[30] > 44)
s.add(a1[5] != 43 )
s.add( a1[31] != 88 )
s.add( a1[31] > 35)
s.add(a1[20] <= 101 )
s.add( a1[15] > 64 )
s.add( a1[4] != 43)
s.add(a1[17] > 56 )
s.add( (a1[25] << 6) % 21 == 4 )
s.add( a1[28] <= 115)
s.add(a1[20] != 43 )
s.add( a1[2] <= 82 )
s.add( a1[2] > 39)
s.add(a1[23] > 34 )
s.add( a1[7] > 52 )
s.add( a1[14] > 44)
s.add(a1[3] <= 83 )
s.add( 59 * a1[9] % 86 == 69 )
s.add( a1[23] <= 103)
for i in range(32):
    s.add(a1[i]>=33)
    s.add(a1[i]<127)
print(s.check())
tmp=s.model()
flag=[]
for i in a1:
    flag.append(tmp[i].as_long())
for i in flag:
    print(chr(i),end="")
```
10. 密码正确,但是他喵的居然没给我flag艹，就把这个提交了也不让通过，就到这了吧:![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/e4358c448a8a4877a693ae8db510ef83.png#pic_center)
### 4.[网鼎杯 2020 青龙组]jocker
#### 题目出处：[你是jocker吗？反正我是](https://buuoj.cn/challenges#%5B%E7%BD%91%E9%BC%8E%E6%9D%AF%202020%20%E9%9D%92%E9%BE%99%E7%BB%84%5Djocker)
1. ida打开逻辑很清晰，前面是输入flag，然后经过一层wrong和omg加密，后面接上一个Smc自解密，再根个解密出来的函数，好吧其实有点**复杂**：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/f98f446abaa242469744c59e2098d7ff.png#pic_center)
2. 先进入wrong函数，发现知识简单的异或和加法，而omg就是简单的比较，但是有点挑衅：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/5b2552533ccf4fdf97d97adafc6e8f64.png#pic_center)
3. ![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/c87ae7e6285e43c09e169b26d55115b2.png#pic_center)
4. 自此可以写脚本解出第一层flag：

```
a=[0x66, 0x6B, 0x63, 0x64, 0x7F, 0x61, 
0x67, 0x64, 0x3B, 0x56, 0x6B, 0x61, 0x7B, 
0x26, 0x3B, 0x50, 0x63, 0x5F, 0x4D, 0x5A, 0x71, 0x0C, 0x37, 0x66]
for i in range(len(a)):
    if  i&1!=0:
        print(chr(a[i]+i),end="")
    else:
        print(chr(a[i]^i),end="")
```
**flag{fak3_alw35_sp_me!!}**

5. 但是输入发现这并不是真的flag：![](https://img-blog.csdnimg.cn/direct/98e65c301a8b42958c5ad1afa08418b7.png#pic_center)
6. 仔细观察发现，第一层的flag并没有进入到Scm自解密函数中，因此需要额外解密处encrypt函数，根据Smc自解密逻辑，在IDC中输入以下脚本，运行后从定义函数即可还原encrypt函数和finally函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/58eec668c98f4cbda6ac846f15e2e500.png#pic_center)
7. encrypt函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/4cce1bcf8aac4f38bcd6fdefd671db04.png#pic_center)
8. finally函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/3b11769b8c2247d7ad4b9ac62cd300fc.png#pic_center)
9. 其中encrypt函数也是简单的异或比较，提取出来unk_403040出的数组值后于与Buffer="hahahaha_do_you_find_me?"进行异或，代码如下：

```
res=[0x0E, 0x0D, 0x09, 
  0x06, 0x13, 
  0x05, 0x58, 0x56, 
  0x3E, 0x06, 
  0x0C, 0x3C, 0x1F, 
  0x57, 0x14, 
  0x6B, 0x57, 0x59, 
  0x0D, ]
print(len(res))
print(len(key))
for i in range(len(res)):
    print(chr((res[i])^ord(key[i])),end="")
#flag{d07abccf8a410c
```
10. 上面给出的res数组只有19位所以输出的flag也仅有19位，后面还有5位只能继续向后观察finally函数，但是finally函数设置了rand随机数，逻辑也不明显值给出了字符串："**%tp&:**" 刚好是5位,并没有给出加密过程，似乎陷入了死胡同。。。后面的输出也在挑衅我们找不到flag。。。。
11. 首先将"**%tp&:**"字符串也之前的Buffer后5位进行异或，发现并不符合flag的特征，真是烦：

```
res=[0x0E, 0x0D, 0x09, 
  0x06, 0x13, 
  0x05, 0x58, 0x56, 
  0x3E, 0x06, 
  0x0C, 0x3C, 0x1F, 
  0x57, 0x14, 
  0x6B, 0x57, 0x59, 
  0x0D, 
  37, 116, 112, 38, 58]
print(len(res))
print(len(key))
for i in range(len(res)):
    print(chr((res[i])^ord(key[i])),end="")
 #flag{d07abccf8a410cA+C
```
11. 再猜想flag的最后一位是应该"}"，直接用"}"与"**%tp&:**"的最后一位":"异或得出结果位71，假设flag的最后5位是异或再与"**%tp&:**"比较，写出解密脚本：

```
print([chr(ord(i)^71) for i in "%tp&:"])
```
输出：['b', '3', '7', 'a', '}']，有点像flag的感觉，将器与前面的拼接起来得到：**flag{d07abccf8a410cb37a}**，去提交发现居然过了！！！！！！？但还是看不懂最后finally的逻辑，汇编代码逻辑也一言难尽，贴上来等待有缘人吧：![](https://img-blog.csdnimg.cn/direct/c250b225b4134a9e9241b9b081a09c91.png#pic_center)![](https://img-blog.csdnimg.cn/direct/9b4c225685694be7b353cfc5270a99ad.png#pic_center)
#### 总结：有些加密过程对flag是无意义的，平常逆向的时候可以探索qc，比赛时可以直接跳过，分析重要部分，抓紧时间。


 




