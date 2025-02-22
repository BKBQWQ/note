@[TOC](BUUCTF刷题集合)
### 1. [GUET-CTF2019]re
#### 题目地址：[[GUET-CTF2019]re](https://buuoj.cn/challenges#%5BGUET-CTF2019%5Dre)
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

 




