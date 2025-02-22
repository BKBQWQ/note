
@[TOC](ESCTF_reverse题解)
## 逆吧腻吧
1. 下载副本后无壳，直接拖入ida分析分析函数逻辑：![](https://img-blog.csdnimg.cn/direct/c902a5d6afba498ba825a95b3adeeceb.png#pic_center)
2. ida打开如下：![](https://img-blog.csdnimg.cn/direct/7f60a0aa0eb34001b5f4f9cab1552b64.png#pic_center)
3. 提取出全局变量res的数据后，编写异或脚本进行解密：

```
a=[0xBF, 0xA9, 0xB9, 
  0xAE, 0xBC, 
  0x81, 0x8D, 0xC9, 
  0x96, 0x99, 
  0xCA, 0x97, 0xC9, 
  0xA5, 0x8E, 
  0xCA, 0xA5, 0x88, 
  0x9F, 0x8C, 
  0x9F, 0x88, 0x89, 
  0x9F, 0x87]
for i in a:
    print(chr(i^0xFA),end="")
# ESCTF{w3lc0m3_t0_reverse}
```
## babypy
1. 拿到题目副本，发现时python的.exe文件。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/990af5a250c64ffabb67810b51a424df.png#pic_center)
2. 将python的.exe文件返回成源码需要用到pyinstxtractor.py这个脚本，使用如下命令：**python pyinstxtractor.py 文件名.exe**,和**uncompyle6**(或者在线网站)。还原python文件：![](https://img-blog.csdnimg.cn/direct/1cec1a9005384ac3bb27c74f4fab5a66.png#pic_center)
3. 注意python version这一栏，标识了题目使用的python版本，后面给main.pyc文件还原时需要用到python相应版本的**魔术字**(版本号)。
4. 在得到的文件夹中找到struct文件，查看器**字节码E3**前面的的16个字节(如果没有着需要自己根据**相应python版本**手动添加)，上面显示python的版本为:3.8,器相应的版本为**0x55,0x0d,0x0d,0x0a**，将其添加到main文件的前8个字节(使用16进制编辑器)：![](https://img-blog.csdnimg.cn/direct/a1008d2e6ca54ef88fa5558e01e55269.png#pic_center)
5. 随后使用在线网站(或者**uncompyle6工具**)进行反编译(修改main文件的后缀为.pyc)[在线网站如下](https://www.lddgo.net/string/pyc-compile-decompile)：

```
# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Version : Python 3.8

res = [
    146,
    58,
    34,
    106,
    210,
    118,
    54,
    242,
    106,
    154,
    60,
    164,
    14,
    154,
    176,
    108,
    44,
    60,
    66,
    194,
    56,
    194,
    66,
    106,
    194,
    4]
flag = input('Please input flag:')
for i in range(len(flag)):
    if (ord(flag[i]) * 1314 ^ 520) % 250 != res[i]:
        print('error!!!')
    print('yeah you get it Q_W_Q!')
    return None

```
5. 最后编写脚本暴力破解，采用深度搜索的算法，根据生成的flag去指定筛选真正的flag：

```
def DFS(deep):
    if deep == 0:   #一个flag试探完毕
        for i in flag:
            print((i),end="")
        print()
    else:
        for j in range(65,128):
            if (j * 1314 ^ 520) % 250  == check[deep - 1]:
                flag[deep - 1] = chr(j)
                DFS(deep - 1)
check =[54,
    242,
    106,
    154,
    60,
    164,
    14,
    154,
    176,
    108,
    44,
    60,
    66,
    194,
    56,
    194,
    66,
    106,
    194]
flag = [0]*19
flag_1="ESCTF{"
DFS(len(check))
```![](https://img-blog.csdnimg.cn/direct/199a3935ef60449aa1a986f4fc4550c2.png#pic_center)
6. 可以看到其中又python_reverse等字样,直接用这个来指定：

```

def DFS(deep):
    if deep == 0:   #一个flag试探完毕
        if flag[18]=="e" and flag[17]=="s" and flag[16]=="r" and flag[15]=="e" and flag[14]=="v" and flag[13]=="e" and flag[12]=="r":
            for i in flag:
                print((i),end="")
            print()
    else:
        for j in range(65,128):
            if (j * 1314 ^ 520) % 250  == check[deep - 1]:
                flag[deep - 1] = chr(j)
                DFS(deep - 1)
check =[54,
    242,
    106,
    154,
    60,
    164,
    14,
    154,
    176,
    108,
    44,
    60,
    66,
    194,
    56,
    194,
    66,
    106,
    194]
flag = [0]*19
flag_1="ESCTF{"
DFS(len(check))
``
8. 寻找到可能的flag提交：
![](https://img-blog.csdnimg.cn/direct/75de76ced59846ebbb36174cb69765c0.png#pic_center)
## babypolyre
1. 拿到题目后无壳，直接拖入ida反汇编，从start函数直接跳到main函数：![](https://img-blog.csdnimg.cn/direct/234fd0c4e06f41988d012ab298acf3c0.png#pic_center)
![](https://img-blog.csdnimg.cn/direct/8ac9dfa6982b4a5f88ec2d7d21333d17.png#pic_center)
2. 明显的虚假控制流平坦化，这里简单讲一下什么是平坦化，平坦化就是将原本嵌套多层的语句，改为只用1个switch加while循环来实现，下面使用python语句来表现一个循环语句平坦化：

```
#原程序
res=[1,-1,2,-2,3,-3]
for i in range(len(res)):
    if res[i] < 0:
        res[i]<<=1
        res[i]+=10
        if res[1]&1==1:
            res[i]*=2
    else :
        res[i]^=13
        res[i]*=4
        # if res[1]
print(res)

res=[1,-1,2,-2,3,-3]
#手动添加平坦换后
i=0
while i<len(res):
    b=(int(res[i]<0)^1)+1
    while True:
        match b:
            case 0:
                break
            case 1:
                res[i]<<=1
                b=3
                
            case 2:
                res[i]^=13
                b=4
                
            case 3:
                res[i]+=10
                b=(res[i]&1)*5
                
            case 4:
                res[i]*=4
                break
                
            case 5:
                res[i]*=2
                break
    i+=1
print(res)
```
![](https://img-blog.csdnimg.cn/direct/803b835372ae4709afbfe58556869987.png#pic_center)
4. 其实现的功能仍然是一样的，只不过将一个循环里的多个语句放在了不同的子模块中，再通过子模块之间的相互控制，来达到原有程序的效果。详细的平坦换请看下面这篇文章：[控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)
5. 知道控制流平坦化后，可以使用符号化执行来简化程序，使程序的可读性增强，便于反汇编，使用deflat.py脚本即可去除平坦化：命令如下![](https://img-blog.csdnimg.cn/direct/f3d2880d316648b48d15e42bced043ea.png#pic_center)
6. -f后是文件名，--addr后是要平坦化的函数首地址，执行后效果如下：![](https://img-blog.csdnimg.cn/direct/34b9a66b035f4681989b68ffe00c3972.png#pic_center)![汇编视图](https://img-blog.csdnimg.cn/direct/b06b4e252e54467cbc14b321e2ee61d8.png#pic_center)![](https://img-blog.csdnimg.cn/direct/ba1d174db1924760b4a662bcc41354aa.png#pic_center)
7. 这里可以看到，去平坦化后的程序刻度性增强，不过其中还有一些出题人塞进去的虚假指令(恒真/假)，永远不会执行。
8. 例如：第一个if语句后面的 **((((_BYTE)dword_603054 - 1) * (_BYTE)dword_603054) & 1) != 0**条件就永远为假**(n*(n-1))&1**这个结果恒等于0，所以前面的条件恒假，即if语句里面的程序根本不会执行，类似的虚指令后面还有16个，需要清除：![](https://img-blog.csdnimg.cn/direct/70b7f74dbf0741e3b484058591930b9c.png#pic_center)
9. 这里使用idapython脚本来快速去除，这里**脚本的逻辑**：将jnz指令的条件跳转修改为直接跳转，因为后面的**jmp语句永远不会执行**，后面的while循环同理，只会执行一次，因此利用脚本将**jnz的条件跳转**直接改为**jmp进行直接跳转**(顺跳)，源程序相当于：![](https://img-blog.csdnimg.cn/direct/c60d17b7d03b47458ae7386681bf7ca0.png#pic_center)
```
st = 0x0000000000400620 #main开始
end = 0x0000000000402144 #main结束
 
def patch_nop(start,end):
    for i in range(start,end):
        ida_bytes.patch_byte(i, 0x90)		#修改指定地址处的指令  0x90是最简单的1字节nop
 
def next_instr(addr):
    return addr+idc.get_item_size(addr)		#获取指令或数据长度，这个函数的作用就是去往下一条指令
    
 
 
addr = st
while(addr<end):
    next = next_instr(addr)
    if "ds:dword_603054" in GetDisasm(addr):	#GetDisasm(addr)得到addr的反汇编语句
        while(True):
            addr = next
            next = next_instr(addr)
            if "jnz" in GetDisasm(addr):
                dest = idc.get_operand_value(addr, 0)		#得到操作数，就是指令后的数
                ida_bytes.patch_byte(addr, 0xe9)     #0xe9 jmp后面的四个字节是偏移
                ida_bytes.patch_byte(addr+5, 0x90)   #nop第五个字节
                offset = dest - (addr + 5)  #调整为正确的偏移地址 也就是相对偏移地址 - 当前指令后的地址
                ida_bytes.patch_dword(addr + 1, offset) #把地址赋值给jmp后
                print("patch bcf: 0x%x"%addr)
                addr = next
                break
    else:
        addr = next
```
8. 利用脚本修改后的汇编指令，反编译程序如下，去除掉后面16个虚指令：![](https://img-blog.csdnimg.cn/direct/f0f2eb0b673d4372980bc8d6fc961a6f.png#pic_center)![](https://img-blog.csdnimg.cn/direct/38567dc54bbb4cb7b8bf20827f8c1209.png#pic_center)
9. 前期准备结束，正式开始分析函数实现的功能，**第一个循环**的逻辑是将最后输入的回车符"\n"转化为0，**第二个循环**：将输入的字符串每8个一组(共64个bit)进行一下处理，**大于零**则左移1位(乘2)，**小于零**则左移1位后与0xB0004B7679FA26B3异或。这里由于变量v4是**64位的有符号数**，左移根据其最高位来判定符号，1为负数，0为正数：![](https://img-blog.csdnimg.cn/direct/4d41f332e5d540edad9e57072a6792c6.png#pic_center)
10. 最后，Jami后的字符串与程序给定的数据相比较，因为8个字节一组，所以将程序给定的48个字节分为6组整合到一起：![](https://img-blog.csdnimg.cn/direct/6bec91170feb4732a555c5fe2d34d00d.png#pic_center)
11. 最后解密脚本如下，脚本里面使用到的**逻辑**：原先的**正数**(最高位的符号位为0)左移1后一定是**偶数**(左移后低位自动用0补充)，而原先的**负数**(最高位的符号位为1)左移1后(变为偶数)再与0xB0004B7679FA26B3(奇数)异或，结果一定是奇数，也就是说，最后结果(加密一次)里面的偶数原先一定是正数，而结果里面的奇数原先一定是负数，所以根据**每次结果奇偶性**即可判定上一次该值是否为正或者负,如果是负数则需要给最高位(第64为)补上1(补上因为加密是左移而**溢出的1**)，为正数不用补(加密是左移溢出的是0，相当于没有溢出)：

```
a=[0x7FE7E49BD585CC6C,0x520100780530EE16,0x4DC0B5EA935F08EC,0x342B90AFD853F450,
0x8B250EBCAA2C3681,0x55759F81A2C68AE4]
key=0xB0004B7679FA26B3
for res in a:
    for j in range(64): #循环64次
        tmp=res&1
        if tmp == 1:#判定是否为奇数(为奇数则上轮加密是为负数)，在二进制下最低为为1则是奇数
            res ^= key
        res>>=1
        if tmp==1:
            res+=0x8000000000000000 #如果该次加密前是负数()，把左移漏掉的最高位1补回来

    #输出，大小端续转化输出
    k=0
    while k<8:
        print(chr(res&0xff),end="")
        res>>=8
        k+=1
#ESCTF{1229390-6c20-4c56-ba70-a95758e3d1f8}
```
## easy_re
1. 先用upx工具脱壳进行与脱壳，手动脱壳可以去看这篇：[手动脱壳](https://blog.csdn.net/yjh_fnu_ltn/article/details/136601447?spm=1001.2014.3001.5502)，完成后直接进入ida分析：![](https://img-blog.csdnimg.cn/direct/6da3cd957a6849c593bdbc0157c3ff3a.png#pic_center)
2. 进入ida发现加密函数时典型的base64：![](https://img-blog.csdnimg.cn/direct/60374c5fd56c42f9b3d65498796ee3aa.png#pic_center)
3. 密文为**ZL0pLwfxHmLQnEabfLiGPYiYJ2aQP205U5i8fd0i**，找到base64的编码表即可，初步判断时下面这张表，直接拿去用网站解密发现不对，再返回来寻找其他表：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/3a78025e525d4ebdaa07e136fd4e5c73.png#pic_center)
4. 最后再init函数里面调用的函数中找到下面这张表：![](https://img-blog.csdnimg.cn/direct/5c7fd60713424b97b0a9c6349332f214.png#pic_center)
5. 拿去用网站解密，解出flag：![](https://img-blog.csdnimg.cn/direct/256cb028cf8b486c89131abb374faece.png#pic_center)
## re1
1. 拿到题目，uxp工具脱壳后拉入ida分析，进入main函数分析，其主要逻辑为接受一个输入，然后判断一下长度大于12，然后对输入的flag进行分组，税后调用了j_encode函数，后续一个判断，似乎是调用了三个函数，但是双击键入发现函数并不存在：
![](https://img-blog.csdnimg.cn/direct/6ca7bbd0288f47b2944dc4765426489b.png#pic_center)
2. 这说明qword_140029370这个函数地址还需要其他函数来赋值过来(初始化生成函数)：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/378432e0df784ffebeabff7d31958e0d.png#pic_center)
3. 进入j_encode查看逻辑，发现其中存在一大段数据，并在最后对其进行批量异或操作后：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/143afd4281d248c9b60160cdfbedf2bc.png#pic_center)![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/a5faf270024b4cc399a0b689121080da.png#pic_center)
4. 可见上面的三个循环异或操作是在还原函数，解题只需要还原出这三个函数，再分析器内部的逻辑即可得到flag，提取出代码中的数据后(其中又两段数据曹勇strcpy的形式，但里面各又一个ASIIC码为0的字符没有被显示，再汇编模式下可以看见)：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/0e9702997e34483a9ef8f65e9e2eb531.png#pic_center)
5. 还原函数的脚本如下：

```
a=[
0x2E,
0xE5,
0x8A,
0x46,
0x2E,
0xEF,
0x6A,
0x42,
0x27,
0xDC,
0x41,
0x48,
0x61,
0x1A,
0x27,
0xE7,
0x94,
0x1E,
0x30,
0x52,
0x74,
0xED,
0x5A,
0x42,
0x22,
0x5F,0xB1,0x13,0x78,0xED,
0x1A,
0x42,0x62,0x27,0xDC,0x29,
0x5C,
3,
0xE1,0x27,0xE7,0x94,0x47,0x25,
3,
0xE1,0x22,0x5F,0xB1,
0x13,
0x6E,
0x2E,0x57,0xA6,0x2E,0xE5,0xA2,
0x46,
0xA5,0x2E,
0xE5,
0xA2,
0x46,
0x2E,
0x57,
0xA6,0x2E,0xE5,0x8E,0x67,0xA5
]
print(len(a))
for i in a:
    print('{:0>2}'.format(hex(i^0x66)[2:]),end=" ")

print()
b=[0x3F,
0xF4,
0x9B,
0x37,
0x3F,
0xFE,
0x7B,
0x53,
0xB0,
0x33,0x53,0x67,0x18,2,0x19,0x13,0xB0,0x33,0x53,0x63,0x28,0x18,2,5,0x3F,0xB0,0xB6,0x77,0x77,0x77,0x77,0x3F,0xB0,0xB5,0x7F,0x77,0x77,0x77,0x3F,0x46,0xB7,0x3F,0x46,0xAC,0xFD,0x73,0x7B,0xFD,0x2B,0x7B,0x67,0x4F,0xAF,2,0x67,0x3F,0x88,0xB6,0x3F,0x4E,0xA6,0xB,0x9A,0x3F,0x46,0xB7,0x3F,0xF4,0xB3,0x37,0xB4,0x3F,0xB0,0xB7,0x77,0x77,0x77,0x77,0x3F,0xF4,0x9F,0x76,0x3F,0xF4,0xB3,0x37,0xB4,
]
print(len(b))
for i in b:
    print('{:0>2}'.format(hex(i^0x77)[2:]),end=" ")
print()
c=[0x17,
0xDC,
0xB3,
0x1F,
0x17,
0xD6,
0x53,
0x7B,
0x98,
0x1b,
0x7b,
0x57,
0x30,
0x37,
0,
0x26,
0x98,
0x1B,
0x7b,
0x53,
0x30,
0x2a,
0,
0x39,
0xD4,
0x63,
0x7B,
0xD4,
 0x2B,
 0x7B,
 0x57,
 0x66,
 0xA8,
 0x2A,
 0x4A,
 0xD4,
 0x23,
 0x7B,
 0x5B,
 0xD4,
 0x2B,
 0x7B,
 0x53,
 0x66,
 0xA8,
 0x2A,
 0x56,
 0x17,
 0x98,
 0x9F,
 0x5F,
 0x5F,
 0x5F,
 0x5F,
 0xB4,
 0x52,
 0x17,
 0x98,
 0x9F,
 0x5F,
 0x5F,
 0x5F,
 0x5F,
 0x17,
 0xDC,
 0xB7,
 0x5E,
 0xB4,
 0x5F,
 0x17,
 0xDC,
 0x9B,
 0x1F,
 0x9C,]
print(len(c))
for i in c:
    print('{:0>2}'.format(hex(i^0x5f)[2:]),end=" ")
```
![](https://img-blog.csdnimg.cn/direct/d1e4b4cd94ad4ea696dfbacc66e1236b.png#pic_center)
6. 将拿到的数据使用十六进制编辑器写入文件，再将文件拖入ida反编译分析汇编代码，其中有一个函数按F5显示源代码错误，就直接分析其汇编代码(也不长)：![](https://img-blog.csdnimg.cn/direct/d8d3551f96504ffaa7ae51b060c6f126.png#pic_center)
7. 上面函数应该使用了RCX寄存器和栈传递了参数，然后与解密后的数据进行比较，可以用脚本反向异或得到部分flag：

```
a=[0x7C072E27^0x12345678,0x87654321^0x87653A4F]
for i in range(len(a)):
    while a[i]:
        print(chr(a[i]&0xff),end="")
        a[i]>>=8
```

![](https://img-blog.csdnimg.cn/direct/738debfa3ee04ceb8ef85d0f2aae6f21.png#pic_center)
9. 函数2直接给出了部分flag字符串：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/c3b23cbef33a423cb47bb31c3f1d0c2e.png#pic_center)
10.  函数3，F5显示元代码错误，直接分析汇编代码，直接进行比较：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/4c13c22d87c34e54853a2cd90a7439d1.png#pic_center)
11. 解密脚本如下：

```
a=[0x795F686F,0x665F756F]
for i in range(len(a)):
    while a[i]:
        print(chr(a[i]&0xff),end="")
        a[i]>>=8
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/f6701f5c7585426a9beb54daed498728.png#pic_center)
12. 将得到的3各字符串拼接起来即可获得flag：**oh_you_found_our_x3nny**，包上ESCTF即可提交。
##  你是个好孩子
1. 下载附件后你会得到3个文件，根据题目要求，将其还原成一个PE文件，具体的PE文件结构自行学习，这里只给出拼接回去的方法，用十六进制编辑器打开4个文件：将**未命名4**开头的两个字节**mz**改为大写，**未命名2**开头的两个字节**pe**改为大写，将**未命名1**开头的一个字节**00**去掉(这里我在**节表**的前面多塞入了一个字节需要去掉)。修改后将**未命名2**复制放在**未命名4**后面，接着继续放入**未命名1**，最后放入**未命名3**，保存**未命名4**并修改后缀为.exe，即可执行该PE文件，输出：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/0a864ff600184608bbdc8c2c366556aa.png#pic_center)
2. 拖入ida分析，发现无论输入什么都只会输出**you are bad boy or girl**，将其用ESCTF包上后提交，发现提交错误：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/c4843010851e4cdfa9afae6f7da04fe5.png#pic_center)
3. 根据题目的提示，应该是**好孩子**而不是**坏孩子**，将bad改为good，即"you are good boy or girl"，再包上ESCTF进行提交发现正确，所以正确的flag为**ESCTF{you are good boy or girl}**：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/3593dd99e18d40b9ba8016031cc440cb.png#pic_center)
## 完结撒花  Q_W_Q















