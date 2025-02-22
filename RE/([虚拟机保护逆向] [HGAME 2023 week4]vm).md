@[TOC]([虚拟机保护逆向] [HGAME 2023 week4]vm)
### 虚拟机逆向的注意点：
1. 根基题目来看，这是一道虚拟机保护逆向的题，这里的虚拟机不是传统意义上像VMware 的虚拟机，这里只是一个程序，执行了像cpu那样取指令、执行指令的操作，与汇编指令类似，但是这里的指令硬件编码经过了作者的修改(opcode)，再结合其本身的编译器,和一些虚拟cpu的环境，来实现类似于cpu执行指令的操作，给逆向增加难度。 虚拟机的逆向题，一般分三个步骤：首先根据逻辑推测出各种寄存器(通用寄存器 和 ip)，ip是指向当前硬件编码的指针，有他取出指令，然后根据程序具体取出的硬件编码和其对应的函数(指令)功能，来逆向出代表硬件编码的指令，最后根据函数功能编写脚本，结合题目中的硬件编码数组(opcode)来逆向出虚拟机实际执行的指令，根据指令实现的功能就可以对应逆向出flag。

2. 程序查壳没有，直接使用ida打开，打开后如下：
​​![描述](https://img-blog.csdnimg.cn/direct/1136c47c66514ce59f88db12dedcc11c.png#pic_center)
 3. 根基函数逻辑重命名后：
![](https://img-blog.csdnimg.cn/direct/50a7f46b9af64b0a911b54299f220051.png#pic_center)
3. 根据主函数可知，输入的flag是40位，输入完成后由vm_cpu函数进行操作，进入vm_cpu函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/890a092900ab41ad92fa4ac22f74f6c4.png#pic_center)
4. 将a1类型改为声明int *方便查看。vm_cpu函数做了一个while循环，但直接看上去似乎着while循环执行的是重复错做，没有对a1[6]累加，直接从汇编层面可以看出着确实是一个循环，退出条件是从opcode中取出的硬件编码是0xff，猜想一改是在sub_140001940函数中对[rax+18h]这个内存出进行了加法操作，实现后移。所以可以大胆猜想[rax+18h](a1[6])就是我们找的"ip寄存器"。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/c61261e26d8c472fa859073510226db1.png#pic_center)
5. 引入下列题目提示的结构体(这里描述的就是虚拟机的结构体)，并将函数中的所有a1全部转化成vm类型，便于查看逻辑：
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/2f99d8c9076f424c8ba80182f3be1e7e.png#pic_center)
6. 进入while循环里的函数，发现这里就是执行指令的函数位置：
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/a7933f033cca428c949e33c7fedd2417.png#pic_center)
7. 将a1声明位vm类型后分析这里函数的功能，分析后如下 ：
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/d44f9ae1ad7b43cfbb313d63f929c572.png#pic_center)
### 具体每个函数的功能，和其对应的硬件编码的*长度* 和 *含义*，都分析出来后就可以编写脚本将题目的opcode转化位vm实际执行的指令 ：
1. mov函数：
![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/ada89824b6a54f5d9ab92b89e5429af7.png#pic_center)
2.  push函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/b95377e5dcac414ead964d529819ecc4.png#pic_center)
3. operation函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/4fb85c4915444adab7946fecfdb26c74.png#pic_center)
4. cmp函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/0179489853e04c1c97d6f95b20c60d63.png#pic_center)
5. jz函数：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/bfa079f52fff48a594e2ad7a104af5a0.png#pic_center)
### 分析完成函数功能后就可以编写脚本输出虚拟机实际执行的指令了：
```
opcode = [0x00, 0x03, 0x02, 0x00, 0x03, 0x00, 0x02, 0x03, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x02, 0x32,
          0x03, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
          0x01, 0x00, 0x00, 0x03, 0x02, 0x64, 0x03, 0x00, 0x02, 0x03,
          0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x01, 0x00, 0x00, 0x03,
          0x00, 0x08, 0x00, 0x02, 0x02, 0x01, 0x03, 0x04, 0x01, 0x00,
          0x03, 0x05, 0x02, 0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x02,
          0x00, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x01, 0x03, 0x00,
          0x03, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03, 0x01, 0x28,
          0x04, 0x06, 0x5F, 0x05, 0x00, 0x00, 0x03, 0x03, 0x00, 0x02,
          0x01, 0x00, 0x03, 0x02, 0x96, 0x03, 0x00, 0x02, 0x03, 0x00,
          0x00, 0x00, 0x00, 0x04, 0x07, 0x88, 0x00, 0x03, 0x00, 0x01,
          0x03, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03,
          0x01, 0x28, 0x04, 0x07, 0x63, 0xFF, 0xFF]
i=0
#还原成x86指令
for j in range(10000000):

    #直到FF为止结束，循环出口位置
    if opcode[i]==0xff:
        break

    # 开始匹配每次取出的指令
    match opcode[i]:
        case 0x00:  #mov指令

            print("(%d)"%(i),end="")#输出当前指令的位置，可以当成jz,jmp,jnz的跳转标记

            tmp=opcode[i+1] #取出第一个操作数
            if tmp==0:
                print("mov reg[0],flag[reg[2]]")
            elif tmp==1:
                print("mov flag[reg[2]],reg[0]")

            elif tmp==2:
                print("mov reg[%d],reg[%d]"%(opcode[i+2],opcode[i+3]))
            elif tmp==3:
                print("mov reg[%d],%d"%(opcode[i+2],opcode[i+3]))
            i+=4    #指令长度为4

        case 0x01:  #push指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            tmp=opcode[i+1] #push的读取下一个指令
            if tmp==0:
                print("push reg[0]")
            elif tmp==1:
                print("push reg[0]")
            elif tmp==2:
                print("push reg[2]")
            elif tmp==3:
                print("push reg[3]")
            i+=2    #指令长度
        
        case 0x02:  #pop指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            tmp=opcode[i+1]
            if tmp==0:
                print("pop reg[0]")
            elif tmp==1:
                print("pop reg[1]")
            elif tmp==2:
                print("pop reg[2]")
            elif tmp==3:
                print("pop reg[3]")
            i+=2    #指令长度

        case 0x03:  #运算指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            tmp=opcode[i+1]     #取出第一个操作数，判断运算方式
            if tmp==0:
                print("add reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            elif tmp==1:
                print("sub reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            elif tmp==2:
                print("mul reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            elif tmp==3:
                print("xor reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            elif tmp==4:
                print("shl reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            elif tmp==5:
                print("shr reg[%d],reg[%d]"%(opcode[i + 2],opcode[i + 3]))
            i+=4    #指令长度为4

        case 0x04:  #cmp指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            print("cmp reg[0],reg[1]")
            i+=1
        case 0x05:  #jmp指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            print("jmp %d"%(opcode[i + 1]))
            i+=2
        case 0x06:  #jz指令
            print("(%d)"%(i),end="")#输出当前指令的位置

            print("jz %d"%(opcode[i + 1]))
            i+=2    #jz指令长度为
        case 0x07:
            print("(%d)"%(i),end="")#输出当前指令的位置

            print("jnz %d"%(opcode[i + 1]))
            i+=2

```
1. 执行的指令如下：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/cff852d207a04ca48cf4f65b03546916.png#pic_center)
2. 利用所学的汇编知识分析汇编指令实现的功能：上述指令表示的功能实际是一个循环，其中循环体内对输入的flag与内存中flag数组后面偏移50的数据进行加法，后与偏移为100处的数据异或，然后执行位移操作(实际上是高8位与低8位互换)，最后于偏移为150位置的数据进行比较。![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/cd9f199d85ec42199d03b7d515094982.png#pic_center)
3. 提取flag后面偏移的数组后，根据逻辑编写处解密脚本如下:

```
a = [155, 168, 2, 188, 172, 156, 206, 250, 2, 185, 255, 58, 116, 72, 25, 105, 232, 3, 203, 201,
      255, 252, 128, 214, 141, 215, 114, 0, 167, 29, 61, 153, 136, 153, 191, 232, 150, 46, 93, 87]
  
b=[201, 169, 189, 139,  23, 194, 110, 248, 245, 110, 99,  99, 213, 70,  93, 22, 152,  56, 48, 115, 
   56, 193,  94, 237, 176, 41,  90,  24, 64, 167, 253,  10,  30, 120, 139, 98, 219,  15, 143, 156,]

c = [18432, 61696, 16384, 8448, 13569, 25600, 30721, 63744, 6145, 20992, 9472, 23809, 18176, 64768, 26881, 23552,
      44801, 45568, 60417,
      20993, 20225, 6657, 20480, 34049, 52480, 8960, 63488, 3072, 52992, 15617, 17665, 33280, 53761, 10497, 54529, 1537,
      41473, 56832, 42497, 51713]
c=c[::-1]
flag=[0]*40
for i in range(len(a)):
    flag[i]=((c[i]>>8)&0xff + (c[i]<<8))
    flag[i]^=b[i]
    flag[i]-=a[i]
for i in flag:
    print(chr(i&0xff),end="")
```
### 总结：虚拟机在逆向题中属于分析过程比较繁琐，难度较大的类型，但是结合具体的方法分析虚拟机执行的指令后也能轻松解决。下一期会继续逆向这个题目，逆向出本题的源代码(毕竟这才是逆向的终极步骤)，加深对cpu(虚拟机)对指令的操作。
