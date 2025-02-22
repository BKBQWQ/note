@[toc](PE文件格式)
1. 例如像.exe .elf .all .sys为后缀的文件都是PE文件，下面以hello world.exe文件作为分析样本。
2. 下面是PE文件的整体结构：
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146146.png)

## PE头：
1. 学习PE文件格式主要学习的时PE文件的PE头，如何加载到内存，从何处开始运行、运行中需要的动态来链接库DLL有哪些、需要多大的堆/栈内存等，都以结构体的形式储存在PE头中。
2. PE头包含一下几个部分：DOS头，DOS存根，NT头，.text(代码)(节区头)，.data(数据)(节区头)，.rsrc(资源节)(节区头)。
### DOS头
1. ![在这里插入图片描述](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145597.png)
2. DOS头结构体如下：
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145227.png)

4. DOS头最重要的成员有两个：第一个**e_magic** : 前两个字节指明了DOS签名**4D5A**(MZ),第二个:**e_lfanew**,指明了**NT头**在文件内的偏移。
### DOS存根
1. ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145777.png)
2. DOS存根部分是上个时代遗留下来的产物，在windos平台下不会执行这段命令，但是在DOS环境下运行时会执行，显示出”This program cannot be run in DOS mode“，DOS存根为的就是在DOS环境下显示一些有用的信息二存在。
3. 在DOS下查看，前13个字节会被翻译成汇编代码，调用了21号中断的09号功能，来显示后面字符串的内容：
5. ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145695.png)
![](https://img-blog.csdnimg.cn/direct/ad4024f747964387acb7b0a872b4f6f5.png#pic_center)
### NT头
1. 根据DOS头最后的4个字节找到PE头在文件中的偏移：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145331.png)
2. NT头结果提如下：![=](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222145478.png)
3. 首位的4个字节为签名：**50 4F 00 00** -> “**PE**”
4. 其次是一个文件头(IMAGE_FILE_HEADER)和可选头(IMAGE_OPTIONAL_HEADER)，下面来分别查看这两个结构体
#### NT头：文件头
1. ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146962.png)
2. 去掉前面4个字节的标识后，后面的20个字节就是NT头的文件头：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146732.png)
3. 第一个**Machine**指明了运行平台，每个CPU都拥有唯一的Machine码。
4. 第二个**NumberOfSections**指明了文件中存在的节区的数目
5. 倒数第二个**SIzeOfOptionalHeader**指明了后续可选头的大小为**00F0**(注意这个是小端序)
#### NT头：可选头
1. ![在这里插入图片描述](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146093.png)
2. 可选头的结构体如下：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146521.png)
3. 其中包含的星系非常丰富，要完全认权可以自行查看微软的开发文档，则合理只介绍几个重要的结构
4. **ImageBase**指出文件被加载到内存时优先装入的基地址。
5. **AddressOfEntryPoint**有EP的RVA(文件被加载到内存中的相对前面**ImageBase**的偏移),指明了最先执行的代码的起始地址,有**EIP = ImageBase+AddressOfEntryPoint**，EIP寄存器指向要执行的代码。
6. **SizeOfHeader**指出了整个PE头的大小。
7. 最后一项**DataDirectory**，其由时**IMAGE_DATA_DIRECTORY**构成的数组，IMAGE_DATA_DIRECTORY结构体如下：![在这里插入图片描述](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146898.png)
8. 第一项是RVA(加载到内存中是的偏移地址)，Size(当前表的大小)。
9. 节表的内容如下：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147163.png)
10.在最后一项**DataDirectory**中主要重点关注，第一项导出目录(**导出表**) 和 第二项导入目录(**导入表**) ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222146018.png)
9. 从上面可见，该hello.exe程序没有导出表，但是又一个导入表，其RVA为 : **00008000**(但是这只是导入表的RVA，不是其在文件中的偏移，后面会进行转换)

### 节区头

1. 节区头的结构体：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147843.png)
2. **Name**指明了节的名字。
3. **VirtualAddress**指明了节的偏移RVA(相对于ImageBase)
4. **PointerToRawData**节在文件中的偏移
5. **Charactercis**节的属性，是可读、可写。
####  .text(代码)(节区头)
1. 
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147031.png)
2. 说明 **.text节区** 的RVA是 **00001000**，FOA是 **00000400** ，之间相差了00000C00。
####   .data(数据)(节区头)
1. 
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147456.png)
2. 说明 **.data节区** 的RVA是**00003000**，FOA是**00002200**. 之间相差了00000E00。
#### .rdata
1. ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147538.png)
2. 说明**.rdata节区**的RVA是**00004000**，FOA是**00002400**，之间相差00001C00。
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147521.png)

#### .idata，导入表
![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147740.png)

1. 说明**.idata节区**的RVA是**00008000**，FOA是**00003000**，之间相差00005000
2. .idata中包含导入函数的信息，即程序运行时需要调用的外部函数（或API）的信息。查看RVA：**00008000**刚好和前面查看的**导入表RVA**相同，说明.idata段的开头就是导入表的所在位置，但是现在只知道RVA(其加载到内存中后的偏移地址)，并不知道其FOA(在文件中的偏移)。
3. 但是由于.idata的RVA刚好和导入表的RVA相同，所以直接使用.idata的FOA(PointerToRawData)，作为导入表的在文件中的偏移**00003000**，去查得导入表，其一共导入了两个库(一个占20字节，最后20字节全为0)：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147592.png)
4. 根据导入表的结构体：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147962.png)
5. 其中那么字段指明了导入的动态链接库DLL的名字的RVA**000086E8**，安静其转化为FOA即可定位到该库的具体位置：**000086E8-00005000(前面在idata中计算出的RVA与FOA的差值)=36E8**,定位到下面这张图的位置,库的名字叫**KERNEL32.dll**，KERNEL32.dll是Windows操作系统中一个非常核心的32位动态链接库（DLL）文件，它对系统运行至关重要。：![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147771.png)
6. 查看第二个动态链接库：**00008760-00005000=0003760**，定位到下面这张图，**msvcrt.dll**：![在这里插入图片描述](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147411.png)
## 最后给出一个PE文件的16进制编辑器中的截图，找到其中每一个头的信息，和导入表等：
1. 原图如下：![在这里插入图片描述](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147046.png)
2. 标识各个部分后如下：

![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405222147224.png)









