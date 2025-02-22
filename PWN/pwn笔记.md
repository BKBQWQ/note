# PWN笔记

## 1、remote、recvuntil、send、sendline、interactive：

* `remote函数`：用于建立与远程主机的连接，并返回一个用于**输入输出**操作的remote对象。

![image-20240507203148562](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072031624.png)

* `recvuntil函数`：在进行**远程程序调试**或**漏洞利用**时，从目标程序或服务端**接受输出**知道接受到**指定字符串**为止，主要用来从目标程序获取特定信息，例如、等待某个特定的提示信息，其通过不间断的读取远程连接的数据，然后进行匹配检查(与指定字符串)



* `send函数`：函数负责向**远程程序**发送数据，不添加其他**任何字符**
* `sendline函数`：函数负责向**远程程序**发送数据，在数据最后自动添加一个**换行符\n**

![image-20240505204824951](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072029048.png)

* `interactive函数`：在已经使用**remote建立远程连接**，并通过漏洞获取了**主机的控制权shell**时，一般利用**system("/bin/sh")**来获取主机的控制权，使用该函数 **启动一个交互式的shell会话** ，方便直接与远程系统进行交互，如执行命令等。前提是需要先获取一定的控制权。



* `process函数` ：启动一个的 **本地可执行文件** 作为一个子进程。（主要用于本地）
* `elf函数`：用于解析和操作 **ELF格式** 的可执行文件 ，对象提供了多种方法来访问和操作ELF文件的内容，通过`elf.plt[fun_name]`和`elf.got[fun_name]`，你可以分别获取指定函数（在这个例子中是`read`）在程序的 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 中的地址。



## 2、bytes.fromhex(a)，encode()，l/rjust()，u64/u32()

* `bytes.fromhex()函数`：将**十六进制字符串**转化为字节对象，所以，如果接受的输入**十六进制字符串**不是偶数位时(字符**两两一组**)，将会报错，因为每个十六进制字符只能表示4bit，而一个字节对象是8bit。

* `encode()函数`：字符串类型（str）的方法，它将 **字符串** 编码成字节串（按照ASCII码），通常用于将字符串转换为特定编码的字节表示形式，如UTF-8、**ASCII**等

* 注意```'a'.encode()是一个字节```而`(bytes.fromhex("aa")是一个字节`，但是表示的字节串不一样。

* ``````python
  bytes.fromhex("abcdef")
  ``````

* ``````python
  bytes.fromhex("c")#报错
  ``````



* 

  ``````python
  print((int('22',16)))
  print((bytes.fromhex("22")))
  print(ord('''"'''))
  
  print(bytes.fromhex(hex(ord('a'))[2:]))
  print('a'.encode())
  #b'a'
  #b'a'
  ``````



* `bytes.fromhex()`与`encode()`的区别：<img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405072030870.png" alt="image-20240503225835675" style="zoom:150%;" />

* `ljuist(x,y)`：对 **字节串** (或字符串)左对齐，且总正字长为x，不足长的使用字节y进行补充。

  ``````python
  from pwn import *
  #字节串,用字节串00填充
  a = b'233dc'
  print(hex(u64(a.rjust(8,b'\x00'))))
  
  #字符串，用字符0填充
  a = '233dc'
  print(((a.rjust(8,'0'))))
  ``````

  



## 3、pwn.xor(a,b)

* `xor函数`:其接受两个a,b**字节对象串**(二进制8bit)作为输入，如果两个字节串的长度不一样，则**较短的字节串**会全部被**重复使用**，继续与长的字节串进行异或。

* ``````python
  print(xor(bytes.fromhex('aa'),bytes.fromhex("2222222222222222")))
  print(xor('a'.encode(),'abcd'.encode()))
  ``````



## 4. flat函数：

* 将参数按顺序转化为连续的字节序列

```python
#下面两个等价
payload = p64(pop_rdi_ret) + p64(put) + p64(puts_addr)
payload = flat(pop_rdi_ret,put,puts_addr)
```



## 5. pwngdb使用

1. `b *地址` ：在 **程序** 对应地址处下断点，程序运行到该处时停止(一般与continue **c** 结合使用)。

2. `rwatch *地址` ：在栈上的该地址处下 **硬件读断点** 。
3. `awatch *地址 `： 在栈上的该地址处下 **硬件读写断点** 。
4. `d 断点编号 `：撤销该编号的断点（一般与i b查看断点一起使用）。
5. `x/32xb 0x2222`：查看 **0x2222地址** 处的 **字节** 数据32个
6. `x/32x 0x2222`：查看 **0x2222地址** 处的 **字** 数据32个

![image-20240517211405112](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405172114174.png)

4. `x/<n>f<u> 地址` ： **查看** 指定地址处内存的值，具体细节如下：

![image-20240517211838922](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405172118974.png)



## utf-8 编码

1. latin-1，范围0~255（固定一个字节）:

   ![image-20241006161306719](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202410061613790.png)

   ```
   
   ```

   

2. UTF-8，变长的字符编码：

   > [!IMPORTANT]
   >
   > 在UTF-8编码中，字符可以使用1到4个字节来表示，每种情况遵循不同的格式：
   >
   > 1. **1个字节**：
   >    - 二进制格式：`0xxxxxxx`
   >    - 范围：U+0000 到 U+007F（0到127）
   >    - 这是最基本的拉丁字母表，包括ASCII字符集。
   >
   > 2. **2个字节**：
   >    - 第一个字节的格式：`110xxxxx`
   >    - 第二个字节的格式：`10xxxxxx`
   >    - 范围：U+0080 到 U+07FF（128到2047）
   >    - 这包括拉丁-1补充字符集和其他语言的基本字符。
   >
   > 3. **3个字节**：
   >    - 第一个字节的格式：`1110xxxx`
   >    - 第二个字节的格式：`10xxxxxx`
   >    - 第三个字节的格式：`10xxxxxx`
   >    - 范围：U+0800 到 U+FFFF（2048到65535）
   >    - 这包括大多数的Unicode字符，如汉字、日文、韩文等。
   >
   > 4. **4个字节**：
   >    - 第一个字节的格式：`11110xxx`
   >    - 第二个字节的格式：`10xxxxxx`
   >    - 第三个字节的格式：`10xxxxxx`
   >    - 第四个字节的格式：`10xxxxxx`
   >    - 范围：U+10000 到 U+10FFFF（65536到1114111）
   >    - 这包括辅助平面的Unicode字符，如一些表情符号、古文字等。
   >
   > 在UTF-8编码中，每个字节的高位（bit）模式指示了这个字节是起始字节还是继续字节，以及整个字符需要多少个字节来表示。起始字节的高位1的个数表明了字符的字节长度，而继续字节总是以 `10` 开头。

   

   在将**字节串**解码成**字符串**时：

   * 如果遇到 < b"\x7f" ==> **0xxxxxxx** 就按一个字节解码：
   * 如果遇到  b"\xc1\x80" < b"\xdf\xBF"==> 第一个字节 **110xxxxx** ，第二个字节**10xxxxxx** 就按一个字节解码：

   ```py
   b = b'\xc2\xa0\xc2\x8cN\xc3\xa1\xc3\x86\x7f'
   print(b.decode("utf-8").encode("latin-1"))
   print(hex(ord(b'\xdf\xbf'.decode("utf-8"))))
   ```

   

