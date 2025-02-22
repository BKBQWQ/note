## 题目地址：[CrackRTF](https://buuoj.cn/challenges#CrackRTF)
1. 程序无壳，直接ida打开：![](https://img-blog.csdnimg.cn/direct/032679d4394d42f5b022f6259e92dfad.png#pic_center)
2. 观察基本的逻辑，分别由两次输入密码，并且都是6位，然后再进行加密和字符串的比较。首先观察第一次输入，程序将第一次的输入经过atoi函数处理后与"**@DBApp**"进行拼接，再进行一个加密，观察atoi函数：![](https://img-blog.csdnimg.cn/direct/285574e55cfa4e46b6bb2235459f383e.png#pic_center)
3. 但似乎看不出什么逻辑，直接打断点再动调几次看函数输出的结果，来反向推测出函数功能即可，使用汇编来观察更为直观，直接观察下方图片中的ax寄存器值，将其转化为10进制，发现**1E240**就是**123456**，可见ato函数的功能就是将输入的**6位数字字符**转化位相应的实际值，输入**英文字符**时返回固定为**0**(自行实验)：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/cce21465dfb84a95857812dd05763d4f.png#pic_center)![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/26a0b6594f9a43438e10454de327018f.png#pic_center)
4. 继续下面的if语句判断，根据atoi函数的返回值，确定了输入的password对应整数值必须大于**100000**，限定了password范围(利用这个范围再后面可以直接破解出密码)。
5. 继续跟进后面的加密函数，发现并不是类似与异或的加密，而是使用hash算法，具体是那种hash可以根据器给定的编号**0x8004**：![](https://img-blog.csdnimg.cn/direct/96573e9f252543548e321ec1bc06a389.png#pic_center)
6. 查询资料后发现**0x8004u**hash是sha1加密，几种常见的hash加密编号(价值)如下：[具体的网站在这里](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id)![](https://img-blog.csdnimg.cn/direct/7aca5bdc7df8496ba7422a40c44edf4e.png#pic_center)
![](https://img-blog.csdnimg.cn/direct/5576a0af018a4b1e913a61e111882ef0.png#pic_center)
![](https://img-blog.csdnimg.cn/direct/92af0e3ddcb7401e82ecc65f753162a4.png#pic_center)
7. 根据前文分析出的password范围(**100000~999999**)，编写脚本进行爆破：

```
import hashlib
for i in range(100000,1000000):
    tmp=str(i)+"@DBApp"
    if hashlib.sha1(tmp.encode('utf-8')).hexdigest()=="6e32d0943418c2c33385bc35a1470250dd8923a9":
        print(tmp)
#123321@DBApp
```
8. 所以，破解出来第一次的密码为**123321**，关于sub_401230函数里面的逻辑可以查看这篇[大佬的文章](https://blog.csdn.net/qq_53532337/article/details/121275061?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522171032779316800222814166%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=171032779316800222814166&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-121275061-null-null.142%5Ev99%5Epc_search_result_base5&utm_term=CryptCreateHash&spm=1018.2226.3001.4187)。
9. 继续向后分析第二次加密，其将第一次的结果String1与第二次的输入password_1进行拼接，然后再次加密比较，接下来直接跟进后面的加密函数：![](https://img-blog.csdnimg.cn/direct/8fa4d2805ad94b968c7aa1922b3a0ba2.png#pic_center)
10.发现这里的加密后先前大差不差，但是这次加密函数的编号选择为**0x8003u**，通过查询上面的网站发现是hash中的md5加密，这里如果直接利用脚本破解很不现实，因为第二次加密的password没有给出范围，这就意味着会有128的6次方种情况需要遍历：![](https://img-blog.csdnimg.cn/direct/4abf8cbf99394f4a9c06ac33e88715e3.png#pic_center)
10. 这里继续向后观察最后一个加密函数j_encrpt，传入的参数是两次拼接的password+”@DBApp“(未加密)，j_encrpt函数的逻辑是，找到一个名为 **"AAA"** 的文件从中读取数据给到 **lpBuffer**，然后经过sub_401005函数处理，sub_401005函数是将读取出来的数据与password进行异或并给到原来的**lpBuffer**：![](https://img-blog.csdnimg.cn/direct/bf22b51cf7294f5191a0e1f8905a19e2.png#pic_center)![](https://img-blog.csdnimg.cn/direct/6547f77b0b804c699ea37909602a6d16.png#pic_center)
11. 最后，打开一个名为"dbapp.rtf"的.rtf文件，**.rtf**文件实际上一个word文件，将加密后的lpBuffer写入到"dbapp.rtf"文件，去学习了相关.rtf文件的知识后发现，.rtf写入时在文件头部分 **{\rtf1** 是 **必不可少的**，详细的参照这篇[大佬的文章](https://blog.csdn.net/huang714/article/details/88714731?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522171033367516800184197913%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=171033367516800184197913&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-5-88714731-null-null.142%5Ev99%5Epc_search_result_base5&utm_term=%E4%BD%BF%E7%94%A8c%E6%89%93%E5%BC%80.rtf%E6%96%87%E4%BB%B6&spm=1018.2226.3001.4187)。
![](https://img-blog.csdnimg.cn/direct/e09a17aebec24ab6860eb537376520ce.png#pic_center)
12. 所以，从文件"AAA"终读取出来的数据与password异或后必须出现**{\rtf1** ,这是只需要知道AAA文件中的内容即可异或出第二次的password，这里读取"AAA"文件的类容听说可以使用工具Resource Hacker，但是，这里由第二种方法，直接patch修改**strcmp的条件**后动调，然后去内存中查找从"AAA"提取出来的数据，只需要前6位即可异或出password，如下：![](https://img-blog.csdnimg.cn/direct/7d01fb3eafa34b28b7e29fac7e454720.png#pic_center)![](https://img-blog.csdnimg.cn/direct/57a3a1054b854d63a93f4989dff7cd53.png#pic_center)
13. 这里使用工具Resource Hacker观察"AAA"文件内容一致，工具Resource Hacker原版的下载地址如下：[地址](https://fletime.lanzoux.com/i8pQTimy99c)：![](https://img-blog.csdnimg.cn/direct/ae0635e297bf40f59b4f075314c15807.png#pic_center)
14. 这里直接给出最后提取出来的数据key=[0x05,0x7D,0x41,0x15,0x26,0x01],最后解密脚本如下：
```
res="{\\rtf1"
key=[0x05,0x7D,0x41,0x15,0x26,0x01]
for i in range(len(key)):
    print(chr(ord(res[i])^key[i]),end="")
#~!3a@0
```
15. 所以第二次的password为~!3a@0，回去将strcmp的patch修改回来，再根据得到的flag跑一边即可得到flag=Flag{N0_M0re_Free_Bugs}：![](https://img-blog.csdnimg.cn/direct/ea7bead6483747c6b19099623ee47d6d.png#pic_center)
## 总结：
1. hash算法可根据其编号来选择。
2. .rtf文件的开头必须为 **{\rtf1**。
3. 使用工具**Resource Hacker**可以查看文件内容。
4. 在新建一个.rtf文件时，用16进制编辑器查看里面内容：![](https://img-blog.csdnimg.cn/direct/fc9ce56546d54b4a963ce768b00ab691.png#pic_center)
5. 在里面写入内容后，经过验证发现不同的.rtf文件的文件头都是以**{\rtf1**开头：![](https://img-blog.csdnimg.cn/direct/60920e85a13541879dbb0ec4da5b58c3.png#pic_center)








 







