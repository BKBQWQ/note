# ISCC

## 迷失之门

1. 

   * 进入ida，会有四个表：![image-20240502103104445](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117838.png)

   * 后面的加密逻辑，根据这四个表来：![image-20240502103203118](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117032.png)

   * 加密后的结果在check2：![image-20240502103336870](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117543.png)

   * 根据加密函数，逆向出解密脚本：

     ``````python
     m = [70, 83, 66, 66, 104, 75, 77, 49, 114, 84, 111, 67, 87, 107, 115, 110, 84, 75, 77, 70, 73, 68, 83, 83, 72, 103,54]
     enc = "".join([chr(i) for i in m])
     key=[i for i in b"DABBZXQESVFRWNGTHYJUMKIOLPC"]
     
     # print([i+51 for i in key])
     
     char_sets = [
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
         "abcdefghijklmnopqrstuvwxyz",
         "0123456789+/-=!#&*()?;:*^%"
     ]
     index = []
     for char in enc:
         for i, char_set in enumerate(char_sets):
             if char in char_set:
                 index.append(char_set.index(char) + i * 0x1a)
                 break
         else:
             print("Error: Invalid character in encoded data.")
     
     flag = ""
     for i in range(len(index)):
         flag += chr((key[i] + index[i]))
     
     print(flag)
     #ISCC{b]z~inTmrs{[cVZUN[aSp}
     ``````

  

## CrypticConundrum

1. * upx脱壳后进入ida，main函数观察逻辑：![image-20240502174034508](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117040.png)
   * 要求输入flag，然后进行了mix，Encryption两个函数的加密，最后与v8对比：
     * mix函数，接受一个key参数：![image-20240502174251570](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117231.png)
     * 解密逻辑长且混乱，但是直接看到**return**可以发现又将flag恢复了(真就离谱哈)，所以可以直接跳过分析这函数。
   * Encryption函数，加密逻辑比较简单：![image-20240502174435176](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117267.png)
     * NewEncryption函数，退出时进行了一个倒换，然后到Encryption又倒换了一次，所以这倒换可以忽略：![image-20240502174510271](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142117315.png)
   * 解密脚本，注意v8提取数据的时候，注意大小端序，有两个时多余的：

   ``````python
   res=[0xA7, 0x77, 0xE0, 0x34, 0x23, 0x29, 0x8D, 0x8A,
       0xD2, 0x4B, 0x87, 0xB7, 0xC1, 0x64, 0xF1, 0x08,
       0x86, 0x71, 0x47, 0xDD, 0xED, 0xFA, 0x67, 0x9D,
       0xC7, 0x34]
   key='ISCC'
   for i in range(len(res)):
       res[i]-=10
   
   for i in range(len(res)-1):
       res[i]+=res[i+1]
       res[i]^=ord(key[2])
   
   for i in range(0,len(res)):
       if i%2==0:
           res[i]^=ord(key[i%4])
       res[i]+=ord(key[i%4])
       print(chr(res[i]&0xFF),end="")
   #ISCC{4FNLPmjdU(|2:S8"a3V6}
   ``````

   

## Badcode

1. * 进入ida，前面的不管，直接看后面的逻辑：![image-20240502104038039](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118555.png)

* 分析后，第一个循环：**奇数位+2**，**偶数位-3**。

* 第二个循环：将前面加密后的字符，逐位于与[6,7,4,0,9,4,8,7,2,0,3,8,7,7,1,1,4,8,6,6,6,7,3,7]**异或**。

* 最后进行一个**XXTEA加密**，典型的XXTEA加密，加密后的结果在Buf2，密钥在dword_4E7018，提取出来后脚本加密：![image-20240502104235480](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118956.png)

* XXTEA解密：

  ``````c++
  #include <stdbool.h>
  #include <stdio.h>
  #define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum ^ y) + (k[(p & 3) ^ e] ^ z))
  bool btea(unsigned int *v, int n, unsigned int *k)
  {
      unsigned int z = v[n - 1], y = v[0], sum = 0, e, DELTA = 0x61C88647;
      unsigned int p, q;
      if (n > 1)
      { /* enCoding Part */
          q = 415 / n + 114;
          while (q-- > 0)
          {
              sum += DELTA;
              e = (sum >> 2) & 3;
              for (p = 0; p < (n - 1); p++)
              {
                  y = v[p + 1];
                  z = v[p] += MX;
              }
  
              y = v[0];
              z = v[n - 1] += MX;
          }
          return 0;
      }
      else if (n < -1)
      { /* Decoding Part */
          n = -n;
          q = 52 / n + 6;
          sum = -q * DELTA;
          while (sum != 0)
          {
              e = (sum >> 2) & 3;
              for (p = n - 1; p > 0; p--)
              {
                  z = v[p - 1];
                  y = v[p] -= MX;
              }
  
              z = v[n - 1];
              y = v[0] -= MX;
              sum += DELTA;
          }
          return 0;
      }
      return 1;
  }
  
  int main()
  {
      unsigned int v[11] = {0x6C253785, 0x57E6FA7A, 0x375EA5C0, 0x99634103, 0x98E9CD05, 0xC7B13882};
      unsigned int key[4] = {0x12345678, 0x9ABCDEF0, 0x0FEDCBA98, 0x76543210};
      int n = 6;        // n为要加密的数据个数
      btea(v, -n, key); // 取正为加密，取负为解密
      char *p = (char *)v;
      for (int i = 0; i < 44; i++)
      {
          printf("%c", *p);
          p++;
      }
      return 0;
  }
  
  // @RDEqIz|CvWmuudNkCHU23-x
  
  ``````

  ``````python
  key=[6,7,4,0,9,4,8,7,2,0,3,8,7,7,1,1,4,8,6,6,6,7,3,7]
  flag=""
  a="@RDEqIz|CvWmuudNkCHU23-x"
  for i in range(24):
      flag+=chr(ord(a[i])^key[i])
  
  for i in range(24):
      if i&1==1:
          print(chr(ord(flag[i])-2),end="")
      else:
          print(chr(ord(flag[i])+3),end="")
  ``````

  * flag:**ISCC{KuyDtWcuphMrIQQ721}**

## DLLCode

1. * ida打开，直接进main函数，要求输入24个字符：![image-20240502190209148](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118882.png)

   * 后面循环的逻辑将输入的字符按奇、偶位下标分开，给到v17，v18。

   * 后续，对v17进行了异或加密，但是加密函数时外部导入的动态连接库BH_Dll.dll中的函数，ida进入BH_Dll.dll分析enocde函数，观察(动态调试)逻辑发现是与**ISCC**进行简单的**异或**：![image-20240502190704676](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118319.png)

   * change函数，观察逻辑发现是按表v4，对字符进行**置换**：![image-20240502190905647](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118364.png)

   * 最后sub_D12DA0函数将两次加密(分别是12位)后的字符拼接起来(24位),奇数位在前、偶数位在后，然后与v9进行比较，v9即为最后加密的结果,解密脚本如下。

     ``````python
     res=[0,0x10,0x38,0x14,0x11,9,0x27,0x21,0x1B,0,0x14,3,0x43,0x59,0x53,0x59,0x50,0x4A,0x53,0x53,0x74,0x7D,0x75,0x62]
     res1=res[0:12]
     res2=res[12:24]
     
     key="ISCC"#奇数位异或
     res3=[]
     sub=[2,0,3,1,6,4,7,5,10,8,11,9]#偶数位置换
     for i in sub:
         res3.append(res2[i])
     flag=""
     for i in range(12):
         flag+=chr(ord(key[i%4])^res1[i])
         flag+=chr(res3[i])
     print(flag)
     # ISCC{YWYXSZPdSbJRuStWb@}
     ``````



## WinterBegins

1. ida打开，进入main函数：这里加了一点混淆。![image-20240509171619081](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118402.png)
1. 动调后，发现主要看前面的加密逻辑：![image-20240509171738120](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118912.png)
1. 最后的加密结果要与v4比较，v4经过res **change_site**变换得到：函数逻辑只是两个数据一组，简单的首尾交换位置。![image-20240509171921227](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118463.png)
1. 进入init_v10函数，其也经过了混淆：但是通过动调发现，其功能：使用flag初始化v10，将flag填入v10，若flag中有重复的字符，则v10中保存单个字符＋重复个数。![image-20240509172041186](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118693.png)
1. 后续使用v10进行加密，最后结果给Str1，进去观察加密函数：由三个加密函数构成，从前往后看。![image-20240509172202024](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118084.png)
1. `encode_1函数`：函数都经过了混淆，可以通过动态调试，观察 **寄存器的变化** 来推测相关功能，后续的`encode_2函数`,`encode_3函数`同样可以通过动态调试推测功能：

* `encode_3函数`：功能使一个查表替代的功能实现，表在 **byte_7FF67C9FE340**中，输出一下这个表：![image-20240509172748151](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118722.png)

​	![image-20240509173041882](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118585.png)

* 根据查的表可以推测前面的函数设计将输入的v10进行一定操作，将其转化为 **下标** ，

* `encode_2函数`：加密主要在这两个位置，观察逻辑不难发现，一个减'A'加4，一个减'0'，减A的前面多放入了一个11（后面解密判断使-A还是-0要用到）：![image-20240509173319798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142118014.png)

  ![image-20240509173338323](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405091733365.png)

* `encode_2函数`，这里判断了当前位置是数字还是其他字符，不同的话有不同的操作：![image-20240509173800352](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142119708.png)

* `encode_1函数`：大致看看，在结合其为后面函数传入的参数，应该是将输入的flag转化为encode_2输入的样式，经过动调发现是将输入的flag按照AISSC码转化为对应的16进制字节串：![image-20240509173954147](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142119558.png)

  ![image-20240509174316886](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142119103.png)

7. 最后提取出来加密后的数据：直接使用内置的printf函数输出即可![image-20240509174503382](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405142119760.png)
8. 解密脚本如下，最后将输出转化为对应个数的字符即可：

``````python
table="冻笔新诗懒写寒炉美酒时温醉看墨花月白恍疑雪满前村"
enc="美酒恍疑时温寒炉美酒寒炉寒炉懒写墨花前村时温时温前村恍疑醉看恍疑寒炉懒写醉看懒写墨花恍疑醉看美酒墨花寒炉墨花时温墨花懒写醉看前村美酒醉看月白墨花美酒墨花前村美酒墨花新诗醉看月白墨花新诗醉看前村月白寒炉懒写醉看月白墨花前村墨花"
index=0
idx_list=[]
while index<=len(enc):
    temp=enc[index:index+2]
    #temp=temp[::-1]
    idx=table.find(temp)//2
    idx_list.append(idx)
    index+=2

char_list=[]
index=0
while index<len(idx_list):
    if idx_list[index]==11:
        char_list.append(chr(61+idx_list[index+1]))
        index+=2
    else:
        char_list.append(chr(idx_ list[index]+ord('0')))
        index+=1
flag=''
for i in char_list:
    flag+=i
print(flag)
for i in range(0,len(flag),2):
  print(chr(int(flag[i:i+2],16)),end="") 
#ISC2{_i2bydsurjhtzqhqn2h}
#ISCC{_iibydsurjhtzqhqnnh}
``````



## Find_All

1. ida进入main函数：一眼迷宫，直接开解。![image-20240509200527560](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092005648.png)
2. 地图路径：ddsswwdddssssssss。![image-20240509200628879](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092006928.png)
3. 拿到钥匙直接解开图片，但是图片似乎没啥用：![image-20240509200730346](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092007414.png)
4. 返回程序继续看看：汇编中main函数前面有一个函数，但是反编译的时候没有显示出来：![image-20240509202317136](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092023212.png)
5. 进入函数查看，有一群异或操作：应该是加密流程，后面要找到加密的数据。![image-20240509202746046](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092027108.png)
6. 看左边函数列表中encode函数下一个函数：明显的密文，直接上解密脚本。![image-20240509203557705](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092035780.png)
7. 在ida中运行：

``````idapython
v4=[get_wide_byte(0x00581625+i*7) for i in range(24)]
for i in range(0,len(v4) - 1,4):
    v4[i + 2] ^= v4[i+3]
    v4[i + 1] ^= v4[i + 2]
    v4[i] ^= v4[i + 1]
print(v4)
print(bytes(v4).decode())
``````

![image-20240509203723852](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092037935.png)

## I_am_the_Mathematician

1. 进main函数：先进行了一下权限认证：。![image-20240509212418444](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092124538.png)

2. 解出来数学家是Leonardo_Fibonacci(“莱昂纳多·斐波那契”),直接输入进去，果然没错。![image-20240509212559004](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405092125081.png)

3. 提示是： **But you have to decrypt it first**,需要先将code_book解密。

4. 斐波那契总所周知，前两个加等于后一个，开始两个初始化时1，1.前面题目提示了 **The mathematician has a codebook. Who is the mathematician and where is the true code？**(“数学家有一本密码本。谁是那个数学家，真正的代码在哪里？”) 说明这是一个密码本，我们需要查这个密码本，在根据提示Leonardo_Fibonacci(“莱昂纳多·斐波那契”)，自然而然想到 **斐波拉契数列**，根据 **斐波那契数列的值** 来查密码本：

   ``````python
   def fib(n):
       a,b = 0,1
       lis = []
       for i in range(n):
           a,b =b,a+b
           lis.append(a)
       return lis
   
   with open("./code_book_34.txt","r") as file:
       data = file.read()
       file.close()
   
   target = fib(22)
   print(target)
   print(f"ISCC{{{''.join([data[i - 1] if i < len(data) else '' for i in target])}}}")
   #ISCC{IIPrw0sd0vCrMviiZr}
   ``````

   