# 攻防世界reverse_box

## 学习心得

1. * 学习到使用 **gdb脚本** 的调试，利用 **脚本** 自动调试程序并进行爆破。
   * 与平常写的题目不同main函数，也可以接受 **参数**，例如一下源程序。

   ``````c
   #include <stdio.h>
   
   #第一个参数是执行文件是命令行传入参数的个数，第二个是个参数再内存中的地址
   int main(int argc, char *argv[])
   {
       printf("hello:\n");
       printf("%d\n", argc);#输出参数的个数
       printf("%s\n", argv[0]);#输出参数的内容
       printf("%s", argv[1]);
       return 0;
   }
   ``````

   输出：![image-20240516154745383](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161547440.png)

2. 清除这两点手进入题目：ida打开，进入main函数，这里可以看到main函数接受了两个参数，和我们前面的提到的相同，检查的传入的参数个数是否大于二。

![image-20240516155040932](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161550987.png)

3. 进入box函数生成了一个长度为256的v4盒子，然后用输入的flag对盒子进行查表输出其盒子中对应偏移的十六进制。这里原来是题目要求最终输出为下面这段数据：

* `95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a`

4. 这里思路就是得到v4这盒子，然后用应该输出的数据对盒子进行逆查找，用值查其再盒子中对应的下标，根据题目要求的flag格式 `TWCTF{}`, 即 `95` ，在盒子中对应的下标即为 **T** 的ASCII码 **84** 。

5. 进入bos分析：利用随机生成的数(非0)的 **低8位** 作为种子来生成整个盒子。![image-20240516155756533](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161557594.png)

6. 进入汇编来查看随机数的生成：and之后，取出eax(本身是32位)，只取用eax的低8位作为种子密钥来生成box，因此可以在调试的时候将eax的值设置为 **0~255** 继续爆破，然后根据偏移为 **84** 处的值是否为 **95** 来判定爆破的结果是否符合要求，或者，在输入部分正确的flag `WTCTF` 后在地址 **0x080486C3**观察输入的第一个值是否为 `95`。

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161633770.png)

7. ![image-20240516160934378](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161609443.png)

![image-20240516161543315](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161615359.png)

7. gdb调试脚本如下：

``````python

set $i=0
set $total=256

while($i<$total)

  b *0x80485b4
  b *0x8048707
  
  run TWCTF
  
  set $i=$i+1
  set *(char*)($ebp-0xc)=$i
  continue
  
  if ($eax==0x95)
    print $i
    x/256xb $esp+0x1c
    set $i=256
    
  end
  stop
end
end

``````

8. 脚本说明：

   ``````python
   #设置爆破的范围0~255
   set $i=0
   set $total=256
   
   while($i<$total)
     #每次进入都需要打上断点，一次调试结束后gdb会清除掉断点
     #在地址0x080485B4处打上断点，后续为eax传递爆破的数字
     b *0x80485b4
     #在地址0x080485B4处打上断点，后续检查eax的值是否爆破正确
     b *0x8048707
     
     #启动程序，并传入参数TWCTF
     run TWCTF
     
     #计数器加一
     set $i=$i+1
     
     #将栈上的数据覆盖，用爆破的种子即覆盖原来随机生成的种子
     #这里也可以在0x080485B1处打断点，直接为eax赋值为i，是相同的效果
     set *(char*)($ebp-0xc)=$i
      
     #继续执行程序
     continue
     
     #在0x8048707处检查eax的值是否正确，正确则直接输出盒子，不正确则继续执行脚本，调试程序
     if ($eax==0x95)
       #打印爆破出来的种子
       print $i
       #答应盒子，共256个字节，地址从esp+0x1c处开始
       x/256xb $esp+0x1c
       #退出if语句后达到循环条件，直接退出
       set $i=256
       #if语句结束
       end
     #结束一次调试
     stop
   end
   end
   
   ``````

   9.  脚本执行：将上面代码放入source.sh文件，进入调试后直接使用命令 **source source.sh** 即可执行脚本自动调试程序。

   ![image-20240516163016666](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161630744.png)

   ![image-20240516162926871](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161629954.png)

10. 拿到盒子后输出flag：

``````python
table=[
 0xd6,   0xc9 ,   0xc2,    0xce,    0x47,    0xde,    0xda,    0x70,
 0x85,   0xb4 ,   0xd2,    0x9e,    0x4b,    0x62,    0x1e,    0xc3,
 0x7f,   0x37 ,   0x7c,    0xc8,    0x4f,    0xec,    0xf2,    0x45,
 0x18,   0x61 ,   0x17,    0x1a,    0x29,    0x11,    0xc7,    0x75,
 0x02,   0x48 ,   0x26,    0x93,    0x83,    0x8a,    0x42,    0x79,
 0x81,   0x10 ,   0x50,    0x44,    0xc4,    0x6d,    0x84,    0xa0,
 0xb1,   0x72 ,   0x96,    0x76,    0xad,    0x23,    0xb0,    0x2f,
 0xb2,   0xa7 ,   0x35,    0x57,    0x5e,    0x92,    0x07,    0xc0,
 0xbc,   0x36 ,   0x99,    0xaf,    0xae,    0xdb,    0xef,    0x15,
 0xe7,   0x8e ,   0x63,    0x06,    0x9c,    0x56,    0x9a,    0x31,
 0xe6,   0x64 ,   0xb5,    0x58,    0x95,    0x49,    0x04,    0xee,
 0xdf,   0x7e ,   0x0b,    0x8c,    0xff,    0xf9,    0xed,    0x7a,
 0x65,   0x5a ,   0x1f,    0x4e,    0xf6,    0xf8,    0x86,    0x30,
 0xf0,   0x4c ,   0xb7,    0xca,    0xe5,    0x89,    0x2a,    0x1d,
 0xe4,   0x16 ,   0xf5,    0x3a,    0x27,    0x28,    0x8d,    0x40,
 0x09,   0x03 ,   0x6f,    0x94,    0xa5,    0x4a,    0x46,    0x67,
 0x78,   0xb9 ,   0xa6,    0x59,    0xea,    0x22,    0xf1,    0xa2,
 0x71,   0x12 ,   0xcb,    0x88,    0xd1,    0xe8,    0xac,    0xc6,
 0xd5,   0x34 ,   0xfa,    0x69,    0x97,    0x9f,    0x25,    0x3d,
 0xf3,   0x5b ,   0x0d,    0xa1,    0x6b,    0xeb,    0xbe,    0x6e,
 0x55,   0x87 ,   0x8f,    0xbf,    0xfc,    0xb3,    0x91,    0xe9,
 0x77,   0x66 ,   0x19,    0xd7,    0x24,    0x20,    0x51,    0xcc,
 0x52,   0x7d ,   0x82,    0xd8,    0x38,    0x60,    0xfb,    0x1c,
 0xd9,   0xe3 ,   0x41,    0x5f,    0xd0,    0xcf,    0x1b,    0xbd,
 0x0f,   0xcd ,   0x90,    0x9b,    0xa9,    0x13,    0x01,    0x73,
 0x5d,   0x68 ,   0xc1,    0xaa,    0xfe,    0x08,    0x3e,    0x3f,
 0xc5,   0x8b ,   0x00,    0xd3,    0xfd,    0xb6,    0x43,    0xbb,
 0xd4,   0x80 ,   0xe2,    0x0c,    0x33,    0x74,    0xa8,    0x2b,
 0x54,   0x4d ,   0x2d,    0xa4,    0xdc,    0x6c,    0x3b,    0x21,
 0x2e,   0xab ,   0x32,    0x5c,    0x7b,    0xe0,    0x9d,    0x6a,
 0x39,   0x14 ,   0x3c,    0xb8,    0x0a,    0x53,    0xf7,    0xdd,
 0xf4,   0x2c ,   0x98,    0xba,    0x05,    0xe1,    0x0e,    0xa3]
res='95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a'
for i in range(0,len(res),2):
    tmp=int(res[i:i+2],16)
    print(chr(table.index(tmp)),end="")
#TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}
``````

11. 最后

，按理来说，输入相同的flag，其输出的结果应该与上面相对应，但是实际上却是下面这种情况，咱也不知道是啥问题，可能年久失修，box也不正确了吧：

![image-20240516163836986](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405161638068.png)