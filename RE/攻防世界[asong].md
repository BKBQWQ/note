## 攻防世界[asong]

### 学到知识点：

1. 类似于base系列的 **字节串分割**编码技巧。
2. 字符频率统计算法识别。

### 题解：

1. 题目地址：[攻防世界 (xctf.org.cn)](https://adworld.xctf.org.cn/challenges/list?rwNmOdr=1716339906914)

2. ida进入，可以看到就几个函数，进去逐一分析功能：首先时接受用户的输入，再check一下flag的形式，接着读取girl文件来初始化v4，最后进行flag的加密。

![image-20240522091534080](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405220915115.png)

3. 直接从girl函数开始分析，使用循环每次只读取一位字符，利用change_num函数转化为数字v2后，在相对a2偏移为4*v2处记录下该字符出现的次数，所以这是一个统计字符频率的函数，change_num将字符转化为数字下标。

![image-20240522091608206](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405220916253.png)

4. 进入change_num函数：将输入的字符，转化为对应的下标，大小写不进行区分统一为10~35（转化出来的数字时对应字符在v4中的下标）。

![image-20240522092056491](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405220920552.png)

5. 进入encode函数，这里for循环中的 **a2** 与前面计算字符频率时的 **a2** 代表的地址相同，所以for循环中的操作相当于对输入的 **flag字符** ，将其 **ASCII码** 转化为字符在歌词中出现的 **频率** 。

![image-20240522092448255](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405220924295.png)

6. 进入change_sit函数：里面根据一个dword_6020A0数组的，来交换v5数组上的数据，具体的逻辑就是：取dword_6020A0数组上面第i个值j，以此为下标，用v5[j]覆盖v5[i]，简而言之就是 **替换** 。

![image-20240522182715362](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405221827427.png)

7. 进入split函数：对输入的v5进行一个切分，二进制下，当前位的第5位与后一位的高三位组成一个新的值，放入当前位。

![image-20240522184141224](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405221841288.png)

---

1. 后面对其逐一逆向，首先逆向切分：

``````python
#分割bit串
for i in range(len(a)):
    print('{:0>8}'.format(bin(a[i])[2:]),end="")
print()
#001 11101将切分出来的末三位，手动放到字节串前面
res='0011110110000101001111000110100000111100001111101111010101000011101001010011110110100101001100110010011100111110011101101111010100111100111101011000010101110110111101010110100000010011111101010010011000100110101001011000010100111101111101010000011110101001011101100001110100111100001011010000111101101000'
for i in range(0,len(res),8):
  print(hex(int(res[i:i+8],2)),end=",")
``````



2. 字频替换（交换位置change_sit加密，逆向的顺序先做后做无所谓）：

``````python
#字符频率表需要事先准备
mapp={' ': 71, "'": 40, '_': 245, 'a': 104, 'c': 15, 'b': 30, 'e': 169, 'd': 29, 'g': 38, 'f': 19, 'i': 60, 'h': 67, 'k': 20, 'm': 28, 'l': 39, 'o': 165, 'n': 118, 'p': 26, 's': 51, 'r': 61, 'u': 45, 't': 133, 'w': 34, 'v': 7, 'y': 62}
#that_girl词频统计
value=[71, 40, 245, 104, 15, 30, 169, 29, 38, 19, 60, 67, 20, 28, 39, 165, 118, 26, 51, 61, 45, 133, 34, 7, 62]
key=[' ', "'", '_', 'a', 'c', 'b', 'e', 'd', 'g', 'f', 'i', 'h', 'k', 'm', 'l', 'o', 'n', 'p', 's', 'r', 'u', 't', 'w', 'v', 'y']
#查字频表
res_1=[0x3d,0x85,0x3c,0x68,0x3c,0x3e,0xf5,0x43,0xa5,0x3d,
0xa5,0x33,0x27,0x3e,0x76,0xf5,0x3c,0xf5,0x85,0x76,0xf5,
0x68,0x13,0xf5,0x26,0x26,0xa5,0x85,0x3d,0xf5,0x7,0xa9,0x76,
0x1d,0x3c,0x2d,0xf,0x68]
for i in range(len(res_1)):
  print(ord(key[value.index(res_1[i])]),end=",")

``````

3. 位置交换逆向：

``````python
#改变顺序的解
s=[22,   0,   6,   2,  30, 
   24,   9,   1,  21,   7, 
   18,  10,   8,  12,  17, 
   23,  13,   4,   3,  14, 
   19,  11,  20,  16,  15, 
    5,  25,  36,  27,  28, 
   29,  37,  31,   33, 32, 
   26,  34,  35]

i = 1	#最后一个被覆盖的位置是第 s.index[0]=1，这里i取多少都无所谓，判断条件一起更改即可
temp = flag[i] #保存一下覆盖的值
while s.index(i) != 1:
    flag[i] = flag[s.index(i)]
    i = s.index(i)		#用当前i的下标值更新i
flag[i]=temp
print(flag)
for i in range(len(flag)):
  print(chr(flag[i]),end="")
#that_girl_saying_no_fo@_your_vinidcate
``````



### 最后：

1. 听下 **that girl** ：

![image-20240522192728192](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405221927298.png)