###  题目：encode，地址：[encode](https://ctf.show/challenges#encode-274)
1. 查壳发现时upx壳，使用工具脱壳命令"upx -d ***"，如果遇到工具脱不了的壳就手动脱壳，手动脱壳请**帅哥美女**们看这篇[手动脱壳](https://blog.csdn.net/yjh_fnu_ltn/article/details/136601447?spm=1001.2014.3001.5502)。
2. 使用ida打开，观察逻辑后重命名函数：![](https://img-blog.csdnimg.cn/direct/3546259108e045a1bc66849cbb2b2647.png#pic_center)
3. 逻辑为一个换表base64 + 异或 + RC4。其中RC4可以根据函数传入key，进而生成Box盒子来判断：![](https://img-blog.csdnimg.cn/direct/b3686c248f18414185113f33256de9a5.png#pic_center)![](https://img-blog.csdnimg.cn/direct/b9cb5e9688fc47fba83c5b84c3c84654.png#pic_center)
4. 知道逻辑后，先用RC4脚本解密，key=“Flag{This_a_Flag}”,密文为“E8D8BD91871A1E56F53F4889682F96142AF2AB8FED7ACFD5E”,但是仔细观察这里的密文长度为49，完全不对，翻阅网上的答案后，应该时ida将01/0E/0*这类16进制变成字符串时，其中的**0**去掉了，导致密文的长度变小。根据题目要求输入的flag为21位，base64后位(21/3)*4=28位，长度完全对不上。这里想要调出相应的密文，可以用**远程调试**，观察寄存器的值来一位一位的取出加密后的正确密文，这里我直接给出正确的密文[0xE8,0xD8,0xBD,0x91,0x87,0x1A,0x01,0x0E,0x56,0x0F
	,0x53,0xF4,0x88,0x96,0x82,0xF9,0x61,0x42,0x0A,0xF2,0xAB
	,0x08,0xFE,0xD7,0xAC,0xFD,0x5E,0x00]
5. RC4的解密脚本如下:

```
#RC4加密
def rc4(key, ciphertext):
    # 初始化S盒
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
 
    # 生成密钥流
    i = 0
    j = 0
    keystream = []
    for _ in range(len(ciphertext)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        k = sbox[(sbox[i] + sbox[j]) % 256]
        keystream.append(k)
    # print(keystream)
 
    # 解密密文
    plaintext = []
    for i in range(len(ciphertext)):
        m = ciphertext[i] ^ keystream[i]
        plaintext.append(m)
    print(plaintext)
 
    # 将明文转换为字符串
    return ''.join([chr(p) for p in plaintext])

# 测试
key = b"Flag{This_a_Flag}"
ciphertext =[0xE8,0xD8,0xBD,0x91,0x87,0x1A,0x01,0x0E,0x56,0x0F
	,0x53,0xF4,0x88,0x96,0x82,0xF9,0x61,0x42,0x0A,0xF2,0xAB
	,0x08,0xFE,0xD7,0xAC,0xFD,0x5E,0x00]
# for i in ciphertext:
#     print(chr(i),end="")
plaintext = rc4(key, ciphertext)
```
6. 得到结果[35, 21, 37, 83, 8, 26, 89, 56, 18, 106, 57, 49, 39, 91, 11, 19, 19, 8, 92, 51, 11, 53, 97, 1, 81, 31, 16, 92]后异或还原：

```
flag=[35, 21, 37, 83, 8, 26, 89, 56, 18, 106, 57, 49, 39, 91, 11, 19, 19, 8, 92, 51, 11, 53, 97, 1, 81, 31, 16, 92]
key='''Flag{This_a_Flag}'''
res=[]
for i in range(len(flag)):
    res+=[flag[i]^ord(key[i%len(key)])]
print(res)
for i in res:
    print(chr(i),end="")
```
7. 得到**eyD4sN1Qa5Xna7jtnN0RlN5i8lO=**看，最后换表base64解密，网站解密[网站是这个](https://cyberchef.org/#recipe=From_Base64%28%270123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%27,true,false%29&input=ZXlENHNOMVFhNVhuYTdqdG5OMFJsTjVpOGxPPQ)：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/aeee0b23ed7543fea202b25b87fc771c.png#pic_center)
8. 最后flag=BJD{0v0_Y0u_g07_1T!}
### 总结：ida在阿济格0x01/0x02/0x0*等16进制的数据转化位字符串时会将0去掉，导致长度不对等，此时需要手动调试还原。


