@[TOC](攻防世界 * 2)
# 题目：EASYHOOK
### 题目地址：[](https://adworld.xctf.org.cn/challenges/list)
1. 拿到程序后无壳直接ida32打开，发现逻辑如下，输入长度为19的flag后经过一个**sub_401220函数**，然后创建一个文件并阿静flag写入这个文件：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/3a9ffe64f853436d9130ed0f6740e94a.png#pic_center)
2. 进入**sub_401220函数**一时间没看懂，也没有加密函数：![函数](https://img-blog.csdnimg.cn/direct/241003bae0834bdaa5f76d34095b7c0b.png#pic_center)
3. 接着进入**sub_401240函数**，发现有点像比较函数，但看逻辑似乎是**This_is_not_the_flag**自己作比较，当长度result为21时直接返回，但是This_is_not_the_flag的长度只有20，这个函数好像什么都没有做，但是程序里面已经没有多余的函数，去左边导航条去看函数：![](https://img-blog.csdnimg.cn/direct/0e3b4d9f01cd4731ba8f6842dc8c960c.png#pic_center)
4. 左边导航条发现main函数前面还有若干函数，去注意观察一下，发现左边导航栏的函数在主程序里面的sub_401220函数里面都有调用过，下面去观察sub_401220函数的逻辑。
5. 结合题目的提示，此题为hook题目，哪必须得右hook的函数和hook的目标函数，并且要具备hook的安装函数，保证被hook的函数在后面任然可以重新执行。仔细分析程序的逻辑，发现sub_401220函数时一个hook函数，里面执行了**安装hook**的程序，而在**hook的目标函数**中又执行了一个**加密flag函数**(我们要找的目标函数)，随后重新恢复了被**hook的程序(writefile)**，并从新调用了该程序：
![安装hook的函数](https://img-blog.csdnimg.cn/direct/6cbdc47c0f2b4d0fb822fd9700797164.png#pic_center)
![](https://img-blog.csdnimg.cn/direct/31d2d4138f5449038e18f373281ff171.png#pic_center)![](https://img-blog.csdnimg.cn/direct/2d0f83923419412c8f5036c5263bb7bc.png#pic_center)
6. 找到真正的加密函数后即可对flag进行解密，其中加密的逻辑比较简单：奇数进行异或，偶数的化将其后面两个位置出的字符拿出来并与当前下标异或后放在当前位置，最后一位(下标为18)与0x13异或，然后与内存中的数据进行比较：![](https://img-blog.csdnimg.cn/direct/c0f8acd6c6eb4c68b3bff852599b6d6f.png#pic_center)
7. 解密脚本如下：
```
flag=[0x61, 0x6A, 0x79, 0x67, 0x6B, 0x46, 0x6D, 0x2E, 0x7F, 0x5F, 
  0x7E, 0x2D, 0x53, 0x56, 0x7B, 0x38, 0x6D, 0x4C, 0x6E]
print(len(flag))
res=[0]*22
for i in range(len(flag)):
    if i%2==1:
        res[i]=(chr((flag[i]^i)+i))
    else :
        res[i+2]=(chr(flag[i]^i))
for i in res:
    print(i,end="")
#flag{Ho0k_w1th_Fun}
```
8. 根据逻辑可以知道首位的f不会影响flag，实测如下：![](https://img-blog.csdnimg.cn/direct/82153480db75443f93bb42db1a469644.png#pic_center)
### 总结：最后来聊一下hook
1. hook(钩子),就是在执行程序的时候在程序的某个位置(一般在开头位置)，安装一个钩子(实际上就是段内跳转的jmp指令)，这个钩子的作用时跳到去执行其他函数，从而对当前函数进行阻断。当然，也可以，另外加一个程序在执行完hook的目标函数后，可以对当前**被hook的函数**进行恢复(上面的题目就是这种)，然后再调用它(即上面题目中的writefile函数)。
2. 下面我给出一种简单的hook程序，对print_hello函数进行hook，不让其打印hello world，反而其打印我们指定的其他字符串：

```
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <windows.h>

void print_hello()
{
    printf("hello word!\n");
}

//hook的目标函数
void hooked_function()
{
    printf("what why how?\n");
}

// 安装钩子
void niyaogansha()
{
    unsigned char jmp_code[10] = {0};
    jmp_code[0] = 0xE9;
    long long offset = (long long)hooked_function - ((long long)print_hello + 5);
    *(long long *)&jmp_code[1] = offset;

    // 保留原有的权限
    DWORD oldProtect = 0;
    // 修改指令页面的权限
    VirtualProtect((void *)print_hello, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void *)print_hello, jmp_code, 5);
}

int main()
{
    niyaogansha();
    print_hello();
    printf("done");
    return 0;
}
```![](https://img-blog.csdnimg.cn/direct/fd64c3e17ede4885ad7f0b4c8003f925.png#pic_center)

3. 上面我们对void print_hello()函数进行了hook，再其函数头部用jmp指令覆盖掉其原有的指令，转而去执行void hooked_function()函数。






