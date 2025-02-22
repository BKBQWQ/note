## 攻防世界[GoodRe]

### 学到知识：

1. 逆向三分懂，七分蒙即可。
2.  **TEA** 算法快速识别（蒙）：
   * 数据处理的形式：进入加密时的数据和加密结束后的数据，处理时数据的分组等等，都能用来识别TEA算法。
   * 关键数据识别，循环次数，dalte值，key。

3. 题目地址：[攻防世界 (xctf.org.cn)](https://adworld.xctf.org.cn/challenges/list?rwNmOdr=1716710474365)

### 题解：

1. 动调，需要输入输入，后面输出error。

![image-20240526205940185](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262059240.png)

2. 进入main函数看逻辑：要求输入的长度为64，完事后进一个循环，while循环中处理了一堆数据，后面加密时使用，依次看这两个函数。

   ![image-20240526210047301](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262103114.png)

   * `check_num`函数：其中查了一个十六进制字符表，光静态分析不方便，直接上动态调试来分析，按其中的要求十六进制必须是大写，不然白费，观察rax寄存器的值，他是返回值，将我们的输入转化为了对应的数值，所以函数的功能就是 **每8个一组** 挨个查 **十六进制表** 返回字符对应的数值。

   ![image-20240526210414998](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262104065.png)

   ![image-20240526210819447](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262108489.png)

   ![image-20240526210904368](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262109413.png)

   * `init_num`函数：逻辑比较简单，将传入的a2放到a1数组中，前面多放一个4(不知道有啥用)，一起动调看一下，确实把v6的值放进入了。

   ![image-20240526211126187](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262111235.png)

   ![image-20240526211342484](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262113516.png)

   * 最后这个循环的逻辑就清楚了：进行了三个组参数的初始化，首先数我们输入的字符每 **8个一组** 转化为对应的 **十六进制数值** ，其次用0x11初始化v14，再使用程序本身自带的 **dword_5580AECA2020** 初始化v15/v8。

3. 循环结束后续重复调用了四个一样的函数，这里推测大概率是加密函数了（后续直接就判断并输出error），但是v11，v12，v13似乎还并未初始化，这里直接去看汇编观察传入了哪些参数：这里是传入了两个地址，一个是前面初始化的v14，一个是，前面初始化的我们输入，这里换一个清晰点的输入 **6677888899999999AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF** 。

![image-20240526212505398](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262125436.png)

![image-20240526212425055](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262124092.png)

![image-20240526212121822](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262121853.png)

4. 这里仔细观察下一个encode函数，其接受的参数：其直接从 **AAAAAAAA** 开始接受，跳过了中间的 **99999999** ，下一个encode函数任然如此，跳过了 **BBBBBBBB** ，直接从 **CCCCCCCC** 开始。结合前面初始化时将我们输入的64个字符每8个一组进行分组，共8组，说明这加密函数是将分组后的数据两两一起加密，最后共加调用encode函数4次，加密4次，刚好架构8组数据全部加密完，再众多加密函数中，大概率只有TEA加密时需要将两个数据同时进行加密，所以可以盲猜该算法可能时TEA加密。

![image-20240526212557121](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262125154.png)

![image-20240526212744972](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262127003.png)

5. 进入该函数查看：其中一大堆函数，首先看到显眼的32，while循环的轮数为32与TEA算法刚好契合，里面还有两串数值 **0x830A5376** 和 **0x1D3D2ACF** 生成了v9，v9在后面函数中被调用过一次，猜测v9应该就是 **dalte** （动调拿到0x9E3779B9），再找key，a2被调用三次一次传入不同的地址，取不同地址处的值来初始化v10，v11，v12，v13，虽然地址不同但初始化最后都为0x11（前面循环时只用0x11来初始化v14），观察函数调用时传入的参数逻辑，v6就是sum，函数调用中对sum采用的是加 **dalte** 且是再循环开始时，v4、v5就是待加密的两个值。

![image-20240526213719764](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262137803.png)

![image-20240526214737552](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262147591.png)

![image-20240526213409452](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262134502.png)

6. 最后的加密结果是由 **dword_56267207D020** 处的值来初始化是，直接提取即可，解密脚本如下,注意最后全部时大写才行：

``````c++
// 魔改TEA
#include <debugapi.h>
#include <stdio.h>
int main()
{
    unsigned int key[4] = {0x11, 0x11, 0x11, 0x11};                                                                             // 密钥
    unsigned int value[8] = {0x79AE1A3B, 0x596080D3, 0x80E03E80, 0x846C8D73, 0x21A01CF7, 0x0C7CACA32, 0x45F9AC14, 0x0C5F5F22F}; // 密文

    int dalte = 0x9e3779b9;
    int i = 0, j = 0, h = 0;
    int wheel = 32; // 轮数
    unsigned int sum = 0;

    // 逆算法
    for (i = 0; i < 8; i++, i++)
    {
        sum = (dalte * (wheel));
        // 每轮加密
        // for (j = 0; j < 4; ++j)
        {
            for (h = 0; h < wheel; ++h)
            {
                value[i + 1] -= (key[3] + (value[i] >> 5)) ^ (sum + value[i]) ^ (key[2] + 16 * value[i]);
                value[i] -= (key[1] + (value[i + 1] >> 5)) ^ (sum + value[i + 1]) ^ (key[0] + 16 * value[i + 1]);
                sum -= dalte;
            }
        }
    }
    for (i = 0; i < 8; i++)
    {
        printf("%X", value[i]);
    }
    return 0;
}
//7DEA3F6D3B3D6C0C620864ADD2FA2AE1A61F2736F0060DA0B97E8356D017CE59
``````

7. 最后验证结果正确：

![image-20240526214948280](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405262149333.png)
