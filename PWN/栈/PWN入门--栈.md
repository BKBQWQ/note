# PWN入门--栈溢出

### 栈概要

1. 介于网上各种wp在栈溢出利用脚本方面浅入浅出，深入讲一下栈溢出利用时，地址如何计算，栈中垃圾数据如何填充，函数调用时 **参数** 在栈中的分布， **栈帧**的生成，函数**返回值ip**在栈中的摆放位置，填充垃圾数据时大小的确定和 **原返回值** 的利用等等。
2. 本文以下面源代码位实例，各位自行生成其 **32位** 和 **64位** 的程序：

``````c++
#include <stdio.h>
void fun(int a,int b)
{
    printf("%d",a+b);
}
int main()
{
    int a=1,b=2;
    printf("enter fun\n");
    fun(a,b);
    return 0;
}
``````



#### 栈帧

1. `栈帧`：利用 **ebp寄存器** 访问栈内局部变量、参数、函数返回地址等的手段。
2. 在一个函数的开头，通常会有`push ebp;mov ebp,esp`这一组指令：![image-20240507154958259](https://s2.loli.net/2024/05/07/SJNxZk3R1PQvOXe.png)
3. 当一个函数被调用时，会在程序的调用栈上开辟一块空间，这块空间就是 **栈帧** ，首先时保存当前指针寄存器（ **push ebp** ），该值指向 **调用函数者** (例子中即位main函数的底部)的栈底部；接下来，为新栈帧分配空间（ **mov ebp,esp** ），这个空间用于存放函数的参数、局部变量以及返回地址，函数在后面以 **ebp为基地址** 来访问函数内部的变量。
4. 例如，在main函数中，**[ebp+var_C]** 和 **[ebp+var_10]** 来访问变量a，b，该ebp即为main函数的栈低指针（为什么是栈低？因为mov ebp,esp指令使bp和sp同值，后续sp寄存器如何变化栈如何上涨，ebp寄存器都不会变化）：![image-20240507155750697](https://s2.loli.net/2024/05/07/BvaGo5fXHu16e3D.png)
5. 下面动调追踪这个过程

* 从此处开始生成main函数的栈帧。![image-20240507161443030](https://s2.loli.net/2024/05/07/ucWwT1AKJEhOLeZ.png)

* 观察右边ebp寄存器和栈的数值，ebp寄存器 **0xFF95F6A8** 已经指向栈低：<img src="https://s2.loli.net/2024/05/07/2US9GTJLMqKQtvP.png" alt="image-20240507161701901" style="zoom:67%;" />

* 继续观察如何利用bp寄存器来访问局部变量，可以看到使用 **ebp寄存器** 为基地址给参数完成赋值，参数在栈中的位置如图中右下角，并且只要在main函数中ebp寄存器的值就不会变化：![image-20240507162105764](https://s2.loli.net/2024/05/07/tKCGxMXSdvaB17w.png)

* 后面看到盗用fun函数的过程，使用栈完成传参，此时还没有进入到fun函数，所以其 **栈帧** 还并未生成：![image-20240507162733874](https://s2.loli.net/2024/05/07/9KD6WLSHlwQBckj.png)

* 进入fun函数，首先使用`push ebp;mov ebp,esp`来生成 **fun函数的栈帧** ，将原main函数的ebp值栈低入栈保存，再为ebp换上新的esp寄存器值，作为访问fun函数局部变量等的基址。

* 注意：main函数传递给fun函数的参数与栈帧ebp之间还存在一个地址 **565CE21D** 这时作为fun函数的 **返回地址** ，在栈溢出的漏洞中，我们经常要用我们 **需要的地址** 来覆盖其正常的返回地址，来修改返回值eip的值，从而达到利用栈溢出漏洞的目的（后面覆盖地址的时候会细讲）：![image-20240507163133203](https://s2.loli.net/2024/05/07/CX9WrLMScDob3KJ.png)

* 最后退出fun函数，需要将原ebp的值恢复，关闭并销毁fun函数的栈帧：通常使用与生成栈帧相反的指令`mov esp,ebp；pop ebp`，该例子中使用 **leave** 指令同理，用于快速关闭栈帧。

* Leave指令在汇编语言中用于**快速关闭栈帧，通常出现在函数的末尾**。

  Leave 指令的主要作用是恢复堆栈指针（ESP）和基址指针（EBP）到它们之前的值，从而释放分配给当前函数调用的堆栈空间。具体来说：

  1. **恢复堆栈指针**：Leave 指令将 EBP 寄存器的内容复制到 ESP 寄存器中，这样做的效果是将堆栈指针恢复到函数调用前的位置。
  2. **恢复基址指针**：接着，Leave 指令从堆栈中弹出之前保存的 EBP 的值，恢复到 EBP 寄存器，这样就恢复了基址指针到调用本函数前的地址。
  3. **简化操作**：使用 Leave 指令可以替代序列 "mov esp, ebp; pop ebp" 的两条单独指令，它使得关闭栈帧的操作更加简洁。

* ![image-20240507164401559](https://s2.loli.net/2024/05/07/kWofBV8YngIuz5K.png)

* 最后，在main函数中删除栈(在调用者还是在被调用者中清除栈，取决于函数的调用规定)。

#### 栈漏洞利用

1. 前面说完函数调用过成中返回值、栈帧、局部变量等问题，后面来讨论栈漏洞如何进行利用，以具体题目为例。

2. 题目地址：[jarvisoj_level2](https://buuoj.cn/challenges#jarvisoj_level2)

3. 这次从栈的角度详细，计算垃圾数据填充大小时多少，system函数的参数如何传递的问题。

4. buf只有136个字节大小，但是read函数给了256个输入，必然存在栈溢出：![image-20240507165958563](https://s2.loli.net/2024/05/07/bQy68ROvUKCLHju.png)

5. 其函数的栈示意图如下，那么返回地址一改填充在哪里？传递的参数地址有一改放哪里呢？:<img src="https://s2.loli.net/2024/05/07/1aOYhU5KSEZL7uq.png" alt="image-20240507170038228" style="zoom:67%;" />

6. 动调进入vulnerable_function函数，观察其栈中的变化：

7. * 此时vulnerable_function函数的栈帧已经生成：可以以ebp寄存器为基地址来访问变量buf。![image-20240507170853404](https://s2.loli.net/2024/05/07/uXxPrZS4RhDmMi7.png)
   * 再看ebp寄存器指向栈处的下面一位，那是该函数的返回值，该地址即为main函数中 **call    vulnerable_function** 的后一位指令地址：![image-20240507171208342](https://s2.loli.net/2024/05/07/XS1z4rymhUBeqaw.png)
   * 观察，调用system函数的过程，先将使用的参数地址入栈，再 **call system**，(后面伪造指令时要按此为依据)：![image-20240507171554654](https://s2.loli.net/2024/05/07/zM8fUouNkspXZPy.png)
   * 后续调用read函数来读取输入：此时是溢出的关键，观察栈中的变化，其将 **buf的首地址** 和 read函数读取的大小 均入栈。![image-20240507172025116](https://s2.loli.net/2024/05/07/tgDSTb1aR2xFLwk.png)
   * 开始接受输入：输入从buf的首地址开始，一直向下延申buf数组的大小，计算一下如果按正常的 **buf数组大小** 即0x88来输入，其最后应该在栈中的什么地方：**0xFFA669A0+0x88=0xFFA66A28** 。
   * 观察 **0xFFA66A28** 在栈中的位置：恰好位于该函数的栈底即ebp所指向的位置，再往后两个字节不就是我们梦寐以求的返回地址了吗。<img src="https://s2.loli.net/2024/05/07/pNjhikbeGyTnUrE.png" alt="image-20240507172641261" style="zoom:67%;" />
   * 由上面分析可以看出来，平常在进行栈溢出时，地址、大小的计算、垃圾数据的填充，除了要算上 **buf数组本身** 的大小以外 还要将该函数生成栈帧时(push ebp)的ebp/rbp的数据进行覆盖，填充的大小为 **136+4** , 最后才能到达梦寐以求的 **返回值地址**。
   * 前面已经分析如何覆盖到返回值的地址，但是光有返回值还不行，还需要给 **call system**传参才能达到提权的目的( **system("\bin\sh")** )，观察前面在调用system指令时，先将传入的参数地址入栈，然后才再call system，所以我们在向栈中填入数据时要遵循这个步骤。
   * 那么如何构造才能达到push 的目的？：原先正常在进入到system函数时，栈中的数据应该是如下表现：所以我们构造的栈应该满足该结构。**传入的参数地址** 在system的返回值下面(先入栈)，而后就是 **返回值地址** (后入栈)

   ![image-20240507180400872](https://s2.loli.net/2024/05/07/j839tlzygc1OEIZ.png)

   * 在前面 **0xFFA66A28+4**的位置填入我们需要跳转到的位置 **804845C** (任意call system指令处)，执行该指令会自动向 **0xFFA66A28+4**  处填入system的返回值地址，所以只需要在该位置的下面**0xFFA66A28+4+4** 处再填入push的参数地址即可模仿该栈的样式。
   * 那再栈溢出后需不需要考虑 **esp寄存器的值** 呢，毕竟如果esp寄存器在退出read函数后不指向**0xFFA66A28+4** 那么call指令自动填充的返回值与push参数地址的位置就差远了，其实这个完全不用考虑，一位esp寄存器的值开始在栈帧生成后就一直保存在ebp寄存器中，在函数运行时ebp寄存器的值不会变化，而栈溢出的数据也不会影响到ebp的值(但是关闭栈帧时会影响)，所以esp寄存器在退出read函数后一定会指向 **FFA66A2C** ，不管是否溢出。

   8. 最后解题脚本如下：

   ``````python
   from pwn import *
    
   p = remote('node5.buuoj.cn',25955)
   
   full=136+4
   sys_address=0x804849E
   shell_address=0x804A024
   
   payload = b'a'*(full)+p32(sys_address)+p32(shell_address)
   p.sendline(payload)
   p.interactive()
   
   ``````

   <img src="https://s2.loli.net/2024/05/07/i9RH6tqQ2rZANVu.png" alt="image-20240507180621342" style="zoom:67%;" />

   9. 毕了吧！！！

   