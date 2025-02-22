@[TOC](全国大学生信息安全赛 : CISCN)

---



## 1.[CISCN 2022 东北]happymath
1. 题目链接：[[CISCN 2022 东北]happymath](https://www.nssctf.cn/problem/2405)
1. 

---

##  2.[CISCN 2023 初赛]ezbyte

### 注意：[参考文章]([通过DWARF Expression将代码隐藏在栈展开过程中-软件逆向-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-271891.htm))

1. 通过 **DWARF Expression** 将代码隐藏在栈展开过程中，在DWARF 3标准中引入了一个DWARF Expression，可以将它理解为一个 **基于栈的虚拟机** ，由标准C++库解释执行它，它包含一系列的字节码，提供了读取程序运行内存的Handle，但不支持写入程序运行内存。在运行完一个DWARF Expression后，将处于 **栈顶** 的值作为这个 **DWARF Expression的值** ，可以将这个值赋值给 **寄存器** 。这个虚拟机提供了完备的算术，寻址，栈操作，乃至于流程转移指令，因此，它是图灵完备的。
2. 这些指向一个事实：我们可以将 **恶意代码/混淆代码** 转换成 **DWARF Expression** ，嵌入到程序中，在 **栈展开** 的过程中由标准C++库解释执行它们。

---



1. 题目链接：[[CISCN 2023 初赛]ezbyte](https://www.nssctf.cn/problem/4052)
2. 进入分析，发现有一段汇编程序，反编译时被跳过了：但是前面没有r12的代码。

![image-20240516224429677](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405162244738.png)

3. 结合题目，应该时被隐藏在其他每个字节码中了，check中有一个函数，没有返回 **__noreturn** ：` __noreturn是一个C语言中的关键字，用于声明一个函数不会返回到调用者。这个关键字告诉编译器，如果函数执行到了结束，那么它就会直接跳转到程序的终止点，而不会返回到调用者。这有助于提高程序的性能和安全性。`

![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405162250204.png)



4. 后面了解到，这里程序应该时抛出了一个 **异常** ，然后由异常 **修改了程序中r12** 的值：当触发异常的时候，程序会沿着 **调用链** 不断向上进行 **栈展开** ，直到寻找到能处理这个异常的catch块。然而在这个过程中 **DWARF调试信息** 完成这个恢复过程，而在DWARF 3标准中引入了一个 **DWARF Expression** ，这个WARF Expression变相就是一个 **虚拟机** 。到此，我们大致就可以知道，我们的操作就是被隐藏在了这个 **栈展开中DWARF的“虚拟机”字节码** 中，在Linux中我们执行```readelf -wf ezbyte > out.txt``` 或者使用 `readelf -wf ezbyte_patch | grep '^ *DW_CFA_val_expression'` 筛选一下将DWARF 调试信息打印出来:

![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405172045278.png)

``````python
  DW_CFA_val_expression: r12 (r12) (
    DW_OP_constu: 2616514329260088143; 
    DW_OP_constu: 1237891274917891239; 
    DW_OP_constu: 1892739; 
    DW_OP_breg12 (r12): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_constu: 8502251781212277489; 
    DW_OP_constu: 1209847170981118947; 
    DW_OP_constu: 8971237; 
    DW_OP_breg13 (r13): 0; 
    DW_OP_plus; DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or; 
    DW_OP_constu: 2451795628338718684; 
    DW_OP_constu: 1098791727398412397; 
    DW_OP_constu: 1512312; 
    DW_OP_breg14 (r14): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or; 
    DW_OP_constu: 8722213363631027234; 
    DW_OP_constu: 1890878197237214971;
    DW_OP_constu: 9123704; 
    DW_OP_breg15 (r15): 0; 
    DW_OP_plus; 
    DW_OP_xor; 
    DW_OP_xor; 
    DW_OP_or)
``````



![image-20240516231403082](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405162314124.png)

![image-20240516232010685](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405162320739.png)

5. 分析一下这些机器指令：

![image-20240516233145940](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405162331976.png)

6. 所以解密脚本，输入的flag经过 加 ，异或，异或，后应该为0(因为r12为0)：

``````
r15 = (0 ^ 8722213363631027234 ^ 1890878197237214971) - 9123704
r14 = (0 ^ 2451795628338718684 ^ 1098791727398412397) - 1512312
r13 = (0 ^ 8502251781212277489 ^ 1209847170981118947) - 8971237
r12 = (0 ^ 2616514329260088143 ^ 1237891274917891239) - 1892739
data = "65363039656662352d653730652d346539342d616336392d6163333164393663"
flag = ""
for i in range(0, len(data), 2):
    byte = bytes.fromhex(data[i:i + 2])
    flag += byte.decode("utf-8")
flag="flag{" + flag+ "3861}"
print(flag)
#flag{e609efb5-e70e-4e94-ac69-ac31d96c3861}
``````

7. 最后调试到的修改r12寄存器位置，这里应该已经执行完成 **栈展开** 、**虚拟机**操作过程，最后返回执行结果，利用RCX跳回到 **0x404DE3** 处执行最后输出 **yes** 。

![image-20240517220633067](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405172206147.png)

![image-20240517220724126](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202405172207283.png)

---

## 3.第三题

3. 