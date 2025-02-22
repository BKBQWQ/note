[TOC]



> [!NOTE]
>
> 如果提取数据时，循环的次数控制不好，可能回**导致脚本报错**：
>
> ![image-20241118110712766](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411181107874.png)
>
> 每一个断点处必须配合一个 **wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1)** 来处理该断点产生的终点信号。



# ida一键提取指定数据的idc脚本：



> [!NOTE]
>
> 打断点**提取数据**（或者**修改数据**）时，是在断点处的**汇编代码执行前**完成的了。

主要函数解释：

* **start_process(path, args, sdir)** ：启动进程并附加调试器，可以指定调试的参数
* **run_to(ea)** ：控制调试器，运行到指定地址ea处
* **wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1)** ： 等待直到**进程挂起(WFNE_SUSP)** 然后**继续执行(WFNE_CONT)**，这里前提是要在提取数据的位置 **打断点** ，触发断点时进程挂起，提取完数据后继续执行
* **get_wide_byte(ea)**、**get_wide_word(ea)**、**get_wide_dword(ea)** ：获取指定地址ea处的值（1字节，2字节，4字节）
* **get_reg_value("ECX")**、**get_reg_value("CL")** ：获取指定寄存器的值
* **auto res = object()** ：声明一个数组对象，大小在使用的时候自动变化

最好配合断点，在该位置提取数据（**必须要先打断点**），且一个断点对应一个**wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1)** ：

![image-20241116121734533](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411161217589.png)

```c
#include <idc.idc>

static main() {
    auto max_eax, max_ebx, second_ebx, third_eax;
    auto eax, ebx, ecx, ebp, addr_val;
	auto res = object(); // 一个数组对象
    auto path = "C:\\Users\\BKBQWQ\\Desktop\\rust1.exe"; // 路径
    auto args = "arg1 arg2"; // 命令行参数
    auto sdir = "C:\\Users\\BKBQWQ\\Desktop"; // 初始目录
    // 启动调试器
    if (start_process("","","") != 1) // start_process(path, args, sdir) ==> 使用默认配置
    {
        message("Failed to start the process\n");
        return;
    }
    
    // 循环提取数据
    auto code;
    auto i;
    for (i = 0; i < 31; i++) {
        // run_to(0x0007FF72FA159B4); // 运行到指定位置 后获取数据
        code = wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1); // 等待一个暂停事件进程挂起 然后继续执行 直到下一个挂起点（前提是要打断点）
        
        // 获取指定地址处的数据
        ebp = get_reg_value("EBP");
        addr_val = get_wide_byte(ebp);	// 获取指定地址处的数据 ==> 1个字节
        addr_val = get_wide_word(ebp);	// 获取指定地址处的数据 ==> 2个字节
        addr_val = get_wide_dword(ebp);	// 获取指定地址处的数据 ==> 4个字节
        
        // 获取寄存器的数据
        tmp1 = get_reg_value("ECX"); // 直接获取 CL 寄存器的值
        tmp2 = get_reg_value("CL");  // 直接获取 CL 寄存器的值
        tmp3 = get_reg_value("eax"); // 直接获取 eax 寄存器的值
        
        set_reg_value(tmp2,"rdx");   // 设置rdx寄存器的值
        // msg("%d,", ecx); // 输出结果
        res[i] = ecx; // 用数组存储提取出来的结果
    }
    
    msg("\n数据个数：%d \n数据值：",i);
    
    // 遍历对象 x 的属性并输出
    auto j;
    for (j = 0; j < i; j++) {
         msg("%d,", res[j]);
    }
    msg("\nout ...");
}
```

idapython中调用idc的所有库函数 ：

```python
from idc import *   # 导入idc的所有函数
path = "C:\\Users\\BKBQWQ\\Desktop\\rust1.exe" # 路径
args = "arg1 arg2" # 命令行参数
sdir = "C:\\Users\\BKBQWQ\\Desktop" # 初始目录
res = []

# 启动调试器
if idc.start_process("", "", "") != 1 :
    print("Failed to start the process\n")
    exit(0)
# 循环提取数据
for i in range(10): 
    code = wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1) # 等待一个暂停事件进程挂起 然后继续执行 直到下一个挂起点（前提是要打断点）
    tmp = get_reg_value("rax") # 直接获取 CL 寄存器的值
    set_reg_value(tmp,"rdx");   # 设置rdx寄存器的值
    res.append(ecx) # 用数组存储提取出来的结果
    
print("out ... :")
print("提取的值 :",end="")
for i in range(len(res)):
    print(res[i],end=",")

```

idapython patch

```py
import idc
for i in range(0x0041D000,0x0041E600):
    patch_byte(i,get_wide_byte(i)^3)
print('done')


address =0x600B00# judge的首地址
for i in range(182):# 进行182次异或并修改IDA中的数据
	ida_bytes.patch_byte(address +i,idc.get_wide_byte(address +i)^0xC)
print("Done")


from idc import *   # 导入idc的所有函数
res = "CKaBxfgTQEvLpyhSTfFa_DlaQfvn'PFE;x2H"
start_addr = 0x00007FFF58421A70
for i in range(len(res)): 
    patch_byte(start_addr + i,ord(res[i]))
    
print("done")
```

idapython 获取交叉引用（data、code）：

1. 主要函数：

   **代码**：

   * idc.get_first_fcref_to(orginal) 	#代码交叉引用
   * idc.get_first_fcref_from(addr)

   **数据**：

   * idc.get_first_dref_to(orginal)	#数据的交叉引用
   * idc.get_first_dref_from(addr)

```py
#交叉引用：在地址addr处  from ==> "双击" ；to ==> "ctrl + x"
# 代码
orginal = 0x000000000400410
addr = idc.get_first_fcref_to(orginal)
print(hex(addr))
while(addr != ida_idaapi.BADADDR):
    addr = idc.get_next_fcref_to(orginal,addr)
    print(hex(addr))
    
# 数据
orginal = 0x0000000000400C1F
addr = idc.get_first_dref_to(orginal)
print(hex(addr))
while(addr != ida_idaapi.BADADDR):
    addr = idc.get_next_dref_to(orginal,addr)
    print(hex(addr))
```



## 远程提取：

先配置好调试选项：

<img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411181100870.png" alt="image-20241118110008813" style="zoom: 80%;" />

![image-20241118110035042](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411181100152.png)

打上断点后直接跑脚本即可：

![image-20241118110112400](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411181101506.png)

