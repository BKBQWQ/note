[TOC]

# OLLVM 去控制流平坦化

1. docker 跑工具：-f ==> 要操作的**文件路径** ；--addr ==> 文件中要操作的**函数地址** ：

   ```sh
   docker run -it --rm -v $PWD:/home/bkbqwq --privileged 49f1440f6dae /bin/bash #启动docker
   python3 deflat.py -f /root/deflat/flat_control_flow/samples/bin/check --addr 0x400530
   ```

2. idcpython脚本去除不透明谓词：

   ```py
   import idc  # 导入 IDC 模块，提供对 IDA Pro 核心功能的访问
   
   # 定义一个函数，用于获取当前地址的下一条指令的地址
   def next_instr(addr):
       return addr + get_item_size(addr)  # 获取当前指令的大小，并将其加到当前地址上
   
   # 获取 .bss 段的结束地址
   st = ida_segment.get_segm_by_name('.text').start_ea  # 获取 .bss 段的起始地址
   end = ida_segment.get_segm_by_name('.text').end_ea  # 获取 .bss 段的结束地址
   
   # 初始化 addr 为 .bss 段的起始地址
   addr = st
   
   # 循环直到 addr 超过 .bss 段的结束地址
   while(addr < end):
       next = next_instr(addr)  # 获取下一条指令的地址
       # 检查当前地址的反汇编代码中是否包含特定的字符串
       if "ds:dword_603054" in GetDisasm(addr):
           # 如果找到，进入一个无限循环，直到找到 `jnz` 指令
           while(True):
               addr = next  # 更新当前地址为下一条指令
               next = next_instr(addr)  # 更新下一条指令的地址
               # 检查当前地址的反汇编代码中是否包含 `jnz` 指令
               if "jnz" in GetDisasm(addr):
                   # 获取 `jnz` 指令的目标地址
                   dest = get_operand_value(addr, 0)
                   # 将 `jnz` 指令替换为 `jmp` 指令
                   idc.patch_byte(addr, 0xe9)
                   # 将 `jnz` 指令的第五个字节替换为 nop 指令（0x90）
                   idc.patch_byte(addr+5, 0x90)
                   # 计算跳转偏移量，并更新 `jmp` 指令的目标地址
                   offset = dest - (addr + 5)
                   idc.patch_dword(addr + 1, offset)
                   print("patch bcf: 0x%x" % addr)  # 打印补丁地址
                   addr = next  # 更新当前地址为下一条指令
                   break  # 跳出无限循环
       else:
           addr = next  # 如果当前地址不包含特定字符串，更新地址为下一条指令
   ```

3. 