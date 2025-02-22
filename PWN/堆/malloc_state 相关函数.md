# malloc_state 相关函数

## 1. malloc_consolidate函数：

### 功能：

1. 合并 fastbin 中的 chunk，并放入unsorted bin中

### 基本流程：

```c
//glibc-2.27
static void malloc_consolidate(mstate av)
{
  mfastbinptr *fb;          /* current fastbin being consolidated */
  mfastbinptr *maxfb;       /* last fastbin (for loop control) */
  mchunkptr p;              /* current chunk being consolidated */
  mchunkptr nextp;          /* next chunk to consolidate */
  mchunkptr unsorted_bin;   /* bin header */
  mchunkptr first_unsorted; /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int nextinuse;
  mchunkptr bck;
  mchunkptr fwd;

  atomic_store_relaxed(&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin(av, NFASTBINS - 1);
  fb = &fastbin(av, 0);
  do
  {
    p = atomic_exchange_acq(fb, NULL);
    if (p != 0)
    {
      do
      {
        {
          unsigned int idx = fastbin_index(chunksize(p));
          if ((&fastbin(av, idx)) != fb)
            malloc_printerr("malloc_consolidate(): invalid chunk size");
        }

        check_inuse_chunk(av, p);
        nextp = p->fd;

        /* Slightly streamlined version of consolidation code in free() */
        size = chunksize(p);
        nextchunk = chunk_at_offset(p, size); // 获取相邻的物理高地址的chunk地址
        nextsize = chunksize(nextchunk);      // 获取相邻的物理高地址的chunk的size

        if (!prev_inuse(p)) // fastbin 向前物理地址上相邻的chunk合并，向物理低地址
        {
          prevsize = prev_size(p); // fastbin向前合并
          size += prevsize;
          p = chunk_at_offset(p, -((long)prevsize));
          unlink(av, p, bck, fwd);
        }

        if (nextchunk != av->top) // 当前fastbin中的chunk与top chunk不相邻，就能进行合并，向物理高地址
        {
          nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // 判断相邻高地址的chunk是否被释放

          if (!nextinuse) // 如果prev_inuse位为0，代表被释放，直接合并
          {
            size += nextsize;
            unlink(av, nextchunk, bck, fwd);
          }
          else // 如果上上个chunk的prev_inuse位为1，上一个chunk代表没有被释放，要将prev_inuse位清0
            clear_inuse_bit_at_offset(nextchunk, 0);

          // 合并完成后就放入unsorted bin中
          first_unsorted = unsorted_bin->fd;
          unsorted_bin->fd = p;
          first_unsorted->bk = p;

          if (!in_smallbin_range(size))
          {
            p->fd_nextsize = NULL;
            p->bk_nextsize = NULL;
          }

          set_head(p, size | PREV_INUSE); // 设置新的 chunk头
          p->bk = unsorted_bin;
          p->fd = first_unsorted;
          set_foot(p, size); // 设置下一个高地址的chunk的prev_size位，位当前chunk大小
        }

        else // 与top chunk相邻就放入top chunk
        {
          size += nextsize;
          set_head(p, size | PREV_INUSE);
          av->top = p;
        }

      } while ((p = nextp) != 0);
    }
  } while (fb++ != maxfb);
}
```

![image-20240813171938646](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408131719705.png)

## 2.__libc_malloc函数：

### 功能：

1. 执行malloc(1)，时首先调用_libc_malloc。
2. 检查__malloc_hook函数指针.。(在glibc2.34以后， _libc_malloc不会检查malloc_hook)
3. 处理来自应用程序的内存分配请求，并根据请求的大小分配相应数量的字节（调用**_int_malloc函数**来分配，分配的细节载 **_int_malloc函数**中）。

注意：**在tcache中拿chunk时**，不是根据count来判断释放存在空闲bin，而是通过**entries[tc_idx]里面的指针是否为空**来判断(在libc2.29之前，在之后就以counts来判断是否有剩余)：

libc2.29![image-20240816164608661](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408161646828.png)

libc2-30:

![image-20240816164723997](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408161647114.png)



### 基本流程：

```c
//glibc-2.23
void *
__libc_malloc(size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  // 先检查__malloc_hook释放为空，存在函数指针就去执行，该钩子可以被用户设置为自定义的内存分配函数。
  void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);
  if (__builtin_expect(hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS(0));

  arena_get(ar_ptr, bytes); // 尝试获取一个内存分配区（arena）

  // 调用_int_malloc获取chunk
  victim = _int_malloc(ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */

  // chunk获取失败
  if (!victim && ar_ptr != NULL)
  {
    LIBC_PROBE(memory_malloc_retry, 1, bytes);
    ar_ptr = arena_get_retry(ar_ptr, bytes); // 获取另一个可用的分配区（arena）
    victim = _int_malloc(ar_ptr, bytes);     // 再次调用 _int_malloc 尝试分配内存。
  }

  if (ar_ptr != NULL) // 如果 ar_ptr 不为空，解锁分配区的互斥锁。
    (void)mutex_unlock(&ar_ptr->mutex);

  assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
         ar_ptr == arena_for_chunk(mem2chunk(victim))); // 进行断言检查，确保返回的 victim 指针要么指向一个通过 mmap 分配的内存块，要么确保分配区与 victim 相关联。
  return victim;                                        // 返回分配的指针，分配失败将返回NULL
}

define arena_get(ptr, size) do {ptr = thread_arena;arena_lock (ptr, size);} while (0)
define arena_lock(ptr, size) do {if (ptr && !arena_is_corrupt (ptr)) (void) mutex_lock (&ptr->mutex);							   else	ptr = arena_get2 ((size), NULL); } while (0)
    
    
//glibc-2.27
void *
__libc_malloc(size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);
  if (__builtin_expect(hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS(0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size(bytes, tbytes);
  size_t tc_idx = csize2tidx(tbytes);

  MAYBE_INIT_TCACHE();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache && tcache->entries[tc_idx] != NULL)
  {
    return tcache_get(tc_idx);
  }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
  {
    victim = _int_malloc(&main_arena, bytes);
    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           &main_arena == arena_for_chunk(mem2chunk(victim)));
    return victim;
  }

  arena_get(ar_ptr, bytes);

  victim = _int_malloc(ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
  {
    LIBC_PROBE(memory_malloc_retry, 1, bytes);
    ar_ptr = arena_get_retry(ar_ptr, bytes);
    victim = _int_malloc(ar_ptr, bytes);
  }

  if (ar_ptr != NULL)
    __libc_lock_unlock(ar_ptr->mutex);

  assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
         ar_ptr == arena_for_chunk(mem2chunk(victim)));
  return victim;
}
```

## 3. _int_malloc

### 功能：

1. 分配相应大小的chunk。

2. ```
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   int main(void)
   {
       int i=0,judge,size;
       unsigned long* chunk;
       for(i = 0;i<100;i++)
       {
            printf("1.malloc a chunk\n2.free the chunk");
            scanf("%d",&judge);
            if(judge = 1)
            {
                scanf("%d",&size);
                chunk = malloc(size);
            }
            else
            {
                free(chunk);
            }
       }
       return 0;	
   }
   
   ```

   

### 基本流程：

```c
//glibc-2.27
_int_malloc(mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb; /* normalized request size */
  unsigned int idx;   /* associated bin index */
  mbinptr bin;        /* associated bin */

  mchunkptr victim;     /* inspected/selected chunk */
  INTERNAL_SIZE_T size; /* its size */
  int victim_index;     /* its bin index */

  mchunkptr remainder;          /* remainder from a split */
  unsigned long remainder_size; /* its size */

  unsigned int block; /* bit map traverser */
  unsigned int bit;   /* bit map traverser */
  unsigned int map;   /* current word of binmap */

  mchunkptr fwd; /* misc temp for linking */
  mchunkptr bck; /* misc temp for linking */

  const char *errstr = NULL;

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  checked_request2size(bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely(av == NULL))
  {
    void *p = sysmalloc(nb, av);
    if (p != NULL)
      alloc_perturb(p, bytes);
    return p;
  }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long)(nb) <= (unsigned long)(get_max_fast()))
  {
    idx = fastbin_index(nb);
    mfastbinptr *fb = &fastbin(av, idx);
    mchunkptr pp = *fb;
    do
    {
      victim = pp;
      if (victim == NULL)
        break;
    } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd, victim)) != victim);
    if (victim != 0)
    {
      if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0))
      {
        errstr = "malloc(): memory corruption (fast)";
      errout:
        malloc_printerr(check_action, errstr, chunk2mem(victim), av);
        return NULL;
      }
      check_remalloced_chunk(av, victim, nb);
      void *p = chunk2mem(victim);
      alloc_perturb(p, bytes);
      return p;
    }
  }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

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

  else
  {
    idx = largebin_index(nb);
    if (have_fastchunks(av))
      malloc_consolidate(av);
  }

  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

  for (;;)
  {
    int iters = 0;
    while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av))
    {
      bck = victim->bk;
      if (__builtin_expect(victim->size <= 2 * SIZE_SZ, 0) || __builtin_expect(victim->size > av->system_mem, 0))
        malloc_printerr(check_action, "malloc(): memory corruption",
                        chunk2mem(victim), av);
      size = chunksize(victim);

      /*
         If a small request, try to use last remainder if it is the
         only chunk in unsorted bin.  This helps promote locality for
         runs of consecutive small requests. This is the only
         exception to best-fit, and applies only when there is
         no exact fit for a small chunk.
       */

      if (in_smallbin_range(nb) &&
          bck == unsorted_chunks(av) &&
          victim == av->last_remainder &&
          (unsigned long)(size) > (unsigned long)(nb + MINSIZE))
      {
        /* split and reattach remainder */
        remainder_size = size - nb;
        remainder = chunk_at_offset(victim, nb);
        unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
        av->last_remainder = remainder;
        remainder->bk = remainder->fd = unsorted_chunks(av);
        if (!in_smallbin_range(remainder_size))
        {
          remainder->fd_nextsize = NULL;
          remainder->bk_nextsize = NULL;
        }

        set_head(victim, nb | PREV_INUSE |
                             (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head(remainder, remainder_size | PREV_INUSE);
        set_foot(remainder, remainder_size);

        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }

      /* remove from unsorted list */
      unsorted_chunks(av)->bk = bck;
      bck->fd = unsorted_chunks(av);

      /* Take now instead of binning if exact fit */

      if (size == nb)
      {
        set_inuse_bit_at_offset(victim, size);
        if (av != &main_arena)
          victim->size |= NON_MAIN_ARENA;
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }

      /* place chunk in bin */

      if (in_smallbin_range(size))
      {
        victim_index = smallbin_index(size);
        bck = bin_at(av, victim_index);
        fwd = bck->fd;
      }
      else
      {
        victim_index = largebin_index(size);
        bck = bin_at(av, victim_index);
        fwd = bck->fd;

        /* maintain large bins in sorted order */
        if (fwd != bck)
        {
          /* Or with inuse bit to speed comparisons */
          size |= PREV_INUSE;
          /* if smaller than smallest, bypass loop below */
          assert((bck->bk->size & NON_MAIN_ARENA) == 0);
          if ((unsigned long)(size) < (unsigned long)(bck->bk->size))
          {
            fwd = bck;
            bck = bck->bk;

            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
          }
          else
          {
            assert((fwd->size & NON_MAIN_ARENA) == 0);
            while ((unsigned long)size < fwd->size)
            {
              fwd = fwd->fd_nextsize;
              assert((fwd->size & NON_MAIN_ARENA) == 0);
            }

            if ((unsigned long)size == (unsigned long)fwd->size)
              /* Always insert in the second position.  */
              fwd = fwd->fd;
            else
            {
              victim->fd_nextsize = fwd;
              victim->bk_nextsize = fwd->bk_nextsize;
              fwd->bk_nextsize = victim;
              victim->bk_nextsize->fd_nextsize = victim;
            }
            bck = fwd->bk;
          }
        }
        else
          victim->fd_nextsize = victim->bk_nextsize = victim;
      }

      mark_bin(av, victim_index);
      victim->bk = bck;
      victim->fd = fwd;
      fwd->bk = victim;
      bck->fd = victim;

#define MAX_ITERS 10000
      if (++iters >= MAX_ITERS)
        break;
    }

    /*
       If a large request, scan through the chunks of current bin in
       sorted order to find smallest that fits.  Use the skip list for this.
     */

    if (!in_smallbin_range(nb))
    {
      bin = bin_at(av, idx);

      /* skip scan if empty or largest chunk is too small */
      if ((victim = first(bin)) != bin &&
          (unsigned long)(victim->size) >= (unsigned long)(nb))
      {
        victim = victim->bk_nextsize;
        while (((unsigned long)(size = chunksize(victim)) <
                (unsigned long)(nb)))
          victim = victim->bk_nextsize;

        /* Avoid removing the first entry for a size so that the skip
           list does not have to be rerouted.  */
        if (victim != last(bin) && victim->size == victim->fd->size)
          victim = victim->fd;

        remainder_size = size - nb;
        unlink(av, victim, bck, fwd);

        /* Exhaust */
        if (remainder_size < MINSIZE)
        {
          set_inuse_bit_at_offset(victim, size);
          if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA;
        }
        /* Split */
        else
        {
          remainder = chunk_at_offset(victim, nb);
          /* We cannot assume the unsorted list is empty and therefore
             have to perform a complete insert here.  */
          bck = unsorted_chunks(av);
          fwd = bck->fd;
          if (__glibc_unlikely(fwd->bk != bck))
          {
            errstr = "malloc(): corrupted unsorted chunks";
            goto errout;
          }
          remainder->bk = bck;
          remainder->fd = fwd;
          bck->fd = remainder;
          fwd->bk = remainder;
          if (!in_smallbin_range(remainder_size))
          {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
          }
          set_head(victim, nb | PREV_INUSE |
                               (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head(remainder, remainder_size | PREV_INUSE);
          set_foot(remainder, remainder_size);
        }
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }
    }

    /*
       Search for a chunk by scanning bins, starting with next largest
       bin. This search is strictly by best-fit; i.e., the smallest
       (with ties going to approximately the least recently used) chunk
       that fits is selected.

       The bitmap avoids needing to check that most blocks are nonempty.
       The particular case of skipping all bins during warm-up phases
       when no chunks have been returned yet is faster than it might look.
     */

    ++idx;
    bin = bin_at(av, idx);
    block = idx2block(idx);
    map = av->binmap[block];
    bit = idx2bit(idx);

    for (;;)
    {
      /* Skip rest of block if there are no more set bits in this block.  */
      if (bit > map || bit == 0)
      {
        do
        {
          if (++block >= BINMAPSIZE) /* out of bins */
            goto use_top;
        } while ((map = av->binmap[block]) == 0);

        bin = bin_at(av, (block << BINMAPSHIFT));
        bit = 1;
      }

      /* Advance to bin with set bit. There must be one. */
      while ((bit & map) == 0)
      {
        bin = next_bin(bin);
        bit <<= 1;
        assert(bit != 0);
      }

      /* Inspect the bin. It is likely to be non-empty */
      victim = last(bin);

      /*  If a false alarm (empty bin), clear the bit. */
      if (victim == bin)
      {
        av->binmap[block] = map &= ~bit; /* Write through */
        bin = next_bin(bin);
        bit <<= 1;
      }

      else
      {
        size = chunksize(victim);

        /*  We know the first chunk in this bin is big enough to use. */
        assert((unsigned long)(size) >= (unsigned long)(nb));

        remainder_size = size - nb;

        /* unlink */
        unlink(av, victim, bck, fwd);

        /* Exhaust */
        if (remainder_size < MINSIZE)
        {
          set_inuse_bit_at_offset(victim, size);
          if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA;
        }

        /* Split */
        else
        {
          remainder = chunk_at_offset(victim, nb);

          /* We cannot assume the unsorted list is empty and therefore
             have to perform a complete insert here.  */
          bck = unsorted_chunks(av);
          fwd = bck->fd;
          if (__glibc_unlikely(fwd->bk != bck))
          {
            errstr = "malloc(): corrupted unsorted chunks 2";
            goto errout;
          }
          remainder->bk = bck;
          remainder->fd = fwd;
          bck->fd = remainder;
          fwd->bk = remainder;

          /* advertise as last remainder */
          if (in_smallbin_range(nb))
            av->last_remainder = remainder;
          if (!in_smallbin_range(remainder_size))
          {
            remainder->fd_nextsize = NULL;
            remainder->bk_nextsize = NULL;
          }
          set_head(victim, nb | PREV_INUSE |
                               (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head(remainder, remainder_size | PREV_INUSE);
          set_foot(remainder, remainder_size);
        }
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
      }
    }

  use_top:
    /*
       If large enough, split off the chunk bordering the end of memory
       (held in av->top). Note that this is in accord with the best-fit
       search rule.  In effect, av->top is treated as larger (and thus
       less well fitting) than any other available chunk since it can
       be extended to be as large as necessary (up to system
       limitations).

       We require that av->top always exists (i.e., has size >=
       MINSIZE) after initialization, so if it would otherwise be
       exhausted by current request, it is replenished. (The main
       reason for ensuring it exists is that we may need MINSIZE space
       to put in fenceposts in sysmalloc.)
     */

    victim = av->top;
    size = chunksize(victim);

    if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset(victim, nb);
      av->top = remainder;
      set_head(victim, nb | PREV_INUSE |
                           (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head(remainder, remainder_size | PREV_INUSE);

      check_malloced_chunk(av, victim, nb);
      void *p = chunk2mem(victim);
      alloc_perturb(p, bytes);
      return p;
    }

    /* When we are using atomic ops to free fast chunks we can get
       here for all block sizes.  */
    else if (have_fastchunks(av))
    {
      malloc_consolidate(av);
      /* restore original bin index */
      if (in_smallbin_range(nb))
        idx = smallbin_index(nb);
      else
        idx = largebin_index(nb);
    }

    /*
       Otherwise, relay to handle system-dependent cases
     */
    else
    {
      void *p = sysmalloc(nb, av);
      if (p != NULL)
        alloc_perturb(p, bytes);
      return p;
    }
  }
}

```

## 4. __libc_free

#### 功能：

1. 检查__free_hook函数指针(在glibc2.34以后， _libc_free不会检查free_hook)：

注意：在libc2-29前，进入tcache时没有存在tcache->key值检查，来识别double free：

libc-2.28![image-20240816170030938](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408161700088.png)

libc-2.29:![image-20240816165942161](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408161659328.png)

![image-20240816170319389](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408161703497.png)

#### 流程：

```c
//glibc-2.27
    void __libc_free(void *mem)
{
  mstate ar_ptr;
  mchunkptr p; /* chunk corresponding to mem */

  // 先检查free_hook函数指针是否为空，不为空就去调用该函数
  void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);
  if (__builtin_expect(hook != NULL, 0))
  {
    (*hook)(mem, RETURN_ADDRESS(0));
    return;
  }

  if (mem == 0) /* free(0) has no effect */
    return;

  p = mem2chunk(mem); // 用户使用的指针转化，指向chunk头
  // mmap空间释放
  if (chunk_is_mmapped(p)) /* release mmapped memory. */
  {
    /* See if the dynamic brk/mmap threshold needs adjusting.
 Dumped fake mmapped chunks do not affect the threshold.  */
    if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold && chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX && !DUMPED_MAIN_ARENA_CHUNK(p))
    {
      mp_.mmap_threshold = chunksize(p);
      mp_.trim_threshold = 2 * mp_.mmap_threshold;
      LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
                 mp_.mmap_threshold, mp_.trim_threshold);
    }
    munmap_chunk(p);
    return;
  }
  // 不是mmap空间，调用int_free来释放
  MAYBE_INIT_TCACHE();

  ar_ptr = arena_for_chunk(p); // 找到对应的内存分配区（arena）
  _int_free(ar_ptr, p, 0);
}
```

## 5. _int_free

### 流程：

```

```

