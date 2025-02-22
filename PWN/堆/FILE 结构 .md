# FILE 结构 

## FILE 介绍

1. FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。FILE 结构定义在 libio.h 中，如下所示：

   ```c
   struct _IO_FILE {
     int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
   #define _IO_file_flags _flags
   
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
   #if 0
     int _blksize;
   #else
     int _flags2;
   #endif
     _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
   
   #define __HAVE_COLUMN /* temporary */
     /* 1+column number of pbase(); 0 is unknown. */
     unsigned short _cur_column;
     signed char _vtable_offset;
     char _shortbuf[1];
   
     /*  char* _save_gptr;  char* _save_egptr; */
   
     _IO_lock_t *_lock;
   #ifdef _IO_USE_OLD_IO_FILE
   };
   struct _IO_FILE_complete
   {
     struct _IO_FILE _file;
   #endif
   #if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
     _IO_off64_t _offset;
   # if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
     /* Wide character stream stuff.  */
     struct _IO_codecvt *_codecvt;
     struct _IO_wide_data *_wide_data;
     struct _IO_FILE *_freeres_list;
     void *_freeres_buf;
   # else
     void *__pad1;
     void *__pad2;
     void *__pad3;
     void *__pad4;
   
     size_t __pad5;
     int _mode;
     /* Make sure we don't get into trouble again.  */
     char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
   #endif
   };
   ```

   一共大小为：0xE8
   
   ![image-20240807142015006](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071420413.png)
   
   进程中的 **FILE 结构**会通过**_chain 域**彼此连接形成一个链表，链表头部用全局变量**_IO_list_all** 表示，通过这个值我们可以遍历所有的 FILE 结构。
   
   在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：**stdin、stdout、stderr**。因此在初始状态下，**_IO_list_all**（指针） 指向了一个有这些文件流构成的链表，但是需要注意的是这三个文件流位于 **libc.so 的数据段**。而我们使用 fopen 创建的文件流是**分配在堆内存**上的。
   
   
   
   > [!NOTE]
   >
   > 问题：为什么 **_IO_2_1_stderr_ 的类型是_IO_FILE_plus**，但是 **_chain是IO_file类型的指针**，却能指向它 ：
   >
   > 这个问题涉及到标准 I/O 库（`<stdio.h>` 或 `<cstdio>`）内部的一些实现细节。在标准 C 和 C++ 库中，标准输入输出流（如 `stdin`, `stdout`, 和 `stderr`）是由 `_IO_FILE` 类型的对象来表示的。然而，在实际的库实现中，这些对象通常会有一些额外的数据成员来支持更复杂的功能。这就是为什么你会看到 `_IO_FILE_plus` 这种类型。
   >
   > 以下是几个关键点来解释这种类型的差异：
   >
   > 1. **_IO_FILE 和 _IO_FILE_plus:**
   >    - `_IO_FILE` 是一个基本的文件流类型，它定义了文件流的基本功能。
   >    - `_IO_FILE_plus` 是 `_IO_FILE` 的扩展版本，包含了更多额外的功能和数据成员。这些额外的功能可能包括缓冲区管理、锁定机制等。
   >
   > 2. **指针类型转换:**
   >    - 在标准库中，`_IO_FILE_plus` 类型的对象通常被用作标准输入输出流的实现。
   >    - 但是，对于程序员来说，他们通常只接触到 `_IO_FILE` 类型。这是因为 `_IO_FILE_plus` 的额外成员对大多数应用程序来说是隐藏的。
   >    - 因此，当标准库将 `_IO_2_1_stdin_`（或其他标准流）暴露给程序员时，它会通过 `(FILE *)` 类型转换来实现。这样做是为了确保向后兼容性和一致性，因为大多数程序员和库函数期望的是 `_IO_FILE` 类型。
   >
   > 3. **类型兼容性:**
   >    - `_IO_FILE` 和 `_IO_FILE_plus` 之间是兼容的。也就是说，`_IO_FILE_plus` 可以被视为 `_IO_FILE` 的一个子集，因此可以将 `_IO_FILE_plus` 对象的地址赋给 `_IO_FILE` 类型的指针。
   >
   > 总结一下，`_IO_2_1_stdin_` 是 `_IO_FILE_plus` 类型的对象，而 `stdin` 指针是 `_IO_FILE` 类型的。通过 `(FILE *)` 类型转换，`stdin` 被初始化为指向 `_IO_2_1_stdin_` 的地址，这样就可以使用 `_IO_FILE` 类型的接口来访问标准输入流了。
   >
   > 这种做法确保了标准库的内部实现可以更灵活地扩展功能，同时保持了对现有代码的兼容性。程序员通常不需要关心这些内部细节，只需使用 `stdin`, `stdout`, 和 `stderr` 即可。
   >
   > 
   
   我们可以在 libc.so 中找到 stdin\stdout\stderr 等符号，这些符号是指向 FILE 结构的指针，真正结构的符号是：
   
   ```c
   _IO_2_1_stderr_
   _IO_2_1_stdout_
   _IO_2_1_stdin_
   ```
   
   ![image-20240812203808627](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408122038690.png)
   
   但是事实上_ IO_FILE 结构外包裹着另一种结构_**IO_FILE_plus**，其中包含了一个重要的**指针 vtable** 指向了一**系列函数指针**。
   
   ![image-20240812204934027](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408122049143.png)
   
   在 libc2.23 版本下，**32 位的 vtable 偏移为 0x94**，**64 位偏移为 0xd8**：
   
   ```c
   struct _IO_FILE_plus
   {
       _IO_FILE    file;
       IO_jump_t   *vtable;
   }
   ```
   
   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408111623009.png" alt="image-20240811162358858"  />
   
   
   
   vtable 是 IO_jump_t 类型的指针，IO_jump_t 中保存了一些函数指针，在后面我们会看到在一系列标准 IO 函数中会调用这些函数指针：
   
   ```c
   void * funcs[] = {
      1 NULL, // "extra word"
      2 NULL, // DUMMY
      3 exit, // finish
      4 NULL, // overflow
      5 NULL, // underflow
      6 NULL, // uflow
      7 NULL, // pbackfail
      
      8 NULL, // xsputn  #printf
      9 NULL, // xsgetn
      10 NULL, // seekoff
      11 NULL, // seekpos
      12 NULL, // setbuf
      13 NULL, // sync
      14 NULL, // doallocate
      15 NULL, // read
      16 NULL, // write
      17 NULL, // seek
      18 pwn,  // close
      19 NULL, // stat
      20 NULL, // showmanyc
      21 NULL, // imbue
   };
   ```
   
   ![image-20240807143240508](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202408071432770.png)
   
   

## fread：

1. fread 是标准 IO 库函数，作用是从文件流中读数据，函数原型如下：

   ```c
   size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
   ```

   - buffer 存放读取数据的缓冲区。
   - size：指定每个记录的长度。
   - count： 指定记录的个数。
   - stream：目标文件流。
   - 返回值：返回读取到数据缓冲区中的记录个数

   fread 的代码位于 / libio/iofread.c 中，函数名为_IO_fread，但真正的功能实现在子函数 _IO_sgetn 中：

   ```c
   _IO_size_t
   _IO_fread (buf, size, count, fp)
        void *buf;
        _IO_size_t size;
        _IO_size_t count;
        _IO_FILE *fp;
   {
     ...
     bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
     ...
   }
   ```

   在**_ IO_sgetn**  函数中会调用 _IO_XSGETN，而 _ IO_XSGETN 是_IO_FILE_plus.vtable 中的函数指针，在调用这个函数时会首先**取出 vtable 中的指针**然后再进行调用：

   ```c
   _IO_size_t
   _IO_sgetn (fp, data, n)
        _IO_FILE *fp;
        void *data;
        _IO_size_t n;
   {
     return _IO_XSGETN (fp, data, n);
   }
   ```

   在默认情况下函数指针是指向_IO_file_xsgetn 函数的：

   ```c
     if (fp->_IO_buf_base
             && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
           {
             if (__underflow (fp) == EOF)
           break;
   
             continue;
           }
   ```

   

## fwrite

1. fwrite 同样是标准 IO 库函数，作用是向文件流写入数据，函数原型如下：

   ```c
   size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
   ```

   - buffer: 是一个指针，对 fwrite 来说，是要**写入数据的地址**;
   - size: 要写入内容的单字节数;
   - count: 要进行写入 size 字节的数据项的个数;
   - stream: 目标文件指针;
   - 返回值：实际写入的数据项个数 count。

   fwrite 的代码位于 / libio/iofwrite.c 中，函数名为_ IO_fwrite。 在_ IO_fwrite 中主要是调用_IO_XSPUTN 来实现写入的功能。

   根据前面对_ IO_FILE_plus 的介绍，可知_ IO_XSPUTN 位于_IO_FILE_plus 的 vtable 中，调用这个函数需要**首先取出 vtable 中的指针**，再跳过去进行调用。

   ```c
   written = _IO_sputn (fp, (const char *) buf, request);
   ```

   在_ IO_XSPUTN 对应的默认函数_ IO_new_file_xsputn 中会调用同样位于 vtable 中的_IO_OVERFLOW：

   ```c
    /* Next flush the (full) buffer. */
         if (_IO_OVERFLOW (f, EOF) == EOF)
   ```

   _ IO_OVERFLOW 默认对应的函数是 _ IO_new_file_overflow：

   ```c
   if (ch == EOF)
       return _IO_do_write (f, f->_IO_write_base,
                f->_IO_write_ptr - f->_IO_write_base);
     if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
       if (_IO_do_flush (f) == EOF)
         return EOF;
   ```



## fopen

1. fopen 在标准 IO 库中用于打开文件，函数原型如下：

   ```c
   FILE *fopen(char *filename, *type);
   ```

   - filename: 目标文件的路径
   - type: 打开方式的类型
   - 返回值: 返回一个文件指针

   在 fopen 内部会**创建 FILE 结构**并进行一些初始化操作，下面来看一下这个过程：

   * 首先在 fopen 对应的函数__fopen_internal 内部会**调用 malloc 函数**，**分配 FILE 结构的空间**。因此我们可以获知 **FILE 结构是存储在堆上**的：

   ```c
   *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
   ```

   * 之后会为创建的 FILE 初始化 vtable，并调用_IO_file_init 进一步初始化操作：

   ```c
   _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
   _IO_file_init (&new_f->fp);
   ```

   * 在_IO_file_init 函数的初始化操作中，会调用_IO_link_in 把**新分配的 FILE 链入_IO_list_all 为起始的 FILE 链表**中，采用头插法，：

   ```c
   void
   _IO_link_in (fp)
        struct _IO_FILE_plus *fp;
   {
       if ((fp->file._flags & _IO_LINKED) == 0)
       {
         fp->file._flags |= _IO_LINKED;
         fp->file._chain = (_IO_FILE *) _IO_list_all;
         _IO_list_all = fp;
         ++_IO_list_all_stamp;
       }
   }
   ```

   * 之后__fopen_internal 函数会调用_IO_file_fopen 函数打开目标文件，_IO_file_fopen 会根据用户传入的打开模式进行打开操作，总之最后会调用到系统接口 open 函数，这里不再深入：

   ```c
   if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
       return __fopen_maybe_mmap (&new_f->fp.file);
   ```

   总结一下 fopen 的操作是

   - 使用 **malloc** 分配 FILE 结构
   - 设置 FILE 结构的 **vtable**
   - **初始化**分配的 FILE 结构
   - 将初始化的 FILE 结构**链入 FILE 结构链表**中
   - 调用系统调用打开文件

## fclose：

1. fclose 是标准 IO 库中用于关闭已打开文件的函数，其作用与 fopen 相反。

   ```c
   int fclose(FILE *stream)
   ```

   功能：关闭一个文件流，使用 fclose 就可以把缓冲区内最后剩余的数据**输出到磁盘文件**中，并释放文件指针和有关的缓冲区。

   fclose 首先会调用_ IO_unlink_it 将指定的 FILE **从_chain 链表中脱链** :

   ```c
   if (fp->_IO_file_flags & _IO_IS_FILEBUF)
       _IO_un_link ((struct _IO_FILE_plus *) fp);
   ```

   之后会调用_ IO_file_close_it 函数，_IO_file_close_it 会调用系统接口 close 关闭文件:

   ```c
   if (fp->_IO_file_flags & _IO_IS_FILEBUF)
       status = _IO_file_close_it (fp);
   ```

   最后调用 vtable 中的_ IO_FINISH，其对应的是_IO_file_finish 函数，其中会调用 free 函数释放之前分配的 FILE 结构:

   ```c
   _IO_FINISH (fp);
   ```



## printf/puts

1. printf 和 puts 是常用的输出函数，在 printf 的参数是以'\n'结束的纯字符串时，printf 会被优化为 puts 函数并去除换行符。

2. puts 在源码中实现的函数是_ IO_puts，这个函数的操作与 fwrite 的流程大致相同，函数内部同样会调用 vtable 中的_ IO_sputn，结果会执行_IO_new_file_xsputn，最后会调用到系统接口 write 函数。

3. printf 的调用栈回溯如下，同样是通过**_IO_file_xsputn** 实现

   ```c
   vfprintf+11
   _IO_file_xsputn
   _IO_file_overflow
   funlockfile
   _IO_file_write
   write
   ```