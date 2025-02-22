[TOC]

# house of banana

> [!NOTE]
>
> ## 利用条件
>
> 1. 可以泄露 `libc` 地址和堆地址 ==> 伪造 link_map，和 large bin attack
> 2. 可以任意地址写一个堆地址（通常使用 `large bin attack`）==> 覆盖 _rtld_global 结构体中 _dl_ns的 _ns_loaded 指针
> 3. 能够从 `main` 函数0返回或者调用 `exit` 函数 ==> 触发banana
>
> 注意： 使用 `setcontext` 来控制寄存器打 `orw` 的话，需要在 `2.29` 版本以上才行（ `2.27` 没有办法让 `rdx` 或 `rdi` 为堆地址），但是可以用下面的这几个gadget进行转化： 
>
> **__rpc_thread_key_cleanup** ：
>
> ![image-20241110204632218](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411102046341.png)
>
> **clntunix_call** ：
>
> ![image-20241110205625909](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411102056969.png)
>
> ![image-20241110205904271](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411102059330.png)
>
> ![image-20241110205925991](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411102059043.png)
>
> **getkeyserv_handle** ：
>
> ![image-20241110205751938] (https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411102057000.png)

调用链子：

```sh
exit-> __run_exit_handlers -> _dl_fini -> _dl_fini+520(setcontext)
```

## 原理

1. **link_map 结构体** 的存储方式和堆块链表类似，是通过 `l_next` 和 `l_prev` 指针来连接的,而这个链表的头指针就是 `_rtld_global` 结构体中 _dl_ns 的 `_ns_loaded` 所存储的地址：

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051106541.png" alt="image-20241105110652423" style="zoom: 50%;" />

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051107006.png" alt="image-20241105110715947" style="zoom:50%;" />

2. banana的原理就是 ：覆盖l_next的值，伪造_rtld_globa结构体里面用ns_loaded所连接的link_map结构体，最终是在于link_map里面，伪造其中的一些数据，最终执行**((fini_t) array[i]) ()** 

<img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051132719.png" alt="image-20241105113211630" style="zoom:50%;" />

3. 看一下一般情况下的调用链：

   首先要进入else分支，必须绕过if中的条件，但是我们覆盖的不是_ns_loaded结构体，所以不用关心这个检查：

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051138295.png" alt="image-20241105113858224" style="zoom:50%;" />

4. 第一个检查，循环中的if条件必须满足，要过assert的检查，而且要**将maps中填入地址**：

   **这里在覆盖l_next指针时，需要覆盖倒数第二个link_map的l_next字段（倒数第三个link_map的l_next字段的值）** 这样最后计算出来的 **i == nload**

   ```c
    for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next) // 通过l_next指针遍历所有的link_map
   	    /* Do not handle ld.so in secondary namespaces.  */
   	    if (l == l->l_real) // l 与link_map结构体中的l_real比较 l_real必须指向自己
   	      {
                   assert (i < nloaded); // nloaded是节点数 要保证训话次数i < link_map节点数
   
                   maps[i] = l; // 将地址放入maps数组中，后续的循环会直接从maps中那地址
                   l->l_idx = i;
                   ++i;
   
                   /* Bump l_direct_opencount of all objects so that they
                      are not dlclose()ed from underneath us.  */
                   ++l->l_direct_opencount;
   	      }
   	  assert (ns != LM_ID_BASE || i == nloaded); // 通过上面的循环后才能过掉这个检查
   	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);// 通过上面的循环后才能过掉这个检查
   ```

   ![image-20241105114451798](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051144068.png)

   顺利过掉检查：

   ![image-20241105115015595](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051150776.png)

5. 第二个检查：

   ```c
   #define	DT_FINI_ARRAY	26
   #define	DT_FINI_ARRAYSZ	28
   #define DT_FINI		13
   
   	  for (i = 0; i < nmaps; ++i)
   	    {
   	      struct link_map *l = maps[i];
   
   	      if (l->l_init_called)
   		{
   		  /* Make sure nothing happens if we are called twice.  */
   		  l->l_init_called = 0;
   
   		  /* Is there a destructor function?  */
   		  if (l->l_info[DT_FINI_ARRAY] != NULL
   		      || l->l_info[DT_FINI] != NULL)
   		    {
   		      /* When debugging print a message first.  */
   		      if (__builtin_expect (GLRO(dl_debug_mask)
   					    & DL_DEBUG_IMPCALLS, 0))
   			_dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
   					  DSO_FILENAME (l->l_name),
   					  ns);
   
   		      /* First see whether an array is given.  */
   		      if (l->l_info[DT_FINI_ARRAY] != NULL)
   			{
   			  ElfW(Addr) *array =
   			    (ElfW(Addr) *) (l->l_addr
   					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
   			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
   					    / sizeof (ElfW(Addr)));
   			  while (i-- > 0)
   			    ((fini_t) array[i]) ();
   			}
   
   		      /* Next try the old-style destructor.  */
   		      if (l->l_info[DT_FINI] != NULL)
   			DL_CALL_DT_FINI
   			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
   		    }
   ```

   <img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051202917.png" alt="image-20241105120211835" style="zoom:50%;" />

   

   保证 **l_info[26]不为空** ：

   ![image-20241105121012462](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051210727.png)

   > [!NOTE]
   >
   > d_un是一个联合体，即其中的**成员共享一块内存区域**，但是可以通过不同的变量访问相同的值

   这里先给一个指针array赋值：l->l_info[26]指向的 d_un 结构体中的 d_ptr终端的值。

   如果此时将 l->l_info[26] 覆盖为**l->l_info[26]的地址** ，那么array的值将会为 **l->l_info[27]**中的值(l->l_addr给为0)

   再给**i赋值** ：l->l_info[28] 指向的 d_un 结构体中的 d_val 终端的值 右移3位（除8）。<_dl_fini+446>

   如果将 l->l_info[28] 设置为 **l->l_info[28]的地址** 那么 **l->l_info[29] 除以8就是 i的值** 。

   ![image-20241105121455752](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051214053.png)

6. 最后调用到array[i]中的函数：

   ![image-20241105125037376](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411051250549.png)



## 例子：

题目：强网杯 baby_heap

1. 首先覆盖掉 鲷属第二个link_map结构体的 l_next 的值，指向堆上面：

![image-20241105202206520](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052022655.png)

2. 再堆上伪造好 fake_link_map 结构体，l_real，l_info[26]，l_info[27]，l_info[28]，l_info[29]：

   ![image-20241105202341675](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052023789.png)

3. 执行 _di_fini 函数：

   这里取出 l_real 字段与自身地址比较

   ![image-20241105211707102](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052117615.png)

   保证 l->l_info[26] 不能为 NULL：

   ![image-20241105212013335](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052120405.png)

   通过 fake_l_info[26] 中的地址取到 fake_l_info[27]的值 作为 array。再通过 fake_l_info[27]中的地址 取到 fake_l_info[28]的值除以8作为 i。最后根据array 和 i的值 取出函数地址去调用：

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052134512.png)

   调用到[rax]上的函数地址，此时rdx寄存器的值为4，即i的值。该次函数调用结束之后会将rax寄存器的值 传递给rdx（可以借助这个配合setcontext + 61 完成栈迁移）：

   ![image-20241105213910156](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052139312.png)

   这里将rax 即array数组的尾地址(因为源码的循环中是i--)传递给rdx存储，随后更新rax的值，取到下一个函数地址取执行，这是rdx为函数数组array的尾地址：

   ![image-20241105214248854](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202411052142006.png)

   

   