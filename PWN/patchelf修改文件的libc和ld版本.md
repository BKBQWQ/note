# patchelf修改文件的libc和ld版本

## 编译：

1. 使用特定的libc来编译文件：

   ```sh
   gcc test.c -o test -no-pie /home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
   
   gcc test.c -o test -no-pie /home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so
   ```

buuctf的libc资源： https://buuoj.cn/resources 

syscall系统调用：https://syscalls.w3challs.com

python下载包 换源：pip install -i https://pypi.tuna.tsinghua.edu.cn/simple  +  包名

1. protoc:
   * proto生成python的打包pack库：protoc --python_out=. lzl.proto
   * proto生成 c     的打包pack库：protoc --c_out=. lzl.proto
   * proto生成c++的打包pack库：protoc --cpp_out=. lzl.proto

<img src="https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202409132058480.png" alt="image-20240913205846391" style="zoom:50%;" />

> [!NOTE]
>
> ubuntu16.04 : **2.23-0ubuntu11.2**
>
> ubuntu18.04: **2.27-3ubuntu1.4**
>
> ubuntu20.04: **2.31-0ubuntu9.2**
>
> b"/bin/sh\x00" = 0x0068732f6e69622f

## ROPgadget + grep

```sh
# 包括转移字符[、]
ROPgadget --binary libc-2.31.so  --only "mov|call" | grep "mov rdx, qword ptr \[rdi"

# 搜索特定指令 -E 指定多种匹配情况 
ROPgadget --binary libc-2.31.so  --only "pop|ret" | grep -E "pop rdi|pop rdx|pop rsi|pop rax"

```



## patchelf修改加载时的库

1. 使用工具glibc-all-in-one，下载对应的libc和ld：

   ```sh
   cat list
   cat old_list
   ./download 2.23-0ubuntu3_amd64 
   ```




1. 使用patchelf工具，使用上面下载的libc和ld版本，指定好两个文件的路径：

   ```sh
   #libc-2.23    64位
   patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so ./pwn
   patchelf --add-needed /home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so ./pwn
   #libc-2.23    32位
   patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so ./pwn
   patchelf --add-needed /home/kali/Desktop/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc-2.23.so ./pwn
   
   #libc-2.27	  64位 tcache无double_free_检查
   patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so ./pwn
   patchelf --add-needed /home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so ./pwn
   
   #libc-2.27_1.5 64位	 tcache有double_free_检查
   patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1.5_amd64/ld-2.27.so ./pwn
   patchelf --add-needed /home/kali/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1.5_amd64/libc-2.27.so ./pwn
   
   #libc-3.35
   patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/ld-linux-x86-64.so.2 ./pwn
   patchelf --add-needed /home/kali/Desktop/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6 ./pwn
   ```



## 源码调试

```sh
#libc-2.23
gcc test.c -o test -no-pie /home/kali/Desktop/source_code/glibc-2.23_lib/lib/libc-2.23.so

patchelf --set-interpreter /home/kali/Desktop/source_code/glibc-2.23_lib/lib/ld-2.23.so ./test
patchelf --add-needed /home/kali/Desktop/source_code/glibc-2.23_lib/lib/libc-2.23.so ./test

#libc-2.25
gcc test.c -o test -no-pie /home/kali/Desktop/source_code/glibc-2.25_lib/lib/libc-2.25.so
patchelf --set-interpreter /home/kali/Desktop/source_code/glibc-2.25_lib/lib/ld-2.25.so ./test
patchelf --add-needed /home/kali/Desktop/source_code/glibc-2.25_lib/lib/libc-2.25.so ./test

#libc-2.29
gcc test.c -o test -no-pie /home/kali/Desktop/source_code/glibc-2.29_lib/lib/libc-2.29.so
patchelf --set-interpreter /home/kali/Desktop/source_code/glibc-2.29_lib/lib/ld-2.29.so ./test
patchelf --add-needed /home/kali/Desktop/source_code/glibc-2.29_lib/lib/libc-2.29.so ./test

#libc-2.32
gcc test.c -o test -no-pie /home/kali/Desktop/source_code/glibc-2.32_lib/lib/libc-2.32.so
patchelf --set-interpreter /home/kali/Desktop/source_code/glibc-2.32_lib/lib/ld-2.32.so ./test
patchelf --add-needed /home/kali/Desktop/source_code/glibc-2.32_lib/lib/libc-2.32.so ./test


#libc-2.38
gcc test.c -o test -no-pie /home/kali/Desktop/source_code/glibc-2.38_lib/lib/libc.so.6 

patchelf --set-interpreter /home/kali/Desktop/source_code/glibc-2.38_lib/lib/ld-linux-x86-64.so.2 ./test
patchelf --add-needed /home/kali/Desktop/source_code/glibc-2.38_lib/lib/libc.so.6 ./test
```

pwn中的堆关闭 **延迟合并** ：

![image-20250101215854371](https://gitee.com/poppy-qwq/cloudimage/raw/master/img1/202501012158465.png)

