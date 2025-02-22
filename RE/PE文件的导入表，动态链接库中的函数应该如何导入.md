## 导入地址表IAT
1. IAT保存的内容与windos操作系统的核心进程、内存、DLL结构有关。IAT是一种表格，用来记录程序正在使用哪些库中的哪些函数。
## 动态链接库(DLL)
1. ![](https://img-blog.csdnimg.cn/direct/07850fe2163b4665b35516dfdf6f379c.png#pic_center)
2. 常见的kernel.dll就是一个非常重要的动态链接库，其中包含了运行程序时需要使用到的函数，后续结合导入描述符(**IMAGE_IMPORT_DESCRIPTOR**)中的内容，观察PE装载器时如何将kernel.dll中需要用到的函数装载进入到IAT中的。
## 导入函数
1. 一个程序往往需要使用到多个动态链接库，其以结构体的形式存在于**IMPORT Directory Table**(导入表)中。
2. 这里依旧以上一篇的hello.exe文件为例， 首先要找到**IMPORT Directory Table**(导入表)的位置，这在上一篇文章中有详细介绍([PE文件格式](https://blog.csdn.net/yjh_fnu_ltn/article/details/138135659?spm=1001.2014.3001.5501))，定位到**00003000**:![](https://img-blog.csdnimg.cn/direct/c2cf9f7c4a0e4828825de773a71ef31f.png#pic_center)
3. 这里可以看到整个导入表，导入表是一个数组，其最后一个元素为NULL(权全为00)，当前数组共有两个元素，即两个DLL需要导入，其中的每一个元素结构体为**IMAGE_IMPORT_DESCRIPTOR**(导入描述符)：![](https://img-blog.csdnimg.cn/direct/307cb1272f7d45b49c0e8c383e228310.png#pic_center)
4. 前四个字节为**INT**，其指向了该动态链接库要导入哪些函数，最后一个 **FirstThunk**为“”IAT“”，即PE文件加载到内存中时**函数地址**需要填入的位置，倒数第二个**name**字段则指向了该动态链接库的名称的地址(这里的地址都是**RVA**(在内存中的偏移)，要变成在文件中的偏移**FOA**需要里面前面那片文章中的公式进行转换)。
5. **86E8**->**36E8**,动态链接库名称的位置:![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/7904f993188340a1a450bb2da5cc8052.png#pic_center)
6. 从动态链接库中导入函数时，首先需要在IID中拿到**OriginalFirstThunk**(INT)，这里存储了所有需要导入的函数信息，是一个指针数组(其中存储都是以RVA的形式)，数组中的每一个元素均指向结构体为**IMAGE_IMPORT_BY_NAME**的元素，**IMAGE_IMPORT_BY_NAME**第一个元素为函数的编号(hint)，第二个元素时需要导入的函数的名字，下面以kernel.dll来为实例观察需要导入哪些函数：![](https://img-blog.csdnimg.cn/direct/ee6e5b1c604844e8b4079816a06734ba.png#pic_center)
7. 根据kernel.dll的**IMAGE_IMPORT_DESCRIPTOR**的第一个元素定位到**INT**，其中的RVA需要转化为FOA在文件中的偏移，兄弟们看上一篇后自行转化过来：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/5d57d1b63d094d9d9d011fc058d1646a.png#pic_center)
8. 观察其中的第一个元素**0000836C**，它指明了第一个函数**IMAGE_IMPORT_BY_NAME**结构体的RVA，转化为FOA **0000336C**，观察在文件中的偏移：![](https://img-blog.csdnimg.cn/direct/0cf4c8052f434b5180b9d2abf38300c9.png#pic_center)
9. 首位的**010D**是函数的编号，后面是函数的名称**DeleteCriticalSection**，那他要被装载到内存中的什么地方呢，就需要根据前面的**IMAGE_IMPORT_DESCRIPTOR**(导入描述符)中的IAT指明的位置RVA **000081D4**,下面进入到内存中观察函数是否被装载到此处。
10.使用x64dbg打开hello.exe文件 ：![](https://img-blog.csdnimg.cn/direct/84a6c0b04de14a5b91d6c60944fb2aa3.png#pic_center)
10. 可以看到文件被加载到内存中的基地址是400000(ImageBase)，后续要根据ImageBase基地址和RVA偏移地址相加求出VA绝对地址：**000081D4**+**400000**=**4081D4**，在内存中跳转到该位置，查看其内容是否为**DeleteCriticalSection**函数的地址：![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/010d1a409258472aac85a08fa0d8c9b2.png#pic_center)


11. 根据内存中4081D4内存地址处的注释，可以确定该处的值**00007FF99FD2A710**是函数**DeleteCriticalSection**的起始地址，后续共kermel.dll需要导入的23个函数全部导入到内存中。
12. 在内存中可以直接使用RVA来查看一下动态链接库的名字是不是在**ImageBase+RVA**处，根据前面的RVA**86E8**，在内存中跳转到**4086E8**：![](https://img-blog.csdnimg.cn/direct/669d9ee133ad479a8c28e4a11fb154ee.png#pic_center)
13. 接着在INT中看下一个函数，RVA是**00008384**->**00003384**,可以看出编号是**0131**，名字是**EnterCriticalSection**：![](https://img-blog.csdnimg.cn/direct/f838f9f635894ba2bc56716d83262498.png#pic_center)
14. 下面再内存中找到RVA为**000081D4**，观察该处后面第二个位置函数是不是**EnterCriticalSection**(第一个位置的函数已经被导入)，结合内存中的值可以说是一模一样，后面的函数一次再INT中取值，找到对应的函数名，通过GetProcAddress方法拿到对应函数的地址，再将其填入IAT，一致循环知道INT被拿完，则所需的kernel.dll动态链接库中的全部函数均导入完毕。后续第二个动态链接库msvcrt.dll也依照上面的方法进行导入：![](https://img-blog.csdnimg.cn/direct/3edeedefbef74e0d97dd88e5472a593f.png#pic_center)
15. 另外，再代码中我们可以看到，调用动态链接库导入的函数，都是以取一个地址后，call该地址处的值来进行调用，而不是直接call函数的地址，为什么要进行一次**中转**呢？：![](https://img-blog.csdnimg.cn/direct/7f6f0e4399ee4815acbba16656a4c8c2.png#pic_center)
16. 第一点：hello.exe等可执行文件，并不知道自己要工作再哪总平台上，哪种环境中，再各种不同的环境下kernel.dll的版本都不相同，而相应库中的函数位置也不相同，所以不能直接再call后面跟上函数的具体地址(这样就只能保证在当前一个平台下使用)，需要给定一个内存单元（如4081D4），程序在具体环境下运行时，动态的将需要的库函数地址放在此处。
17. 第二点：DLL的重定位DLL文件的imageBase不会时一个固定的值，如果内存中该位置被占了，那么PE装载器就需要重新定位基地址，所以无法直接将函数的实际地址直接写在指令中，并且PE文件中也指定kernel.dll中导入的函数应该在内存中的RVA()。











 
