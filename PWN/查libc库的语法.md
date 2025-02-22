# 查libc库的语法

1. 根据 **函数偏移的后三位** 查libc的ID：

   ```sh
   ./find printf b40 puts 970
   ```

   ![image-20240704205058779](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407042050849.png)

2. 根据 **libc的ID** 查其他函数的偏移：

   ```sh
   ./dump libc6-i386_2.31-0ubuntu9_amd64
   ```

   ![](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407042052561.png)

3. 查看一个libc库是否在数据库中，会返回libc的ID：

   ```sh
   ./identify db/libc6-amd64_2.12.1-0ubuntu10.4_i386.so
   ```

   ![image-20240704210633049](https://gitee.com/poppy-qwq/cloudimage/raw/master/img/202407042106250.png)

4. 下载一个libc到数据库中：

   ```sh
   ./download libc6_2.23-0ubuntu10_amd64
   ```

   