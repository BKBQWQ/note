# docker

1. 查看doucker运行状态：

   ```sh
   sudo service docker status
   ```

2. **开启和停止**docker服务：

   ```sh
   sudo service docker start
   sudo service docker stop
   ```

3. 开机在启动docker，可以设置自启动：

   ```sh
   sudo systemctl enable docker
   
   sudo systemctl disable docker（关闭自启动）
   ```

4. 查看已经拉取的docker镜像：

   ```sh
   sudo docker images
   ```

   