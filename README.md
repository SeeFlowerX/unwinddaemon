# unwinddaemon

## 编译步骤

- 同步AOSP
- 在AOSP源码文件夹下创建`system/extras/unwinddaemon`文件夹
- 将本项目的`Android.bp`和`main.cpp`放入上一步创建的文件夹
- 在AOSP源码文件夹下打开终端，执行下面的命令进行编译
    ```bash
    . build/envsetup.sh
    lunch aosp_arm64-eng
    mmma system/extras/unwinddaemon
    ```
- 编译成功后，产物在`out/target/product/generic_arm64/system/bin/unwinddaemon`

## 使用

将`out/target/product/generic_arm64/system/bin/unwinddaemon`推送到手机的`/data/local/tmp`，授予可执行权限

然后执行`/data/local/tmp/unwinddaemon`即可
