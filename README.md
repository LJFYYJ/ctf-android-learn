# ctf-android-learn
android安全学习笔记

第一部分 [加密与解密](./密码学/加密与解密.md)

第二部分 [android安全基础知识](./android安全学习/android安全学习.md)

  * android
  * android studio项目开发
    * 项目结构
    * Android SDK
    * Android NDK
  * android逆向
    * APK文件
    * Dalvik虚拟机
    * Genymotion模拟器
    * Android Debug Bridge
    * JEB静态分析APK
    * JEB动态调试APK
    * log动态调试
    * Dalvik层混淆
    * IDA静态分析lib库
    * IDA动态调试lib库

第三部分 [ISCC2021LOCKK题解](./LOCKK题解/ISCC2021LOCKK题解.md)

* 程序运行
* 静态分析
  * JEB静态分析APK
  * IDA静态分析so
* 动态分析
  * IDA pro attach进程
  * 调试得到所有subkeys
* 解密算法
  * Base64 解码
  * 变种AES解密
  * AES原理

第四部分 [Android 系统架构](./android_framework/android_framework.md)

- Android系统架构
- Android Framework通信
  - APP启动流程
  - init进程
  - zygote进程
  - SystemServer进程
  - binder通信
  - handler通信
- binder通信实现
  * service端
    * aidl文件
  * client端
  * 实现效果
  * AIDL源码分析

第五部分 [android app渗透测试-Activity、Service](./android攻击面/android攻击面整理.md)

* 获取apk源代码
  * vdexExtrator使用
* 观察清单文件
* Activity漏洞挖掘
  * Activity越权漏洞示例
  * Activity拒绝服务攻击
  * Activity劫持
* Service漏洞挖掘
  * Service非授权访问
  * Service消息伪造
  * Service拒绝服务
  * 防护原理
* CTF实例
  * 程序运行
  * 攻击面确定
  * 静态逆向分析
  * POC编写
    * AIDL绑定CoreService
    * 通过MiscService的intent启动WebActivity

第六部分 [android hook frida学习](./android-hook/android-hook学习.md)

* 环境配置
* 基本能力Ⅰ：hook参数、修改结果
* 基本能力Ⅱ：参数构造、方法重载、隐藏函数的处理
* 中级能力：远程调用
* 高级能力：互联互通、动态修改
* 简单脚本
  * 综合案例：在安卓10上dump蓝牙接口和实例
* Hook Native层
* 动静态结合逆向WhatsApp

