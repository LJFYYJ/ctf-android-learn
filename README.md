# ctf-android-learn
android安全学习笔记

第一部分 [加密与解密](./密码学/加密与解密.md)

第二部分 [程序员的自我修养](./程序员的自我修养/程序员的自我修养.md)

- 静态链接、可执行文件装载、动态链接

第三部分  [二进制安全学习](./二进制安全学习/二进制安全学习.md)

- 栈漏洞、格式化字符串漏洞、堆漏洞基本原理

第四部分 [android开发](./android开发/android开发.md)

- android 四大组件

第五部分 [android安全基础知识](./android安全学习/android安全学习.md)

  * android
  * android studio项目开发
    * 项目结构、Android SDK、Android NDK
  * android逆向基础
    * JEB静态动态分析APK
    * IDA静态动态分析lib库

第六部分 [ISCC2021LOCKK题解](./LOCKK题解/ISCC2021LOCKK题解.md)

* 程序运行
* 静态分析APK和so
* 动态分析
  * IDA pro patch反调试、动调得到所有subkeys
* 变种AES解密

第七部分 [Android 系统架构](./android_framework/android_framework.md)

- Android系统架构
- Android Framework通信
  - APP启动流程
- binder通信应用实现

第八部分 android hook 学习

- [EdXposed](./android_hook/edxposed/edxposed学习.md)
  - 原理、安装、使用（HOOK函数、修改属性、主动调用函数）
- [frida](./android_hook/frida/frida学习.md)
  - 原理、使用配置
  - 基本使用：参数构造、方法重载、主动调用
  - 远程调用、python和javascript互联互通
  - 在安卓10上dump蓝牙接口和实例
  - 动静态结合逆向WhatsApp

* [Objection](./android_hook/objection/objection学习.md)
  * 内存漫游、wallbreaker插件、FRIDA-DEXDump插件

- [HTTPS抓包](./android_hook/HTTPS抓包/HTTPS抓包.md)
  - 原理：中间人攻击、双向认证、SSL Pinning
  - 配置：Kali、charles代理配置
  - r0capture使用与分析
    - HTTPS中间人抓包 绕过双向认证、ssl pinning
    - HOOK抓HTTP、HTTPS包
    - 某app ssl pinning抓包实战

第九部分 [android app渗透测试-Activity、Service](./android攻击面/android攻击面整理.md)

* 获取apk源代码
  * vdexExtrator使用
* Activity漏洞挖掘
  * Activity越权漏洞、拒绝服务攻击、劫持
* Service漏洞挖掘
  * Service非授权访问、消息伪造、拒绝服务
* CTF实例

第十部分 [android加壳脱壳学习](./android加壳脱壳/android加壳脱壳学习.md)

- 类加载器原理
- Dex整体加固壳、函数脱取壳、Vmp和dex2C

其他部分

- [Java Web安全](./其他/Web安全学习/JavaWeb安全学习.md)
  - CommonsCollections6利用链学习
  - shiro550反序列化漏洞利用
- [Log4J2漏洞复现及原理分析](./其他/Log4j2漏洞复现/Log4j2漏洞复现.md)

- [逆向安全学习](./其他/逆向安全学习/逆向安全学习.md)
  - 脱壳技术：ESP定律
  - 反调试技术：花指令

