# ISCC2021 LOCKK题解

## 程序运行

输入ISCC{123}，点击ENCRYPT实现加密

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\1-程序加密.png)

点击DERYPT，发现得到一个假flag：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\2-程序解密.png)

## 静态分析

### JEB静态分析APK

JEB打开APK，onClick函数运行时，框内默认为空，点击解密按钮就会出现x函数中的fakeflag，点击加密按钮则会显示y函数中的加密结果。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\3-jeb解析.png)

观察SecureUtil函数，发现是先调用native层的encryptdata函数，再Base64加密。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\4-SecureUtil函数.png)

通过翻看Assets文件夹可以猜测，flag的加密结果放在了log文件中，为：

j9lXGz/eWs4iODrHgTbQZdtXl1RjO82FQhSADajx1vRNnw2NIASP/2mySb2Dqmgh

### IDA静态分析so

#### 寻找encryptData函数

将armeabi-v7a文件夹（另一个文件夹下的so文件IDA反编译结果会和下图示例不同）下的so库拖入IDA中反编译，因为在函数导出列表中并没有找到encryptData函数，说明采用了动态注册的方法，因此找到JNI_OnLoad函数，其包含了简易的反调试信息：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\5-JNI_OnLoad.png)

JNI_OnLoad函数中最下面的部分与native注册函数RegisterNatives(env, class, method, numMethods)的格式类似，注意到off_1D004：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\6-JNI_OnLoad下面.png)

双击进入，里面的sub_4B8C就是要找的函数encryptData。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\7-sub_4B8C.png)

#### encryptData函数

进入sub_4B8C函数后，第一步是修复函数参数。native函数的前两个参数都为JNIEnv *,  jclass，原encryptData的参数类型为context和byte[]对应到jni中应该为jobject和jbyteArray类型，返回值也为jbyteArray类型。

更改参数类型前：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\8-更改参数类型前.png)

更改参数类型：选中第一行，右击鼠标后，选择Set item type，打开修改框修改 。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\9-更改参数类型.png)

`jbyteArray __fastcall sub_4B8C(JNIEnv * env, jclass thiz, jobject context, jbyteArray input)`

函数参数修复完成后，开始分析程序，可以看出最主要的关键函数为sub_4C3C、sub_5134和sub_5038：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\10-关键函数分析.png)

后面主要涉及到的函数，浅蓝色为相比于原始AES的被修改部分：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\11-主要函数思维导图.png)

#### 包签名检查函数sub_4C3C

sub_4C3C中简单修复函数参数、修改变量名称后：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\12-包签名检查函数.png)

检查部分签名：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\13-签名检查.png)

检查包名是否为com.iscclockk

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\14-包名检查.png)

#### 初始key生成函数sub_5134

函数输出可以通过动态调试直接得到，可以识别出append函数和md5函数
![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\15-初始key生成函数.png)

##### append函数

可以看到有basic_string::append的信息

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\16-识别append函数.png)

##### md5函数

可发现md5的初始变量魔数

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\17-md5函数识别.png)

#### 主要的处理函数sub_5038

可以识别sub_5880处为主要加密函数

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\18-主要处理函数.png)

这里也初始化了16位的iv，基本上这里就可以初步判断出来加密方法。iv为0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,  0xAA

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\19-iv.png)

##### 加密函数sub_5880

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\20-sub_5880 1.png)

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\21-sub_5880 2.png)

###### key扩展函数sub_558C

首先关注key扩展函数sub_558C：

AES基础知识：https://www.davidwong.fr/blockbreakers/aes.html

一般来说应该Rotword函数实现的功能为将00 01 02 03转换为01 02 03 00，也就是：

| 0    | 1    | 2    | 3    |
| ---- | ---- | ---- | ---- |
| 1    | 2    | 3    | 0    |

但是该函数的实现却是：

| 0    | 1    | 2    | 3    |
| ---- | ---- | ---- | ---- |
| 0    | 3    | 2    | 1    |

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\22-rotword.png)

接下来的部分，则是在获取S盒内容，S盒内容采用数论的方法生成：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\23-获取S盒内容.png)

S盒sub_5970

在sub_5970函数中，可以根据魔数0x63进一步确定该部分可以生成S盒；在函数的最后用到了传入的参数a1，可以通过动态调试来确定v2就是标准的S盒：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\24-S盒生成函数.png)

###### 轮计算函数sub_56AC

进入sub_56AC函数中，可以看到前面获取S盒内容进行字节替换：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\25-每轮计算获取S盒内容.png)

后半部分则是行移位，这里行移位与标准的AES也有不同：

对于原始数据：

| 0    | 1    | 2    | 3    |
| ---- | ---- | ---- | ---- |
| 4    | 5    | 6    | 7    |
| 8    | 9    | 10   | 11   |
| 12   | 13   | 14   | 15   |

标准AES移位后：

| 0    | 5    | 10   | 15   |
| ---- | ---- | ---- | ---- |
| 4    | 9    | 14   | 3    |
| 8    | 13   | 2    | 7    |
| 12   | 1    | 6    | 11   |

 题目中移位后：

| 0    | 13   | 10   | 7    |
| ---- | ---- | ---- | ---- |
| 4    | 1    | 14   | 11   |
| 8    | 5    | 2    | 15   |
| 12   | 9    | 6    | 3    |

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\26-移位.png)

之后根据Rotword和ShiftRows步骤的修改，相应改变AES解密代码，可得到结果。

## 动态分析

### IDA pro attach进程

步骤可参考博客：https://blog.csdn.net/LJFYYJ/article/details/125976850?spm=1001.2014.3001.5502

在右侧的Modules模块中可以找到加载后的libLibs.so库。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\27-IDA libs库.png)

双击进入后，可以方便的查看到我们想看的函数。但是因为我们最关心的函数不是导出函数，没法在这里直接看到，所以需要计算偏移地址才能找到。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\28-lib库导出函数.png)

### 调试得到所有subkeys

首先在IDA静态分析窗口继续分析：

- 初始key生成函数sub_5134，先生成初始密钥
- 初始密钥由key扩展函数sub_558C，生成每轮的密钥
- 每轮的密钥在轮计算函数sub_56AC中用到

在sub_56AC中可以看出所有的轮密钥存储在byte_1D0AC中：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\29-subkeys存储位置.png)

为了看某行的偏移地址，可以按下图所示使几个窗口同步，这样在Pseudocode-B窗口选择的某行地址会在IDA View-A窗口中自动高亮。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\30-查看偏移地址.png)

此时可以看到用到byte_1D0AC的代码偏移地址0x000056BA：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\31-得到偏移地址.png)

而libLibs.so的基地址可以在动态调试的Modules窗口看到，为92D94000

通过将两个地址相加就可以找到我们函数的内存地址，为:

0x92D94000+0x000056BA=0x92D996BA

在动态调试的IDA主窗口中按G键，在弹出的窗口中输入该地址，点击OK：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\32-IDA地址跳转.png)

找到该地址后，点击该地址左侧的蓝点位置，弹出断点设置窗口，点击OK：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\33-设置断点.png)

该行变成红色说明打下了断点，断点设置完成后，再在模拟器中输入123，并点击Encrypt：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\34-重新运行程序.png)

可以看到程序运行到了我们加断点的位置，92DB10AC就是subkeys所在的地方。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\35-运行到断点所在位置.png)

然后按下G键，输入92DB10AC，就可以看到subkeys的数据：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\36-subkeys数据.png)

可以看到subkeys从0x31开始，一直到0x4A结束，后面是appEnv。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\37-subkeys结束位置.png)

在IDA选中0x31到0x4A的所有数据，点击Edit中的Export data：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\38-IDA导出数据.png)

就可以方便的导出subkeys.txt的所有数据了：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\39-IDA完成数据导出.png)

```
unsigned char ida_chars[] =
{
  0x31, 0x62, 0x35, 0x63, 0x32, 0x31, 0x38, 0x61, 0x36, 0x38, 
  0x35, 0x39, 0x66, 0x63, 0x66, 0x32, 0x03, 0x99, 0x06, 0x98, 
  0x31, 0xA8, 0x3E, 0xF9, 0x07, 0x90, 0x0B, 0xC0, 0x61, 0xF3, 
  0x6D, 0xF2, 0xEE, 0x94, 0x3A, 0x95, 0xDF, 0x3C, 0x04, 0x6C, 
  0xD8, 0xAC, 0x0F, 0xAC, 0xB9, 0x5F, 0x62, 0x5E, 0xBC, 0x5B, 
  0x90, 0x5A, 0x63, 0x67, 0x94, 0x36, 0xBB, 0xCB, 0x9B, 0x9A, 
  0x02, 0x94, 0xF9, 0xC4, 0xC3, 0x79, 0x09, 0x78, 0xA0, 0x1E, 
  0x9D, 0x4E, 0x1B, 0xD5, 0x06, 0xD4, 0x19, 0x41, 0xFF, 0x10, 
  0x07, 0xFA, 0x1F, 0xFB, 0xA7, 0xE4, 0x82, 0xB5, 0xBC, 0x31, 
  0x84, 0x61, 0xA5, 0x70, 0x7B, 0x71, 0x21, 0xAB, 0x3E, 0xAA, 
  0x86, 0x4F, 0xBC, 0x1F, 0x3A, 0x7E, 0x38, 0x7E, 0x9F, 0x0E, 
  0x43, 0x0F, 0xBA, 0x00, 0x24, 0x01, 0x3C, 0x4F, 0x98, 0x1E, 
  0x06, 0x31, 0xA0, 0x60, 0x99, 0x3F, 0xE3, 0x6F, 0xD4, 0x75, 
  0x35, 0x74, 0xE8, 0x3A, 0xAD, 0x6A, 0xEE, 0x0B, 0x0D, 0x0A, 
  0x77, 0x34, 0xEE, 0x65, 0x3A, 0x6D, 0x1D, 0x6C, 0xD2, 0x57, 
  0xB0, 0x06, 0x3C, 0x5C, 0xBD, 0x0C, 0x4B, 0x68, 0x53, 0x69, 
  0xBF, 0x28, 0xF0, 0x29, 0x6D, 0x7F, 0x40, 0x2F, 0x51, 0x23, 
  0xFD, 0x23, 0x1A, 0x4B, 0xAE, 0x4A
};
```

## 解密算法

### Base64 解码

因为加密时采用了Base64.encode(str, 0)的形式，所以也要采用相同的形式对加密结果进行解密。

加密后字符串为：

j9lXGz/eWs4iODrHgTbQZdtXl1RjO82FQhSADajx1vRNnw2NIASP/2mySb2Dqmgh

新建一个Android Studio项目，写下如下代码并运行项目：

```java
String s = "j9lXGz/eWs4iODrHgTbQZdtXl1RjO82FQhSADajx1vRNnw2NIASP/2mySb2Dqmgh";
byte[] b = Base64.decode(s, Base64.DEFAULT);
String output = "";
for(int i=0;i<b.length-1;i++){
	output += Integer.toString(b[i] & 0xff) + ", ";
}
output += Integer.toString(b[b.length -1]);
Log.v("lockk", output);
```

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\40-base64解密.png)

可以在logcat中看到输出的值为：

143, 217, 87, 27, 63, 222, 90, 206, 34, 56, 58, 199, 129, 54, 208, 101, 219, 87, 151, 84, 99, 59, 205, 133, 66, 20, 128, 13, 168, 241, 214, 244, 77, 159, 13, 141, 32, 4, 143, 255, 105, 178, 73, 189, 131, 170, 104, 33

### 变种AES解密

到目前为止，解密程序所需的所有数据我们已经全部得到了。

第一个是iv，在主要的处理函数sub_5038中，值为：

0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,  0xAA

第二个是subkeys，动态调试出来

第三个是上一步Base64解密后的数值

我们知道这个变种的AES修改了Key扩展函数，但因为我们直接获取了subkeys，所以可以不再关注这个地方；另外还修改了行移位，这一部分需要我们修改原始AES。

对于原始数据：

| 0    | 1    | 2    | 3    |
| ---- | ---- | ---- | ---- |
| 4    | 5    | 6    | 7    |
| 8    | 9    | 10   | 11   |
| 12   | 13   | 14   | 15   |

变种行移位：

| 0    | 13   | 10   | 7    |
| ---- | ---- | ---- | ---- |
| 4    | 1    | 14   | 11   |
| 8    | 5    | 2    | 15   |
| 12   | 9    | 6    | 3    |

行移位的代码修改为下图所示即可：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\41-行移位代码修改.png)

修改原版的aes解密算法，可得到最终的flag。

## AES原理

参考链接：https://www.davidwong.fr/blockbreakers/aes.html

AES 是一种分组密码，可以加密和解密不少于 128 位的明文。根据密钥长度可分为AES-128 AES-192和AES-256，密钥长度不同，AES的加密轮数也不同。

AES的工作模式分为ECB、CBC、CFB等：

- ECB是最简单和最早的模式，首先是密钥扩展，将加密的数据按照16字节的大小分成若干组，对每组都用同样的密钥加密。
- CBC相比于ECB添加了一个**初始向量**iv（16字节），在将密钥分成若干组之后，第一组与初始化向量异或之后再进行与ECB相同的加密流程，后面的每一组都与上一组的密文进行异或之后再与密钥加密。

要将明文转换为密文，AES 会对其进行多次转换，其中之一是将其与密钥进行异或。由于我们只为 AES 提供**一个密钥**，因此 AES 需要从中派生出许多密钥。

- 这些派生密钥称为**轮密钥**（或通常为**子密钥**）
- 用于派生这些子密钥的过程称为**密钥扩展**`KeyExpansion`

通过三个不同的函数来帮助构建`KeyExpansion()`函数：

- RotWord()
- SubWord()
- Rcon()

### KeyExpansion()

#### RotWord()

将 4 个字节的值作为输入，并返回这 4 个字节的循环作为输出

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\42-rotword.jpg)

#### SubWord()

SubWord 像前面的函数一样接受 4 个字节的输入，并返回 4 个字节的输出。SubWord 基本上是一个**Sbox**，每个字节都根据查找表进行检查并替换为它们的关联值。

这是查找表，要阅读此表，需要将输入分成行和列两部分：

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\42-sbox.png)

#### Rcon()

接受一个整数作为输入，并返回一个 4 个字节的数组，其中 3 个最低有效字节设置为 0。

AES 在GF(2^8)用多项式定义的有限域中操作它的一些变换X^8 + X^4 + X^3 + X + 1。Rcon 是这些奇怪的转换之一，并且rcon(i) = [X^i, 0, 0, 0]在该领域中被定义。这部分可以直接使用查找表。

下面是查找表的golang代码：

```go
var rcon = [256]byte{
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d}
```

#### 例子

在下图中，假设提供给 AES 的密钥是2b7e151628aed2a6abf7158809cf4f3c（十六进制）。这正好填充了四列，并且将是第一个轮密钥。获取下一轮密钥的第一列，步骤如下：

- 取上一轮密钥的最后一列的值并将其赋予rotWord()
- 然后交给 subWord()
- 然后将其与上一轮密钥的第一列进行异或
- 然后将其rcon(round)与round整数（从1开始）进行异或。每个回合都有自己的回合密钥。AES-128 需要10轮，并且将使用 10 + 1 = 11 个轮密钥。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\43-key expansion1.png)

要获得轮密钥的其他3列，只需将**前一列**与**相同索引的前一个轮密钥的列**进行异或。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\44-key expansion2.jpg)

### 轮加密

输入到 AES 的明文，然后被处理直到它成为密文，在内部表示为**4 行 4 列的正方形**。这种 AES 内部方形表示被称为“**状态**”，并且在整个加密（或解密）过程中应用于它的不同转换被重新组合成**轮次，**每个**轮次**涉及不同的**轮密钥**。该**轮密钥**从主密钥生成。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\44-key expansion2.jpg)

每轮主要工作：

1. 字节替换
2. 行移位
3. 列混淆
4. 轮密钥加

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\45-AES round.png)

AES-128 是采用 128 位密钥的 AES 变体，总共有 10 轮。**每一轮都将不同的轮密钥和前一轮的输出作为输入**。请注意，最后一轮与其他轮有点不同，**最后一轮跳过了 MixColumns 转换**。

#### 字节替换

输入一个字节，并根据查找表返回相应的字节。

所使用的表与SubWord中的表一致。

#### 行移位

输入一个4*4的状态进行旋转：

第一行没有被触及，第二行在左边旋转一个位置，第三个位置旋转两个位置，第四个位置旋转三个位置。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\46-行移位.png)

#### 列混淆

通过矩阵相乘实现，将状态阵列的每个列视为系数在(GF(2^8))上、次数小于4的多项式，再与同一个固定的多项式c(x)进行模(x^4+1)乘法运算。注意这里的矩阵乘法和一般的矩阵乘法不同，乘的结果在相加时用的是**异或**运算，最后用结果取代原字节序列。

列混淆中，输入的每个字节都会影响到输出的四个字节。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\47-列混淆.png)

逆向列混淆的方法与列混淆相同，只需要将固定矩阵替换成它的逆矩阵。

#### 轮密钥加

异或状态中的值与轮密钥的值。



最后来看看AES加解密的原理框图：

注意加密时第一轮只有轮密钥加，最后一轮没有列混淆。

![](D:\个人\A大四下\工作\【3】博客项目资源\android学习\lockkimg\48-AES加解密原理框图.png)