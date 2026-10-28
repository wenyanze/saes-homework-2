# S-AES 作业 2

本项目按教材附录 D 完成 S-AES 编程、测试和扩展任务，使用 Python + Tkinter 编写。核心算法不依赖 GUI，可以通过命令行和单元测试复现实验结果。

## 运行

要求 Python 3.10 或更高版本，并安装 Tkinter/Tcl/Tk，无第三方 Python 依赖。测试环境为 Windows、Python 3.13.7。

启动 GUI：

```text
python app.py
```

Windows 也可以双击 `run.bat`。命令行示例：

```text
python saes_cli.py block encrypt D728 4AF5
python saes_cli.py block decrypt 24EC 4AF5
python saes_cli.py text encrypt "S-AES demo" 4AF5
python saes_cli.py multi encrypt double 1234 1A2B 3C4D
python saes_cli.py mitm --pair 1234:F04D --pair BEEF:62E6 --pair CAFE:8ACE
python saes_cli.py cbc encrypt "CBC demo!" 4AF5 1234
```

## GUI 功能

1. **基础分组**：输入16位明文或密文和16位密钥，执行加解密并查看轮变换状态。
2. **ASCII 扩展**：字符串按2字节分组，采用PKCS#7填充，显示密文HEX和恢复文本。
3. **多重加密**：支持双重E-E、三重EEE/EDE以及两密钥EDE2。
4. **中间相遇攻击**：输入一个或多个明密文对，枚举K1/K2并筛选候选，支持取消和分页。
5. **CBC 模式**：输入或生成16位IV，修改指定密文分组，对比篡改前后的解密结果。

## 算法参数

分组和单次加密密钥均为16位，状态按列排列为 `[[n0,n2],[n1,n3]]`。

```text
S-box = (9,4,A,B,D,1,8,5,6,2,0,3,C,E,F,7)
GF(2^4) 模多项式 = x^4 + x + 1
列混淆矩阵 = [[1,4],[4,1]]
逆列混淆矩阵 = [[9,2],[2,9]]
RCON1 = 80，RCON2 = 30
```

加密流程：

```text
ARK(K0) → NS → SR → MC → ARK(K1) → NS → SR → ARK(K2)
```

最后一轮省略列混淆，解密按相反顺序执行逆变换。详细约定和教材算例见[算法说明](算法说明.md)。

## 源码结构

| 文件 | 作用 |
| --- | --- |
| `saes.py` | S-AES核心算法、字节处理、多重加密、MITM和CBC |
| `app.py` | Tkinter GUI，包含五个功能页面 |
| `saes_cli.py` | 命令行接口 |
| `demo.py` | 基础、ASCII、多重加密、MITM和CBC演示 |
| `cross_test.py` | 与另一组C++程序交叉测试 |
| `tests/test_saes.py` | 算法、输入边界、多重加密和攻击测试 |
| `tests/test_gui.py` | CBC界面状态回归测试 |
| `tests/screenshots/` | 运行截图 |
| `tests/validation/` | 本地测试和演示日志 |
| `tests/cross-test/` | 交叉测试报告、CSV和版本信息 |
| `用户指南.md` | 运行环境、输入格式和页面操作 |
| `开发文档.md` | 接口参数、返回值、异常和调用示例 |
| `测试结果.md` | 五关测试结果和运行截图 |
| `算法说明.md` | 算法流程和教材约定 |

公共函数采用snake_case命名。核心分组接口使用整数，界面与CLI使用固定宽度十六进制字符串。

## 验证

执行全部测试：

```text
python -m unittest discover -s tests -v
```

运行演示和命令行自检：

```text
python demo.py
python saes_cli.py self-test
```

复现交叉测试时指定另一组项目目录，目录内需有 `saes.exe`：

```text
python cross_test.py --peer-dir "D:/cNew/s-aes-main/s-aes-main"
```

本地21项自动化测试通过；交叉测试包含1006组基础分组、100组双重和100组三重EEE，全部通过。双方ASCII/CBC填充不同，不能直接交换这些接口的密文，详见[交叉测试报告](tests/cross-test/report.md)。

S-AES仅用于教学，其16位密钥与分组不适用于实际保密。
