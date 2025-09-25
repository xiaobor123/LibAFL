# Python反汇编工具使用说明

这个Python脚本用于反汇编`output.txt`文件中的二进制数据，并将结果输出到`disasm.txt`文件中。它使用`capstone`库来执行ARM架构的反汇编操作。

## 功能特点

- 自动识别`output.txt`文件中的地址标记（`IN: 0x...`）和对应的二进制数据（`OBJD-T: ...`）
- 将十六进制格式的二进制数据转换为字节数组
- 使用capstone库进行ARM指令集的反汇编
- 将反汇编结果格式化输出到`disasm.txt`文件

## 安装依赖

在运行脚本之前，需要安装`capstone`库：

```bash
pip install capstone
```

## 使用方法

1. 确保`output.txt`文件位于脚本的同一目录下
2. 运行脚本：

```bash
python disassemble.py
```

或者直接执行（已添加执行权限）：

```bash
./disassemble.py
```

3. 脚本执行完成后，反汇编结果将保存在`disasm.txt`文件中

## 输出格式

输出文件`disasm.txt`的格式如下：

```
--------------------
Address: 0x40205000
Hex Data: e1a00000e1a01001e1a02002e1a03003
Disassembly:
0x40205000:    mov     r0, r0
0x40205004:    mov     r1, r1
0x40205008:    mov     r2, r2
0x4020500c:    mov     r3, r3
```

## 代码结构说明

- `hex_to_bytes(hex_str)`: 将十六进制字符串转换为字节数组
- `bytes_to_hex(bytes_data)`: 将字节数组转换为十六进制字符串（用于显示）
- `disassemble_file(input_file, output_file)`: 主函数，负责读取输入文件、解析内容、执行反汇编并写入输出文件

## 自定义选项

如果需要修改输入或输出文件的路径，可以编辑脚本末尾的以下变量：

```python
INPUT_FILE = "output.txt"
OUTPUT_FILE = "disasm.txt"
```

## 注意事项

- 脚本假设输入文件`output.txt`的格式遵循特定模式，包含`IN:`和`OBJD-T:`标记
- 如果脚本无法正常运行，可能需要检查capstone库的安装情况或Python环境配置