#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from capstone import *


def hex_to_bytes(hex_str):
    """将十六进制字符串转换为字节数组"""
    # 移除所有空格
    hex_str = hex_str.replace(' ', '')
    
    # 如果十六进制字符串长度是奇数，在前面补0
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
        
    # 每两个字符一组转换为一个字节
    return bytes.fromhex(hex_str)


def augment_with_disassembly(input_file, output_file):
    """保留input_file中的所有内容，并在每句OBJD-T:后一行加上反汇编内容"""
    # 创建ARM反汇编器
    try:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        # 启用详细输出
        md.detail = True
    except Exception as e:
        print(f"Failed to create capstone disassembler: {e}")
        return
    
    # 打开输出文件
    with open(output_file, 'w') as out_f:
        # 读取输入文件
        with open(input_file, 'r') as in_f:
            lines = in_f.readlines()
            i = 0
            while i < len(lines):
                line = lines[i]
                out_f.write(line)  # 写入原始行
                
                # 检查是否为OBJD-T行
                if 'OBJD-T:' in line.strip():
                    # 尝试获取对应的地址
                    address = None
                    # 向前查找IN行和地址行
                    j = i - 1
                    while j >= 0:
                        if 'IN:' in lines[j].strip():
                            # 地址应该在下一行
                            if j + 1 < len(lines):
                                addr_line = lines[j + 1].strip()
                                addr_match = re.search(r'(0x[0-9a-fA-F]+):?', addr_line)
                                if addr_match:
                                    try:
                                        address = int(addr_match.group(1), 16)
                                        break
                                    except ValueError:
                                        pass
                            break
                        j -= 1
                    
                    # 提取十六进制数据
                    data_match = re.search(r'OBJD-T:\s*([0-9a-fA-F\s]+)', line)
                    if data_match and address is not None:
                        hex_data = data_match.group(1).strip()
                        try:
                            # 将十六进制数据转换为字节数组
                            bytes_data = hex_to_bytes(hex_data)
                            
                            # 执行反汇编
                            for insn in md.disasm(bytes_data, address):
                                # 在OBJD-T行后添加反汇编内容，保持缩进
                                out_f.write(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
                        except Exception as e:
                            out_f.write(f"\tFailed to disassemble: {e}\n")
                
                i += 1
    
    print(f"Augmentation completed. Results saved to {output_file}")


if __name__ == "__main__":
    # 定义输入和输出文件路径
    INPUT_FILE = "output.txt"
    OUTPUT_FILE = "augmented_output.txt"  # 新的输出文件，避免覆盖原始文件
    
    # 执行增强操作
    augment_with_disassembly(INPUT_FILE, OUTPUT_FILE)