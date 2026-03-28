#!/usr/bin/env python3
"""
分析core指令跳转序列
- 解析反汇编文件，构建PC->函数名映射
- 筛选kernel指令(e开头PC)
- 根据指令长度检测跳转
- 输出跳转序列
"""

import re
import os
from collections import defaultdict

# 配置
DISASM_FILE = "/home/deng/Data/work/问题调试/325/tmp/0325.txt"
CORE0_LOG = "/home/deng/Data/work/问题调试/325/tmp/abc_uart1_core0.log"
CORE1_LOG = "/home/deng/Data/work/问题调试/325/tmp/abc_uart1_core1.log"
OUTPUT_DIR = "/home/deng/Data/work/问题调试/325/tmp"


def parse_disassembly():
    print("正在解析反汇编文件...")

    pc_to_func = {}
    pc_is_branch = {}  # 记录PC是否是跳转指令

    func_pattern = re.compile(r"^(ffffffe[0-9a-f]{9})\s+<(.+)>:")

    # 跳转指令模式
    branch_patterns = [
        r"\bj\s",
        r"\bjal\s",
        r"\bjr\s",
        r"\bjalr\s",
        r"\bbeq\b",
        r"\bbne\b",
        r"\bblt\b",
        r"\bbge\b",
        r"\bbltu\b",
        r"\bbgeu\b",
        r"\bc\.j\b",
        r"\bc\.jal\b",
        r"\bc\.jr\b",
        r"\bc\.jalr\b",
        r"\bc\.beqz\b",
        r"\bc\.bnez\b",
    ]
    branch_regex = re.compile("|".join(branch_patterns))

    current_func = "unknown"

    with open(DISASM_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            func_match = func_pattern.match(line)
            if func_match:
                current_func = func_match.group(2)
                continue

            if line.startswith("ffffffe"):
                parts = line.split(":")
                if len(parts) >= 2:
                    addr = parts[0].strip()
                    if "<" in addr:
                        continue
                    if len(addr) == 16:
                        rest = parts[1].strip()
                        instr = rest[:4] if len(rest) >= 4 else ""
                        if instr and all(c in "0123456789abcdefABCDEF" for c in instr):
                            low10 = addr[-10:]
                            pc_to_func[low10] = (current_func, instr)
                            # 判断是否是跳转指令
                            is_branch = branch_regex.search(rest) is not None
                            pc_is_branch[low10] = is_branch

    print(
        f"  已解析 {len(pc_to_func)} 条指令映射, 其中跳转指令 {sum(pc_is_branch.values())} 条"
    )
    return pc_to_func, pc_is_branch


def get_instruction_length(instr_hex):
    """根据指令码判断指令长度"""
    # 取最低2位
    try:
        low_bits = int(instr_hex[-1], 16) & 0x3
    except:
        return 4  # 默认32位

    # bit[1:0] = 11 表示16位压缩指令，否则为32位
    if low_bits == 0x3:
        return 2  # 16位压缩指令
    else:
        return 4  # 32位指令


def parse_log_file(log_file, pc_to_func, pc_is_branch):
    print(f"正在解析日志文件: {log_file}")

    jumps = []

    pc_pattern = re.compile(r"core[01]_retire\d+_pc:([0-9a-fA-F]{10})")

    prev_pc = None
    prev_instr_len = 4
    prev_pc_key = None  # 记录前一个PC的key
    line_count = 0
    kernel_count = 0

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line_count += 1
            if line_count % 10000000 == 0:
                print(f"  已处理 {line_count} 行...")

            match = pc_pattern.search(line)
            if not match:
                continue

            pc_full = match.group(1)

            if not pc_full.startswith("e"):
                continue

            kernel_count += 1
            pc_low10 = pc_full

            if pc_low10 in pc_to_func:
                func_name, instr_hex = pc_to_func[pc_low10]
            else:
                func_name = "unknown"
                instr_hex = "0000"

            if prev_pc is not None:
                expected_pc = prev_pc + prev_instr_len
                actual_pc = int(pc_full, 16)

                if actual_pc != expected_pc:
                    # 只有当前PC对应的指令是跳转指令时才记录
                    is_branch = pc_is_branch.get(prev_pc_key, False)
                    if is_branch:
                        jumps.append((pc_full, func_name))

            prev_pc = int(pc_full, 16)
            prev_instr_len = get_instruction_length(instr_hex)
            prev_pc_key = pc_low10

    print(f"  总行数: {line_count}, Kernel指令: {kernel_count}, 跳转数: {len(jumps)}")
    return jumps


def write_output(jumps, output_file):
    """写入输出文件"""
    print(f"正在写入输出: {output_file}")
    with open(output_file, "w", encoding="utf-8") as f:
        for pc, func_name in jumps:
            f.write(f"{pc}:{func_name}\n")
    print(f"  已写入 {len(jumps)} 条跳转记录")


def main():
    print("=" * 50)
    print("Core指令跳转分析工具")
    print("=" * 50)

    # 步骤1: 解析反汇编
    pc_to_func, pc_is_branch = parse_disassembly()

    # 步骤2: 处理core0
    print("\n处理 Core0:")
    jumps_core0 = parse_log_file(CORE0_LOG, pc_to_func, pc_is_branch)
    write_output(jumps_core0, os.path.join(OUTPUT_DIR, "core0.log"))

    # 步骤3: 处理core1
    print("\n处理 Core1:")
    jumps_core1 = parse_log_file(CORE1_LOG, pc_to_func, pc_is_branch)
    write_output(jumps_core1, os.path.join(OUTPUT_DIR, "core1.log"))

    print("\n" + "=" * 50)
    print("分析完成!")
    print(f"  core0: {len(jumps_core0)} 条跳转")
    print(f"  core1: {len(jumps_core1)} 条跳转")
    print("=" * 50)


if __name__ == "__main__":
    main()
