#!/usr/bin/env python3
"""
解析处理器核pc trace中的所有函数跳转

输入：
    1. 反汇编文件：0325.txt
    2. pc trace文件：pc.txt

输出：
    1. core0 trace中的所有函数跳转入口文件：core0_func_trace.txt
    2. core1 trace中的所有函数跳转入口文件：core1_func_trace.txt
"""

import re
import os

def parse_pc_trace(pc_file):
    """解析PC trace文件，返回core0和core1的PC列表"""
    core0_pcs = []
    core1_pcs = []
    
    with open(pc_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            match = re.match(r'(core\d+)_retire\d*_pc:([0-9a-fA-F]+)', line)
            if match:
                core_id = match.group(1)
                pc_value = match.group(2).lower()
                
                if core_id == 'core0':
                    core0_pcs.append(pc_value)
                elif core_id == 'core1':
                    core1_pcs.append(pc_value)
    
    return core0_pcs, core1_pcs

def parse_disassembly(disasm_file):
    """解析反汇编文件，构建PC到函数名的映射"""
    pc_to_func = {}
    func_entries = []
    current_function = None
    
    addr_pattern = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:')
    instr_pattern = re.compile(r'^([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+([a-z]+)\s+')
    
    with open(disasm_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            func_match = addr_pattern.match(line)
            if func_match:
                addr = func_match.group(1).lower()
                func_name = func_match.group(2)
                current_function = func_name
                pc_to_func[addr] = func_name
                func_entries.append((int(addr, 16), func_name))
                continue
            
            instr_match = instr_pattern.match(line)
            if instr_match and current_function:
                addr = instr_match.group(1).lower()
                pc_to_func[addr] = current_function
    
    func_entries.sort(key=lambda x: x[0])
    return pc_to_func, func_entries

def detect_jumps(pcs):
    """
    检测PC序列中的跳转
    返回: 跳转的PC列表 (即下一条指令不是PC+4的位置)
    """
    jumps = []
    
    for i in range(len(pcs) - 1):
        current_pc = int(pcs[i], 16)
        next_pc = int(pcs[i + 1], 16)
        
        # 如果下一条PC不是当前PC+4，则认为是跳转
        if next_pc != current_pc + 4:
            jumps.append(pcs[i + 1])  # 记录跳转目标的PC
    
    return jumps

def get_func_with_offset(pc, pc_to_func, func_entries):
    """获取PC对应的函数名+offset"""
    pc_int = int(pc, 16)
    
    if pc in pc_to_func:
        func_name = pc_to_func[pc]
        offset = 0
        return f"{func_name}+0x{offset:x}"
    
    # Try to find the function by looking at different address formats
    pc_hex = format(pc_int, 'x')
    
    # Try truncated addresses (last 8 or 12 hex chars)
    for truncate_len in [12, 8]:
        if len(pc_hex) > truncate_len:
            truncated = pc_hex[-truncate_len:]
            for entry_addr, func_name in func_entries:
                entry_hex = format(entry_addr, 'x')
                if entry_hex.endswith(truncated):
                    offset = pc_int - entry_addr
                    return f"{func_name}+0x{offset:x}"
    
    # Binary search for nearest function entry
    lo, hi = 0, len(func_entries) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        entry_addr = func_entries[mid][0]
        if entry_addr <= pc_int:
            if mid == len(func_entries) - 1 or func_entries[mid + 1][0] > pc_int:
                func_name = func_entries[mid][1]
                offset = pc_int - entry_addr
                return f"{func_name}+0x{offset:x}"
            lo = mid + 1
        else:
            hi = mid - 1
    
    return f"unknown+0x{pc}"

def write_output(jumps, pc_to_func, func_entries, output_file):
    """写入输出文件"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for pc in jumps:
            func_info = get_func_with_offset(pc, pc_to_func, func_entries)
            f.write(f"{pc}:{func_info}\n")

def main():
    # 文件路径
    base_dir = r"C:\Users\zhaoyang\Documents\20260327_debug"
    pc_file = os.path.join(base_dir, "pc.txt")
    disasm_file = os.path.join(base_dir, "0325.txt")
    core0_output = os.path.join(base_dir, "core0_func_trace.txt")
    core1_output = os.path.join(base_dir, "core1_func_trace.txt")
    
    print("正在解析PC trace文件...")
    core0_pcs, core1_pcs = parse_pc_trace(pc_file)
    print(f"  Core0: {len(core0_pcs)} 条PC记录")
    print(f"  Core1: {len(core1_pcs)} 条PC记录")
    
    print("正在解析反汇编文件...")
    pc_to_func, func_entries = parse_disassembly(disasm_file)
    print(f"  解析了 {len(pc_to_func)} 个地址映射")
    
    # 检测跳转
    print("正在检测跳转...")
    core0_jumps = detect_jumps(core0_pcs)
    core1_jumps = detect_jumps(core1_pcs)
    print(f"  Core0跳转次数: {len(core0_jumps)}")
    print(f"  Core1跳转次数: {len(core1_jumps)}")
    
    # 写入输出文件
    print("正在写入输出文件...")
    write_output(core0_jumps, pc_to_func, func_entries, core0_output)
    write_output(core1_jumps, pc_to_func, func_entries, core1_output)
    
    print(f"完成!")
    print(f"  Core0输出: {core0_output}")
    print(f"  Core1输出: {core1_output}")

if __name__ == "__main__":
    main()
