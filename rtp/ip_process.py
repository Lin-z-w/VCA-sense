#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rtp_process_fixed.py
从 pcap 中提取 RTP 包（使用 tshark 强制按端口 decode），按连接 (ip.src:udp.src -> ip.dst:udp.dst) 分组，
每个连接输出一个 CSV。避免重复计入同一帧（使用 frame.number 去重）。

用法:
  python rtp_process_fixed.py capture.pcap
或指定 tshark 路径:
  python rtp_process_fixed.py capture.pcap --tshark "D:\Software\wireshark\tshark.exe"

参数:
  --max-ports   最多尝试多少个最活跃的 UDP 端口 (默认 50)
"""
from __future__ import annotations
import subprocess
import sys
import os
import csv
import argparse
from collections import Counter, defaultdict

DEFAULT_TSHARK = r"D:\Software\wireshark\tshark.exe"

def run_cmd(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr

def collect_udp_ports(pcap_file, tshark_path, verbose=False):
    cmd = [
        tshark_path, "-r", pcap_file,
        "-T", "fields", "-e", "udp.srcport", "-e", "udp.dstport",
        "-Y", "udp", "-E", "separator=,"
    ]
    code, out, err = run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"tshark 提取 UDP 端口失败:\n{err}")
    ports = []
    for line in out.splitlines():
        if not line.strip():
            continue
        cols = [c.strip() for c in line.split(",")]
        for c in cols:
            if c and c.isdigit():
                ports.append(int(c))
    cnt = Counter(ports)
    if verbose:
        print("[INFO] UDP ports frequency (top 20):")
        for p,c in cnt.most_common(20):
            print(f"  {p}: {c}")
    sorted_ports = [p for p,_ in cnt.most_common()]
    return sorted_ports

def extract_rtp_on_port(pcap_file, tshark_path, port, seen_frames, verbose=False):
    """
    对指定端口强制 decode 为 RTP 并提取字段，返回 record 列表；
    使用 seen_frames 集合跳过已处理的 frame.number，避免重复计入。
    """
    cmd = [
        tshark_path, "-r", pcap_file,
        "-d", f"udp.port=={port},rtp",
        "-Y", "rtp",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "udp.srcport",
        "-e", "ip.dst",
        "-e", "udp.dstport",
        "-e", "ip.id",  # 新增：提取 IP ID 字段
        "-e", "rtp.seq",
        "-E", "separator=|"
    ]
    code, out, err = run_cmd(cmd)
    if code != 0:
        # 如果 tshark 对该端口 decode 出错（部分版本/端口情况），返回空并打印警告
        if verbose:
            print(f"[WARN] port {port} decode failed or no rtp: {err.strip()}")
        return []
    records = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        # 预期 8 个字段: frame | time | ip.src | udp.src | ip.dst | udp.dst | ip.id | rtp.seq
        if len(parts) < 8:
            continue
        try:
            frame_no = int(parts[0])
        except:
            continue
        # 去重：若 frame 已在 seen_frames 中，则跳过（避免同一帧被不同端口重复解析计数）
        if frame_no in seen_frames:
            continue
        # 标记为已处理
        seen_frames.add(frame_no)
        rec = {
            "frame": frame_no,
            "time": parts[1],
            "ip_src": parts[2],
            "udp_src": parts[3],
            "ip_dst": parts[4],
            "udp_dst": parts[5],
            "ip_id": parts[6],  # 新增：IP ID 字段
            "rtp_seq": parts[7],
            "port_forced": port
        }
        records.append(rec)
    if verbose and records:
        print(f"[INFO] port {port} yielded {len(records)} records (after dedup).")
    return records

def save_grouped_csv(records, outdir):
    grouped = defaultdict(list)
    for r in records:
        key = f"{r['ip_src']}:{r['udp_src']}->{r['ip_dst']}:{r['udp_dst']}"
        grouped[key].append(r)
    os.makedirs(outdir, exist_ok=True)
    for key, recs in grouped.items():
        # 合理化文件名
        filename = key.replace(":", "_").replace("->", "_to_").replace(".", "_")
        outfile = os.path.join(outdir, f"{filename}.csv")
        # 按 frame 排序
        recs.sort(key=lambda x: x["frame"])
        with open(outfile, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["frame", "time", "ip_src", "udp_src", "ip_dst", "udp_dst", "ip_id", "rtp_seq", "port_forced"])
            for r in recs:
                w.writerow([r["frame"], r["time"], r["ip_src"], r["udp_src"], r["ip_dst"], r["udp_dst"], r["ip_id"], r["rtp_seq"], r["port_forced"]])
        print(f"[OK] 保存 {len(recs)} 条到 {outfile}")

def main():
    parser = argparse.ArgumentParser(description="从 pcap 中提取 RTP seq 并按 (ip:port->ip:port) 保存为 CSV (避免重复计数)")
    parser.add_argument("pcap", help="输入 pcap 文件")
    parser.add_argument("--tshark", default=DEFAULT_TSHARK, help=f"tshark 路径 (默认: {DEFAULT_TSHARK})")
    parser.add_argument("--outdir", default="result", help="输出目录")
    parser.add_argument("--max-ports", type=int, default=50, help="尝试的最大 UDP 端口数量 (默认 50)")
    parser.add_argument("--verbose", action="store_true", help="打印调试信息")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[ERROR] pcap 文件不存在: {args.pcap}")
        sys.exit(2)
    if not os.path.exists(args.tshark):
        print(f"[ERROR] tshark 未找到: {args.tshark}")
        sys.exit(2)

    if args.verbose:
        print(f"[INFO] 使用 tshark: {args.tshark}")
        print(f"[INFO] 解析 pcap: {args.pcap}")

    ports = collect_udp_ports(args.pcap, args.tshark, verbose=args.verbose)
    if not ports:
        print("[WARN] pcap 中未发现 UDP 流")
        sys.exit(0)

    # 限制尝试端口列表长度
    try_ports = ports[:args.max_ports]
    if args.verbose:
        print(f"[INFO] 将尝试以下端口 (最多 {args.max_ports}): {try_ports}")

    all_records = []
    seen_frames = set()
    for port in try_ports:
        recs = extract_rtp_on_port(args.pcap, args.tshark, port, seen_frames, verbose=args.verbose)
        if recs:
            all_records.extend(recs)

    if not all_records:
        print("[RESULT] 未解析到任何 RTP 包（尝试了端口，但均无结果）。")
        sys.exit(0)

    save_grouped_csv(all_records, args.outdir)
    print("[DONE] 完成。")

if __name__ == "__main__":
    main()