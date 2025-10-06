#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd

def analyze_rtp(csv_file):
    # 读取CSV
    df = pd.read_csv(csv_file)

    # 去掉NaN
    df = df[['frame', 'ip_src', 'udp_src', 'ip_dst', 'udp_dst', 'rtp_seq']].dropna()

    # 转换类型
    df['frame'] = df['frame'].astype(int)
    df['udp_src'] = df['udp_src'].astype(int)
    df['udp_dst'] = df['udp_dst'].astype(int)
    df['rtp_seq'] = df['rtp_seq'].astype(int)

    total = len(df)

    # 用 (ip_src, udp_src, ip_dst, udp_dst) 区分连接
    conn_key = ['ip_src', 'udp_src', 'ip_dst', 'udp_dst']

    repeat_count = 0
    rollback_count = 0

    for conn, group in df.groupby(conn_key):
        seqs = group['rtp_seq'].values

        # 1. 重复数 = 总数 - 唯一数
        repeat_count += len(seqs) - len(set(seqs))

        # 2. 回退统计时去掉重复 (只保留每个 seq 的第一次出现)
        group_no_dup = group.drop_duplicates(subset=['rtp_seq'], keep='first')
        seqs_no_dup = group_no_dup['rtp_seq'].values

        rollback_count += (seqs_no_dup[1:] < seqs_no_dup[:-1]).sum()

    repeat_ratio = repeat_count / total if total > 0 else 0
    rollback_ratio = rollback_count / total if total > 0 else 0

    # 输出
    print("==== RTP Seq Duplicate & Rollback Analysis ====")
    print(f"总包数          : {total}")
    print(f"重复包数        : {repeat_count}")
    print(f"后丢包          : {repeat_ratio:.4%}")
    print(f"回退包数(去重)  : {rollback_count}")
    print(f"前丢包          : {rollback_ratio:.4%}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="分析 RTP 包的 seq 重复与回退情况")
    parser.add_argument("pcap", help="输入 RTP pcap 文件")
    args = parser.parse_args()
    analyze_rtp(args.pcap)
