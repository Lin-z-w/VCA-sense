#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd

def analyze_duplicates_and_rollbacks(csv_file):
    # 读取CSV
    df = pd.read_csv(csv_file)

    # 只保留关心的字段，并去掉NaN
    df = df[['packet_number', 'stream_id', 'offset', 'len']].dropna()

    # 转换类型
    df['stream_id'] = df['stream_id'].astype(int)
    df['offset'] = df['offset'].astype(int)
    df['packet_number'] = df['packet_number'].astype(int)

    total = len(df)

    # =====================
    # 1. 统计重复点 (stream_id + offset)
    # =====================
    dup_groups = df.groupby(['stream_id', 'offset']).size()
    dup_points = (dup_groups > 1).sum()
    dup_ratio = dup_points / total if total > 0 else 0

    # =====================
    # 2. 统计 offset 回退（排除重复包）
    # =====================
    rollback_count = 0
    df_no_dup = df.drop_duplicates(subset=['stream_id', 'offset'], keep='first')

    for stream_id, group in df_no_dup.groupby('stream_id'):
        offsets = group.sort_values('packet_number')['offset'].values
        rollback_count += (offsets[1:] < offsets[:-1]).sum()

    rollback_ratio = rollback_count / total if total > 0 else 0

    # =====================
    # 输出
    # =====================
    print("==== QUIC Stream Duplicate & Offset Rollback Analysis ====")
    print(f"有效包数        : {total}")
    print(f"重复点数        : {dup_points}")
    print(f"后丢包          : {dup_ratio:.4%}")
    print(f"offset回退包数  : {rollback_count}")
    print(f"前丢包          : {rollback_ratio:.4%}")

    if dup_points > 0:
        print("\n重复的 (stream_id, offset):")
        print(dup_groups[dup_groups > 1])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="分析 RTP 包的 seq 重复与回退情况")
    parser.add_argument("pcap", help="输入 RTP pcap 文件")
    args = parser.parse_args()
    analyze_duplicates_and_rollbacks(args.pcap)
