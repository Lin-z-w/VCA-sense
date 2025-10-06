import pandas as pd
import sys

def analyze_packet_loss_simple(file_path):
    """
    简化的丢包率分析版本
    """
    # 读取数据
    df = pd.read_csv(file_path, sep='\t')
    
    # 按rtp_seq排序
    df = df.sort_values('rtp_seq').reset_index(drop=True)
    
    forward_loss = 0
    backward_loss = 0
    
    # 用于记录每个seq出现的最小和最大ip_id
    seq_records = {}
    
    for i, row in df.iterrows():
        rtp_seq = row['rtp_seq']
        ip_id = row['ip_id']
        
        if rtp_seq in seq_records:
            # 后向丢包检查：同一个seq的ip_id差异过大
            prev_ip_id = seq_records[rtp_seq]
            if abs(ip_id - prev_ip_id) > 3:
                backward_loss += 1
                print(f"后向丢包: seq={rtp_seq}, ip_id变化 {prev_ip_id} -> {ip_id}")
            # 更新为最新的ip_id
            seq_records[rtp_seq] = ip_id
        else:
            # 前向丢包检查：查找附近的seq进行对比
            seq_records[rtp_seq] = ip_id
            
            # 找到所有大于当前seq的记录
            larger_seqs = [s for s in seq_records.keys() if s > rtp_seq]
            if larger_seqs:
                # 取最小的那个大于当前seq的值
                ref_seq = min(larger_seqs)
                if abs(ip_id - seq_records[ref_seq]) > 3:
                    forward_loss += 1
                    print(f"前向丢包: seq={rtp_seq}, ip_id={ip_id}, 参考seq={ref_seq}, 参考ip_id={seq_records[ref_seq]}")
    
    total_packets = len(df)
    
    print("\n=== 简化的丢包率统计 ===")
    print(f"总分组数: {total_packets}")
    print(f"前向丢包次数: {forward_loss}")
    print(f"后向丢包次数: {backward_loss}")
    print(f"前向丢包率: {forward_loss/total_packets*100:.2f}%")
    print(f"后向丢包率: {backward_loss/total_packets*100:.2f}%")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python packet_analyzer_simple.py <csv文件路径>")
        sys.exit(1)
    
    analyze_packet_loss_simple(sys.argv[1])