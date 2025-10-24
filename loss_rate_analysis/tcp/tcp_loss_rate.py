from scapy.all import *
from collections import defaultdict
import sys
import bisect

class FlowAnalyzer:
    def __init__(self, id_threshold=3):
        self.id_threshold = id_threshold
        
    def extract_flow_key(self, packet):
        """提取五元组作为流标识"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-UDP"
            else:
                return f"{src_ip}-{dst_ip}-{proto}"
        return None
    
    def get_packet_id(self, packet):
        """获取网络层头部序号（IP ID）"""
        if IP in packet:
            return packet[IP].id
        return 0
    
    def analyze_flow(self, packets):
        """分析单条流的丢包率（基于原始算法）"""
        max_seq = 0
        pkt_count = 0
        num_out_of_order = 0
        num_loss_before = 0
        num_loss_after = 0
        
        # 使用有序字典存储序列号和对应的包信息
        packets_map = {}  # seq -> (packet, packet_id)
        seq_list = []     # 保持有序的序列号列表，用于二分查找
        
        for packet in packets:
            if not hasattr(packet, 'seq'):
                continue
                
            pkt_count += 1
            current_seq = packet.seq
            current_id = self.get_packet_id(packet)
            
            if current_seq > max_seq:
                max_seq = current_seq
                packets_map[current_seq] = (packet, current_id)
                # 维护有序列表
                bisect.insort(seq_list, current_seq)
                continue
            else:
                if current_seq not in packets_map:
                    # 乱序包：第一次收到这个序列号
                    num_out_of_order += 1
                    
                    # 二分查找小于当前seq的最大序列号（下界）
                    pos = bisect.bisect_left(seq_list, current_seq)
                    if pos > 0:  # 存在小于当前seq的包
                        lower_seq = seq_list[pos - 1]
                        lower_packet, lower_id = packets_map[lower_seq]
                        
                        # 检查网络层头部序号差值
                        id_diff = current_id - lower_id
                        if id_diff >= self.id_threshold:
                            num_loss_before += 1
                            
                else:
                    # 重复包：之前已经收到过这个序列号
                    prev_packet, prev_id = packets_map[current_seq]
                    id_diff = current_id - prev_id
                    
                    # 检查网络层头部序号差值
                    if id_diff >= self.id_threshold:
                        num_loss_after += 1
                
                # 更新包信息
                packets_map[current_seq] = (packet, current_id)
                if current_seq not in seq_list:
                    bisect.insort(seq_list, current_seq)
        
        # 计算丢包率
        if pkt_count > 0:
            loss_rate_before = num_loss_before / (pkt_count + num_loss_before)
            loss_rate_after = num_loss_after / pkt_count
        else:
            loss_rate_before = loss_rate_after = 0.0
            
        return {
            'total_packets': pkt_count,
            'out_of_order_packets': num_out_of_order,
            'loss_before_count': num_loss_before,
            'loss_after_count': num_loss_after,
            'loss_rate_before': loss_rate_before,
            'loss_rate_after': loss_rate_after,
            'max_sequence': max_seq
        }
    
    def analyze_pcap(self, pcap_file):
        """分析整个pcap文件"""
        print(f"Analyzing pcap file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading pcap file: {e}")
            return {}
        
        # 按流分组数据包
        flows = defaultdict(list)
        for packet in packets:
            flow_key = self.extract_flow_key(packet)
            if flow_key:
                flows[flow_key].append(packet)
        
        # 分析每条流
        results = {}
        for flow_key, flow_packets in flows.items():
            print(f"Analyzing flow: {flow_key} ({len(flow_packets)} packets)")
            results[flow_key] = self.analyze_flow(flow_packets)
        
        return results
    
    def print_results(self, results):
        """打印分析结果"""
        print("\n" + "="*80)
        print("Flow Analysis Results (Based on IP ID Difference)")
        print("="*80)
        print(f"Using ID threshold: {self.id_threshold}")
        
        for flow_key, stats in results.items():
            print(f"\nFlow: {flow_key}")
            print(f"  Total packets: {stats['total_packets']}")
            print(f"  Out-of-order packets: {stats['out_of_order_packets']}")
            print(f"  Forward loss events: {stats['loss_before_count']}")
            print(f"  Backward loss events: {stats['loss_after_count']}")
            print(f"  Forward loss rate: {stats['loss_rate_before']:.6f} ({stats['loss_rate_before']*100:.4f}%)")
            print(f"  Backward loss rate: {stats['loss_rate_after']:.6f} ({stats['loss_rate_after']*100:.4f}%)")
            print(f"  Max sequence number: {stats['max_sequence']}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python tcp_loss_rate.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    analyzer = FlowAnalyzer(id_threshold=3)  # 使用IP ID差值阈值3
    results = analyzer.analyze_pcap(pcap_file)
    analyzer.print_results(results)

if __name__ == "__main__":
    main()