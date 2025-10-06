#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import csv
import re
import tempfile
from collections import defaultdict

TSHARK_PATH = r"D:\Software\wireshark\tshark.exe"

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "quic.packet_number",
    "quic.stream.stream_id",
    "quic.stream.offset",
    "quic.stream.length"
]

_MULTI_SPLIT_RE = re.compile(r"[,\s;]+")


def split_multi(s):
    if not s:
        return []
    return [p for p in _MULTI_SPLIT_RE.split(s.strip()) if p]


def choose_ip(ip4, ip6):
    return ip4 if ip4 else (ip6 if ip6 else "")


def sanitize_filename(name: str):
    return re.sub(r"[<>:\"/\\|?*\s]+", "_", name)


def extract_tls_sessions(tls_keys_file):
    """
    从密钥文件中提取完整的TLS会话
    每个会话包含CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
    CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET
    返回会话列表，每个会话是一个包含5行密钥的字符串
    """
    with open(tls_keys_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    # 预期的密钥类型顺序
    expected_types = [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET", 
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET"
    ]
    
    sessions = []
    current_session = []
    current_client_random = None
    
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            key_type = parts[0]
            client_random = parts[1]
            
            # 如果是新的客户端随机数，开始新的会话
            if current_client_random != client_random:
                if current_session and len(current_session) == 5:
                    sessions.append("\n".join(current_session))
                elif current_session:
                    print(f"⚠️  不完整的会话，找到 {len(current_session)}/5 个密钥")
                
                current_session = [line]
                current_client_random = client_random
            else:
                # 同一会话的继续
                current_session.append(line)
    
    # 添加最后一个会话
    if current_session and len(current_session) == 5:
        sessions.append("\n".join(current_session))
    elif current_session:
        print(f"⚠️  不完整的会话，找到 {len(current_session)}/5 个密钥")
    
    print(f"📋 提取到 {len(sessions)} 个完整的TLS会话")
    return sessions


def test_tshark_with_keys(pcap_file, key_content):
    """
    使用给定的密钥内容测试tshark是否能成功解析
    返回(成功标志, 输出内容)
    """
    temp_key_path = None
    try:
        # 创建临时密钥文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.keylog', delete=False, encoding='utf-8') as temp_key:
            temp_key.write(key_content)
            temp_key_path = temp_key.name
        
        cmd = [
            TSHARK_PATH,
            "-r", pcap_file,
            "-o", f"tls.keylog_file:{temp_key_path}",
            "-Y", "quic && quic.stream",
            "-T", "fields",
            "-E", "separator=|"
        ]
        for f in TSHARK_FIELDS:
            cmd += ["-e", f]
        
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        
        # 清理临时文件
        try:
            os.unlink(temp_key_path)
        except:
            pass
        
        # 检查是否成功解析到QUIC流数据
        if proc.returncode == 0:
            lines = [line for line in proc.stdout.splitlines() if line.strip()]
            # 检查是否有有效的QUIC流数据（包含stream_id）
            valid_lines = [line for line in lines if len(line.split('|')) > 9 and line.split('|')[9].strip()]
            if valid_lines:
                return True, proc.stdout
            else:
                print("    📊 解析成功但未找到QUIC流数据")
        return False, proc.stdout
        
    except subprocess.TimeoutExpired:
        # 清理临时文件
        try:
            if temp_key_path:
                os.unlink(temp_key_path)
        except:
            pass
        return False, "Timeout"
    except Exception as e:
        # 清理临时文件
        try:
            if temp_key_path:
                os.unlink(temp_key_path)
        except:
            pass
        return False, str(e)


def find_correct_keys(pcap_file, tls_keys_file):
    """
    尝试所有TLS会话密钥，找到能够成功解析pcap文件的密钥
    返回(成功标志, 密钥内容, 输出内容)
    """
    print("🔍 正在提取TLS会话密钥...")
    sessions = extract_tls_sessions(tls_keys_file)
    
    if not sessions:
        print("❌ 未找到任何完整的TLS会话")
        return False, None, None
    
    for i, session_keys in enumerate(sessions, 1):
        print(f"🔑 正在尝试第 {i}/{len(sessions)} 个TLS会话...")
        
        success, output = test_tshark_with_keys(pcap_file, session_keys)
        
        if success:
            # 提取客户端随机数以标识会话
            first_line = session_keys.split('\n')[0]
            client_random_short = first_line.split()[1][:16] + "..."
            print(f"✅ 第 {i} 个TLS会话解析成功 (Client Random: {client_random_short})")
            return True, session_keys, output
        else:
            print(f"❌ 第 {i} 个TLS会话解析失败")
    
    print("❌ 所有TLS会话都无法解析该pcap文件")
    return False, None, None


def run_tshark_with_correct_keys(pcap_file, tls_keys_file):
    """
    自动找到正确的密钥并运行tshark
    """
    success, key_content, output = find_correct_keys(pcap_file, tls_keys_file)
    
    if success:
        return output
    else:
        # 如果自动查找失败，回退到原始方法（使用整个文件）
        print("🔄 尝试使用整个密钥文件...")
        cmd = [
            TSHARK_PATH,
            "-r", pcap_file,
            "-o", f"tls.keylog_file:{tls_keys_file}",
            "-Y", "quic",
            "-T", "fields",
            "-E", "separator=|"
        ]
        for f in TSHARK_FIELDS:
            cmd += ["-e", f]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)
        
        # 检查是否有有效数据
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        valid_lines = [line for line in lines if len(line.split('|')) > 9 and line.split('|')[9].strip()]
        if valid_lines:
            print("✅ 使用整个密钥文件解析成功")
        else:
            print("⚠️  使用整个密钥文件但未找到QUIC流数据")
        
        return proc.stdout


def parse_tshark_lines(stdout):
    records = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))

        (frame_number, time_epoch,
         ip_src4, ip_src6, ip_dst4, ip_dst6,
         udp_srcport, udp_dstport,
         pkt_num_field, stream_id_field, offset_field, length_field) = parts[:12]

        ip_src = choose_ip(ip_src4.strip(), ip_src6.strip())
        ip_dst = choose_ip(ip_dst4.strip(), ip_dst6.strip())

        stream_ids = split_multi(stream_id_field)
        offsets = split_multi(offset_field)
        lengths = split_multi(length_field)
        pkt_nums = split_multi(pkt_num_field)

        count = max(len(stream_ids), len(offsets), len(lengths), len(pkt_nums), 1)

        for i in range(count):
            records.append({
                "frame_number": frame_number.strip(),
                "time_epoch": time_epoch.strip(),
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "udp_srcport": udp_srcport.strip(),
                "udp_dstport": udp_dstport.strip(),
                "packet_number": pkt_nums[i] if i < len(pkt_nums) else "",
                "stream_id": stream_ids[i] if i < len(stream_ids) else "",
                "offset": offsets[i] if i < len(offsets) else "",
                "len": lengths[i] if i < len(lengths) else ""
            })
    return records


def group_by_directional_connection(records):
    grouped = defaultdict(list)
    for r in records:
        a_ip, a_port = r["ip_src"], r["udp_srcport"]
        b_ip, b_port = r["ip_dst"], r["udp_dstport"]
        if not a_ip or not b_ip or not a_port or not b_port:
            continue
        # 方向敏感 key
        key = (a_ip, a_port, b_ip, b_port)
        grouped[key].append(r)
    return grouped


def write_per_connection_csv(grouped, output_dir):
    summary = []
    for key, recs in grouped.items():
        a_ip, a_port, b_ip, b_port = key
        fname = f"conn_{sanitize_filename(a_ip)}_{a_port}_to_{sanitize_filename(b_ip)}_{b_port}.csv"
        out_path = os.path.join(output_dir, fname)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "frame_number", "time_epoch",
                "ip_src", "ip_dst", "udp_srcport", "udp_dstport",
                "packet_number", "stream_id", "offset", "len"
            ])
            writer.writeheader()
            for r in recs:
                writer.writerow(r)

        total_bytes = 0
        for r in recs:
            try:
                total_bytes += int(r.get("len") or 0)
            except ValueError:
                pass
        summary.append({
            "connection_file": fname,
            "a_ip": a_ip, "a_port": a_port,
            "b_ip": b_ip, "b_port": b_port,
            "packet_count": len(recs),
            "total_stream_bytes": total_bytes
        })
        print(f"✅ 保存 {a_ip}:{a_port} → {b_ip}:{b_port} -> {out_path}")
    return summary


def write_summary_csv(summary, output_dir):
    out = os.path.join(output_dir, "connections_summary.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "connection_file", "a_ip", "a_port", "b_ip", "b_port",
            "packet_count", "total_stream_bytes"
        ])
        writer.writeheader()
        for s in summary:
            writer.writerow(s)
    print(f"\n✅ 汇总保存为 {out}")


def main():
    if len(sys.argv) < 4:
        print("用法: python quic_conn_analysis.py <pcap_file> <tls_keys_file> <output_dir>")
        sys.exit(1)

    pcap_file, tls_keys_file, output_dir = sys.argv[1:4]
    
    if not os.path.exists(pcap_file):
        print(f"❌ pcap文件不存在: {pcap_file}")
        sys.exit(1)
    
    if not os.path.exists(tls_keys_file):
        print(f"❌ 密钥文件不存在: {tls_keys_file}")
        sys.exit(1)
    
    os.makedirs(output_dir, exist_ok=True)

    print("🚀 开始QUIC流分析...")
    stdout = run_tshark_with_correct_keys(pcap_file, tls_keys_file)
    records = parse_tshark_lines(stdout)
    print(f"📊 解析到 {len(records)} 条QUIC流记录")
    
    grouped = group_by_directional_connection(records)
    print(f"🔗 找到 {len(grouped)} 个QUIC连接")
    
    summary = write_per_connection_csv(grouped, output_dir)
    write_summary_csv(summary, output_dir)
    
    print("\n🎉 分析完成！")


if __name__ == "__main__":
    main()