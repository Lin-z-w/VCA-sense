#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import csv
import re
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


def run_tshark(pcap_file, tls_keys_file):
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
    os.makedirs(output_dir, exist_ok=True)

    stdout = run_tshark(pcap_file, tls_keys_file)
    records = parse_tshark_lines(stdout)
    grouped = group_by_directional_connection(records)
    summary = write_per_connection_csv(grouped, output_dir)
    write_summary_csv(summary, output_dir)


if __name__ == "__main__":
    main()
