from flask import Flask, request, jsonify
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.all import rdpcap
import os
import time

app = Flask(__name__)

# QoE 评估的系数
UDB = 1.2
UI = 4.3
UD = 4.4
UQ = 1.0

def QOE(pcap_file, server_ip):
    packets = rdpcap(pcap_file)
    timestamps = [packet.time for packet in packets if IP in packet and TCP in packet]
    packet_sizes = [len(packet) for packet in packets if IP in packet and TCP in packet]

    bitrates = [(packet_sizes[i] * 8) / (timestamps[i] - timestamps[i - 1])
                for i in range(1, len(timestamps)) if (timestamps[i] - timestamps[i - 1]) > 0]

    bitrate_differences = [abs(bitrates[i] - bitrates[i - 1]) for i in range(1, len(bitrates))]

    initial_buffer_time = calculate_initial_buffer_time(packets, server_ip)
    stall_time = calculate_stall_duration(packets, bitrates)
    quality_switches = calculate_quality_switches(packets)

    qoe_score = (sum(bitrates) / 1e9 +
                 UDB * sum(bitrate_differences) / 1e9 +
                 UI * initial_buffer_time +
                 UD * stall_time +
                 UQ * quality_switches)

    return qoe_score

# 处理 POST 请求
@app.route('/qoe', methods=['POST'])
def get_qoe():
    data = request.get_json()
    pcap_file = data.get('pcap_file')
    server_ip = data.get('server_ip')

    if not pcap_file or not server_ip:
        return jsonify({"error": "Missing pcap_file or server_ip"}), 400

    try:
        qoe_score = QOE(pcap_file, server_ip)
        return jsonify({"qoe_score": qoe_score}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 时延计算
def calculate_latency(pcap_file):
    packets = rdpcap(pcap_file)
    timestamps = {}
    for packet in packets:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if (ip_src, ip_dst) not in timestamps:
                timestamps[(ip_src, ip_dst)] = []
            timestamps[(ip_src, ip_dst)].append(packet.time)

    delays = []
    for key, value in timestamps.items():
        for i in range(1, len(value)):
            delay = (value[i] - value[i - 1]) * 1000
            delays.append(delay)
            print(f"Delay from {key[0]} to {key[1]}: {delay} ms")
    return delays
# qoe_server 监听请求
def handle_request():
    # 假设 output.pcap 已经生成
    pcap_file = 'output.pcap'
    delays = calculate_latency(pcap_file)

    # 根据时延结果判断是否需要调用流量整形
    if max(delays) > 100:  # 假设时延超过 100ms 需要进行流量整形
        print("高时延检测，启动流量整形")
        os.system("python3 traffic_shaper.py")  # 调用流量整形

if __name__ == "__main__":
    app.run(port=5000)
    while True:
        handle_request()
        time.sleep(5)  # 定时检查
