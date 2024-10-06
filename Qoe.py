# from scapy.all import *
# from scapy.layers.inet import IP,TCP
# from flask import Flask, request, jsonify
# import requests
#
# app = Flask(__name__)
#
# # 权重系数
# UDB = 1.2  # 比特率之差的系数
# UI = 4.3   # 初始缓冲系数
# UD = 4.4   # 卡顿时间系数
# UQ = 1.0   # 视频质量切换频率系数
#
# def is_tcp_syn(packet):
#     # 判断TCP包是否是SYN包
#     return TCP in packet and packet[TCP].flags & 0x02
#
# def find_first_data_packet(packets, server_ip):
#     # 找到服务器发送的第一个数据包的时间
#     for packet in packets:
#         if IP in packet and TCP in packet and packet[IP].src == server_ip:
#             return packet.time
#     return None
#
# def calculate_initial_buffer_time(packets, server_ip):
#     # 计算初始缓冲时间
#     first_syn_time = None
#     for packet in packets:
#         if is_tcp_syn(packet):
#             first_syn_time = packet.time
#             break
#
#     if first_syn_time is None:
#         raise ValueError("未找到SYN包。")
#
#     first_data_time = find_first_data_packet(packets, server_ip)
#     if first_data_time is None:
#         raise ValueError("未找到服务器发送的数据包。")
#
#     return float(first_data_time - first_syn_time)
#
# def calculate_bitrate(packet_size, delta_time):
#     # 计算比特率（比特/秒）
#     return float(packet_size * 8) / float(delta_time) if delta_time > 0 else 0
#
# def calculate_stall_duration(packets, bitrates, bitrate_threshold=500000):
#     # 计算卡顿时间
#     stall_duration = 0
#     is_stalling = False
#     stall_start_time = 0
#
#     for i in range(len(bitrates)):
#         if bitrates[i] < bitrate_threshold:
#             if not is_stalling:
#                 is_stalling = True
#                 stall_start_time = packets[i].time
#         else:
#             if is_stalling:
#                 is_stalling = False
#                 stall_end_time = packets[i].time
#                 stall_duration += float(stall_end_time - stall_start_time)
#
#     return stall_duration
#
# def calculate_quality_switches(packets):
#     # 计算视频质量切换的次数
#     quality_switches = 0
#     last_quality = None
#
#     for packet in packets:
#         if TCP in packet and b"GET" in bytes(packet[TCP].payload):
#             request_line = bytes(packet[TCP].payload).split(b"\r\n")[0]
#             if b"video_" in request_line:
#                 current_quality = request_line.split(b"video_")[1].split(b"_")[0]
#                 if last_quality and current_quality != last_quality:
#                     quality_switches += 1
#                 last_quality = current_quality
#
#     return quality_switches
#
# def QOE(pcap_file, server_ip):
#     # 综合QoE计算
#     packets = rdpcap(pcap_file)
#     timestamps = [float(packet.time) for packet in packets if IP in packet and TCP in packet]
#     packet_sizes = [float(len(packet)) for packet in packets if IP in packet and TCP in packet]
#
#     # 计算比特率
#     bitrates = [calculate_bitrate(packet_sizes[i], timestamps[i] - timestamps[i - 1])
#                 for i in range(1, len(timestamps))]
#
#     bitrate_differences = [abs(bitrates[i] - bitrates[i - 1]) for i in range(1, len(bitrates))]
#
#     # 计算各QoE指标
#     initial_buffer_time = calculate_initial_buffer_time(packets, server_ip)
#     stall_time = calculate_stall_duration(packets, bitrates)
#     quality_switches = calculate_quality_switches(packets)
#
#     # 综合QoE得分
#     qoe_score = (
#         sum(bitrates) / 1e9 +
#         UDB * sum(bitrate_differences) / 1e9 +
#         UI * initial_buffer_time +
#         UD * stall_time +
#         UQ * quality_switches
#     )
#
#     try:
#         response = requests.post("http://localhost:5000/qoe", json={"qoe_score": qoe_score})
#         response.raise_for_status()
#     except requests.exceptions.RequestException as e:
#         print(f"Failed to send QoE score: {e}")
#
#     return qoe_score
# @app.route('/getQoEResults', methods=['GET'])
# def get_qoe_results():
#     pcap_path = '/home/luo/Desktop/test01.pcap'  # pcap文件路径
#     server_ip = request.args.get('server_ip', '192.168.5.130')  # 服务器IP
#     qoe_score = QOE(pcap_path, server_ip)
#     print(f"Received QoE Score: {qoe_score}")
#     return jsonify({"qoe_score": qoe_score})
#
#
# @app.route('/qoe', methods=['POST'])
# def receive_qoe():
#     data = request.get_json()
#     qoe_score = data.get('qoe_score')
#     print(f"Received QoE Score: {qoe_score}")
#     return jsonify({"status": "success"}), 200
#
# if __name__ == '__main__':
#     app.run(port=5000)
# 使用示例
#pcap_file = 'output.pcap'
#server_ip = '192.168.25.129'
#pcap_file = '/home/luo/Desktop/test01.pcap'  # pcap文件路径
#server_ip = '192.168.5.130'  # 视频服务器的IP地址

#qoe_score = QOE(pcap_file, server_ip)
#print(f"QoE Score: {qoe_score}")

from flask import Flask, request, jsonify
from scapy.all import *
from scapy.layers.inet import IP,TCP

# 权重系数
UDB = 1.2  # 比特率之差的系数
UI = 4.3   # 初始缓冲系数
UD = 4.4   # 卡顿时间系数
UQ = 1.0   # 视频质量切换频率系数

app = Flask(__name__)

def is_tcp_syn(packet):
    return TCP in packet and packet[TCP].flags & 0x02

def find_first_data_packet(packets, server_ip):
    for packet in packets:
        if IP in packet and TCP in packet and packet[IP].src == server_ip:
            return packet.time
    return None

def calculate_initial_buffer_time(packets, server_ip):
    first_syn_time = None
    for packet in packets:
        if is_tcp_syn(packet):
            first_syn_time = packet.time
            break

    if first_syn_time is None:
        raise ValueError("未找到SYN包。")

    first_data_time = find_first_data_packet(packets, server_ip)
    if first_data_time is None:
        raise ValueError("未找到服务器发送的数据包。")

    return float(first_data_time - first_syn_time)

def calculate_bitrate(packet_size, delta_time):
    return float(packet_size * 8) / float(delta_time) if delta_time > 0 else 0

def calculate_stall_duration(packets, bitrates, bitrate_threshold=500000):
    stall_duration = 0
    is_stalling = False
    stall_start_time = 0

    for i in range(len(bitrates)):
        if bitrates[i] < bitrate_threshold:
            if not is_stalling:
                is_stalling = True
                stall_start_time = packets[i].time
        else:
            if is_stalling:
                is_stalling = False
                stall_end_time = packets[i].time
                stall_duration += float(stall_end_time - stall_start_time)

    return stall_duration

def calculate_quality_switches(packets):
    quality_switches = 0
    last_quality = None

    for packet in packets:
        if TCP in packet and b"GET" in bytes(packet[TCP].payload):
            request_line = bytes(packet[TCP].payload).split(b"\r\n")[0]
            if b"video_" in request_line:
                current_quality = request_line.split(b"video_")[1].split(b"_")[0]
                if last_quality and current_quality != last_quality:
                    quality_switches += 1
                last_quality = current_quality

    return quality_switches

def QOE(pcap_file, server_ip):
    packets = rdpcap(pcap_file)
    timestamps = [float(packet.time) for packet in packets if IP in packet and TCP in packet]
    packet_sizes = [float(len(packet)) for packet in packets if IP in packet and TCP in packet]

    bitrates = [calculate_bitrate(packet_sizes[i], timestamps[i] - timestamps[i - 1])
                for i in range(1, len(timestamps))]

    bitrate_differences = [abs(bitrates[i] - bitrates[i - 1]) for i in range(1, len(bitrates))]

    initial_buffer_time = calculate_initial_buffer_time(packets, server_ip)
    stall_time = calculate_stall_duration(packets, bitrates)
    quality_switches = calculate_quality_switches(packets)

    qoe_score = (
        sum(bitrates) / 1e9 +
        UDB * sum(bitrate_differences) / 1e9 +
        UI * initial_buffer_time +
        UD * stall_time +
        UQ * quality_switches
    )

    return qoe_score

@app.route('/qoe', methods=['POST'])
def get_qoe():
    try:
        data = request.get_json()
        app.logger.info(f"Received data: {data}")
        pcap_file = data.get('pcap_file')
        server_ip = data.get('server_ip')
        if not pcap_file or not server_ip:
            return jsonify({"error": "Missing pcap_file or server_ip"}), 400

        qoe_score = QOE(pcap_file, server_ip)
        return jsonify({"qoe_score": qoe_score}), 200
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000)
