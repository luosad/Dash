import time
from scapy.layers.inet import IP, TCP
from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from multiprocessing import Value


def analyze_packets(pcap_file, congestion_status, threshold=100):
    """
    分析 pcap 文件中的数据包并计算时延，更新共享内存中的拥塞状态。

    :param pcap_file: 要分析的 pcap 文件路径
    :param congestion_status: 共享内存变量，用于表示拥塞状态（1 表示拥塞，0 表示无拥塞）
    :param threshold: 拥塞检测的时延阈值，超过此值认为存在拥塞（单位：毫秒）
    """
    # 从 pcap 文件加载数据包
    packets = rdpcap(pcap_file)

    # 初始化字典来存储每个数据包的时间戳
    timestamps = {}

    # 提取每个数据包的时间戳
    for packet in packets:
        if packet.haslayer(Ether) and packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if (ip_src, ip_dst) not in timestamps:
                timestamps[(ip_src, ip_dst)] = []
            timestamps[(ip_src, ip_dst)].append(packet.time)

    # 计算每对源-目的IP地址之间的时延
    for key, value in timestamps.items():
        ip_src, ip_dst = key
        for i in range(1, len(value)):
            delay = (value[i] - value[i - 1]) * 1000  # 转换为毫秒
            print(f"Delay from {ip_src} to {ip_dst}: {delay:.2f} ms")

            # 根据延迟更新拥塞状态
            if delay > threshold:
                congestion_status.value = 1  # 表示检测到拥塞
                print(f"Network congestion detected for {ip_src} -> {ip_dst}")
            else:
                congestion_status.value = 0  # 无拥塞


if __name__ == '__main__':
    # 创建一个共享的整数变量，初始值为0（无拥塞）
    congestion_status = Value('i', 0)

    # 运行数据包分析，并将共享内存变量传递给函数
    analyze_packets('test.pcap', congestion_status)

    # 根据共享内存的状态输出结果
    if congestion_status.value == 1:
        print("Network is currently congested!")
    else:
        print("No congestion detected.")
