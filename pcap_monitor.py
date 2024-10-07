# This is a sample Python script.
from telnetlib import IP
from scapy.layers.inet import IP,TCP

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

from scapy.all import *
from scapy.layers.l2 import Ether

# 从pcap文件加载数据包
packets = rdpcap('test.pcap')

# 初始化字典来存储每个数据包的时间戳
timestamps = {}

# 提取每个数据包的时间戳
for packet in packets:
    if packet.haslayer(Ether):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if (ip_src, ip_dst) not in timestamps:
                timestamps[(ip_src, ip_dst)] = []
            timestamps[(ip_src, ip_dst)].append(packet.time)

# 计算每对源目的IP地址之间的时延
for key, value in timestamps.items():
    ip_src, ip_dst = key
    for i in range(1, len(value)):
        delay = (value[i] - value[i - 1])*1000
        print(f"Delay from {ip_src} to {ip_dst}: {delay} ms")
