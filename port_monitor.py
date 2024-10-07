from scapy.all import *
import time
from collections import defaultdict

# 用于存储每个连接的 SYN 包时间
connections = defaultdict(float)

def calculate_rtt(syn_time, ack_time):
    "计算往返时间 (RTT)"
    return (ack_time - syn_time) * 1000  # 转换为毫秒

def check_congestion(rtt, threshold=100):
    "检测拥塞，若 RTT 超过阈值则认为存在拥塞"
    if rtt > threshold:
        return True
    return False

def process_packet(packet):
    "处理捕获的数据包"
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        port = packet[TCP].dport

        # 只处理指定端口的流量
        if port == 80:
            # TCP SYN 包，标志开始时间
            if packet[TCP].flags == 'S':
                connections[packet[TCP].seq] = time.time()
            
            # TCP ACK 包，计算往返时间
            elif packet[TCP].flags == 'A':
                if packet[TCP].ack in connections:
                    rtt = calculate_rtt(connections[packet[TCP].ack], time.time())
                    congested = check_congestion(rtt)
                    congestion_status = "Congested" if congested else "Normal"
                    print(f"RTT for {src_ip} to {dst_ip}: {rtt:.2f} ms - Status: {congestion_status}")
                    
                    # 移除已处理的连接
                    del connections[packet[TCP].ack]

def monitor_port_latency(interface, port):
    """监控指定接口和端口的流量"""
    # 开始 sniff 数据包，指定过滤器
    sniff(iface=interface, filter=f'tcp port {port}', prn=process_packet)

if __name__ == '__main__':
    # 设置要监控的网络接口和端口
    interface = 'eth0'  # 主机的网络接口
    port = 80           # 监控端口
    print(f"开始监控接口 {interface} 上的端口 {port} 的延迟...")
    monitor_port_latency(interface, port)
