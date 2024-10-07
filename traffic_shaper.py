import os
import time
import random
from multiprocessing import Process, Value, Manager
from scapy.all import sniff
from scapy.layers.inet import IP


class TokenBucket:
    def __init__(self, rate, burst):
        self.rate = rate  # 令牌生成速率
        self.burst = burst  # 桶的容量
        self.tokens = burst  # 初始令牌数为桶的容量
        self.last_refill_time = time.time()

    def add_tokens(self):
        now = time.time()
        elapsed_time = now - self.last_refill_time
        new_tokens = elapsed_time * self.rate
        self.tokens = min(self.burst, self.tokens + new_tokens)
        self.last_refill_time = now

    def consume(self, num_tokens):
        self.add_tokens()
        if self.tokens >= num_tokens:
            self.tokens -= num_tokens
            return True
        return False


class TrafficShaper:
    def __init__(self, interface, congestion_status, clients):
        self.interface = interface  # 无线网络接口名称
        self.congestion_status = congestion_status
        self.clients = clients  # 动态共享客户端列表
        self.buckets = {}  # 用来存储每个客户端的令牌桶

    def get_or_create_bucket(self, client_id, rate, burst):
        """为每个客户端创建或获取其独立的令牌桶"""
        if client_id not in self.buckets:
            self.buckets[client_id] = TokenBucket(rate, burst)
        return self.buckets[client_id]

    def monitor_bandwidth(self, client_id):
        """通过ifconfig获取实际带宽并动态调整流量"""
        try:
            result = os.popen(f'ifconfig {self.interface}').read()
            lines = result.split("\n")
            for line in lines:
                if "TX packets" in line:
                    tx_bytes = int(line.split()[4])  # 提取发送的字节数
                    print(f"客户端 {client_id} 当前发送字节数: {tx_bytes}")
                    return tx_bytes
        except Exception as e:
            print(f"获取带宽信息失败: {e}")
            return 0

    def apply_tc_limit(self, client_id, rate):
        """通过 tc 命令来限制接口的传输速率"""
        try:
            print(f"为客户端 {client_id} 设置限速为 {rate}kbps")
            os.system(f"tc qdisc add dev {self.interface} root tbf rate {rate}kbps burst 32kbit latency 400ms")
        except Exception as e:
            print(f"设置带宽失败: {e}")

    def monitor_channel_quality(self, client_id):
        """监测信道质量并根据质量调整带宽限制"""
        try:
            # 获取信道质量信息
            result = os.popen(f"iwconfig {self.interface}").read()
            for line in result.split("\n"):
                if "Link Quality" in line:
                    quality = int(line.split("=")[1].split("/")[0])  # 提取信道质量
                    signal_level = int(line.split("=")[2].replace("dBm", ""))  # 提取信号强度
                    print(f"客户端 {client_id} 当前信道质量: {quality}, 信号强度: {signal_level} dBm")
                    return quality, signal_level
        except Exception as e:
            print(f"信道质量监测失败: {e}")
            return 0, -100

    def start_traffic_shaping(self, client_id):
        """开始监测和调整每个客户端的流量"""
        while True:
            # 监控信道质量并动态调整
            quality, signal_level = self.monitor_channel_quality(client_id)

            # 根据信道质量调整流量整形策略
            if quality < 50 or signal_level < -70:
                print(f"客户端 {client_id} 信道质量差，降低速率")
                self.apply_tc_limit(client_id, 1000)  # 降低速率为 1000 kbps
            else:
                current_tx_bytes = self.monitor_bandwidth(client_id)
                if current_tx_bytes > 1024 * 1024:  # 示例带宽阈值
                    print(f"客户端 {client_id} 发送数据过多，降低速率")
                    self.apply_tc_limit(client_id, 2000)  # 设置限速为 2000 kbps
                else:
                    self.apply_tc_limit(client_id, 5000)  # 恢复速率为 5000 kbps

            time.sleep(1)

    def handle_client_request(self, client_id, data_size, priority=1):
        """处理每个客户端的请求，基于优先级和带宽"""
        bucket = self.get_or_create_bucket(client_id, rate=500 * 1024, burst=1024 * 1024)  # 为每个客户端设置默认速率
        adjusted_size = data_size // priority  # 调整数据大小
        if bucket.consume(adjusted_size):
            print(f"客户端 {client_id} 发送了 {data_size} 字节数据")
            return True
        else:
            print(f"客户端 {client_id} 等待令牌...")
            return False


def discover_clients(interface, clients):
    """通过监听网络流量动态发现新的客户端"""

    def packet_handler(packet):
        if packet.haslayer(IP):
            client_ip = packet[IP].src  # 假设客户端是发送数据的源
            if client_ip not in clients:
                print(f"发现新客户端: {client_ip}")
                clients.append(client_ip)

    sniff(iface=interface, prn=packet_handler, store=False)


def perform_traffic_shaping(congestion_status, interface, clients):
    shaper = TrafficShaper(interface=interface, congestion_status=congestion_status, clients=clients)

    # 创建多个客户端的流量整形进程
    processes = []
    for client_id in clients:
        p = Process(target=shaper.start_traffic_shaping, args=(client_id,))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


if __name__ == '__main__':
    congestion_status = Value('i', 0)  # 初始无拥塞
    interface = "wlan0"  # 设置你的无线接口名称

    with Manager() as manager:
        clients = manager.list()  # 使用 Manager 的共享列表来存储动态客户端
        client_discovery_process = Process(target=discover_clients, args=(interface, clients))
        client_discovery_process.start()

        traffic_shaping_process = Process(target=perform_traffic_shaping, args=(congestion_status, interface, clients))
        traffic_shaping_process.start()

        client_discovery_process.join()
        traffic_shaping_process.join()
