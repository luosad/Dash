import os
import time
from multiprocessing import Process, Value
from scapy.all import sniff, sendp
from scapy.layers.inet import IP, TCP

class TrafficShaper:
    def __init__(self, interface, congestion_status):
        self.interface = interface  # 无线网络接口名称
        self.congestion_status = congestion_status

    def monitor_bandwidth(self):
        """通过ifconfig获取实际带宽并动态调整流量"""
        try:
            result = os.popen(f'ifconfig {self.interface}').read()
            lines = result.split("\n")
            for line in lines:
                if "TX packets" in line:
                    tx_bytes = int(line.split()[4])  # 提取发送的字节数
                    return tx_bytes
        except Exception as e:
            print(f"获取带宽信息失败: {e}")
            return 0

    def apply_tc_limit(self, rate):
        """通过 tc 命令来限制接口的传输速率"""
        try:
            os.system(f"tc qdisc add dev {self.interface} root tbf rate {rate}kbps burst 32kbit latency 400ms")
        except Exception as e:
            print(f"设置带宽失败: {e}")

    def monitor_channel_quality(self):
        """监测信道质量并根据质量调整带宽限制"""
        try:
            # 获取信道质量信息
            result = os.popen(f"iwconfig {self.interface}").read()
            for line in result.split("\n"):
                if "Link Quality" in line:
                    quality = int(line.split("=")[1].split("/")[0])  # 提取信道质量
                    signal_level = int(line.split("=")[2].replace("dBm", ""))  # 提取信号强度
                    return quality, signal_level
        except Exception as e:
            print(f"信道质量监测失败: {e}")
        return 0, -100  # 在出现错误时返回一个默认的元组

    def start_traffic_shaping(self):
        """开始监测和调整流量"""
        while True:
            # 监控信道质量并动态调整
            quality, signal_level = self.monitor_channel_quality()
            print(f"当前信道质量: {quality}, 信号强度: {signal_level} dBm")

            # 根据信道质量调整流量整形策略
            if quality < 50 or signal_level < -70:
                print("信道质量差，降低速率")
                self.apply_tc_limit(1000)  # 降低速率为 1000 kbps
            else:
                current_tx_bytes = self.monitor_bandwidth()
                print(f"当前发送字节数: {current_tx_bytes}")
                if current_tx_bytes > 1024 * 1024:  # 示例带宽阈值
                    print("发送数据过多，降低速率")
                    self.apply_tc_limit(2000)  # 设置限速为 2000 kbps
                else:
                    self.apply_tc_limit(5000)  # 正常情况下恢复速率为 5000 kbps

            time.sleep(1)

def perform_traffic_shaping(congestion_status, interface):
    shaper = TrafficShaper(interface=interface, congestion_status=congestion_status)
    shaper.start_traffic_shaping()

if __name__ == '__main__':
    congestion_status = Value('i', 0)  # 初始无拥塞
    interface = "wlan0"  # 设置你的无线接口名称
    traffic_shaping_process = Process(target=perform_traffic_shaping, args=(congestion_status, interface))
    traffic_shaping_process.start()
    traffic_shaping_process.join()
