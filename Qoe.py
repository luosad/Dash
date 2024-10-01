# from scapy.all import *  
# from scapy.layers.inet import IP ,TCP
# UDB=1 #比特率之差的系数
# UI=4.3 #初始缓冲系数
# UD=4.4 #卡顿时间系数

# def is_tcp_syn(packet):  
#     #判断TCP包是否是SYN包  
#     if TCP in packet and packet[TCP].flags == 0x02:  
#         return True  
#     return False  
  
# def find_first_data_packet(packets, src_ip, dst_ip):  
#     #找到从src_ip到dst_ip的第一个数据包的时间
#     for packet in packets:  
#         if IP in packet and TCP in packet:  
#             ip_layer = packet.getlayer(IP)  
#             if (ip_layer.src == src_ip and ip_layer.dst == dst_ip  and not is_tcp_syn(packet)):  
#                 return packet.time  

#     return None        
  
# def calculate_initial_buffer_time(pcap_path, src_ip, dst_ip):  
#     #计算初始缓冲时间
#     try:  
#         packets = rdpcap(pcap_path)  
#         first_syn_time = None  
#         for i in range(len(packets)-2):  
#             if is_tcp_syn(packets[i]) and is_tcp_syn(packets[i+1]) and not is_tcp_syn(packets[i+2]):  
#                 first_syn_time = packets[i].time  
#                 break  
#         if first_syn_time is None:  
#             raise ValueError("SYN packet not found in the pcap file.")  
          
#         first_data_time = find_first_data_packet(packets, src_ip, dst_ip)  
#         if first_data_time is None:  
#             raise ValueError("Data packet from server to destination not found.")  
          
#         return (first_data_time - first_syn_time)  
#     except Exception as e:  
#         print(f"An error occurred: {e}")  
#         return None  
  
# def calculate_bitrate(packet_size, delta_time):  
#     #计算码率（比特/秒）
#    if delta_time == 0:  
#         raise ValueError("Delta time cannot be zero.")  
#    return (packet_size * 8) / delta_time  

# def calculate_stall_duration(timestamps,bitrates):  
#     stall_start_time = None  # 卡顿开始时间  
#     stall_duration = 0  
#     bitrate_threshold = 500  # 设定卡顿比特率的阈值（秒）
#     stall_time = 0  # 累计卡顿时间  
#     is_stalling = False  # 当前是否处于卡顿状态  
#     for i in range(len(bitrates)):  
#         if  bitrates[i] < bitrate_threshold :  
#             if not is_stalling:  
#                 is_stalling = True  
#                 stall_start_time = timestamps[i]   
#         else:  
#             if is_stalling:  
#                 is_stalling = False  
#                 stall_end_time = timestamps[i-1]  
#                 stall_duration = (stall_end_time - stall_start_time)
#                 stall_time+=(stall_end_time - stall_start_time)
#                 # if stall_duration>0:
#                 #     print(f"Stutter detected from {stall_start_time} to {stall_end_time}, duration: {stall_duration:.6f} seconds")  
#                 stall_duration = 0  # 重置卡顿时间  
#     return stall_time            


# def QOE(pcap_path, src_ip, dst_ip):  
#     # 读取pcap文件  
#     packets = rdpcap(pcap_path)  
#     # 初始化变量  
#     total_bits = 0
#     bitrates = []  
#     bitrate_differences=[]  
#     timestamps = []   
#     packet_sizes = []  
      
#     # 遍历每个数据包  
#     for packet in packets:  
#         if packet.haslayer(IP):  
#             ip_layer = packet.getlayer(IP)  
#             if ip_layer.src == src_ip and ip_layer.dst == dst_ip:  
#                 timestamp = packet.time  
#                 packet_size = len(packet)  
#                 timestamps.append(timestamp)  
#                 packet_sizes.append(packet_size)  
      
#     # 计算码率  
#     for i in range(1, len(timestamps)):  
#         delta_time = (timestamps[i] - timestamps[i-1]) 
#         #print (delta_time)
#         if delta_time != 0:  
#             bitrate = calculate_bitrate(packet_sizes[i-1], delta_time)  
#             #print (bitrate)
#             bitrates.append(bitrate)  
#     total_bits=sum(bitrates)

#     total_bits_diffe=0
#     # 比特率之差        
#     for i in range(1, len(bitrates)):  
#      bitrate_difference = bitrates[i] - bitrates[i-1] 
#      bitrate_difference=abs(bitrate_difference) 
#      #print(bitrate_difference)
#      bitrate_differences.append(bitrate_difference)  
#     total_bits_diffe=sum(bitrate_differences)

#     initial_buffer_time = calculate_initial_buffer_time(pcap_path, src_ip, dst_ip)     
#     # 打印卡顿时间（假设每个数据包间隔代表一次卡顿检测）
#     stall_time=calculate_stall_duration(timestamps,bitrates)  
#     print(stall_time)
#     return  total_bits/1000000000+UDB*total_bits_diffe/1000000000+UI*initial_buffer_time+UD*stall_time
  
# # 调用函数  
# print(QOE('D:/VSCode_Project/SRTP/test01.pcap', "192.168.5.130", "192.168.5.1")) 


# # # stall_start_time = None  # 卡顿开始时间  
# #     stall_duration = 0  
# #     bitrate_threshold = 500  # 设定卡顿比特率的阈值（秒）
# #     stall_time = 0  # 累计卡顿时间  
# #     is_stalling = False  # 当前是否处于卡顿状态  
# #     # 判断卡顿并计算卡顿时间  
# #     for i in range(len(bitrates)):  
# #         if  bitrates[i] < bitrate_threshold :  
# #             if not is_stalling:  
# #                 is_stalling = True  
# #                 stall_start_time = timestamps[i]   
# #         else:  
# #             if is_stalling:  
# #                 is_stalling = False  
# #                 stall_end_time = timestamps[i-1]  
# #                 stall_duration = (stall_end_time - stall_start_time)
# #                 stall_time+=(stall_end_time - stall_start_time)
# #                 # if stall_duration>0:
# #                 #     print(f"Stutter detected from {stall_start_time} to {stall_end_time}, duration: {stall_duration:.6f} seconds")  
# #                 stall_duration = 0  # 重置卡顿时间  


from scapy.all import rdpcap, TCP, IP

# 权重系数
UDB = 1.2  # 比特率之差的系数
UI = 4.3   # 初始缓冲系数
UD = 4.4   # 卡顿时间系数
UQ = 1.0   # 视频质量切换频率系数

def is_tcp_syn(packet):
    # 判断TCP包是否是SYN包
    return TCP in packet and packet[TCP].flags & 0x02

def find_first_data_packet(packets, server_ip):
    # 找到服务器发送的第一个数据包的时间
    for packet in packets:
        if IP in packet and TCP in packt and packet[IP].src == server_ip:
            return packet.time
    return None

def calculate_initial_buffer_time(packets, server_ip):
    # 计算初始缓冲时间
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
    # 计算比特率（比特/秒）      
    return float(packet_size * 8) / float(delta_time) if delta_time > 0 else 0

def calculate_stall_duration(packets, bitrates, bitrate_threshold=500000):
    # 计算卡顿时间
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
    # 计算视频质量切换的次数
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
    # 综合QoE计算
    packets = rdpcap(pcap_file)
    timestamps = [float(packet.time) for packet in packets if IP in packet and TCP in packet]
    packet_sizes = [float(len(packet)) for packet in packets if IP in packet and TCP in packet]
    
    # 计算比特率
    bitrates = [calculate_bitrate(packet_sizes[i], timestamps[i] - timestamps[i - 1]) 
                for i in range(1, len(timestamps))]
    
    bitrate_differences = [abs(bitrates[i] - bitrates[i - 1]) for i in range(1, len(bitrates))]
    
    # 计算各QoE指标
    initial_buffer_time = calculate_initial_buffer_time(packets, server_ip)
    stall_time = calculate_stall_duration(packets, bitrates)
    quality_switches = calculate_quality_switches(packets)

    # 综合QoE得分
    qoe_score = (
        sum(bitrates) / 1e9 +
        UDB * sum(bitrate_differences) / 1e9 +
        UI * initial_buffer_time +
        UD * stall_time +
        UQ * quality_switches
    )
    
    return qoe_score

# 使用示例
pcap_file = 'D:/VSCode_Project/SRTP/test01.pcap'  # 替换为您的pcap文件路径
server_ip = '192.168.5.130'  # 替换为视频服务器的IP地址

qoe_score = QOE(pcap_file, server_ip)
print(f"QoE Score: {qoe_score}")
