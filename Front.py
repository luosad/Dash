import tkinter as tk
from tkinter import ttk
import subprocess
import requests
import threading
import time
import json

class FrontApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dash评估系统")

        self.qoe_before_label = ttk.Label(root, text="流量整形前QoE结果: ")
        self.qoe_after_label = ttk.Label(root, text="流量整形后QoE结果: ")

        self.start_button = ttk.Button(root, text="开始抓包", command=self.start_capture)

        self.start_button.pack(pady=10)
        self.qoe_before_label.pack(pady=10)
        self.qoe_after_label.pack(pady=10)

    def start_capture(self):
        capture_thread = threading.Thread(target=self.capture_task)
        capture_thread.start()

    def capture_task(self):
        command = ["tcpdump", "-i", "any", "-w", "output.pcap"]
        process = subprocess.Popen(command)
        time.sleep(5)
        process.terminate()
        process.wait()
        self.fetch_qoe_results()

    def fetch_qoe_results(self):
        qoe_thread = threading.Thread(target=self.qoe_task)
        qoe_thread.start()

    def qoe_task(self):
        try:
            # Adjust the paths and server IP as necessary
            results = [self.send_request("http://localhost:5000/qoe", "/home/luo/Desktop/test01.pcap", "192.168.5.130", "before"),
                       self.send_request("http://localhost:5000/qoe", "/home/luo/Desktop/test01.pcap", "192.168.5.130", "after")]
            self.root.after(0, self.update_labels, results)
        except Exception as e:
            print(f"请求异常: {e}")

    def send_request(self, url, pcap_file, server_ip, qoe_type):
        headers = {'Content-Type': 'application/json'}
        data = {'pcap_file': pcap_file, 'server_ip': server_ip, 'type': qoe_type}
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            return response.json().get("qoe_score", "N/A")
        else:
            return f"请求失败，状态码: {response.status_code}"

    def update_labels(self, results):
        self.qoe_before_label.config(text=f"流量整形前QoE结果: {results[0]}")
        self.qoe_after_label.config(text=f"流量整形后QoE结果: {results[1]}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FrontApp(root)
    root.mainloop()