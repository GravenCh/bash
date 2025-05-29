#!/bin/python3
import os
import sys
import psutil
import re
import time
import requests
import socket
import threading
import subprocess
import logging
import json

# 配置日志记录
logging.basicConfig(filename='/var/log/monitor-report.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 全局配置
config = {
    "server_address": "",
    "pwd": "",
    "delay": "-",
    "Pocketlossrate": "- %",
    "status": 0
}

# 检查并记录缺少的依赖，确保不终止脚本
def check_dependencies():
    required_modules = ['psutil', 'requests', 'socket', 're', 'time', 'json', 'threading']
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            logging.warning(f"警告：缺少模块 {module}，请手动安装。")

check_dependencies()

# 异常捕获并记录日志
def log_error(e):
    logging.error(f"发生错误: {e}")

def log_info(message):
    logging.info(message)

def log_warning(message):
    logging.warning(message)

# 获取命令行参数
def get_opt():
    global config
    for i in range(1, len(sys.argv)):
        if sys.argv[i].find("-a=", 0, 3) != -1:
            config["server_address"] = sys.argv[i][3:]
        elif sys.argv[i].find("-p=", 0, 3) != -1:
            config["pwd"] = sys.argv[i][3:]

    if not config["server_address"] or not config["pwd"]:
        print(f"{sys.argv[0]} -p=<password> -a=<server_address>")
        sys.exit()

# 获取系统运行时间
def caltime(sys_time, boot_time):
    tmp = sys_time - boot_time
    day = int(tmp / 60 / 60 / 24)
    tmp -= 60 * 60 * 24 * day
    hr = int(tmp / 60 / 60)
    tmp -= 60 * 60 * hr
    min = int(tmp / 60)
    sec = int(tmp) - 60 * min
    time_list = [day, hr, min, sec]
    if time_list[0] != 0:
        return str(time_list[0]) + "天" + str(time_list[1]) + "时"
    elif time_list[1] != 0:
        return str(time_list[1]) + "时" + str(time_list[2]) + "分"
    elif time_list[2] != 0:
        return str(time_list[2]) + "分" + str(time_list[3]) + "秒"
    else:
        return str(time_list[3]) + "秒"

# 获取网络 IP 地址
def get_network_ip(ipv4, ipv6):
    try:
        # 获取IPv6地址
        result = subprocess.run(["ip", "-6", "addr", "show"], stdout=subprocess.PIPE, text=True, check=True)
        ipv6_addresses = re.findall(r"inet6\s+([a-fA-F0-9:]+(?:/[0-9]+)?)", result.stdout)
        
        # 过滤掉本地地址及环回地址（如::1, fe80::）
        for address in ipv6_addresses:
            # 去除掩码部分，只保留纯粹的IP地址
            ip_address = address.split('/')[0]
            if not ip_address.startswith("fe") and ip_address != "::1":
                ipv6.append(ip_address)
    except subprocess.CalledProcessError as e:
        log_error(f"获取IPv6信息失败: {e}")
        ipv6.append("error")

    try:
        # 获取IPv4地址
        result = subprocess.run(["ip", "addr", "show"], stdout=subprocess.PIPE, text=True, check=True)
        ipv4_addresses = re.findall(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)", result.stdout)

        # 过滤掉127.0.0.1（回环地址）
        for address in ipv4_addresses:
            # 去除掩码部分，只保留纯粹的IP地址
            ip_address = address.split('/')[0]
            if "127.0.0.1" not in ip_address:
                ipv4.append(ip_address)
    except subprocess.CalledProcessError as e:
        log_error(f"获取IPv4信息失败: {e}")
        ipv4.append("error")

# 获取 TCP 连接数
def get_tcp_connection():
    total_connections = int(subprocess.check_output("ss -t -a | wc -l", shell=True).strip())
    established_connections = int(subprocess.check_output("ss -t state established | wc -l", shell=True).strip())
    time_wait_connections = int(subprocess.check_output("ss -t state time-wait | wc -l", shell=True).strip())
    return total_connections, established_connections, time_wait_connections

# 获取 UDP 连接数
def get_udp_connection():
    total_udp_connections = int(subprocess.check_output("ss -u -a | wc -l", shell=True).strip())
    return total_udp_connections

# 获取网络流量
def get_netflow():
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]  # 跳过前两行标题
            RX, TX = sum(int(line.split()[1]) for line in lines), sum(int(line.split()[9]) for line in lines)
        return (TX, RX)
    except Exception as e:
        log_error(f"获取流量数据时出错: {e}")
        return (0, 0)

# 获取延迟和丢包率
def get_delay():
    global config
    try:
        tmp = subprocess.check_output("ping 139.155.183.218 -c 10 -i 0.1", shell=True, text=True)
        delay_flag = re.compile(r'.*/(.*)/.*/.*')
        Pocketlossrate_flag = re.compile(r' ([0-9]*\.*[0-9]*)% ')
        config["delay"] = str(int(float(re.search(delay_flag, tmp).group(1)))) if delay_flag else "error"
        config["Pocketlossrate"] = str(int(float(re.search(Pocketlossrate_flag, tmp).group(1)))) + " %" if Pocketlossrate_flag else "error"
    except Exception as e:
        log_error(f"获取延迟或丢包率失败: {e}")
        config["delay"] = "error"
        config["Pocketlossrate"] = "error"

# 获取 CPU 信息
def get_cpuinfo():
    try:
        total_tmp = sum(psutil.cpu_percent(interval=0.1, percpu=False) for _ in range(3))
        cpu_percent = round(total_tmp / 3, 2)
        cpu_cnt = psutil.cpu_count(logical=True)
        cpu_logical_percent_list = [
            round(sum(psutil.cpu_percent(interval=0.1, percpu=True)[i] for _ in range(3)) / 3, 2)
            for i in range(cpu_cnt)
        ]
        return [cpu_percent, cpu_logical_percent_list]
    except Exception as e:
        log_error(f"获取CPU信息失败: {e}")
        return [0, []]

# 获取内存使用情况
def get_memory_info():
    try:
        vir_memory_list = psutil.virtual_memory()
        vir_total = vir_memory_list[0]
        vir_used = vir_memory_list[0] - vir_memory_list[1]
        memory_percent = round(vir_used / vir_total * 100, 2)
        return vir_total, vir_used, memory_percent
    except Exception as e:
        log_error(f"获取内存信息失败: {e}")
        return 0, 0, "error"

# 获取交换区信息
def get_swap_info():
    try:
        swap_memory_list = psutil.swap_memory()
        swap_total = swap_memory_list[0]
        swap_used = swap_memory_list[1]
        if swap_total == 0:
            return swap_total, swap_used, 0
        swap_percent = round(swap_used / swap_total * 100, 2)
        return swap_total, swap_used, swap_percent
    except Exception as e:
        log_error(f"获取交换区信息失败: {e}")
        return 0, 0, "error"

# 获取磁盘使用情况
def get_disk_usage():
    try:
        disk_usage = psutil.disk_usage('/')
        return disk_usage.total, disk_usage.used, disk_usage.percent
    except Exception as e:
        log_error(f"获取磁盘使用情况失败: {e}")
        return 0, 0, "error"

# 发送数据到服务器
def send_data_to_server(post_data):
    try:
        response = requests.post(url=config["server_address"], data=json.dumps(post_data), timeout=30)
        if response.status_code != 200:
            log_warning(f"发送数据失败，HTTP 状态码: {response.status_code}，返回信息：{response.text}")
        else:
            log_info(f"汇报成功: {response.text}")
    except requests.RequestException as e:
        log_error(f"发送数据失败: {e}")

def calc_bytes(bytes_num):
    unit = ['B','KB','MB','GB','TB','PB','EB','ZB','YB']
    cnt = 0
    while bytes_num >= 1024:
        bytes_num = bytes_num / 1024
        cnt = cnt + 1
    return f"{round(bytes_num,2)} {unit[cnt]}"

def func():
    data = {}
    data['password'] = config["pwd"]
    hostname = socket.gethostname()
    data['hostname'] = hostname
    boot_time = psutil.boot_time()
    sys_time = time.time()
    run_time = caltime(sys_time, boot_time)
    data['sys_time'] = sys_time
    data['run_time'] = run_time

    # 获取其他系统信息
    data['cpu_percent'], data['cpu_logical_percent_list'] = get_cpuinfo()
    memory_total, memory_used, data['memory_percent'] = get_memory_info()
    swap_total, swap_used, data['swap_percent'] = get_swap_info()
    disk_total, disk_used, data['disk_percent'] = get_disk_usage()
    data['memory_total'] = calc_bytes(memory_total)
    data['memory_used'] = calc_bytes(memory_used)
    data['swap_total'] = calc_bytes(swap_total)
    data['swap_used'] = calc_bytes(swap_used)
    data['disk_total'] = calc_bytes(disk_total)
    data['disk_used'] = calc_bytes(disk_used)

    ipv4 = []
    ipv6 = []
    get_network_ip(ipv4, ipv6)
    data['ipv4'] = ipv4
    data['ipv6'] = ipv6

    data['tcp_total'], tcp_established, tcp_time_wait = get_tcp_connection()
    data['tcp_stat'] = {
        "ESTABLISHED": tcp_established,
        "TIME_WAIT": tcp_time_wait,
    }
    data['udp_total'] = get_udp_connection()

    net_last_tx, net_last_rx = get_netflow()
    time.sleep(0.5)
    net_tx, net_rx = get_netflow()
    data['net_sent_speed'] = f"{calc_bytes((net_tx - net_last_tx) / 0.5)} /s"
    data['net_recv_speed'] = f"{calc_bytes((net_rx - net_last_rx) / 0.5)} /s"
    data['net_sent'] = calc_bytes(net_tx)
    data['net_recv'] = calc_bytes(net_rx)

    # 获取延迟和丢包率
    data['delay'] = config["delay"]
    data['Pocketlossrate'] = config["Pocketlossrate"]

    # 发送数据到服务器
    send_data_to_server(data)

# 运行主程序
if __name__ == "__main__":
    get_opt()
    while True:
        try:
            func()
            get_delay()
        except Exception as e:
            log_error(f"执行 func 时发生错误: {e}")
