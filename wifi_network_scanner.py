import scapy.all as scapy
import socket
import ipaddress
import nmap
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def get_network_range():
    local_ip = get_local_ip()
    if not local_ip:
        return None
    network_prefix = '.'.join(local_ip.split('.')[:3])
    return f"{network_prefix}.1/24"

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=0.5, verbose=False, multi=True)[0]
    devices = []
    for answer in answered_list:
        devices.append({"ip": answer[1].psrc, "mac": answer[1].hwsrc})
    return devices

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-T5 -F --min-parallelism 50 --max-retries 1")
        ports = [str(port) for port in nm[ip]['tcp']] if 'tcp' in nm[ip] else []
        return ", ".join(ports) if ports else "Không có"
    except:
        return "Không xác định"

def check_status(ip, devices):
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL)
        return "Đang hoạt động"
    except subprocess.CalledProcessError:
        for device in devices:
            if device["ip"] == ip:
                return "Đang hoạt động"
        return "Đăng tắt"

def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return "Không xác định"

def ip_to_number(ip):
    return int(ipaddress.IPv4Address(ip))

def scan_network():
    network_range = get_network_range()
    if not network_range:
        return []

    devices = scan(network_range)
    results = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_device = {executor.submit(scan_ports, device["ip"]): device for device in devices}
        vendor_futures = {executor.submit(get_vendor, device["mac"]): device for device in devices}
        
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            try:
                ports = future.result()
            except Exception:
                ports = "Không xác định"
            results.append({
                "status": "Đang kiểm tra...",
                "ip": device["ip"],
                "mac": device["mac"],
                "device_name": "Đang lấy dữ liệu...",
                "ports": ports
            })
        
        for future in as_completed(vendor_futures):
            device = vendor_futures[future]
            try:
                vendor = future.result()
            except Exception:
                vendor = "Không xác định"
            for result in results:
                if result["mac"] == device["mac"]:
                    result["device_name"] = vendor
                    break
        
        for result in results:
            result["status"] = check_status(result["ip"], devices)

    sorted_results = sorted(results, key=lambda x: ip_to_number(x["ip"]))
    return sorted_results

if __name__ == "__main__":
    devices = scan_network()
    for d in devices:
        print(d)