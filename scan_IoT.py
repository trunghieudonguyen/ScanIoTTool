from flask import Flask, request, jsonify
import subprocess
import re
import time

app = Flask(__name__)

def check_postgresql_status():
    result = subprocess.run(["systemctl", "is-active", "postgresql"], capture_output=True, text=True)
    return "active" in result.stdout.strip()

def start_postgresql():
    if not check_postgresql_status():
        subprocess.run(["sudo", "systemctl", "start", "postgresql"], check=True)
        time.sleep(2)

def check_msf_db_status():
    try:
        result = subprocess.run(["msfconsole", "-q", "-x", "db_status; exit"],
                                capture_output=True, text=True, timeout=15)
        return "[*] Connected to msf" in result.stdout
    except subprocess.TimeoutExpired:
        return False

def connect_msf_db():
    if not check_msf_db_status():
        msf_commands = "db_connect msf:msf@127.0.0.1/msf; exit"
        subprocess.run(["msfconsole", "-q", "-x", msf_commands], capture_output=True, text=True, timeout=20)

def run_nmap(target_ip):
    try:
        result = subprocess.run(["nmap", "-sV", "--script", "vulners.nse", target_ip],
                                capture_output=True, text=True, timeout=60)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""

def parse_nmap_output(output):
    return list(set(re.findall(r'CVE-\d{4}-\d+', output)))

def run_metasploit(target_ip):
    msf_commands = f"db_nmap -sV --script=vulners.nse {target_ip}; vulns; exit"
    process = subprocess.Popen(["msfconsole", "-q", "-x", msf_commands],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        output, error = process.communicate(timeout=120)
        return output
    except subprocess.TimeoutExpired:
        process.kill()
        return ""

def parse_msf_output(output):
    return list(set(re.findall(r'CVE-\d{4}-\d+', output)))

@app.route('/check_security', methods=['POST'])
def check_security():
    data = request.get_json()
    ip_address = data.get('ip')
    if not ip_address:
        return jsonify({'status': 'error', 'message': 'Không có IP được cung cấp!'}), 400

    start_postgresql()
    connect_msf_db()

    nmap_output = run_nmap(ip_address)
    nmap_vulns = parse_nmap_output(nmap_output)

    msf_output = run_metasploit(ip_address)
    msf_vulns = parse_msf_output(msf_output)

    all_vulns = set(nmap_vulns + msf_vulns)

    return jsonify({
        'status': 'success',
        'security_info': {
            'ip': ip_address,
            'vulnerabilities': list(all_vulns) if all_vulns else ['Không có lỗ hổng nào được phát hiện']
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
