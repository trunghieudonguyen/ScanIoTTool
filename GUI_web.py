from flask import Flask, render_template, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import wifi_network_scanner
import socket
import pandas as pd
import json
import os
import pytz
from datetime import datetime, timezone
from scan_IoT import run_nmap, parse_nmap_output, run_metasploit, parse_msf_output

app = Flask(__name__, static_url_path='/static')

#Múi giờ Việt Nam
VN_TZ = pytz.timezone('Asia/Ho_Chi_Minh')

# Cấu hình database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_history.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # 🔹 Đảm bảo dòng này có mặt và nằm sau db

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    mac = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    services = db.Column(db.Text, nullable=True)
    security_checked = db.Column(db.Boolean, default=False)
    device_type = db.Column(db.String(50), nullable=True)
    open_ports = db.Column(db.String(200), nullable=True)
    vulnerability_count = db.Column(db.Integer, nullable=True)  # <-- Đảm bảo tên đúng

with app.app_context():
    db.create_all()

devices_cache = []

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Không xác định"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan_network():
    global devices_cache
    devices_cache = wifi_network_scanner.scan_network()
    for device in devices_cache:
        device['device_type'] = get_device_name(device['ip'])
        existing_device = ScanHistory.query.filter_by(ip=device['ip']).first()

        open_ports = device.get('ports', [])
        services = device.get('services', [])

        open_ports_list = open_ports.split(", ") if isinstance(open_ports, str) else []
        open_ports_str = ", ".join(sorted(set(open_ports_list))).strip(", ") if open_ports_list else "N/A"
        services_str = ", ".join(sorted(set(map(str, services)))) if services else "N/A"

        if existing_device:
            existing_device.mac = device['mac']
            existing_device.device_type = device['device_type']
            existing_device.open_ports = open_ports_str  # Cập nhật lại
            existing_device.services = services_str
            existing_device.timestamp = datetime.now(pytz.timezone('Asia/Ho_Chi_Minh'))
        else:
            new_entry = ScanHistory(
                ip=device['ip'],
                mac=device['mac'],
                device_type=device['device_type'],
                open_ports=open_ports_str,  # Đảm bảo đúng định dạng
                services=services_str,
                timestamp = datetime.now(pytz.timezone('Asia/Ho_Chi_Minh'))
            )

            db.session.add(new_entry)

    db.session.commit()

    return jsonify({'status': 'success', 'devices': devices_cache})

@app.route('/check_security', methods=['POST'])
def check_security():
    ip_address = request.json.get('ip')
    if not ip_address:
        return jsonify({'status': 'error', 'message': 'Không có IP được cung cấp!'}), 400

    # Tìm thiết bị trong cache
    device_info = next((d for d in devices_cache if d['ip'] == ip_address), None)
    if not device_info:
        return jsonify({'status': 'error', 'message': 'Không tìm thấy thiết bị!'}), 404

    # Chạy kiểm tra bảo mật
    nmap_vulns = parse_nmap_output(run_nmap(ip_address))
    msf_vulns = parse_msf_output(run_metasploit(ip_address))
    all_vulns = list(set(nmap_vulns + msf_vulns)) or ["Chưa tìm thấy lỗ hổng bảo mật"]

    # Kiểm tra xem thiết bị đã có trong database chưa
    history = ScanHistory.query.filter_by(ip=ip_address).order_by(ScanHistory.timestamp.desc()).first()

    if history:
        # Cập nhật thông tin bảo mật
        history.security_checked = True
        history.vulnerability_count = len(all_vulns) if all_vulns != ["Chưa tìm thấy lỗ hổng bảo mật"] else 0
        history.services = ", ".join(all_vulns)
    else:
        # Nếu chưa có, thêm mới
        history = ScanHistory(
            ip=device_info['ip'],
            mac=device_info['mac'],
            timestamp = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Ho_Chi_Minh'))),
            vulnerability_count=len(all_vulns) if all_vulns != ["Chưa tìm thấy lỗ hổng bảo mật"] else 0,
            services=", ".join(all_vulns),
            security_checked=True
        )
        db.session.add(history)

    db.session.commit()  # Lưu thay đổi vào database

    security_info = {
        'ip': device_info['ip'],
        'mac': device_info['mac'],
        'open_ports': device_info.get('ports', 'N/A'),
        'vulnerabilities': all_vulns,
        'recommendations': 'Cập nhật firmware và đóng các cổng không cần thiết.'
    }

    return jsonify({'status': 'success', 'security_info': security_info})

@app.route('/history')
def history_page():
    histories = ScanHistory.query.filter_by(security_checked=True).order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', histories=histories)

@app.route('/history/api')
def history_api():
    histories = ScanHistory.query.filter_by(security_checked=True).order_by(ScanHistory.timestamp.desc()).all()

    data = [{
        "id": h.id,
        "ip": h.ip,
        "mac": h.mac,
        "timestamp": h.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "vulnerability_count": len(h.services.split(", ")) if h.services and h.services != "N/A" else 0
    } for h in histories]

    return jsonify({"status": "success", "histories": data})

@app.route('/search', methods=['POST'])
def search_devices():
    query = request.json.get('query', '').lower()
    results = [d for d in devices_cache if any(query in str(value).lower() for value in d.values())]
    return jsonify({'status': 'success', 'devices': results})

@app.route('/export', methods=['GET'])
def export_to_excel():
    if not devices_cache:
        return jsonify({'status': 'error', 'message': 'Vui lòng quét mạng trước khi xuất dữ liệu!'}), 400

    df = pd.DataFrame(devices_cache)
    file_path = os.path.join(os.getcwd(), 'scan_results.xlsx')
    df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True)

def load_cve_info(cve_id, base_dir="cvelist"):
    try:
        parts = cve_id.split("-")
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            return {"error": "CVE ID không hợp lệ. Định dạng đúng: CVE-YYYY-NNNN."}

        year, number = parts[1], parts[2]
        folder = f"{year}/{int(number) // 1000}xxx"
        json_file = os.path.join(base_dir, folder, f"{cve_id}.json")

        print(f"🔎 Đang kiểm tra file: {json_file}")  # In ra để kiểm tra đường dẫn

        if not os.path.exists(json_file):
            print("❌ Không tìm thấy file:", json_file)
            return {"error": f"Không tìm thấy dữ liệu cho {cve_id}"}

        with open(json_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        impact = data.get("impact", {}).get("cvss", [{}])[0]
        return {
            "cve_id": data.get("CVE_data_meta", {}).get("ID", "N/A"),
            "description": data.get("description", {}).get("description_data", [{}])[0].get("value", "Không có mô tả."),
            "severity": impact.get("baseSeverity", "Không xác định"),
            "base_score": impact.get("baseScore", "N/A"),
            "attack_vector": impact.get("attackVector", "N/A"),
            "privileges_required": impact.get("privilegesRequired", "N/A"),
            "user_interaction": impact.get("userInteraction", "N/A"),
            "references": [ref.get("url", "N/A") for ref in data.get("references", {}).get("reference_data", [])]
        }

    except Exception as e:
        return {"error": f"Lỗi xử lý dữ liệu: {str(e)}"}

@app.route("/search_cve/<cve_id>")
def search_cve(cve_id):
    result = load_cve_info(cve_id)
    return jsonify(result), (200 if "error" not in result else 404)

@app.route("/search_cve")
def search_cve_page():
    return render_template("search_cve.html")

if __name__ == '__main__':
    app.run(debug=True, port=5001)
