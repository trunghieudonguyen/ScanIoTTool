# ScanIoT Tool

## Mô tả
ScanIoT Tool là một công cụ bảo mật IoT giúp quét và đánh giá bảo mật của các thiết bị IoT trong mạng. Công cụ này sử dụng Flask để cung cấp giao diện web và các thư viện như Scapy, Nmap, và Pandas để phân tích dữ liệu.

## Yêu cầu hệ thống
- Hệ điều hành: Kali Linux (hoặc Ubuntu)
- Python 3.7+
- Các thư viện Python cần thiết (được liệt kê trong `requirements.txt`)

## Cài đặt
### 1. Cài đặt các thư viện cần thiết
Bạn có thể cài đặt tất cả các thư viện bằng cách chạy lệnh sau:
```bash
pip3 install -r requirements.txt --break-system-packages
```
Hoặc nếu dùng môi trường ảo (venv):
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Cài đặt các công cụ bổ trợ
Một số công cụ như `nmap` có thể cần được cài đặt thủ công:
```bash
sudo apt update && sudo apt install -y python3-nmap python3-scapy python3-flask python3-flask-migrate python3-pandas
```

## Cách sử dụng
1. Chạy ứng dụng bằng lệnh:
```bash
python3 GUI_web.py
```
2. Mở trình duyệt và truy cập:
```
http://127.0.0.1:5000
```
3. Bắt đầu quét các thiết bị IoT trong mạng của bạn.

## Lưu ý
- Chạy công cụ với quyền root nếu cần quyền truy cập mạng:
```bash
sudo python3 GUI_web.py
```
- Công cụ này chỉ nên được sử dụng trong phạm vi cho phép.

## Tác giả
- **Nguyễn Khắc Hoàng Anh, Đỗ Nguyễn Trung Hiếu, Trần Văn Quang Khải** - Dự án NCKH sinh viên.

## Giấy phép
MIT License.

