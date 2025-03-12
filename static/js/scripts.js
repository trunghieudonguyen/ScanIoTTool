// scripts.js
async function startScan() {
    let modal = document.getElementById('scanModal');
    let scanStatus = document.getElementById('scanStatus');
    let progress = document.querySelector('.progress');

    // Đảm bảo modal đang bị ẩn trước khi hiển thị
    modal.style.display = 'flex';
    scanStatus.innerText = "Đang quét mạng...";
    progress.style.width = "0%";

    let currentWidth = 0;
    let interval = setInterval(() => {
        if (currentWidth < 90) {
            currentWidth += 10;
            progress.style.width = currentWidth + "%";
        }
    }, 500);

    try {
        const response = await fetch('/scan');  
        const data = await response.json();

        clearInterval(interval);
        progress.style.width = "100%";

        setTimeout(() => {
            modal.style.display = 'none'; 
        }, 1000);

        if (data.status === 'success') {
            scanStatus.innerText = "Hoàn tất!";
            populateTable(data.devices);
        } else {
            scanStatus.innerText = "Lỗi: Không tìm thấy thiết bị!";
        }
    } catch (error) {
        clearInterval(interval);
        progress.style.width = "100%";
        scanStatus.innerText = "Lỗi khi quét mạng!";

        setTimeout(() => {
            modal.style.display = 'none';
        }, 1000);
    }
}  

function populateTable(devices) {
    const tbody = document.querySelector('#devicesTable tbody');
    tbody.innerHTML = '';

    devices.forEach(device => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${device.ip}</td>
            <td>${device.mac}</td>
            <td>${device.device_type || 'Không xác định'}</td>
            <td>${device.ports || '-'}</td>
            <td>${device.status || 'Không rõ'}</td>
            <td>
                <button class="check-security-btn" onclick="checkSecurity('${device.ip}')">
                    🔒 Kiểm tra bảo mật
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}        

async function searchDevices() {
    const query = document.getElementById('searchInput').value;
    const response = await fetch('/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
    });

    const data = await response.json();
    if (data.status === 'success') {
        populateTable(data.devices);
    }
}

async function checkSecurity(ip) {
    const response = await fetch('/check_security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });

    const data = await response.json();
    if (data.status === 'success') {
        alert(`Thông tin bảo mật cho ${ip}:\n${JSON.stringify(data.security_info, null, 2)}`);
    } else {
        alert(`Lỗi: ${data.message}`);
    }
}

document.addEventListener("DOMContentLoaded", function () {
    let modal = document.getElementById("scanModal");
    modal.style.display = "none"; // Đảm bảo modal bị ẩn khi trang web vừa mở
});
