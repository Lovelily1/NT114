<p align="center">
  <img src="https://www.uit.edu.vn/sites/vi/files/banner_uit.png" alt="Trường Đại học Công nghệ Thông tin | University of Information Technology">
</p>

# AN APPROACH TO THE ANALYSIS OF FILELESS MALWARE BASED ON MEMORY FORENSICS (MỘT CÁCH TIẾP CẬN TRONG VIỆC PHÂN TÍCH MÃ ĐỘC PHI MÃ DỰA TRÊN PHÁP CHỨNG BỘ NHỚ)

## THÀNH VIÊN
| Họ tên | MSSV |
| ------ | ---- |
| Nguyễn Khánh Linh | 22520769 |
| Phạm Thị Cẩm Tiên | 22521473 |

## HƯỚNG DẪN

Đây là script hỗ trợ tự động khởi chạy MemProcFS và Volatility3 sau đó lưu trữ các kết quả cần thiết cho quá trình phân tích pháp chứng bộ nhớ. 
Cách chạy: 

Bước 1: Tải MemProcFS và Volatility3

MemProcFS: https://github.com/ufrisk/MemProcFS

Volatility3: https://github.com/volatilityfoundation/volatility3

Bước 2: Thay đổi giá trị ở phần CẤU HÌNH cho phù hợp với hệ thống.
<img width="1112" height="183" alt="image" src="https://github.com/user-attachments/assets/3297644e-2ef8-44bc-af2a-d4073aceb797" />

Bước 3: Chạy chương trình bằng lệnh: 
```python auto_analysis.py -f "<path-to-memdump>" -p <PID1>,<PID2>,...```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/baa88357-4ea2-4272-963a-c7d9574bf269" />

Hoặc 
```python auto_analysis.py -f "<path-to-memdump>"```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e84736da-1f06-4a57-b0e8-da4e26f2a4c4" />


Kết quả sẽ được lưu ở C:\MemoryAnalysis và có thể thay đổi được tại mục CẤU HÌNH.

Bước 4: Chạy chương trình lọc kết quả được xuất ra ở bước 3

Lệnh chạy chương trình: ```python ioc_scanner_auto.py "<path-to-step-3-output-folder>" [-o <path-to-file-output>] --pid <PID1>,<PID2>,...```

<img width="835" height="77" alt="image" src="https://github.com/user-attachments/assets/696d9990-2e2b-4ee5-b3e4-0ebcce1789cc" />

Ghi chú: File output có dạng .json
