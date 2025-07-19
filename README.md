Đây là script hỗ trợ tự động khởi chạy MemProcFS và Volatility3 sau đó lưu trữ các kết quả cần thiết cho quá trình phân tích pháp chứng bộ nhớ. 
Cách chạy: 

Bước 1: Tải MemProcFS và Volatility3

MemProcFS: https://github.com/ufrisk/MemProcFS

Volatility3: https://github.com/volatilityfoundation/volatility3

Bước 2: Thay đổi giá trị ở phần CẤU HÌNH cho phù hợp với hệ thống.
<img width="1112" height="183" alt="image" src="https://github.com/user-attachments/assets/3297644e-2ef8-44bc-af2a-d4073aceb797" />

Bước 3: Chạy chương trình bằng lệnh: 
```python auto_analysis.py -f "C:\Users\nguye\Documents\kovter.mem" -p 8128```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/baa88357-4ea2-4272-963a-c7d9574bf269" />

Hoặc
```python auto_analysis.py -f "C:\Users\nguye\Documents\kovter.mem"```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e84736da-1f06-4a57-b0e8-da4e26f2a4c4" />


Kết quả sẽ được lưu ở C:\MemoryAnalysis và có thể thay đổi được tại mục CẤU HÌNH.
