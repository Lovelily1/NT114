Đây là script hỗ trợ tự động khởi chạy MemProcFS và Volatility3 sau đó lưu trữ các kết quả cần thiết cho quá trình phân tích pháp chứng bộ nhớ. 
Cách chạy: 

Bước 1: Tải MemProcFS và Volatility3

MemProcFS: https://github.com/ufrisk/MemProcFS

Volatility3: https://github.com/volatilityfoundation/volatility3

Bước 2: Thay đổi giá trị ở phần CẤU HÌNH cho phù hợp với hệ thống.
<img width="1017" height="413" alt="image" src="https://github.com/user-attachments/assets/91255a0a-099d-4ccf-be01-aa072df0872b" />

Bước 3: Chạy chương trình bằng lệnh: 
```python auto_analysis.py```
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/057fac96-b7ae-49e0-967c-343b33335f9c" />
Hoặc:
```python Auto_and_End.py```
Nếu muốn tự động dừng MemProcFS sau khi phân tích xong.

Kết quả sẽ được lưu ở C:\MemoryAnalysis và có thể thay đổi được tại mục CẤU HÌNH.
