import os
import subprocess
import time
import shutil
from datetime import datetime
import sys
import argparse

# ==== ĐỌC ĐỐI SỐ TỪ DÒNG LỆNH ====
parser = argparse.ArgumentParser(description="Memory Forensics Automation Script (Grouped by PID)")
parser.add_argument("-f", "--mem", required=True, help="Đường dẫn đến file memory dump (.raw/.mem)")
parser.add_argument("-p", "--pids", help="Danh sách PID cần phân tích, phân cách bằng dấu phẩy (không bắt buộc)")
args = parser.parse_args()

MEMORY_IMAGE = args.mem
INPUT_PIDS = args.pids

# ==== CẤU HÌNH CỐ ĐỊNH ====
MEMPROCFS_EXE = r"C:\Users\nguye\Downloads\MemProcFS_files_and_binaries-win_x64-latest\MemProcFS.exe"
VOLATILITY3 = r"C:\Users\nguye\Downloads\volatility3-2.26.0\vol.py"
BAT_FILE = "run_memprocfs.bat"
MOUNT_POINT = "M:\\"
RESULT_BASE_DIR = r"C:\MemoryAnalysis"

STATIC_PATHS = [
    r"sys\proc\proc-v.txt",
    r"sys\net\netstat-v.txt",
    r"forensic\findevil\findevil.txt",
    r"forensic\findevil\yara.txt"
]

HKLM_PATHS = [
    r"registry\HKLM\SYSTEM\CurrentControlSet\Services",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"registry\HKLM\SYSTEM\ControlSet001\Control\ComputerName"
]

# ==== XỬ LÝ PID ====
if INPUT_PIDS:
    pids = [pid.strip() for pid in INPUT_PIDS.split(",") if pid.strip().isdigit()]
else:
    pids = []

# ==== CHẠY MEMPROCFS ====
with open(BAT_FILE, "w") as f:
    f.write("@echo off\n")
    f.write(f'"{MEMPROCFS_EXE}" -f "{MEMORY_IMAGE}" -forensic 1\n')
    f.write("pause\n")

print("[*] Đang mở CMD và khởi chạy MemProcFS...")
subprocess.run(f'start "MemProcFS" cmd /k "{BAT_FILE}"', shell=True)

# ==== CHỜ FIND_EVIL MOUNT ====
print("[*] Đang chờ MemProcFS mount và xử lý xong forensic (tối đa 10 phút)...")
check_file = os.path.join(MOUNT_POINT, r"forensic\findevil\findevil.txt")
max_wait = 600
interval = 5
elapsed = 0

while not os.path.isfile(check_file):
    time.sleep(interval)
    elapsed += interval
    print(f"  ...chờ {elapsed}/{max_wait} giây", end="\r")
    if elapsed >= max_wait:
        print(f"\n[❌] Quá thời gian chờ ({max_wait} giây) nhưng chưa thấy file: {check_file}")
        exit(1)

print("\n[+] MemProcFS đã mount và sinh forensic đầy đủ (findevil.txt đã sẵn sàng).")

# ==== TẠO THƯ MỤC KẾT QUẢ ====
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
result_dir = os.path.join(RESULT_BASE_DIR, f"Result_{timestamp}")
os.makedirs(result_dir, exist_ok=True)

# ==== SAO CHÉP FILE TĨNH ====
print("[*] Đang sao chép các file tĩnh...")
for rel_path in STATIC_PATHS:
    src = os.path.join(MOUNT_POINT, rel_path)
    dest = os.path.join(result_dir, "static_" + rel_path.replace("\\", "_"))
    if os.path.isfile(src):
        try:
            shutil.copy2(src, dest)
            print(f"[+] Copied file: {rel_path}")
        except Exception as e:
            print(f"[!] Lỗi copy file {rel_path}: {e}")

# ==== SAO CHÉP REGISTRY HKLM ====
print("[*] Copy registry HKLM:")
for rel_path in HKLM_PATHS:
    src = os.path.join(MOUNT_POINT, rel_path)
    dest = os.path.join(result_dir, "HKLM_" + rel_path.replace("\\", "_"))
    if os.path.isdir(src):
        try:
            shutil.copytree(src, dest)
            print(f"[+] Copied: {rel_path}")
        except Exception as e:
            print(f"[!] Lỗi copy {rel_path}: {e}")
    else:
        print(f"[!] Không tồn tại: {rel_path}")

# ==== SAO CHÉP THEO PID ====
if pids:
    print("[*] Đang sao chép dữ liệu theo PID (gộp thư mục)...")
    for pid in pids:
        pid_root = os.path.join(MOUNT_POINT, "pid", pid)
        pid_dir = os.path.join(result_dir, pid)
        os.makedirs(pid_dir, exist_ok=True)

        if not os.path.isdir(pid_root):
            print(f"[!] Không có thư mục cho PID {pid}")
            continue

        # cmdline
        cmdline_file = os.path.join(pid_root, "win-cmdline.txt")
        if os.path.isfile(cmdline_file):
            shutil.copy2(cmdline_file, os.path.join(pid_dir, "cmdline.txt"))

        # handles.txt
        handles_txt = os.path.join(pid_root, "handles", "handles.txt")
        if os.path.isfile(handles_txt):
            shutil.copy2(handles_txt, os.path.join(pid_dir, "handles.txt"))

        # modules
        modules_dir = os.path.join(pid_root, "files", "modules")
        if os.path.isdir(modules_dir):
            try:
                shutil.copytree(modules_dir, os.path.join(pid_dir, "modules"))
                print(f"[+] Copied modules của PID {pid}")
            except Exception as e:
                print(f"[!] Lỗi copy modules: {e}")

        # handles dir
        handles_dir = os.path.join(pid_root, "files", "handles")
        if os.path.isdir(handles_dir):
            try:
                shutil.copytree(handles_dir, os.path.join(pid_dir, "handles"))
                print(f"[+] Copied handles dir của PID {pid}")
            except Exception as e:
                print(f"[!] Lỗi copy handles dir: {e}")

        # ==== CHẠY MALFIND ====
        print(f"[+] Chạy malfind cho PID {pid}...")
        output_file = os.path.join(pid_dir, "malfind.txt")
        cmd = [
            "python", VOLATILITY3,
            "-f", MEMORY_IMAGE,
            "windows.malfind",
            "--pid", pid
        ]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, text=True)
            lines = result.stdout.splitlines()

            keep_lines = []
            capture = False
            for line in lines:
                if "Offset(P)" in line or "Protection" in line:
                    capture = True
                if capture and line.strip():
                    keep_lines.append(line)

            if not keep_lines:
                keep_lines = lines

            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(keep_lines))

            print(f"    [+] Đã lưu malfind.txt vào {output_file}")

        except Exception as e:
            print(f"    [!] Lỗi khi chạy malfind cho PID {pid}: {e}")
else:
    print("[*] Không nhập PID → Bỏ qua phần xử lý theo PID và malfind.")

# ==== TẮT MEMPROCFS ====
print("\n[*] Đang tìm và tắt MemProcFS...")
try:
    import psutil
    for proc in psutil.process_iter(['pid', 'name']):
        if "memprocfs.exe" in proc.info['name'].lower():
            print(f"[+] Tìm thấy MemProcFS (PID: {proc.pid}) → Đang tắt...")
            proc.terminate()
            proc.wait(timeout=5)
            print("[+] Đã tắt MemProcFS.")
except Exception as e:
    print(f"[!] Không thể tắt MemProcFS tự động: {e}")

print(f"\n[✅] Hoàn tất! Kết quả đã lưu tại: {result_dir}")
