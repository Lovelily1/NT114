import os
import subprocess
import time
import shutil
from datetime import datetime
import sys

sys.setrecursionlimit(5000)

# ==== CẤU HÌNH ====
MEMPROCFS_EXE = r"C:\Users\nguye\Downloads\MemProcFS_files_and_binaries-win_x64-latest\MemProcFS.exe"
MEMORY_IMAGE = r"C:\Users\nguye\Documents\kovter.mem"
VOLATILITY3 = r"C:\Users\nguye\Downloads\volatility3-2.26.0\vol.py"  # Đường dẫn tới vol.py
BAT_FILE = "run_memprocfs.bat"
MOUNT_POINT = "M:\\"
WAIT_SECONDS = 500
RESULT_BASE_DIR = r"C:\MemoryAnalysis"

# ==== DANH SÁCH FILE/THƯ MỤC TĨNH ====
STATIC_PATHS = [
    r"sys\proc\proc-v.txt",
    r"sys\net\netstat-v.txt",
    r"forensic\findevil\findevil.txt",
    r"forensic\findevil\yara.txt"
]

# ==== REGISTRY HKLM ====
HKLM_PATHS = [
    r"registry\HKLM\SYSTEM\CurrentControlSet\Services",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"registry\HKLM\SYSTEM\ControlSet001\Control\ComputerName"
]

# ==== NHẬP PID ====
pids_input = input("Nhập danh sách PID cần trích xuất (phân cách bằng dấu phẩy): ").strip()
pids = [pid.strip() for pid in pids_input.split(",") if pid.strip().isdigit()]
if not pids:
    print("[❌] Không có PID hợp lệ.")
    exit(1)

# ==== CHẠY MEMPROCFS ====
with open(BAT_FILE, "w") as f:
    f.write("@echo off\n")
    f.write(f'"{MEMPROCFS_EXE}" -f "{MEMORY_IMAGE}" -forensic 1\n')
    f.write("pause\n")

print("[*] Đang mở CMD và khởi chạy MemProcFS...")
subprocess.run(f'start "MemProcFS" cmd /k "{BAT_FILE}"', shell=True)

# ==== CHỜ MOUNT ====
print(f"[*] Chờ {WAIT_SECONDS} giây để MemProcFS mount và phân tích xong...")
time.sleep(WAIT_SECONDS)

# ==== TẠO THƯ MỤC KẾT QUẢ ====
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
result_dir = os.path.join(RESULT_BASE_DIR, f"Result_{timestamp}")
os.makedirs(result_dir, exist_ok=True)

# ==== KIỂM TRA MOUNT ====
check_file = os.path.join(MOUNT_POINT, r"sys\proc\proc-v.txt")
if not os.path.isfile(check_file):
    print("[❌] MemProcFS chưa mount đúng hoặc chưa xong.")
    exit(1)

# ==== SAO CHÉP FILE TĨNH ====
print("[*] Đang sao chép các file/thư mục tĩnh...")
for rel_path in STATIC_PATHS:
    src = os.path.join(MOUNT_POINT, rel_path)
    dest = os.path.join(result_dir, rel_path.replace("\\", "_"))
    if os.path.isfile(src):
        try:
            shutil.copy2(src, dest)
            print(f"[+] Copied file: {rel_path}")
        except Exception as e:
            print(f"[!] Lỗi copy file {rel_path}: {e}")

# ==== SAO CHÉP REGISTRY: HKLM ====
print("[*] Copy registry HKLM:")
for rel_path in HKLM_PATHS:
    src = os.path.join(MOUNT_POINT, rel_path)
    dest = os.path.join(result_dir, rel_path.replace("\\", "_"))
    if os.path.isdir(src):
        try:
            shutil.copytree(src, dest)
            print(f"[+] Copied: {rel_path}")
        except Exception as e:
            print(f"[!] Lỗi copy {rel_path}: {e}")
    else:
        print(f"[!] Không tồn tại: {rel_path}")

# ==== SAO CHÉP DỮ LIỆU THEO PID ====
print("[*] Đang sao chép dữ liệu theo PID...")
for pid in pids:
    pid_root = os.path.join(MOUNT_POINT, "pid", pid)
    if not os.path.isdir(pid_root):
        print(f"[!] Không có thư mục cho PID {pid}")
        continue

    # cmdline
    cmdline_file = os.path.join(pid_root, "win-cmdline.txt")
    if os.path.isfile(cmdline_file):
        shutil.copy2(cmdline_file, os.path.join(result_dir, f"{pid}_win-cmdline.txt"))

    # handles.txt
    handles_txt = os.path.join(pid_root, "handles", "handles.txt")
    if os.path.isfile(handles_txt):
        shutil.copy2(handles_txt, os.path.join(result_dir, f"{pid}_handles.txt"))

    # modules
    modules_dir = os.path.join(pid_root, "files", "modules")
    if os.path.isdir(modules_dir):
        try:
            shutil.copytree(modules_dir, os.path.join(result_dir, f"{pid}_modules"))
            print(f"[+] Copied modules của PID {pid}")
        except Exception as e:
            print(f"[!] Lỗi copy modules: {e}")

    # handles
    handles_dir = os.path.join(pid_root, "files", "handles")
    if os.path.isdir(handles_dir):
        try:
            shutil.copytree(handles_dir, os.path.join(result_dir, f"{pid}_handles_dir"))
            print(f"[+] Copied handles của PID {pid}")
        except Exception as e:
            print(f"[!] Lỗi copy handles: {e}")

# ==== CHẠY VOLATILITY3 MALFIND (lọc kết quả thực tế) ====
print("\n[*] Đang chạy volatility3 malfind theo PID (lọc kết quả)...")
for pid in pids:
    output_file = os.path.join(result_dir, f"{pid}_malfind.txt")
    cmd = [
        "python", VOLATILITY3,
        "-f", MEMORY_IMAGE,
        "windows.malfind",
        "--pid", pid
    ]
    print(f"[+] Chạy malfind cho PID {pid}...")
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, text=True)
        lines = result.stdout.splitlines()

        # Lọc phần có kết quả thực tế
        keep_lines = []
        capture = False
        for line in lines:
            if "Offset(P)" in line or "Protection" in line:
                capture = True
            if capture and line.strip():
                keep_lines.append(line)

        if not keep_lines:
            keep_lines = lines  # fallback nếu không có gì được giữ

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(keep_lines))

        print(f"    [+] Đã lọc và lưu kết quả malfind vào: {output_file}")

    except Exception as e:
        print(f"    [!] Lỗi khi chạy malfind cho PID {pid}: {e}")

print(f"\n[✅] Hoàn tất toàn bộ! Dữ liệu đã lưu tại: {result_dir}")
