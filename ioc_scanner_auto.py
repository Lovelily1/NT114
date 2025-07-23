import os
import re
import json
import csv
import argparse
from datetime import datetime

# ===================== IOC SIGNATURES ===================== #

SIGNATURES = [
    {
        "name": "Process Spawned from Explorer (Suspicious)",
        "target": "static_sys_proc_proc-v.txt",
        "regex": re.compile(r"Parent:.*explorer\\.exe.*\n.*Image:.*\\(powershell|cmd|wscript|mshta)\\.exe", re.IGNORECASE)
    },
    {
        "name": "Fake svchost from user folder",
        "target": "cmdline.txt",
        "regex": re.compile(r"svchost\\.exe.*\\Users\\", re.IGNORECASE)
    },
    {
        "name": "Suspicious DLL loaded from outside system folders",
        "target": "modules.txt",
        "regex": re.compile(r"Path:\s+(?!C:\\(Windows|Program Files)).*\\.dll", re.IGNORECASE)
    },
    {
        "name": "C2 IP over HTTP/HTTPS",
        "target": "static_sys_net_netstat-v.txt",
        "regex": re.compile(r"\b\d{1,3}(\.\d{1,3}){3}:\d+\s+ESTABLISHED\s+.*:(80|443|8080)\b")
    },
    {
        "name": "HTTP URL in memory or cmdline",
        "target": "*",
        "regex": re.compile(r"https?://[^\s\"']{5,}", re.IGNORECASE)
    },
    {
        "name": "EXECUTE_READWRITE memory region",
        "target": "malfind.txt",
        "regex": re.compile(r"Protection.*EXECUTE_READWRITE", re.IGNORECASE)
    },
    {
        "name": "Shellcode/YARA rule detected",
        "target": "yara.txt",
        "regex": re.compile(r"(Reflective|MZARU|CobaltStrike|Shellcode|XOR)", re.IGNORECASE)
    },
    {
        "name": "Handle write access to DLL/PE",
        "target": "handles.txt",
        "regex": re.compile(r"HandleType:\s+File.*\n.*Path:.*\\.dll.*\n.*Access:.*0x[0-9a-f]+", re.IGNORECASE)
    },
    
    #{
        #"name": "Patched System DLLs (clr/combase/mscoree)",
        #"target": "static_forensic_findevil_findevil.txt",
        #"regex": re.compile(r"PE_PATCHED.*(clr\\.dll|combase\\.dll|mscoree\\.dll)", re.IGNORECASE)
    #},
    #{
        #"name": "RWX in Known DLL",
        #"target": "static_forensic_findevil_findevil.txt",
        #"regex": re.compile(r"Image.*--wxc.*(clr\\.dll|combase\\.dll|mscoree\\.dll)", re.IGNORECASE)
    #},
    #{
        #"name": "Heap RWX Shellcode Detected",
        #"target": "static_forensic_findevil_findevil.txt",
        #"regex": re.compile(r"PRIVATE_RWX.*p-rwx.*HEAP", re.IGNORECASE)
    #},
    #{
        #"name": "Multiple RWX regions in Process (>=3)",
        #"target": "static_forensic_findevil_findevil.txt",
        #"regex": re.compile(r"(PRIVATE_RWX.*p-rwx)", re.IGNORECASE)
    #},
    #{
        #"name": "Generic YARA Threat Match",
        #"target": "static_forensic_findevil_findevil.txt",
        #"regex": re.compile(r"YR_GENERIC_THR.*Windows_Generic_Threat_", re.IGNORECASE)
    #},
    
    {
        "name": "Executable with High Entropy in FindEvil",
        "target": "static_forensic_findevil_findevil.txt",
        "regex": re.compile(r"^.*HIGH_ENTROPY.*\.exe.*Entropy:\s*\[(7\.[1-9]|[89]\.\d+).*$", re.IGNORECASE | re.MULTILINE)
    },
    {
        "name": "YARA Trojan Detection (with PID & Process)",
        "target": "static_forensic_findevil_findevil.txt",
        "regex": re.compile(r"\s+(?P<PID>\d+)\s+(?P<Process>\S+)\s+YR_TROJAN\s+\S+\s+(?P<Description>Windows_Trojan_.*?)\s", re.IGNORECASE)
    },
    {
        "name": "Process name is hash (likely packed or unknown malware)",
        "target": "static_sys_proc_proc-v.txt",
        "regex": re.compile(r"Image:.*\\([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\\.exe", re.IGNORECASE)
    }
]

# ===================== SCAN LOGIC ===================== #

def match_signature(file_path, content, signature):
    if signature["name"] == "Multiple RWX regions in Process (>=3)":
        match_list = signature["regex"].findall(content)
        if len(match_list) >= 3:
            return {
                "signature": signature["name"],
                "file": file_path,
                "matches": [f"RWX Regions: {len(match_list)}"]
            }
        return None

    # CUSTOM HANDLE: HIGH_ENTROPY full line extract
    elif signature["name"] == "Executable with High Entropy in FindEvil":
        matched_lines = []
        for line in content.splitlines():
            if (
                "HIGH_ENTROPY" in line
                and ".exe" in line
                and re.search(r"Entropy:\s*\[(7\.[1-9]|[89]\.\d+)", line)
            ):
                matched_lines.append(line.strip())
        if matched_lines:
            return {
                "signature": signature["name"],
                "file": file_path,
                "matches": matched_lines[:10]
            }
        return None

    else:
        matches = signature["regex"].findall(content)
        if matches:
            return {
                "signature": signature["name"],
                "file": file_path,
                "matches": matches[:5]
            }
        return None

def scan_result_folder(result_path):
    findings = []
    for root, dirs, files in os.walk(result_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for sig in SIGNATURES:
                        if sig["target"] == '*' or sig["target"].lower() == file.lower():
                            result = match_signature(full_path, content, sig)
                            if result:
                                findings.append(result)
            except Exception:
                continue
    return findings

def extract_ip_for_pid(result_path, pid):
    matched_lines = []
    netstat_file = os.path.join(result_path, "static_sys_net_netstat-v.txt")
    if not os.path.exists(netstat_file):
        return []
    with open(netstat_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if re.search(rf"\b{pid}\b", line):
                matched_lines.append(line.strip())
    return matched_lines

def extract_cmdline_for_pid(result_path, pid):
    pid_folder = os.path.join(result_path, pid)
    cmdline_path = os.path.join(pid_folder, "cmdline.txt")
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
        except Exception as e:
            return f"Error reading cmdline.txt for PID {pid}: {e}"
    return f"cmdline.txt not found for PID {pid}"

def extract_pid_lines_from_findevil(result_path, pid):
    """
    Trích xuất tất cả các dòng từ static_forensic_findevil_findevil.txt có chứa PID đã cho
    """
    matches = []
    finde_vil_path = os.path.join(result_path, "static_forensic_findevil_findevil.txt")
    if not os.path.exists(finde_vil_path):
        return matches

    with open(finde_vil_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Dùng regex để tránh nhầm lẫn PID là 1 phần của số khác
            if re.search(rf"\b{pid}\b", line):
                matches.append(line.strip())
    return matches

# ===================== MAIN ===================== #

def main():
    parser = argparse.ArgumentParser(description="Scan MemProcFS Result Folder for Advanced IOCs")
    parser.add_argument("path", help="Path to result folder from auto_analysis.py")
    parser.add_argument("-o", "--output", default="ioc_summary.json", help="Output file name (JSON)")
    parser.add_argument("--pid", help="Comma-separated list of PIDs to extract network connections and cmdline")
    args = parser.parse_args()

    print(f"[+] Đang quét thư mục: {args.path}\n")
    results = scan_result_folder(args.path)

    if args.pid:
        pid_list = [pid.strip() for pid in args.pid.split(",")]
        for pid in pid_list:
            ip_lines = extract_ip_for_pid(args.path, pid)
            cmdline_info = extract_cmdline_for_pid(args.path, pid)
            finde_vil_matches = extract_pid_lines_from_findevil(args.path, pid)

            if ip_lines:
                results.append({
                    "signature": f"Network connections for PID {pid}",
                    "file": "static_sys_net_netstat-v.txt",
                    "matches": ip_lines
                })

            results.append({
                "signature": f"Cmdline for PID {pid}",
                "file": f"{pid}/cmdline.txt",
                "matches": [cmdline_info]
            })

            if finde_vil_matches:
                results.append({
                    "signature": f"FindEvil entries related to PID {pid}",
                    "file": "static_forensic_findevil_findevil.txt",
                    "matches": finde_vil_matches
                })

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"[✓] Đã lưu kết quả IOC vào: {args.output} ({len(results)} phát hiện)")

if __name__ == "__main__":
    main()
