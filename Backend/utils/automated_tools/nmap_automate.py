import subprocess
import shutil
import re
from .db_utils import append_tool_result
from datetime import datetime


def is_valid_domain(domain):
    return bool(re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", domain))


def is_valid_ip(ip):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))


def extract_target_from_nmap(command):
    parts = command.strip().split()
    for part in reversed(parts):
        if is_valid_ip(part) or is_valid_domain(part):
            return part
    return None


def run_nmap_custom(command_str, scan_id=None):
    if not shutil.which("nmap"):
        return {"error": "Nmap not found in PATH"}

    target = extract_target_from_nmap(command_str)
    if not target:
        return {"error": "Target domain or IP not found in command"}

    try:
        print(f"📡 Running: {command_str}")
        process = subprocess.Popen(
            command_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        output_lines = []
        open_ports = []

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break

            if line:
                print(line.strip())  # Live output to terminal
                output_lines.append(line)

                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    if port.isdigit():
                        open_ports.append(int(port))

        full_output = "".join(output_lines)

        if scan_id:
            append_tool_result(
                scan_id=scan_id,
                tool_name="nmap",
                command=command_str,
                output=full_output,
            )

        return {"target": target, "open_ports": open_ports, "raw_output": full_output}

    except Exception as e:
        if scan_id:
            append_tool_result(
                scan_id=scan_id, tool_name="nmap", command=command_str, output=str(e)
            )
        return {"error": str(e)}
