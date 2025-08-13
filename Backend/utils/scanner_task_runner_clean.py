import os
import subprocess
import uuid
import json
from datetime import datetime
import pytz

india = pytz.timezone("Asia/Kolkata")  # ✅ IST timezone


def run_scan_once(domain, collection):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tools_dir = os.path.join(base_dir, "..", "tools")
    suffix = ".exe" if os.name == "nt" else ""

    subfinder = os.path.join(tools_dir, f"subfinder{suffix}")
    dnsx = os.path.join(tools_dir, f"dnsx{suffix}")
    httpx = os.path.join(tools_dir, f"httpx{suffix}")
    nuclei = os.path.join(tools_dir, f"nuclei{suffix}")

    # ✅ Use IST for scan_id timestamp
    scan_id = datetime.now(india).strftime("%Y%m%d%H%M%S") + "_" + str(uuid.uuid4())
    print(f"[AUTO-SCAN] Starting scan session: {scan_id} for {domain}")

    proc = subprocess.run(
        [subfinder, "-d", domain, "-silent"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True,
    )

    if proc.returncode != 0:
        print(f"[AUTO-SCAN] Subfinder failed: {proc.stderr}")
        return {"status": "failed", "reason": "subfinder error"}

    subdomains = list(set(proc.stdout.strip().splitlines()))

    success_count = 0

    for i, sub in enumerate(subdomains, 1):
        row = {
            "scan_id": scan_id,
            "subdomain": sub,
            "subfinder_found": True,
            "domain": domain,
            "scanned_at": datetime.now(india).isoformat(),
        }

        # DNSX
        dnsx_proc = subprocess.run(
            [dnsx, "-silent", "-json"],
            input=sub,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        )
        if dnsx_proc.returncode == 0 and dnsx_proc.stdout.strip():
            try:
                dnsx_entry = json.loads(dnsx_proc.stdout.strip())
                row.update({f"dnsx_{k}": v for k, v in dnsx_entry.items()})
            except json.JSONDecodeError:
                print(f"[AUTO-SCAN] JSON error in dnsx for {sub}")

        # HTTPX
        httpx_proc = subprocess.run(
            [httpx, "-silent", "-json", "-tls-probe"],
            input=sub.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=True,
        )
        if httpx_proc.returncode == 0 and httpx_proc.stdout.strip():
            try:
                decoded = httpx_proc.stdout.decode(errors="ignore").strip()
                if decoded:
                    httpx_entry = json.loads(decoded)
                    for k, v in httpx_entry.items():
                        if k == "tls" and isinstance(v, dict):
                            for subk, subv in v.items():
                                row[f"httpx_tls_{subk}"] = subv
                        elif k != "tls":
                            row[f"httpx_{k}"] = v
            except json.JSONDecodeError:
                print(f"[AUTO-SCAN] JSON error in httpx for {sub}")

        # Nuclei
        if "httpx_url" in row:
            nuclei_proc = subprocess.run(
                [nuclei, "-u", row["httpx_url"], "-json", "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
            )
            if nuclei_proc.returncode == 0 and nuclei_proc.stdout.strip():
                try:
                    lines = nuclei_proc.stdout.strip().splitlines()
                    nuclei_results = [
                        json.loads(line) for line in lines if line.strip()
                    ]
                    row["vulnerabilities"] = nuclei_results
                except json.JSONDecodeError:
                    print(f"[AUTO-SCAN] JSON error in nuclei for {sub}")

        try:
            collection.insert_one(row)
            success_count += 1
        except Exception as e:
            print(f"[AUTO-SCAN] MongoDB insert failed for {sub}: {e}")

    print(
        f"[AUTO-SCAN] Done scanning {domain} with {success_count}/{len(subdomains)} stored."
    )
    return {
        "status": "completed",
        "domain": domain,
        "subdomains_found": len(subdomains),
        "subdomains_stored": success_count,
        "scan_id": scan_id,
    }
