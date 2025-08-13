import socket
import ssl
from datetime import datetime
import requests
import json
import subprocess
import os


def enrich_subdomain_info(subdomain_data):
    return {
        "domain": subdomain_data.get("input") or subdomain_data.get("url"),
        "ip": subdomain_data.get("a", []),
        "http_status": subdomain_data.get("status_code"),
        "webserver": subdomain_data.get("webserver"),
        "tls": subdomain_data.get("tls"),
        "tech": subdomain_data.get("tech", []),
    }


def is_subdomain_of(host, domain):
    """Check if host is a subdomain of domain"""
    if not host or not domain:
        return False

    # Remove protocol if present
    if host.startswith(("http://", "https://")):
        host = host.split("://", 1)[1]

    # Remove port if present
    if ":" in host:
        host = host.split(":")[0]

    # Check if it's exactly the domain or a subdomain
    return host == domain or host.endswith("." + domain)


def clean_temp_files(*file_paths):
    """Clean up temporary files"""
    for file_path in file_paths:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[INFO] Cleaned up: {file_path}")
        except Exception as e:
            print(f"[WARN] Failed to clean {file_path}: {e}")


def run_subfinder_and_enrich(domain):
    base_dir = os.path.dirname(__file__)
    tools_dir = os.path.join(base_dir, "..", "tools")

    subfinder_path = os.path.join(tools_dir, "subfinder.exe")
    dnsx_path = os.path.join(tools_dir, "dnsx.exe")
    httpx_path = os.path.join(tools_dir, "httpx.exe")

    sub_out = os.path.join(tools_dir, "subfinder_output.txt")
    dnsx_out = os.path.join(tools_dir, "dnsx_output.json")
    httpx_input = os.path.join(tools_dir, "httpx_input.txt")
    final_out = os.path.join(tools_dir, "full_output.json")
    enriched_out = os.path.join(tools_dir, "enriched_output.json")

    # Clean up any existing temp files first
    clean_temp_files(sub_out, dnsx_out, httpx_input, final_out, enriched_out)

    try:
        print(f"[INFO] Running subfinder for: {domain}")

        # --- Run subfinder ---
        with open(sub_out, "w") as sf_out:
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                stdout=sf_out,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                print(f"[ERROR] Subfinder failed: {result.stderr}")
                return []

        # Check if subfinder found anything
        if not os.path.exists(sub_out) or os.path.getsize(sub_out) == 0:
            print(f"[WARN] No subdomains found by subfinder for {domain}")
            return []

        print(f"[INFO] Running dnsx...")

        # --- Run dnsx ---
        with open(sub_out, "r") as sf_in, open(dnsx_out, "w") as dx_out:
            result = subprocess.run(
                [dnsx_path, "-silent", "-json"],
                stdin=sf_in,
                stdout=dx_out,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                print(f"[ERROR] DNSx failed: {result.stderr}")
                return []

        print(f"[INFO] Processing dnsx output and filtering hosts...")

        # --- Extract and validate hosts ---
        filtered_hosts = []

        if os.path.exists(dnsx_out):
            with open(dnsx_out, "r") as dx_in:
                for line in dx_in:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            host = data.get("host")
                            if host and is_subdomain_of(host, domain):
                                filtered_hosts.append(host)
                                print(f"[INFO] Valid subdomain: {host}")
                            elif host:
                                print(f"[WARN] Ignored unrelated host: {host}")
                        except json.JSONDecodeError as e:
                            print(
                                f"[WARN] Failed to parse JSON line: {line[:100]}... Error: {e}"
                            )

        if not filtered_hosts:
            print(f"[WARN] No valid subdomains found for {domain}")
            return []

        print(f"[INFO] Found {len(filtered_hosts)} valid subdomains")

        # Write filtered hosts to httpx input file
        with open(httpx_input, "w") as f:
            for host in filtered_hosts:
                f.write(host + "\n")

        print(f"[INFO] Running httpx on {len(filtered_hosts)} hosts...")

        # --- Run httpx ---
        with open(httpx_input, "r") as hx_in, open(final_out, "w") as fx_out:
            result = subprocess.run(
                [httpx_path, "-silent", "-json", "-tls-probe"],
                stdin=hx_in,
                stdout=fx_out,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                print(f"[ERROR] HTTPx failed: {result.stderr}")
                return []

        print(f"[INFO] Processing httpx results and filtering...")

        # --- Process and filter httpx results ---
        enriched_results = []

        if os.path.exists(final_out):
            with open(final_out, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            result = json.loads(line)
                            host_or_url = (
                                result.get("input")
                                or result.get("url")
                                or result.get("host")
                            )

                            # Double-check that this result is for our target domain
                            if host_or_url and is_subdomain_of(host_or_url, domain):
                                print(f"[INFO] Processing valid result: {host_or_url}")
                                info = enrich_subdomain_info(result)
                                info.update(result)  # merge raw + normalized data
                                enriched_results.append(info)
                            else:
                                print(
                                    f"[WARN] Filtered out unrelated result: {host_or_url}"
                                )

                        except json.JSONDecodeError as e:
                            print(
                                f"[WARN] Failed to parse HTTPx JSON: {line[:100]}... Error: {e}"
                            )

        print(f"[INFO] Final results: {len(enriched_results)} valid subdomains")

        # Write enriched results
        if enriched_results:
            with open(enriched_out, "w") as ef:
                json.dump(enriched_results, ef, indent=2)
            print(f"[INFO] Wrote enriched output to: {enriched_out}")
        else:
            print(f"[WARN] No valid results to write")

        return enriched_results

    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return []

    finally:
        # Optional: Clean up temp files (comment out if you want to inspect them)
        # clean_temp_files(sub_out, dnsx_out, httpx_input, final_out)
        pass
