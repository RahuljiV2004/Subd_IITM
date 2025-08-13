import ssl, socket, datetime, requests, json, subprocess, time, tempfile, os, sys
from zapv2 import ZAPv2

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config import get_tool_path


def log(message, level="info"):
    return json.dumps(
        {
            "type": "log",
            "message": message,
            "level": level,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
    )


def run_whatweb_scan(domain):
    try:
        whatweb_path = get_tool_path("whatweb")
        result = subprocess.run(
            ["ruby", whatweb_path, "--log-json=-", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        output = result.stdout.decode("utf-8").strip()
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                return data
            except json.JSONDecodeError:
                continue
        return {"error": "No valid JSON output from WhatWeb"}
    except subprocess.CalledProcessError as e:
        return {"error": f"WhatWeb error: {e.stderr.decode('utf-8')}"}
    except Exception as e:
        return {"error": f"Exception: {str(e)}"}


def get_full_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject_common_name": next(
                        (t[0][1] for t in cert["subject"] if t[0][0] == "commonName"),
                        None,
                    ),
                    "issuer_common_name": next(
                        (t[0][1] for t in cert["issuer"] if t[0][0] == "commonName"),
                        None,
                    ),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber", None),
                    "full_raw": cert,
                }
    except Exception as e:
        return {"error": str(e)}


def get_mxtoolbox_data(domain, api_key):
    try:
        url = f"https://api.mxtoolbox.com/api/v1/lookup/dns/{domain}?authorization={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": True,
                "status": response.status_code,
                "message": response.text,
            }
    except Exception as e:
        return {"error": True, "message": str(e)}


def get_http_statuses(subdomain):
    """
    Probe HTTP and HTTPS for one subdomain.
    """
    statuses = {}
    for scheme in ["http://", "https://"]:
        url = f"{scheme}{subdomain}"
        try:
            resp = requests.get(url, timeout=5, verify=False)
            key = f"{scheme.replace('://', '')}_status"
            statuses[key] = resp.status_code
        except Exception as e:
            key = f"{scheme.replace('://', '')}_status"
            statuses[key] = None
    return statuses


def get_http_status_full(subdomain):
    """
    For given subdomain:
      - Probe HTTP and HTTPS
      - Return:
        {
          "http": [status_code or None, final_url or None, server_header or None],
          "https": [status_code or None, final_url or None, server_header or None]
        }
    """
    results = {
        "http": [None, None, None],
        "https": [None, None, None],
    }
    for scheme in ["http://", "https://"]:
        url = f"{scheme}{subdomain}"
        try:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            key = scheme.replace("://", "")
            results[key] = [resp.status_code, resp.url, resp.headers.get("Server")]
        except Exception:
            key = scheme.replace("://", "")
            results[key] = [None, None, None]
    return results


def get_ip_as_array(subdomain):
    """
    Returns IP address as an array: [IP] or [] if failed.
    """
    try:
        ip = socket.gethostbyname(subdomain)
        return [ip]
    except Exception:
        return []


def get_dnsdumpster_data(domain, api_key):
    try:
        url = f"https://api.dnsdumpster.com/domain/{domain}"
        headers = {"X-API-Key": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": True,
                "status": response.status_code,
                "message": response.text,
            }
    except Exception as e:
        return {"error": True, "message": str(e)}


def run_subfinder_scan(domain, subfinder_path="subfinder"):
    """
    Run subfinder to enumerate subdomains
    """
    try:
        # Create temporary file for output
        with tempfile.NamedTemporaryFile(
            mode="w+", delete=False, suffix=".txt"
        ) as sf_out:
            temp_file_path = sf_out.name

        # Run subfinder command
        result = subprocess.run(
            [subfinder_path, "-d", domain, "-silent", "-o", temp_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        # Read results from output file
        subdomains = []
        if os.path.exists(temp_file_path):
            with open(temp_file_path, "r") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        subdomains.append(
                            {"domain": subdomain, "found_by": "subfinder"}
                        )

            # Clean up temp file
            os.unlink(temp_file_path)

        if result.returncode != 0:
            error_msg = (
                result.stderr.strip() if result.stderr else "Unknown subfinder error"
            )
            return {"error": f"Subfinder error: {error_msg}"}

        return subdomains

    except subprocess.TimeoutExpired:
        return {"error": "Subfinder scan timed out after 5 minutes"}
    except FileNotFoundError:
        return {
            "error": "Subfinder not found. Please ensure subfinder is installed and in PATH"
        }
    except Exception as e:
        return {"error": f"Exception running subfinder: {str(e)}"}


def run_subfinder_and_enhance_streaming(
    domain,
    collection,
    mxtoolbox_api_key,
    dnsdumpster_api_key,
    subfinder_path="subfinder",
):
    yield log(f"Starting Subfinder scan on: {domain}", level="info")
    print(f"🚀 Starting Subfinder scan on: {domain}")

    # Run subfinder scan
    subfinder_result = run_subfinder_scan(domain, subfinder_path)

    if isinstance(subfinder_result, dict) and "error" in subfinder_result:
        yield log(f"❌ Subfinder failed: {subfinder_result['error']}", level="error")
        print(f"❌ Subfinder failed: {subfinder_result['error']}")
        return

    results = subfinder_result
    yield log(f"✅ Subfinder completed. {len(results)} subdomains found.", level="info")
    print(f"✅ Subfinder completed. {len(results)} subdomains found.")

    try:
        collection.delete_many({})
        yield log("🗑️ Cleared existing subdomain records in DB", level="warn")
        print("🗑️ Cleared existing subdomain records in DB")
    except Exception as clear_err:
        err_msg = f"❌ Failed to clear old records: {str(clear_err)}"
        yield log(err_msg, level="error")
        print(err_msg)
        return

    # ✅ Setup ZAP once
    ZAP_ADDRESS = "127.0.0.1"
    ZAP_PORT = "8080"
    ZAP_API_KEY = "vmkqcd8hdro5fc0cct2jv7vvr0"

    try:
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={
                "http": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
                "https": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
            },
        )
        zap_version = zap.core.version
        print(f"[+] Connected to ZAP version: {zap_version}")
        yield log(f"Connected to ZAP version: {zap_version}", level="info")
    except Exception as zap_err:
        zap = None
        warn_msg = f"[❌] Failed to connect to ZAP: {str(zap_err)}"
        print(warn_msg)
        yield log(warn_msg, level="warn")

    for idx, entry in enumerate(results):
        try:
            subdomain = entry.get("domain")
            message = f"[{idx + 1}/{len(results)}] ▶️ Processing: {subdomain}"
            print(message)
            # === IP ===
            ip_data = get_ip_as_array(subdomain)
            # # ✅ HTTP & HTTPS status
            statuses = get_http_status_full(subdomain)

            http_msg = f"🌐 HTTP: {statuses['http']}, HTTPS: {statuses['https']}"
            print(f"   {http_msg}")
            yield log(http_msg, level="info")

            # ✅ SSL Cert
            cert_data = get_full_certificate(subdomain)
            if "error" in cert_data:
                warning = f"⚠️ SSL Fetch Failed: {cert_data['error']}"
                print(f"   {warning}")
                yield log(warning, level="warn")
            else:
                cert_msg = f"🔐 SSL Cert: CN={cert_data.get('subject_common_name')}"
                print(f"   {cert_msg}")
                yield log(cert_msg, level="info")

            # ✅ MXToolbox
            mxtoolbox_data = get_mxtoolbox_data(subdomain, mxtoolbox_api_key)
            if mxtoolbox_data.get("error"):
                warning = f"⚠️ MXToolbox Failed: {mxtoolbox_data.get('message')}"
                print(f"   {warning}")
                yield log(warning, level="warn")
            else:
                success_msg = f"📡 MXToolbox Lookup Success"
                print(f"   {success_msg}")
                yield log(success_msg, level="info")

            # # ✅ DNSDumpster
            # dnsdumpster_data = get_dnsdumpster_data(subdomain, dnsdumpster_api_key)
            # if dnsdumpster_data.get("error"):
            #     warning = f"⚠️ DNSDumpster Failed: {dnsdumpster_data.get('message')}"
            #     print(f"   {warning}")
            #     yield log(warning, level="warn")
            # else:
            #     success_msg = f"🔎 DNSDumpster Lookup Success"
            #     print(f"   {success_msg}")
            #     yield log(success_msg, level="info")

            # # ✅ WhatWeb
            # whatweb_data = run_whatweb_scan(subdomain)
            # if whatweb_data.get("error"):
            #     warning = f"⚠️ WhatWeb Failed: {whatweb_data['error']}"
            #     print(f"   {warning}")
            #     yield log(warning, level="warn")
            # else:
            #     success_msg = f"🕵️ WhatWeb Fingerprint Success"
            #     print(f"   {success_msg}")
            #     yield log(success_msg, level="info")

            # ✅ ZAP Scan
            if zap:
                try:
                    zap.spider.set_option_max_children(1)
                    zap.spider.set_option_max_depth(1)
                    spider_id = zap.spider.scan(f"http://{subdomain}")
                    time.sleep(1)
                    while int(zap.spider.status(spider_id)) < 100:
                        print(f"   🕷️ Spider progress: {zap.spider.status(spider_id)}%")
                        time.sleep(1)
                    print(f"   ✅ Spider done for: {subdomain}")

                    zap.ascan.set_option_thread_per_host(20)
                    zap.ascan.disable_all_scanners()
                    zap.ascan.enable_scanners("40012,40018")  # XSS & SQLi
                    ascan_id = zap.ascan.scan(f"http://{subdomain}")
                    time.sleep(2)
                    while int(zap.ascan.status(ascan_id)) < 100:
                        print(
                            f"   ⚡ Active Scan progress: {zap.ascan.status(ascan_id)}%"
                        )
                        time.sleep(2)
                    print(f"   ✅ Active Scan done for: {subdomain}")

                    zap_alerts = zap.core.alerts(baseurl=f"http://{subdomain}")
                    zap_msg = f"🛡️ ZAP found {len(zap_alerts)} alerts for: {subdomain}"
                    print(f"   {zap_msg}")
                    yield log(zap_msg, level="info")

                    entry["zap_alerts"] = zap_alerts

                except Exception as zap_scan_err:
                    zap_err_msg = (
                        f"⚠️ ZAP scan failed for {subdomain}: {str(zap_scan_err)}"
                    )
                    print(f"   {zap_err_msg}")
                    yield log(zap_err_msg, level="warn")
            else:
                warn_nozap = "⚠️ ZAP not connected; skipping ZAP scan."
                print(f"   {warn_nozap}")
                yield log(warn_nozap, level="warn")
            http_data = get_http_status_full(subdomain)
            # ✅ Add everything
            entry["cert_details"] = cert_data
            entry["http"] = http_data["http"]  # [200] or []
            entry["https"] = http_data["https"]  # [403] or []
            entry["ip"] = ip_data
            entry["mxtoolbox"] = mxtoolbox_data
            # entry["dnsdumpster"] = dnsdumpster_data
            # entry["whatweb"] = whatweb_data
            entry["scanned_at"] = datetime.datetime.utcnow().isoformat()

            # ✅ Store in MongoDB
            res = collection.update_one(
                {"domain": subdomain}, {"$set": entry}, upsert=True
            )
            if res.acknowledged:
                mongo_msg = f"✅ MongoDB Updated: {subdomain}"
                print(f"   {mongo_msg}")
                yield log(mongo_msg, level="success")
            else:
                warn_msg = f"⚠️ MongoDB update not acknowledged for: {subdomain}"
                print(f"   {warn_msg}")
                yield log(warn_msg, level="warn")

            yield json.dumps(entry)

        except Exception as entry_err:
            error_msg = f"❌ Error processing {entry.get('domain', 'unknown')}: {str(entry_err)}"
            print(f"   {error_msg}")
            yield log(error_msg, level="error")
            continue

    print("🏁 Scan & enrichment complete.")
    yield log("🏁 Scan & enrichment complete.", level="success")
