import re
import time
from zapv2 import ZAPv2
import os

# -----------------------------------------------
# ZAP CONFIG - Use environment variables or defaults
ZAP_ADDRESS = os.getenv("ZAP_ADDRESS", "127.0.0.1")
ZAP_PORT = os.getenv("ZAP_PORT", "8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "vmkqcd8hdro5fc0cct2jv7vvr0")

# -----------------------------------------------
# Helpers


def is_valid_domain(domain):
    return bool(re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", domain))


def is_valid_ip(ip):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))


# -----------------------------------------------
# Run single ZAP scan for given subdomain


def run_single_zap_scan(subdomain):
    """
    Connect to ZAP, run Spider + Active Scan on the subdomain, return alerts.
    """
    # ✅ Validate target
    if not (is_valid_domain(subdomain) or is_valid_ip(subdomain)):
        return {"error": f"Invalid target: {subdomain}"}

    try:
        # ✅ Connect ZAP API
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={
                "http": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
                "https": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
            },
        )
        zap_version = zap.core.version
    except Exception as conn_err:
        return {"error": f"Failed to connect to ZAP: {str(conn_err)}"}

    target_url = f"http://{subdomain}"

    try:
        # ✅ Spider
        zap.spider.set_option_max_children(1)
        zap.spider.set_option_max_depth(1)
        spider_id = zap.spider.scan(target_url)
        time.sleep(2)

        while int(zap.spider.status(spider_id)) < 100:
            print(f"[ZAP] Spider progress: {zap.spider.status(spider_id)}%")
            time.sleep(1)

        # ✅ Active Scan
        zap.ascan.set_option_thread_per_host(20)
        zap.ascan.disable_all_scanners()
        zap.ascan.enable_scanners("40012,40018")  # XSS + SQLi

        ascan_id = zap.ascan.scan(target_url)
        time.sleep(2)

        while int(zap.ascan.status(ascan_id)) < 100:
            print(f"[ZAP] Active Scan progress: {zap.ascan.status(ascan_id)}%")
            time.sleep(2)

        # ✅ Get Alerts
        alerts = zap.core.alerts(baseurl=target_url)

        return {"target": subdomain, "zap_version": zap_version, "alerts": alerts}

    except Exception as scan_err:
        return {"error": f"ZAP scan failed: {str(scan_err)}"}
