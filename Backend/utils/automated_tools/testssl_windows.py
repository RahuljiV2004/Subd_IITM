#!/usr/bin/env python3
"""
Windows-compatible SSL/TLS scanner
Alternative to testssl.sh for Windows environments
"""

import subprocess
import socket
import ssl
import json
from datetime import datetime
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))


def run_testssl_scan(target_url):
    """
    Run SSL/TLS security test using Python ssl module
    Alternative to testssl.sh for Windows
    """
    print(f"🔍 Running SSL/TLS analysis on {target_url}...")

    try:
        # Parse target URL
        if "://" in target_url:
            hostname = target_url.split("://")[1].split("/")[0].split(":")[0]
        else:
            hostname = target_url.split("/")[0].split(":")[0]

        port = 443  # Default HTTPS port

        results = {
            "target": target_url,
            "hostname": hostname,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "ssl_issues": [],
            "certificate_info": {},
            "protocols": {},
            "ciphers": [],
        }

        # Test SSL connection
        print(f"🔗 Connecting to {hostname}:{port}...")

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate information
                cert = ssock.getpeercert()
                results["certificate_info"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "signature_algorithm": cert.get("OCSP", {}).get(
                        "signature_algorithm", "Unknown"
                    ),
                }

                # Get SSL/TLS version
                results["protocols"]["tls_version"] = ssock.version()
                results["protocols"]["cipher"] = ssock.cipher()

                print(f"✅ SSL/TLS Version: {ssock.version()}")
                print(f"✅ Cipher: {ssock.cipher()}")

        # Check for common SSL issues
        ssl_issues = []

        # Check certificate expiry
        if cert.get("notAfter"):
            try:
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry - datetime.now()).days

                if days_until_expiry < 30:
                    ssl_issues.append(
                        {
                            "issue": "Certificate Expiry Warning",
                            "severity": "high" if days_until_expiry < 7 else "medium",
                            "description": f"Certificate expires in {days_until_expiry} days",
                            "recommendation": "Renew SSL certificate",
                        }
                    )
            except Exception as e:
                print(f"⚠️ Could not parse certificate expiry: {e}")

        # Check for weak protocols (basic check)
        if results["protocols"]["tls_version"] in [
            "SSLv2",
            "SSLv3",
            "TLSv1",
            "TLSv1.1",
        ]:
            ssl_issues.append(
                {
                    "issue": "Weak SSL/TLS Protocol",
                    "severity": "high",
                    "description": f"Using outdated protocol: {results['protocols']['tls_version']}",
                    "recommendation": "Upgrade to TLS 1.2 or higher",
                }
            )

        # Check cipher strength (basic check)
        cipher_info = results["protocols"]["cipher"]
        if cipher_info and len(cipher_info) >= 2:
            cipher_name = cipher_info[0]
            if any(weak in cipher_name for weak in ["RC4", "DES", "MD5", "NULL"]):
                ssl_issues.append(
                    {
                        "issue": "Weak Cipher Suite",
                        "severity": "medium",
                        "description": f"Weak cipher detected: {cipher_name}",
                        "recommendation": "Use stronger cipher suites",
                    }
                )

        results["ssl_issues"] = ssl_issues

        # Format output
        output = f"=== SSL/TLS Security Analysis for {target_url} ===\n"
        output += f"Target: {hostname}:{port}\n"
        output += f"TLS Version: {results['protocols']['tls_version']}\n"

        if cipher_info:
            output += f"Cipher: {cipher_info[0]} ({cipher_info[1]} bits)\n"

        # Certificate information
        cert_info = results["certificate_info"]
        if cert_info.get("subject"):
            output += f"\n=== Certificate Information ===\n"
            output += f"Subject: {cert_info['subject'].get('commonName', 'Unknown')}\n"
            output += (
                f"Issuer: {cert_info['issuer'].get('organizationName', 'Unknown')}\n"
            )
            output += f"Valid From: {cert_info.get('not_before', 'Unknown')}\n"
            output += f"Valid Until: {cert_info.get('not_after', 'Unknown')}\n"

        # Security issues
        if ssl_issues:
            output += f"\n=== Security Issues Found ===\n"
            for issue in ssl_issues:
                output += f"❌ {issue['issue']} [{issue['severity']}]\n"
                output += f"   {issue['description']}\n"
                output += f"   Recommendation: {issue['recommendation']}\n"
        else:
            output += f"\n✅ No obvious SSL/TLS security issues detected\n"

        print(f"✅ SSL/TLS analysis completed for {target_url}")
        return output

    except socket.timeout:
        error_msg = f"⏱️ Connection timeout to {hostname}:{port}"
        print(error_msg)
        return error_msg
    except socket.gaierror as e:
        error_msg = f"❌ DNS resolution failed for {hostname}: {e}"
        print(error_msg)
        return error_msg
    except ssl.SSLError as e:
        error_msg = f"❌ SSL/TLS error for {hostname}: {e}"
        print(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"❌ SSL/TLS analysis failed: {str(e)}"
        print(error_msg)
        return error_msg


def run_openssl_scan(target_url):
    """
    Alternative SSL scan using OpenSSL command line (if available)
    """
    try:
        # Parse hostname
        if "://" in target_url:
            hostname = target_url.split("://")[1].split("/")[0].split(":")[0]
        else:
            hostname = target_url.split("/")[0].split(":")[0]

        # Try OpenSSL s_client command
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{hostname}:443",
            "-servername",
            hostname,
            "-brief",
        ]

        result = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0:
            output = f"=== OpenSSL Analysis for {target_url} ===\n"
            output += result.stdout
            return output
        else:
            # Fallback to Python SSL analysis
            return run_testssl_scan(target_url)

    except FileNotFoundError:
        # OpenSSL not available, use Python SSL analysis
        return run_testssl_scan(target_url)
    except Exception as e:
        return run_testssl_scan(target_url)


if __name__ == "__main__":
    # Test the scanner
    test_url = "https://www.iitm.ac.in"
    result = run_testssl_scan(test_url)
    print("Result:", result)
