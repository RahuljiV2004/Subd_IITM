import sys
import os
from datetime import datetime

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from scanner.db import upsert_scan
except ImportError:
    import sys

    sys.path.insert(0, "/app")
    from scanner.db import upsert_scan


def append_tool_result(domain, tool_name, result, status="completed"):
    """
    Append a tool result to the domain scan record in MongoDB

    Args:
        domain (str): The domain name
        tool_name (str): Name of the tool (e.g., "nmap", "wpscan")
        result (dict): The tool result data
        status (str): Status of the tool execution
    """
    try:
        # Create the tool result entry
        tool_entry = {
            "tool": tool_name,
            "result": result,
            "status": status,
            "timestamp": datetime.utcnow(),
        }

        # Update the domain scan record with the new tool result
        scan_entry = {
            "domain": domain,
            f"tools.{tool_name}": tool_entry,
            "last_updated": datetime.utcnow(),
        }

        upsert_scan(scan_entry)

    except Exception as e:
        print(f"Error appending tool result for {domain}: {e}")
        # Optionally log to a file or monitoring service
