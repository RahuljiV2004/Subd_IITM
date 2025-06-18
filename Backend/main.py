from flask import Flask, Response, render_template, jsonify
from flask_cors import CORS

import json
import os
from pymongo import MongoClient
from utils.knockpy_runner import run_knockpy_and_enhance_streaming
from nmap import run_single_nmap_scan
app = Flask(__name__)
CORS(app) 
MXTOOLBOX_API_KEY = ""
DNSDUMPSTER_API_KEY = ""

client = MongoClient("mongodb://localhost:27017/")
db = client["subdomain_db"]
collection = db["iitm_subdomains"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results():
    return jsonify(list(collection.find({}, {"_id": 0})))
from flask import request

# @app.route("/api/scan_subdomain", methods=['POST'])
# def scan_subdomain():
#     data = request.json
#     if not data or 'subdomain' not in data:
#         return jsonify({"error": "Missing 'subdomain' in request body."}), 400

#     subdomain = data['subdomain']

#     # 1️⃣ Find the document which has this subdomain in its 'subdomains' dict
#     entry = collection.find_one({"domain": subdomain})
#     if not entry:
#         return jsonify({"error": f"Subdomain '{subdomain}' not found in database."}), 404

#     # 2️⃣ Run nmap
#     nmap_result = run_single_nmap_scan(subdomain)

#     collection.update_one(
#         {"_id": entry["_id"]},
#         {"$set": {"nmap": nmap_result}}
#     )

#     return jsonify({ "subdomain": subdomain, "nmap": nmap_result })

@app.route('/api/getPorts', methods=['GET'])
def get_ports():
    domain = request.args.get('subdomain')

    if not domain:
        return jsonify({"error": "Missing 'subdomain' parameter"}), 400

    # Find document with this domain
    doc = collection.find_one({"domain": domain})

    if not doc:
        return jsonify({"error": "No record found for this domain"}), 404

    # ✅ Extract ports from nested nmap field
    open_ports = doc.get("nmap", {}).get("open_ports", [])

    return jsonify({"open_ports": open_ports}), 200

@app.route("/api/scan_subdomain", methods=['POST'])
def scan_subdomain():
    data = request.json
    if not data or 'subdomain' not in data:
        return jsonify({"error": "Missing 'subdomain' in request body."}), 400

    subdomain = data['subdomain']

    # 1️⃣ Find the document which has this subdomain in its 'subdomains' dict
    entry = collection.find_one({"domain": subdomain})
    if not entry:
        return jsonify({"error": f"Subdomain '{subdomain}' not found in database."}), 404

    # 2️⃣ Run nmap
    nmap_result = run_single_nmap_scan(subdomain)

    collection.update_one(
        {"_id": entry["_id"]},
        {"$set": {"nmap": nmap_result}}
    )

    return jsonify({ "subdomain": subdomain, "nmap": nmap_result })


@app.route("/rescan/stream")
def rescan_stream():
    domain = request.args.get('domain')
    if not domain:
        return "Missing domain parameter", 400

    def generate():
        for message in run_knockpy_and_enhance_streaming(
            domain,
            collection,
            MXTOOLBOX_API_KEY,
            DNSDUMPSTER_API_KEY
        ):
            yield f"data: {message}\n\n"

    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True)
