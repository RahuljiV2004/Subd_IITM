from flask import Flask, Response, render_template, jsonify, request, make_response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from ffuf import run_ffuf_scan, get_good_wordlists
from utils.subfinder import run_subfinder_dnsx_httpx_stream
from datetime import datetime, timedelta
from zap import run_single_zap_scan
from llm.cohere_cve_lookup import generate_scan_comparison_report
import os
import time
from pymongo import MongoClient
from utils.knockpy_runner import run_knockpy_and_enhance_streaming
from nmap import run_single_nmap_scan
from models import User
from dotenv import load_dotenv
from bson.son import SON

load_dotenv()
from flask_mail import Mail, Message
from bson import ObjectId


app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configure Flask-Mail once:
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "rahuljiv2004@gmail.com"
app.config["MAIL_PASSWORD"] = "sdjv yxmp vxcv dkfu"
mail = Mail(app)

# JWT config
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # You can enable later if needed

jwt = JWTManager(app)

# MongoDB connection
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(mongo_uri)
db = client["subdomain_scanner"]
collection = db["scan_results"]
collection_subfinder = db["scan_results_subfinder"]
collection_subfinder1 = db["scan_results_subfinder1"]
tools_dir = os.path.join(os.getcwd(), "tools")
MXTOOLBOX_API_KEY = "abff5a1e-c212-4048-9095-6184c330bf5a"
DNSDUMPSTER_API_KEY = "b9b1399a665b6fe4d62429fc43b4038435090c5f3659a74e747e831a9d902cf3"
SUBFINDER_PATH = os.path.join(tools_dir, "subfinder.exe")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/resultssubfinder")
@jwt_required()
def resultssubfinder():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = user.organization
    print(f"Allowed org: {allowed}")

    # 1. Find latest scan_id for this org
    match_stage = {
        "$match": {"subdomain": {"$regex": f"{allowed}$"}, "scan_id": {"$exists": True}}
    }

    sort_stage = {
        "$sort": SON([("scanned_at", -1)])  # Sort by time
    }

    group_stage = {
        "$group": {"_id": "$scan_id", "latest_time": {"$first": "$scanned_at"}}
    }

    latest_scan = list(
        collection_subfinder.aggregate(
            [
                match_stage,
                sort_stage,
                group_stage,
                {"$sort": {"latest_time": -1}},
                {"$limit": 1},
            ]
        )
    )

    if not latest_scan:
        return jsonify({"error": "No scan data found"}), 404

    latest_scan_id = latest_scan[0]["_id"]
    print(f"Latest scan_id: {latest_scan_id}")

    # 2. Fetch all subdomains from that scan
    subdomains = list(
        collection_subfinder.find(
            {"scan_id": latest_scan_id, "subdomain": {"$regex": f"{allowed}$"}},
            {"_id": 0},
        )
    )

    return jsonify(subdomains)


@app.route("/resultssubfinderchart")
@jwt_required()
def resultssubfinderchart():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = user.organization
    scan_id = request.args.get("scan_id")

    if scan_id:
        # Fetch specific scan_id
        subdomains = list(
            collection_subfinder.find(
                {"scan_id": scan_id, "subdomain": {"$regex": f"{allowed}$"}}, {"_id": 0}
            )
        )

        if not subdomains:
            return jsonify({"error": "No data found for this scan_id"}), 404

        return jsonify(subdomains)
    else:
        # Fetch latest scan_id (default behavior)
        match_stage = {
            "$match": {
                "subdomain": {"$regex": f"{allowed}$"},
                "scan_id": {"$exists": True},
            }
        }

        sort_stage = {"$sort": SON([("scanned_at", -1)])}

        group_stage = {
            "$group": {"_id": "$scan_id", "latest_time": {"$first": "$scanned_at"}}
        }

        latest_scan = list(
            collection_subfinder.aggregate(
                [
                    match_stage,
                    sort_stage,
                    group_stage,
                    {"$sort": {"latest_time": -1}},
                    {"$limit": 1},
                ]
            )
        )

        if not latest_scan:
            return jsonify({"error": "No scan data found"}), 404

        latest_scan_id = latest_scan[0]["_id"]

        subdomains = list(
            collection_subfinder.find(
                {"scan_id": latest_scan_id, "subdomain": {"$regex": f"{allowed}$"}},
                {"_id": 0},
            )
        )

        return jsonify(subdomains)


@app.route("/scan-trends")
@jwt_required()
def scan_trends():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = user.organization

    pipeline = [
        {
            "$match": {
                "subdomain": {"$regex": f"{allowed}$"},
                "scan_id": {"$exists": True},
            }
        },
        {"$addFields": {"scanned_at_date": {"$toDate": "$scanned_at"}}},
        {
            "$group": {
                "_id": "$scan_id",
                "scanned_at_clean": {
                    "$first": {
                        "$dateToString": {
                            "format": "%Y-%m-%dT%H:%M:%S",
                            "date": "$scanned_at_date",
                            "timezone": "Asia/Kolkata",
                        }
                    }
                },
                "subdomains": {"$sum": 1},
                "vulnerabilities": {
                    "$sum": {
                        "$cond": [
                            {
                                "$gt": [
                                    {"$size": {"$ifNull": ["$vulnerabilities", []]}},
                                    0,
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
        {"$sort": {"scanned_at_clean": 1}},
    ]

    results = list(collection_subfinder.aggregate(pipeline))
    if not results:
        return jsonify({"error": "No scan trends found"}), 404

    return jsonify(results)


@app.route("/scan-diff-analysis")
@jwt_required()
def scan_diff_analysis():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = user.organization

    # Step 1: Get the latest two scans with aggregation similar to scan-trends
    pipeline = [
        {
            "$match": {
                "subdomain": {"$regex": f"{allowed}$"},
                "scan_id": {"$exists": True},
            }
        },
        {"$addFields": {"scanned_at_date": {"$toDate": "$scanned_at"}}},
        {
            "$group": {
                "_id": "$scan_id",
                "scanned_at_clean": {
                    "$first": {
                        "$dateToString": {
                            "format": "%Y-%m-%dT%H:%M:%S",
                            "date": "$scanned_at_date",
                            "timezone": "Asia/Kolkata",
                        }
                    }
                },
                "latest_doc": {"$first": "$$ROOT"},  # keep full doc for LLM
                "subdomains": {"$sum": 1},
                "vulnerabilities": {
                    "$sum": {
                        "$cond": [
                            {
                                "$gt": [
                                    {"$size": {"$ifNull": ["$vulnerabilities", []]}},
                                    0,
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
        {"$sort": {"scanned_at_clean": -1}},
        {"$limit": 2},
    ]

    grouped_scans = list(collection_subfinder.aggregate(pipeline))
    if len(grouped_scans) < 2:
        return jsonify({"error": "Not enough scans to analyze"}), 400

    latest_group = grouped_scans[0]
    previous_group = grouped_scans[1]

    # Extract full docs for LLM
    latest_scan = latest_group["latest_doc"]
    previous_scan = previous_group["latest_doc"]

    # Call Cohere LLM for comparison
    try:
        analysis = generate_scan_comparison_report(previous_scan, latest_scan, allowed)
    except RuntimeError as e:
        return jsonify({"error": "LLM analysis failed", "details": str(e)}), 500

    return jsonify(
        {
            "latest_scan": {
                "scan_id": latest_group["_id"],
                "scanned_at_clean": latest_group["scanned_at_clean"],
                "subdomains": latest_group["subdomains"],
                "vulnerabilities": latest_group["vulnerabilities"],
            },
            "previous_scan": {
                "scan_id": previous_group["_id"],
                "scanned_at_clean": previous_group["scanned_at_clean"],
                "subdomains": previous_group["subdomains"],
                "vulnerabilities": previous_group["vulnerabilities"],
            },
            "analysis": analysis,
        }
    )


@app.route("/results")
@jwt_required()
def results():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = user.organization

    pipeline = [
        {
            "$match": {
                "$or": [
                    {"domain": {"$regex": f"{allowed}$"}},
                    {"subdomain": {"$regex": f"{allowed}$"}},
                ]
            }
        },
        {"$addFields": {"scanned_at_date": {"$toDate": "$scanned_at"}}},
        {"$sort": {"scanned_at_date": -1}},
        {
            "$group": {
                "_id": {"$ifNull": ["$subdomain", "$domain"]},
                "latest": {"$first": "$$ROOT"},
            }
        },
        {"$replaceRoot": {"newRoot": "$latest"}},
        {"$sort": {"domain": 1}},
        {"$project": {"_id": 0}},  # 👈 ensures ObjectId is removed
    ]

    results = list(collection.aggregate(pipeline))
    if not results:
        return jsonify({"error": "No stored results"}), 404

    return jsonify(results)


@app.route("/api/assets", methods=["POST"])
@jwt_required()
def save_assets():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    domains = data.get("domains", [])
    ips = data.get("ips", [])
    endpoints = data.get("endpoints", [])
    shodan_key = data.get("shodanKey", "")
    fofa_key = data.get("fofaKey", "")

    asset_doc = {
        "org": user.organization,
        "domains": domains,
        "ips": ips,
        "endpoints": endpoints,
        "shodan_key": shodan_key,
        "fofa_key": fofa_key,
        "created_at": datetime.utcnow(),
    }

    db.assets.insert_one(asset_doc)
    return jsonify({"message": "Assets saved successfully"}), 201


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    existing_user = User.find_by_email(email)
    if existing_user:
        return jsonify({"error": "Email already registered"}), 400

    user = User(email=email, password=password)
    user.save()

    # ✅ Generate OTP and save:
    otp = user.set_otp()

    msg = Message("Verify your email", sender="youremail@gmail.com", recipients=[email])

    # Plain text version
    msg.body = f"Your OTP is: {otp}. It expires in 10 minutes."

    # HTML version
    msg.html = render_template("email/verification.html", otp=otp)

    mail.send(msg)

    resp = jsonify(
        {
            "message": "User registered. Please check your email for the OTP to verify your account.",
            "user": user.to_dict(),
        }
    )
    return resp, 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.find_by_email(email)
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid email or password"}), 401

    # ✅ Block unverified user
    if not user.is_verified:
        return jsonify({"error": "Please verify your email first."}), 403

    user.last_login = datetime.utcnow()
    user.update()

    access_token = create_access_token(identity=str(user._id))
    resp = jsonify({"message": "Login successful", "user": user.to_dict()})
    set_access_cookies(resp, access_token)
    return resp, 200


@app.route("/auth/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    user = User.find_by_email(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    success, message = user.verify_otp(otp)
    if not success:
        return jsonify({"error": message}), 400

    # ✅ Optionally update last login timestamp
    user.last_login = datetime.utcnow()
    user.update()

    # ✅ Create JWT and set it in cookie
    access_token = create_access_token(identity=str(user._id))
    resp = jsonify(
        {"message": "✅ Email verified and logged in!", "user": user.to_dict()}
    )
    set_access_cookies(resp, access_token)

    # ✅ Return the SAME response — so cookie is included!
    return resp, 200


@app.route("/auth/logout", methods=["POST"])
def logout():
    resp = jsonify({"message": "Logged out"})
    # ✅ Clear the cookie
    unset_jwt_cookies(resp)
    return resp, 200


@app.route("/auth/me", methods=["GET"])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())


@app.route("/test")
@jwt_required()
def test():
    return jsonify({"msg": "You are authenticated!"})


@app.route("/rescan/stream_subfinder_dnsx_httpx")
def rescan_stream_subfinder_dnsx_httpx():
    # ✅ 1️⃣ Verify JWT from cookie
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ✅ 2️⃣ Validate domain
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Missing domain parameter"}), 400

    if not domain.endswith(user.organization):
        return jsonify(
            {"error": f"You can only scan domains ending with {user.organization}"}
        ), 403

    def generate():
        yield ": connected\n\n"  # SSE comment/ping

        last_sent = time.time()

        try:
            scan = run_subfinder_dnsx_httpx_stream(domain, collection_subfinder)

            while True:
                try:
                    message = next(scan)
                    # ✅ Add data: exactly once here
                    yield f"data: {message}\n\n"
                    last_sent = time.time()

                except StopIteration:
                    yield 'data: {"type":"done","message":"Pipeline complete"}\n\n'
                    break

                except Exception as e:
                    yield f'data: {{"type":"error","message":"Pipeline error: {str(e)}"}}\n\n'
                    break

                if time.time() - last_sent > 10:
                    yield ": keep-alive\n\n"
                    last_sent = time.time()

                time.sleep(0.5)

        except Exception as e:
            yield f'data: {{"type":"error","message":"Could not start pipeline: {str(e)}"}}\n\n'

    # ✅ 4️⃣ Return SSE response
    return Response(generate(), mimetype="text/event-stream")


@app.route("/rescan/stream_subfinder_dnsx_httpx1")
def rescan_stream_subfinder_dnsx_httpx1():
    # ✅ 1️⃣ Verify JWT from cookie
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ✅ 2️⃣ Validate domain
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Missing domain parameter"}), 400

    if not domain.endswith(user.organization):
        return jsonify(
            {"error": f"You can only scan domains ending with {user.organization}"}
        ), 403

    def generate():
        yield ": connected\n\n"  # SSE comment/ping

        last_sent = time.time()

        try:
            scan = run_subfinder_dnsx_httpx_stream(domain, collection_subfinder1)

            while True:
                try:
                    message = next(scan)
                    # ✅ Add data: exactly once here
                    yield f"data: {message}\n\n"
                    last_sent = time.time()

                except StopIteration:
                    yield 'data: {"type":"done","message":"Pipeline complete"}\n\n'
                    break

                except Exception as e:
                    yield f'data: {{"type":"error","message":"Pipeline error: {str(e)}"}}\n\n'
                    break

                if time.time() - last_sent > 10:
                    yield ": keep-alive\n\n"
                    last_sent = time.time()

                time.sleep(0.5)

        except Exception as e:
            yield f'data: {{"type":"error","message":"Could not start pipeline: {str(e)}"}}\n\n'

    # ✅ 4️⃣ Return SSE response
    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/getPorts", methods=["GET"])
def get_ports():
    domain = request.args.get("subdomain")

    if not domain:
        return jsonify({"error": "Missing 'subdomain' parameter"}), 400

    # Find document with this domain
    doc = collection.find_one({"domain": domain})

    if not doc:
        return jsonify({"error": "No record found for this domain"}), 404

    # ✅ Extract ports from nested nmap field
    open_ports = doc.get("nmap", {}).get("open_ports", [])

    return jsonify({"open_ports": open_ports}), 200


@app.route("/api/getFfuf_subfinder", methods=["GET"])
def get_ffuf():
    domain = request.args.get("subdomain")

    if not domain:
        return jsonify({"error": "Missing 'subdomain' parameter"}), 400

    # Find document with this domain
    doc = collection_subfinder.find_one({"subdomain": domain})

    if not doc:
        return jsonify({"error": "No record found for this domain"}), 404

    # ✅ Extract ffuf results
    ffuf_results = doc.get("ffuf", {}).get("results", [])

    return jsonify({"ffuf": {"results": ffuf_results}}), 200


@app.route("/api/getPorts_subfinder", methods=["GET"])
def get_ports_subfinder():
    domain = request.args.get("subdomain")

    if not domain:
        return jsonify({"error": "Missing 'subdomain' parameter"}), 400

    # Find document with this domain
    doc = collection_subfinder.find_one({"subdomain": domain})

    if not doc:
        return jsonify({"error": "No record found for this domain"}), 404

    # ✅ Extract ports from nested nmap field
    open_ports = doc.get("nmap", {}).get("open_ports", [])

    return jsonify({"open_ports": open_ports}), 200


@app.route("/api/getZapAlerts", methods=["GET"])
def get_zap_alerts():
    domain = request.args.get("subdomain")

    if not domain:
        return jsonify({"error": "Missing 'subdomain' parameter"}), 400

    # ✅ Find document with this domain
    doc = collection.find_one({"domain": domain})

    if not doc:
        return jsonify({"error": "No record found for this domain"}), 404

    # ✅ Extract alerts from nested zap field
    alerts = doc.get("zap", {}).get("alerts", [])

    return jsonify({"alerts": alerts}), 200


@app.route("/api/scan_subdomain", methods=["POST"])
def scan_subdomain():
    data = request.json
    if not data or "subdomain" not in data:
        return jsonify({"error": "Missing 'subdomain' in request body."}), 400

    subdomain = data["subdomain"]
    entry = collection.find_one({"domain": subdomain})
    if not entry:
        return jsonify(
            {"error": f"Subdomain '{subdomain}' not found in database."}
        ), 404

    nmap_result = run_single_nmap_scan(subdomain)

    collection.update_one({"_id": entry["_id"]}, {"$set": {"nmap": nmap_result}})

    return jsonify({"subdomain": subdomain, "nmap": nmap_result})


@app.route("/api/scan_subdomain_subfinder", methods=["POST"])
def scan_subdomain_subfinder():
    data = request.json
    if not data or "subdomain" not in data:
        return jsonify({"error": "Missing 'subdomain' in request body."}), 400

    subdomain = data["subdomain"]
    entry = collection_subfinder.find_one({"subdomain": subdomain})
    if not entry:
        return jsonify(
            {"error": f"Subdomain '{subdomain}' not found in database."}
        ), 404

    nmap_result = run_single_nmap_scan(subdomain)

    collection_subfinder.update_one(
        {"_id": entry["_id"]}, {"$set": {"nmap": nmap_result}}
    )

    return jsonify({"subdomain": subdomain, "nmap": nmap_result})


@app.route("/api/scan_subdomain_zap", methods=["POST"])
def scan_subdomain_zap():
    data = request.json
    if not data or "subdomain" not in data:
        return jsonify({"error": "Missing 'subdomain' in request body."}), 400

    subdomain = data["subdomain"]
    entry = collection.find_one({"domain": subdomain})
    if not entry:
        return jsonify(
            {"error": f"Subdomain '{subdomain}' not found in database."}
        ), 404

    zap_result = run_single_zap_scan(subdomain)

    collection.update_one({"_id": entry["_id"]}, {"$set": {"zap": zap_result}})

    return jsonify({"subdomain": subdomain, "zap": zap_result})


@app.route("/rescan/stream")
def rescan_stream():
    # ✅ 1. Verify JWT from cookie
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ✅ 2. Validate domain param
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Missing domain parameter"}), 400

    if not domain.endswith(user.organization):
        return jsonify(
            {"error": f"You can only scan domains ending with {user.organization}"}
        ), 403

    # ✅ 3. Streaming generator with heartbeat
    def generate():
        yield ": connected\n\n"  # immediate connection ping
        last_sent = time.time()

        # Start the actual scan generator
        scan = run_knockpy_and_enhance_streaming(
            domain, collection, MXTOOLBOX_API_KEY, DNSDUMPSTER_API_KEY
        )

        while True:
            try:
                # Try to get next real result
                message = next(scan)
                yield f"data: {message}\n\n"
                last_sent = time.time()

            except StopIteration:
                # ✅ End of scan: send a final done marker
                yield 'data: {"type":"done","message":"Scan complete"}\n\n'
                break

            except Exception as e:
                # ✅ If scan crashes: send error
                yield f'data: {{"type":"error","message":"{str(e)}"}}\n\n'
                break

            # ✅ Heartbeat: if no data in 10s, send comment
            if time.time() - last_sent > 10:
                yield ": keep-alive\n\n"
                last_sent = time.time()

            # ✅ Small sleep avoids busy loop
            time.sleep(1)

    # ✅ 4. Return properly as SSE response
    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/scan_ffuf", methods=["POST"])
def scan_ffuf():
    data = request.json
    if not data or "subdomain" not in data:
        return jsonify({"error": "Missing 'subdomain' in request body."}), 400

    subdomain = data["subdomain"].strip()
    entry = collection_subfinder.find_one({"subdomain": subdomain})
    if not entry:
        return jsonify(
            {"error": f"Subdomain '{subdomain}' not found in database."}
        ), 404

    wordlists = get_good_wordlists()
    wordlist_dict = {name: path for path, name in wordlists}
    default_wordlist_path = wordlists[0][0] if wordlists else None

    wordlist_name = data.get("wordlist")
    wordlist_path = (
        wordlist_dict.get(wordlist_name) if wordlist_name else default_wordlist_path
    )

    if not wordlist_path:
        return jsonify({"error": "No valid wordlist found or selected."}), 400

    result = run_ffuf_scan(subdomain, wordlist_path)

    if not result["success"]:
        return jsonify(result), 500

    collection_subfinder.update_one(
        {"_id": ObjectId(entry["_id"])},
        {
            "$set": {
                "ffuf": {
                    "url": result["url"],
                    "wordlist": wordlist_name or wordlist_path.split("/")[-1],
                    "results": result["results"],
                }
            }
        },
    )

    return jsonify(
        {
            "subdomain": subdomain,
            "ffuf": {
                "url": result["url"],
                "wordlist": wordlist_name or wordlist_path.split("/")[-1],
                "results": result["results"],
            },
        }
    )


@app.route("/mcp/vulnerability-data", methods=["GET"])
def mcp_vulnerability_data():
    """
    Enhanced MCP endpoint providing comprehensive vulnerability intelligence with live scanning:
    - Subdomain discovery (Subfinder)
    - HTTP/HTTPS analysis (HTTPx)
    - DNS resolution (DNSx)
    - Vulnerability scanning (OWASP ZAP, Nuclei)
    - SSL/TLS certificate analysis
    - IP geolocation and ASN details
    - Technology fingerprinting (WhatWeb, Wappalyzer)
    - Port scanning (Nmap)
    - Directory/file discovery (FFUF)
    - Web vulnerability scanning (Nikto)
    - Risk assessment and CVE information
    """
    target = request.args.get("target")
    scan_type = request.args.get("scan_type", "comprehensive")
    live_scan = request.args.get("live_scan", "true").lower() == "true"
    max_subdomains = int(
        request.args.get("max_subdomains", "10")
    )  # Limit for performance

    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400

    # Import scanning tools - Enhanced version with Windows + WSL support
    try:
        from utils.security_tools_enhanced import (
            run_ffuf_enhanced as run_ffuf_windows,
            run_nuclei_enhanced as run_nuclei_windows,
            run_httpx_enhanced as run_httpx_windows,
            run_nikto_enhanced as run_nikto_scan,
            run_whatweb_enhanced as run_whatweb_scan,
            run_testssl_enhanced as run_testssl_scan,
            get_tools_status,
        )

        print("✅ Enhanced security tools loaded (Windows + WSL support)")

        # Print tool status
        tool_status = get_tools_status()
        print(f"   Tools available: {tool_status['summary']['total_available']} total")
        print(
            f"   Windows: {tool_status['summary']['windows_available']}, WSL: {tool_status['summary']['wsl_available']}"
        )

    except ImportError as e:
        print(f"⚠️ Enhanced tools not available, using individual imports: {e}")
        # Fallback to individual Windows tools
        try:
            from utils.whatweb_windows import run_whatweb_scan
            from utils.automated_tools.nikto_windows import (
                run_nikto_scan,
                run_nikto_scan_simple,
            )
            from utils.automated_tools.testssl_windows import (
                run_testssl_scan,
                run_openssl_scan,
            )
            from utils.security_tools_windows import (
                run_ffuf_windows,
                run_nuclei_windows,
                run_httpx_windows,
                run_dnsx_windows,
            )

            print("✅ Windows-compatible scanning tools loaded")
        except ImportError as e:
            print(f"Warning: Some Windows scanning tools not available: {e}")
            # Fallback imports
            try:
                from utils.whatweb import run_whatweb_scan
                from utils.automated_tools.nikto_clean import run_nikto_scan
                from utils.automated_tools.testssl_runner import run_testssl_scan
            except ImportError as e2:
                print(f"Warning: Fallback scanning tools also not available: {e2}")

    try:
        # Initialize comprehensive response data structure
        vulnerability_data = {
            "target": target,
            "scan_type": scan_type,
            "live_scan": live_scan,
            "timestamp": datetime.utcnow().isoformat(),
            # Core reconnaissance data
            "subdomains": [],
            "dns_records": [],
            "http_analysis": [],
            "ssl_certificates": [],
            # Security findings
            "vulnerabilities": [],
            "ssl_issues": [],
            "nuclei_findings": [],
            # Infrastructure data
            "services": [],
            "open_ports": [],
            "technologies": [],
            "ip_geolocation": [],
            "asn_details": [],
            # Discovery data
            "ffuf_discoveries": [],
            "whatweb_analysis": [],
            "nikto_findings": [],
            "testssl_results": [],
            # Risk intelligence
            "cve_suggestions": [],
            "risk_assessments": [],
            "cohere_analysis": [],
            # Scanning status
            "scan_status": {
                "started_at": datetime.utcnow().isoformat(),
                "completed_scans": 0,
                "failed_scans": 0,
                "skipped_scans": 0,
                "progress_percentage": 0,
            },
            # Summary metrics
            "scan_summary": {
                "total_subdomains": 0,
                "total_services": 0,
                "total_vulnerabilities": 0,
                "total_ssl_issues": 0,
                "total_technologies": 0,
                "risk_level": "unknown",
            },
        }

        # Search for all subdomains related to the target
        target_pattern = (
            target.replace("www.", "").replace("https://", "").replace("http://", "")
        )
        if not target_pattern.endswith(".*"):
            target_pattern = f".*{target_pattern}.*"

        subdomain_docs = list(
            collection_subfinder.find(
                {"subdomain": {"$regex": target_pattern, "$options": "i"}}
            ).limit(max_subdomains)  # Use dynamic limit for performance
        )

        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        total_subdomains = len(subdomain_docs)
        vulnerability_data["scan_summary"]["total_subdomains"] = total_subdomains

        # Process each subdomain with optional live scanning
        for idx, doc in enumerate(subdomain_docs):
            subdomain = doc.get("subdomain", "")

            try:
                # Update progress
                progress = (
                    int(((idx + 1) / total_subdomains) * 100)
                    if total_subdomains > 0
                    else 0
                )
                vulnerability_data["scan_status"]["progress_percentage"] = progress

                print(
                    f"🔍 Processing subdomain {idx + 1}/{total_subdomains}: {subdomain}"
                )

                # === SUBDOMAIN DISCOVERY DATA (Subfinder) ===
                subdomain_data = {
                    "subdomain": subdomain,
                    "domain": doc.get("domain", ""),
                    "scan_id": doc.get("scan_id", ""),
                    "subfinder_found": doc.get("subfinder_found", False),
                    "last_scanned": doc.get("scanned_at", ""),
                }
                vulnerability_data["subdomains"].append(subdomain_data)

                # === LIVE SCANNING ENHANCEMENT ===
                if live_scan and scan_type in ["comprehensive", "deep"]:
                    print(f"🚀 Starting live scans for {subdomain}")

                    # 1. WhatWeb Technology Fingerprinting
                    try:
                        print(f"🔍 Running WhatWeb scan on {subdomain}")
                        whatweb_results = run_whatweb_scan(f"https://{subdomain}")

                        whatweb_analysis = {
                            "subdomain": subdomain,
                            "technologies": [],
                            "raw_output": whatweb_results,
                            "summary": "Technology fingerprinting completed",
                            "scan_timestamp": datetime.utcnow().isoformat(),
                        }

                        # Extract technology info from WhatWeb output
                        if "Technologies Detected:" in whatweb_results:
                            lines = whatweb_results.split("\n")
                            in_tech_section = False

                            for line in lines:
                                if "Technologies Detected:" in line:
                                    in_tech_section = True
                                    continue
                                elif in_tech_section and line.strip().startswith("- "):
                                    tech = line.strip()[2:]  # Remove "- "
                                    whatweb_analysis["technologies"].append(tech)
                                    if tech not in vulnerability_data["technologies"]:
                                        vulnerability_data["technologies"].append(tech)
                                elif in_tech_section and not line.strip():
                                    break  # End of tech section

                        # Also extract from header analysis if available
                        elif "Header Analysis:" in whatweb_results:
                            lines = whatweb_results.split("\n")
                            for line in lines:
                                if any(
                                    tech in line.lower()
                                    for tech in [
                                        "server:",
                                        "x-powered-by:",
                                        "framework",
                                    ]
                                ):
                                    tech_info = line.strip()
                                    whatweb_analysis["technologies"].append(tech_info)
                                    if (
                                        tech_info
                                        not in vulnerability_data["technologies"]
                                    ):
                                        vulnerability_data["technologies"].append(
                                            tech_info
                                        )

                        vulnerability_data["whatweb_analysis"].append(whatweb_analysis)
                        vulnerability_data["scan_status"]["completed_scans"] += 1
                        print(f"✅ WhatWeb scan completed for {subdomain}")

                    except Exception as e:
                        print(f"❌ WhatWeb scan failed for {subdomain}: {e}")
                        vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 2. Nikto Web Vulnerability Scan
                    try:
                        print(f"🔍 Running Nikto scan on {subdomain}")
                        nikto_output = run_nikto_scan(f"https://{subdomain}")

                        # Parse Nikto output for vulnerabilities
                        nikto_findings = {
                            "subdomain": subdomain,
                            "raw_output": nikto_output,
                            "scan_timestamp": datetime.utcnow().isoformat(),
                            "vulnerabilities_found": [],
                        }

                        # Extract vulnerabilities from Nikto output
                        if (
                            nikto_output
                            and "❌" not in nikto_output
                            and "wsl: not found" not in nikto_output
                        ):
                            nikto_lines = nikto_output.split("\n")
                            for line in nikto_lines:
                                line_lower = line.lower()
                                # Look for Nikto findings and security issues
                                if any(
                                    keyword in line_lower
                                    for keyword in [
                                        "osvdb",
                                        "cve",
                                        "vulnerable",
                                        "disclosure",
                                        "security",
                                        "risk",
                                        "exploit",
                                        "weakness",
                                        "potential",
                                        "found:",
                                        "detected:",
                                    ]
                                ):
                                    # Skip common false positives
                                    if any(
                                        skip in line_lower
                                        for skip in [
                                            "scanning",
                                            "starting",
                                            "completed",
                                            "error:",
                                        ]
                                    ):
                                        continue

                                    vuln_data = {
                                        "subdomain": subdomain,
                                        "title": f"Nikto Finding: {line.strip()[:100]}",
                                        "severity": "medium",
                                        "confidence": "medium",
                                        "description": line.strip(),
                                        "solution": "Review finding and implement appropriate security measures",
                                        "tool": "Nikto",
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }

                                    # Determine severity based on keywords
                                    if any(
                                        critical in line_lower
                                        for critical in [
                                            "critical",
                                            "high",
                                            "severe",
                                            "dangerous",
                                        ]
                                    ):
                                        vuln_data["severity"] = "high"
                                        high_risk_count += 1
                                    elif any(
                                        medium in line_lower
                                        for medium in ["medium", "moderate", "warning"]
                                    ):
                                        medium_risk_count += 1
                                    else:
                                        low_risk_count += 1

                                    nikto_findings["vulnerabilities_found"].append(
                                        vuln_data
                                    )
                                    vulnerability_data["vulnerabilities"].append(
                                        vuln_data
                                    )

                        elif "wsl: not found" in nikto_output:
                            print(
                                f"⚠️ WSL dependency issue detected in Nikto output for {subdomain}"
                            )

                        elif "❌" in nikto_output:
                            print(
                                f"⚠️ Error detected in Nikto output for {subdomain}: {nikto_output[:200]}"
                            )

                        else:
                            print(
                                f"ℹ️ No specific vulnerabilities found by Nikto for {subdomain}"
                            )

                        vulnerability_data["nikto_findings"].append(nikto_findings)
                        vulnerability_data["scan_status"]["completed_scans"] += 1

                    except Exception as e:
                        print(f"❌ Nikto scan failed for {subdomain}: {e}")
                        vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 3. SSL/TLS Testing
                    try:
                        print(f"🔍 Running SSL/TLS test on {subdomain}")
                        testssl_output = run_testssl_scan(f"https://{subdomain}")

                        testssl_result = {
                            "subdomain": subdomain,
                            "raw_output": testssl_output,
                            "scan_timestamp": datetime.utcnow().isoformat(),
                            "ssl_issues": [],
                        }

                        # Parse testssl output for SSL/TLS issues
                        if (
                            testssl_output
                            and "❌" not in testssl_output
                            and "wsl: not found" not in testssl_output
                        ):
                            testssl_lines = testssl_output.split("\n")
                            for line in testssl_lines:
                                line_lower = line.lower()
                                # Look for SSL/TLS security issues
                                if any(
                                    issue in line_lower
                                    for issue in [
                                        "weak",
                                        "vulnerable",
                                        "security issues found",
                                        "certificate expiry",
                                        "outdated",
                                        "insecure",
                                        "deprecated",
                                        "not secure",
                                        "warning:",
                                        "critical:",
                                        "error:",
                                        "failed",
                                        "self-signed",
                                        "expired",
                                    ]
                                ):
                                    # Skip informational lines
                                    if any(
                                        skip in line_lower
                                        for skip in [
                                            "connecting",
                                            "scanning",
                                            "checking",
                                        ]
                                    ):
                                        continue

                                    severity = "medium"
                                    if any(
                                        critical in line_lower
                                        for critical in [
                                            "critical",
                                            "high",
                                            "severe",
                                            "vulnerable",
                                            "expired",
                                        ]
                                    ):
                                        severity = "high"
                                        high_risk_count += 1
                                    elif any(
                                        medium in line_lower
                                        for medium in [
                                            "weak",
                                            "outdated",
                                            "deprecated",
                                            "warning",
                                        ]
                                    ):
                                        medium_risk_count += 1
                                    else:
                                        low_risk_count += 1

                                    ssl_issue = {
                                        "subdomain": subdomain,
                                        "issue": "SSL/TLS Security Issue",
                                        "severity": severity,
                                        "description": line.strip(),
                                        "tool": "SSL Analysis",
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }
                                    testssl_result["ssl_issues"].append(ssl_issue)
                                    vulnerability_data["ssl_issues"].append(ssl_issue)

                        elif "wsl: not found" in testssl_output:
                            print(
                                f"⚠️ WSL dependency issue detected in SSL test for {subdomain}"
                            )
                        elif "❌" in testssl_output:
                            print(
                                f"⚠️ Error in SSL test for {subdomain}: {testssl_output[:200]}"
                            )
                        else:
                            print(f"ℹ️ SSL/TLS analysis completed for {subdomain}")

                        vulnerability_data["testssl_results"].append(testssl_result)
                        vulnerability_data["scan_status"]["completed_scans"] += 1
                        print(f"✅ SSL/TLS test completed for {subdomain}")

                    except Exception as e:
                        print(f"❌ SSL/TLS test failed for {subdomain}: {e}")
                        vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 4. FFUF Directory/File Discovery (Windows)
                    if scan_type in ["comprehensive", "deep"]:
                        try:
                            print(f"🔍 Running FFUF directory discovery on {subdomain}")
                            ffuf_results = run_ffuf_windows(f"https://{subdomain}")

                            if ffuf_results and "results" in ffuf_results:
                                for result in ffuf_results["results"]:
                                    status = result.get("status", 0)
                                    url = result.get("url", "")

                                    # Only include interesting findings (not 404s)
                                    if status not in [404, 403]:
                                        discovery_data = {
                                            "subdomain": subdomain,
                                            "url": url,
                                            "status_code": status,
                                            "content_length": result.get("length", 0),
                                            "content_words": result.get("words", 0),
                                            "response_time": result.get("duration", 0),
                                            "scan_timestamp": datetime.utcnow().isoformat(),
                                            "tool": "FFUF",
                                        }
                                        vulnerability_data["ffuf_discoveries"].append(
                                            discovery_data
                                        )

                                        # Count as medium risk if interesting endpoints found
                                        if status in [200, 301, 302]:
                                            medium_risk_count += 1

                            vulnerability_data["scan_status"]["completed_scans"] += 1
                            print(f"✅ FFUF discovery completed for {subdomain}")

                        except Exception as e:
                            print(f"❌ FFUF discovery failed for {subdomain}: {e}")
                            vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 5. Nuclei Vulnerability Templates (Windows)
                    if scan_type in ["comprehensive", "deep"]:
                        try:
                            print(
                                f"🔍 Running Nuclei vulnerability templates on {subdomain}"
                            )
                            nuclei_results = run_nuclei_windows(f"https://{subdomain}")

                            if nuclei_results and "results" in nuclei_results:
                                for result in nuclei_results["results"]:
                                    template_id = result.get("template-id", "unknown")
                                    severity = (
                                        result.get("info", {})
                                        .get("severity", "medium")
                                        .lower()
                                    )

                                    # Count severity levels
                                    if severity in ["critical", "high"]:
                                        high_risk_count += 1
                                    elif severity == "medium":
                                        medium_risk_count += 1
                                    else:
                                        low_risk_count += 1

                                    vuln_data = {
                                        "subdomain": subdomain,
                                        "title": result.get("info", {}).get(
                                            "name", template_id
                                        ),
                                        "severity": severity,
                                        "template_id": template_id,
                                        "description": result.get("info", {}).get(
                                            "description", ""
                                        ),
                                        "reference": result.get("info", {}).get(
                                            "reference", ""
                                        ),
                                        "classification": result.get("info", {}).get(
                                            "classification", {}
                                        ),
                                        "matched_at": result.get(
                                            "matched-at", f"https://{subdomain}"
                                        ),
                                        "extracted_results": result.get(
                                            "extracted-results", []
                                        ),
                                        "tool": "Nuclei",
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }
                                    vulnerability_data["nuclei_findings"].append(
                                        vuln_data
                                    )
                                    vulnerability_data["vulnerabilities"].append(
                                        vuln_data
                                    )

                            vulnerability_data["scan_status"]["completed_scans"] += 1
                            print(f"✅ Nuclei scan completed for {subdomain}")

                        except Exception as e:
                            print(f"❌ Nuclei scan failed for {subdomain}: {e}")
                            vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 6. HTTPx HTTP Analysis (Windows)
                    try:
                        print(f"🔍 Running HTTPx analysis on {subdomain}")
                        httpx_results = run_httpx_windows(f"https://{subdomain}")

                        if httpx_results and "results" in httpx_results:
                            for result in httpx_results["results"]:
                                http_analysis = {
                                    "subdomain": subdomain,
                                    "url": result.get("url", f"https://{subdomain}"),
                                    "status_code": result.get("status_code", 0),
                                    "content_length": result.get("content_length", 0),
                                    "response_time": result.get("response_time", ""),
                                    "tech_stack": result.get("tech", []),
                                    "title": result.get("title", ""),
                                    "server": result.get("webserver", ""),
                                    "cdn": result.get("cdn", ""),
                                    "method": result.get("method", "GET"),
                                    "location": result.get("location", ""),
                                    "scan_timestamp": datetime.utcnow().isoformat(),
                                    "tool": "HTTPx",
                                }
                                vulnerability_data["http_analysis"].append(
                                    http_analysis
                                )

                                # Extract technologies for main list
                                for tech in result.get("tech", []):
                                    if tech not in vulnerability_data["technologies"]:
                                        vulnerability_data["technologies"].append(tech)

                        vulnerability_data["scan_status"]["completed_scans"] += 1
                        print(f"✅ HTTPx analysis completed for {subdomain}")

                    except Exception as e:
                        print(f"❌ HTTPx analysis failed for {subdomain}: {e}")
                        vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 7. OWASP ZAP Vulnerability Scan
                    if scan_type == "comprehensive":
                        try:
                            print(f"🔍 Running OWASP ZAP scan on {subdomain}")
                            zap_results = run_single_zap_scan(subdomain)

                            if zap_results and "alerts" in zap_results:
                                for alert in zap_results["alerts"]:
                                    risk_level = alert.get("risk", "").lower()

                                    # Count risk levels
                                    if risk_level == "high":
                                        high_risk_count += 1
                                    elif risk_level == "medium":
                                        medium_risk_count += 1
                                    elif risk_level == "low":
                                        low_risk_count += 1

                                    vuln_data = {
                                        "subdomain": subdomain,
                                        "title": alert.get(
                                            "name", "Unknown Vulnerability"
                                        ),
                                        "severity": alert.get("risk", "Unknown"),
                                        "confidence": alert.get(
                                            "confidence", "Unknown"
                                        ),
                                        "description": alert.get("description", ""),
                                        "solution": alert.get("solution", ""),
                                        "reference": alert.get("reference", ""),
                                        "cwe_id": alert.get("cweid", ""),
                                        "wasc_id": alert.get("wascid", ""),
                                        "plugin_id": alert.get("pluginid", ""),
                                        "instances": len(alert.get("instances", [])),
                                        "attack": alert.get("attack", ""),
                                        "evidence": alert.get("evidence", ""),
                                        "tool": "OWASP ZAP",
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }
                                    vulnerability_data["vulnerabilities"].append(
                                        vuln_data
                                    )

                            vulnerability_data["scan_status"]["completed_scans"] += 1

                        except Exception as e:
                            print(f"❌ OWASP ZAP scan failed for {subdomain}: {e}")
                            vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 5. Nmap Port Scanning
                    if scan_type == "comprehensive":
                        try:
                            print(f"🔍 Running Nmap scan on {subdomain}")
                            nmap_results = run_single_nmap_scan(subdomain)

                            if nmap_results and "open_ports" in nmap_results:
                                for port_info in nmap_results["open_ports"]:
                                    service_data = {
                                        "subdomain": subdomain,
                                        "port": port_info.get("port", ""),
                                        "protocol": port_info.get("protocol", "tcp"),
                                        "service": port_info.get("service", ""),
                                        "version": port_info.get("version", ""),
                                        "product": port_info.get("product", ""),
                                        "state": port_info.get("state", ""),
                                        "reason": port_info.get("reason", ""),
                                        "banner": port_info.get("banner", ""),
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }
                                    vulnerability_data["services"].append(service_data)
                                    vulnerability_data["open_ports"].append(
                                        service_data
                                    )

                            vulnerability_data["scan_status"]["completed_scans"] += 1

                        except Exception as e:
                            print(f"❌ Nmap scan failed for {subdomain}: {e}")
                            vulnerability_data["scan_status"]["failed_scans"] += 1

                    # 6. FFUF Directory Discovery
                    if scan_type in ["comprehensive", "deep"]:
                        try:
                            print(f"🔍 Running FFUF directory discovery on {subdomain}")
                            ffuf_results = run_ffuf_scan(subdomain)

                            if ffuf_results and "results" in ffuf_results:
                                for result in ffuf_results["results"]:
                                    status = result.get("status", 0)
                                    url = result.get("url", "")

                                    # Comprehensive FFUF discovery data
                                    discovery_data = {
                                        "subdomain": subdomain,
                                        "url": url,
                                        "status_code": status,
                                        "content_length": result.get("length", 0),
                                        "content_words": result.get("words", 0),
                                        "content_lines": result.get("lines", 0),
                                        "response_time": result.get("duration", 0),
                                        "redirect_location": result.get(
                                            "redirectlocation", ""
                                        ),
                                        "tool": "FFUF",
                                        "scan_timestamp": datetime.utcnow().isoformat(),
                                    }
                                    vulnerability_data["ffuf_discoveries"].append(
                                        discovery_data
                                    )

                                    # Consider certain status codes as potential security issues
                                    if status in [200, 401, 403, 500]:
                                        severity = "low"
                                        if status == 500:
                                            severity = "medium"
                                        elif status in [401, 403]:
                                            severity = "low"  # Information disclosure

                                        vuln_data = {
                                            "subdomain": subdomain,
                                            "title": f"Directory/File Discovery - {url}",
                                            "severity": severity,
                                            "confidence": "firm",
                                            "description": f"Discovered accessible endpoint with status {status}",
                                            "solution": "Review exposed endpoints for sensitive information",
                                            "reference": url,
                                            "tool": "FFUF",
                                            "status_code": status,
                                            "content_length": result.get("length", 0),
                                            "scan_timestamp": datetime.utcnow().isoformat(),
                                        }
                                        vulnerability_data["vulnerabilities"].append(
                                            vuln_data
                                        )

                                        if severity == "medium":
                                            medium_risk_count += 1
                                        else:
                                            low_risk_count += 1

                            vulnerability_data["scan_status"]["completed_scans"] += 1

                        except Exception as e:
                            print(f"❌ FFUF scan failed for {subdomain}: {e}")
                            vulnerability_data["scan_status"]["failed_scans"] += 1

                # === READ STORED DATA FROM DATABASE (same as before) ===
                # DNS ANALYSIS DATA (DNSx)
                dns_data = {}
                for key, value in doc.items():
                    if key.startswith("dnsx_") and value:
                        dns_field = key.replace("dnsx_", "")
                        dns_data[dns_field] = value

                if dns_data:
                    dns_record = {"subdomain": subdomain, **dns_data}
                    vulnerability_data["dns_records"].append(dns_record)

            except Exception as e:
                print(f"❌ Error processing subdomain {subdomain}: {e}")
                vulnerability_data["scan_status"]["failed_scans"] += 1
                continue

        # === PROCESS STORED DATABASE DATA FOR ALL SUBDOMAINS ===
        for doc in subdomain_docs:
            subdomain = doc.get("subdomain", "")

            # === HTTP/HTTPS ANALYSIS (HTTPx) ===
            http_data = {}
            tls_data = {}
            for key, value in doc.items():
                if key.startswith("httpx_") and value:
                    if key.startswith("httpx_tls_"):
                        tls_field = key.replace("httpx_tls_", "")
                        tls_data[tls_field] = value
                    else:
                        http_field = key.replace("httpx_", "")
                        http_data[http_field] = value

            if http_data:
                http_analysis = {"subdomain": subdomain, **http_data}
                vulnerability_data["http_analysis"].append(http_analysis)

            # === SSL/TLS CERTIFICATE ANALYSIS ===
            if tls_data:
                ssl_cert = {"subdomain": subdomain, **tls_data}
                vulnerability_data["ssl_certificates"].append(ssl_cert)

            # === TECHNOLOGY FINGERPRINTING ===
            # From HTTPx tech detection
            if "httpx_tech" in doc and doc["httpx_tech"]:
                for tech in doc["httpx_tech"]:
                    if tech not in vulnerability_data["technologies"]:
                        vulnerability_data["technologies"].append(tech)

            # From general technologies field
            for tech in doc.get("technologies", []):
                if tech not in vulnerability_data["technologies"]:
                    vulnerability_data["technologies"].append(tech)

            # === WhatWeb analysis (if available from stored data) ===
            whatweb_data = doc.get("whatweb", {})
            if whatweb_data:
                whatweb_analysis = {
                    "subdomain": subdomain,
                    "technologies": whatweb_data.get("technologies", []),
                    "plugins": whatweb_data.get("plugins", {}),
                    "summary": whatweb_data.get("summary", ""),
                }
                vulnerability_data["whatweb_analysis"].append(whatweb_analysis)

            # === IP GEOLOCATION & ASN DETAILS ===
            if "httpx_ip" in doc or "dnsx_a" in doc:
                ip_address = (
                    doc.get("httpx_ip") or doc.get("dnsx_a", [""])[0]
                    if isinstance(doc.get("dnsx_a"), list)
                    else doc.get("dnsx_a", "")
                )

                # Extract geolocation data (if available from previous scans)
                geolocation_data = doc.get("geolocation", {})
                if geolocation_data or ip_address:
                    geo_info = {
                        "subdomain": subdomain,
                        "ip_address": ip_address,
                        "country": geolocation_data.get("country", "Unknown"),
                        "region": geolocation_data.get("region", "Unknown"),
                        "city": geolocation_data.get("city", "Unknown"),
                        "coordinates": geolocation_data.get("coordinates", {}),
                        "timezone": geolocation_data.get("timezone", "Unknown"),
                    }
                    vulnerability_data["ip_geolocation"].append(geo_info)

                # ASN details (if available)
                asn_data = doc.get("asn", {})
                if asn_data or ip_address:
                    asn_info = {
                        "subdomain": subdomain,
                        "ip_address": ip_address,
                        "asn_number": asn_data.get("asn", "Unknown"),
                        "asn_org": asn_data.get("organization", "Unknown"),
                        "isp": asn_data.get("isp", "Unknown"),
                        "network": asn_data.get("network", "Unknown"),
                    }
                    vulnerability_data["asn_details"].append(asn_info)

            # === NMAP PORT SCANNING DATA ===
            nmap_data = doc.get("nmap", {})
            if nmap_data:
                # Service detection
                open_ports = nmap_data.get("open_ports", [])
                for port_info in open_ports:
                    service_data = {
                        "subdomain": subdomain,
                        "port": port_info.get("port", ""),
                        "protocol": port_info.get("protocol", "tcp"),
                        "service": port_info.get("service", ""),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                        "state": port_info.get("state", ""),
                        "reason": port_info.get("reason", ""),
                        "banner": port_info.get("banner", ""),
                    }
                    vulnerability_data["services"].append(service_data)
                    vulnerability_data["open_ports"].append(service_data)

                # Nmap script results
                script_results = nmap_data.get("scripts", {})
                if script_results:
                    for script_name, script_output in script_results.items():
                        if any(
                            keyword in script_output.lower()
                            for keyword in ["vuln", "exploit", "cve"]
                        ):
                            vuln_data = {
                                "subdomain": subdomain,
                                "title": f"Nmap Script Detection: {script_name}",
                                "severity": "medium",
                                "confidence": "medium",
                                "description": script_output,
                                "solution": "Review and validate finding through manual verification",
                                "tool": "Nmap",
                                "script_name": script_name,
                            }
                            vulnerability_data["vulnerabilities"].append(vuln_data)

            # === OWASP ZAP VULNERABILITY SCANNING ===
            zap_data = doc.get("zap", {})
            if zap_data:
                alerts = zap_data.get("alerts", [])
                for alert in alerts:
                    risk_level = alert.get("risk", "").lower()

                    # Count risk levels
                    if risk_level == "high":
                        high_risk_count += 1
                    elif risk_level == "medium":
                        medium_risk_count += 1
                    elif risk_level == "low":
                        low_risk_count += 1

                    vuln_data = {
                        "subdomain": subdomain,
                        "title": alert.get("name", "Unknown Vulnerability"),
                        "severity": alert.get("risk", "Unknown"),
                        "confidence": alert.get("confidence", "Unknown"),
                        "description": alert.get("description", ""),
                        "solution": alert.get("solution", ""),
                        "reference": alert.get("reference", ""),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", ""),
                        "plugin_id": alert.get("pluginid", ""),
                        "instances": len(alert.get("instances", [])),
                        "attack": alert.get("attack", ""),
                        "evidence": alert.get("evidence", ""),
                        "tool": "OWASP ZAP",
                    }
                    vulnerability_data["vulnerabilities"].append(vuln_data)

            # === NUCLEI VULNERABILITY DETECTION ===
            nuclei_vulns = doc.get("vulnerabilities", [])
            if nuclei_vulns:
                for vuln in nuclei_vulns:
                    nuclei_finding = {
                        "subdomain": subdomain,
                        "template_id": vuln.get("template-id", ""),
                        "template_name": vuln.get("info", {}).get("name", ""),
                        "severity": vuln.get("info", {}).get("severity", "unknown"),
                        "description": vuln.get("info", {}).get("description", ""),
                        "reference": vuln.get("info", {}).get("reference", []),
                        "tags": vuln.get("info", {}).get("tags", []),
                        "matched_at": vuln.get("matched-at", ""),
                        "extracted_results": vuln.get("extracted-results", []),
                        "tool": "Nuclei",
                    }
                    vulnerability_data["nuclei_findings"].append(nuclei_finding)

                    # Also add to main vulnerabilities list
                    vuln_severity = (
                        vuln.get("info", {}).get("severity", "unknown").lower()
                    )
                    if vuln_severity == "high":
                        high_risk_count += 1
                    elif vuln_severity == "medium":
                        medium_risk_count += 1
                    elif vuln_severity == "low":
                        low_risk_count += 1

            # === FFUF DIRECTORY/FILE DISCOVERY ===
            ffuf_data = doc.get("ffuf", {})
            if ffuf_data:
                results = ffuf_data.get("results", [])
                for result in results:
                    status = result.get("status", 0)
                    url = result.get("url", "")

                    # Comprehensive FFUF discovery data
                    discovery_data = {
                        "subdomain": subdomain,
                        "url": url,
                        "status_code": status,
                        "content_length": result.get("length", 0),
                        "content_words": result.get("words", 0),
                        "content_lines": result.get("lines", 0),
                        "response_time": result.get("duration", 0),
                        "redirect_location": result.get("redirectlocation", ""),
                        "tool": "FFUF",
                    }
                    vulnerability_data["ffuf_discoveries"].append(discovery_data)

                    # Consider certain status codes as potential security issues
                    if status in [200, 401, 403, 500]:
                        severity = "low"
                        if status == 500:
                            severity = "medium"
                        elif status in [401, 403]:
                            severity = "low"  # Information disclosure

                        vuln_data = {
                            "subdomain": subdomain,
                            "title": f"Directory/File Discovery - {url}",
                            "severity": severity,
                            "confidence": "firm",
                            "description": f"Discovered accessible endpoint with status {status}",
                            "solution": "Review exposed endpoints for sensitive information",
                            "reference": url,
                            "tool": "FFUF",
                            "status_code": status,
                            "content_length": result.get("length", 0),
                        }
                        vulnerability_data["vulnerabilities"].append(vuln_data)

                        if severity == "medium":
                            medium_risk_count += 1
                        else:
                            low_risk_count += 1

            # === SSL/TLS CERTIFICATE ISSUES & ANALYSIS ===
            # SSL issues from certificate analysis
            ssl_info = doc.get("ssl_info", {})
            if ssl_info:
                ssl_issues = ssl_info.get("issues", [])
                for issue in ssl_issues:
                    ssl_data = {
                        "subdomain": subdomain,
                        "issue": issue.get("type", "SSL/TLS Issue"),
                        "severity": issue.get("severity", "medium"),
                        "description": issue.get("description", ""),
                        "certificate_info": issue.get("cert_details", {}),
                        "tool": "SSL Check",
                    }
                    vulnerability_data["ssl_issues"].append(ssl_data)

            # Additional SSL certificate analysis from TLS data
            if tls_data:
                # Check for common SSL/TLS issues
                cert_chain = tls_data.get("certificate_chain", [])
                if cert_chain:
                    for cert in cert_chain:
                        # Weak signature algorithms
                        sig_alg = cert.get("signature_algorithm", "").lower()
                        if any(weak in sig_alg for weak in ["md5", "sha1"]):
                            ssl_issue = {
                                "subdomain": subdomain,
                                "issue": "Weak Certificate Signature Algorithm",
                                "severity": "medium",
                                "description": f"Certificate uses weak signature algorithm: {sig_alg}",
                                "certificate_info": cert,
                                "tool": "TLS Analysis",
                            }
                            vulnerability_data["ssl_issues"].append(ssl_issue)

            # === CVE SUGGESTIONS & RISK INTELLIGENCE ===
            # Cohere CVE suggestions
            cve_suggestions = doc.get("cohere_cves", [])
            if cve_suggestions:
                for cve in cve_suggestions:
                    cve_data = {
                        "subdomain": subdomain,
                        "cve_id": cve.get("cve_id", ""),
                        "title": cve.get("title", ""),
                        "severity": cve.get("severity", "unknown"),
                        "description": cve.get("description", ""),
                        "affected_technology": cve.get("technology", ""),
                        "source": "Cohere AI Analysis",
                    }
                    vulnerability_data["cve_suggestions"].append(cve_data)

            # Risk assessment data
            risk_score = doc.get("risk_score")
            if risk_score:
                risk_assessment = {
                    "subdomain": subdomain,
                    "risk_score": risk_score,
                    "risk_reason": doc.get("risk_reason", ""),
                    "risk_suggestions": doc.get("risk_suggestions", []),
                    "recommended_tests": doc.get("risk_tests", []),
                    "next_commands": doc.get("next_commands", []),
                    "explanation": doc.get("explanation", ""),
                    "source": "Cohere Risk Analysis",
                }
                vulnerability_data["risk_assessments"].append(risk_assessment)

            # Cohere analysis summary
            if any(key.startswith("cohere_") for key in doc.keys()) or risk_score:
                cohere_data = {
                    "subdomain": subdomain,
                    "analysis_available": True,
                    "cve_count": len(cve_suggestions),
                    "risk_score": risk_score,
                    "has_recommendations": bool(doc.get("next_commands")),
                    "last_analyzed": doc.get("scanned_at", ""),
                }
                vulnerability_data["cohere_analysis"].append(cohere_data)

        # === COMPREHENSIVE SCAN SUMMARY & METRICS ===
        vulnerability_data["scan_summary"] = {
            # Core metrics
            "total_subdomains": len(vulnerability_data["subdomains"]),
            "total_dns_records": len(vulnerability_data["dns_records"]),
            "total_http_services": len(vulnerability_data["http_analysis"]),
            "total_ssl_certificates": len(vulnerability_data["ssl_certificates"]),
            # Security findings
            "total_vulnerabilities": len(vulnerability_data["vulnerabilities"]),
            "total_nuclei_findings": len(vulnerability_data["nuclei_findings"]),
            "total_ssl_issues": len(vulnerability_data["ssl_issues"]),
            "ffuf_discoveries": len(vulnerability_data["ffuf_discoveries"]),
            # Infrastructure
            "total_services": len(vulnerability_data["services"]),
            "total_open_ports": len(vulnerability_data["open_ports"]),
            "total_technologies": len(vulnerability_data["technologies"]),
            # Intelligence data
            "total_cve_suggestions": len(vulnerability_data["cve_suggestions"]),
            "total_risk_assessments": len(vulnerability_data["risk_assessments"]),
            "cohere_analyzed_subdomains": len(vulnerability_data["cohere_analysis"]),
            # Geolocation and network
            "unique_ip_addresses": len(vulnerability_data["ip_geolocation"]),
            "asn_details_available": len(vulnerability_data["asn_details"]),
            "whatweb_analyzed": len(vulnerability_data["whatweb_analysis"]),
            # Risk levels
            "high_risk_vulns": high_risk_count,
            "medium_risk_vulns": medium_risk_count,
            "low_risk_vulns": low_risk_count,
            "risk_level": "high"
            if high_risk_count > 0
            else "medium"
            if medium_risk_count > 0
            else "low"
            if low_risk_count > 0
            else "minimal",
            # Data quality indicators
            "data_completeness": {
                "has_dns_data": len(vulnerability_data["dns_records"]) > 0,
                "has_http_data": len(vulnerability_data["http_analysis"]) > 0,
                "has_ssl_data": len(vulnerability_data["ssl_certificates"]) > 0,
                "has_vulnerability_data": len(vulnerability_data["vulnerabilities"])
                > 0,
                "has_port_data": len(vulnerability_data["open_ports"]) > 0,
                "has_technology_data": len(vulnerability_data["technologies"]) > 0,
                "has_geolocation_data": len(vulnerability_data["ip_geolocation"]) > 0,
                "has_intelligence_data": len(vulnerability_data["cve_suggestions"]) > 0,
            },
        }

        # === ATTACK SURFACE & THREAT ANALYSIS ===
        # Attack surface assessment
        subdomain_count = len(vulnerability_data["subdomains"])
        service_count = len(vulnerability_data["services"])

        attack_surface = "minimal"
        if subdomain_count > 20 or service_count > 50:
            attack_surface = "extensive"
        elif subdomain_count > 10 or service_count > 20:
            attack_surface = "large"
        elif subdomain_count > 3 or service_count > 5:
            attack_surface = "medium"
        elif subdomain_count > 0:
            attack_surface = "small"

        vulnerability_data["attack_surface"] = attack_surface

        # === INTELLIGENT TOOL RECOMMENDATIONS ===
        recommended_tools = []
        tool_rationale = []

        # Recommend based on findings
        if len(vulnerability_data["services"]) > 0:
            recommended_tools.extend(["nmap", "nuclei"])
            tool_rationale.append(
                "Services detected - port scanning and vulnerability checking recommended"
            )

        if len(vulnerability_data["subdomains"]) > 3:
            recommended_tools.append("ffuf")
            tool_rationale.append(
                "Large subdomain set - directory/file discovery recommended"
            )

        if any(
            "web" in tech.lower() or "http" in tech.lower()
            for tech in vulnerability_data["technologies"]
        ):
            recommended_tools.extend(["nikto", "nuclei"])
            tool_rationale.append(
                "Web technologies detected - web vulnerability scanning recommended"
            )

        if len(vulnerability_data["ssl_certificates"]) > 0:
            recommended_tools.append("testssl")
            tool_rationale.append(
                "SSL certificates found - SSL/TLS security testing recommended"
            )

        if high_risk_count > 0:
            recommended_tools.extend(["nuclei", "nikto"])
            tool_rationale.append(
                "High-risk vulnerabilities found - comprehensive scanning needed"
            )

        vulnerability_data["recommended_tools"] = list(set(recommended_tools))
        vulnerability_data["tool_rationale"] = tool_rationale

        # === EXECUTIVE SUMMARY FOR MCP ===
        vulnerability_data["executive_summary"] = {
            "target_assessment": f"Target {target} has {attack_surface} attack surface",
            "key_findings": [
                f"Discovered {subdomain_count} subdomains",
                f"Identified {service_count} network services",
                f"Found {len(vulnerability_data['vulnerabilities'])} vulnerabilities",
                f"Detected {len(vulnerability_data['technologies'])} technologies",
            ],
            "risk_profile": {
                "overall_risk": vulnerability_data["scan_summary"]["risk_level"],
                "critical_issues": high_risk_count,
                "needs_attention": medium_risk_count,
                "total_findings": len(vulnerability_data["vulnerabilities"]),
            },
            "data_sources": {
                "subfinder": len(vulnerability_data["subdomains"]) > 0,
                "dnsx": len(vulnerability_data["dns_records"]) > 0,
                "httpx": len(vulnerability_data["http_analysis"]) > 0,
                "nmap": len(vulnerability_data["services"]) > 0,
                "zap": any(
                    v.get("tool") == "OWASP ZAP"
                    for v in vulnerability_data["vulnerabilities"]
                ),
                "nuclei": len(vulnerability_data["nuclei_findings"]) > 0,
                "ffuf": len(vulnerability_data["ffuf_discoveries"]) > 0,
                "ssl_analysis": len(vulnerability_data["ssl_certificates"]) > 0,
                "cohere_ai": len(vulnerability_data["cohere_analysis"]) > 0,
            },
        }

        return jsonify(vulnerability_data), 200

    except Exception as e:
        return jsonify(
            {
                "error": f"Failed to fetch vulnerability data: {str(e)}",
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ), 500


@app.route("/mcp/health", methods=["GET"])
def mcp_health_check():
    """
    Simple health check endpoint for MCP server connectivity testing
    """
    return jsonify(
        {
            "status": "healthy",
            "service": "IITM Vulnerability Scanner Backend",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "endpoints": {
                "vulnerability_data": "/mcp/vulnerability-data?target=<target>&scan_type=<type>",
                "health": "/mcp/health",
            },
        }
    ), 200


# if __name__ == "__main__":
#     app.run(debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
