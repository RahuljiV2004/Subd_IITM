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


# if __name__ == "__main__":
#     app.run(debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
