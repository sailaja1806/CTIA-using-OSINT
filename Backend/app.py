from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from database import (
    initialize_database,
    create_user,
    authenticate_user,
    get_db
)
import re
import os

app = Flask(__name__)
CORS(app)

initialize_database()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/<path:filename>")
def frontend_files(filename):
    file_path = os.path.join(BASE_DIR, filename)
    if os.path.isfile(file_path):
        return send_from_directory(BASE_DIR, filename)
    return jsonify({"success": False, "message": "File not found"}), 404


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "message": "CTIA API is healthy",
        "status": "online"
    })


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400
    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 6 characters"
        }), 400

    user_id = create_user(name, email, password)
    if user_id is None:
        return jsonify({"success": False, "message": "Email already registered"}), 409

    return jsonify({
        "success": True,
        "message": "Account created successfully",
        "user": {"id": user_id, "name": name, "email": email}
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    user = authenticate_user(email, password)
    if user is None:
        return jsonify({"success": False, "message": "Invalid email or password"}), 401

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
    })


def detect_indicator_type(indicator):
    value = indicator.strip()
    if re.match(r"^(https?|ftp)://", value, re.IGNORECASE):
        return "URL"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256 Hash"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1 Hash"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5 Hash"
    if re.fullmatch(
        r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}",
        value
    ):
        return "IP Address"
    if re.fullmatch(
        r"(?=.{3,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}",
        value
    ):
        return "Domain"
    return "Unknown"


def calculate_risk(malicious=0, suspicious=0, harmless=0, undetected=0):
    total = malicious + suspicious + harmless + undetected
    if total <= 0:
        return {"risk_score": 0, "severity": "Low"}
    score = ((malicious / total) * 100) + ((suspicious / total) * 40)
    score = min(100, round(score))
    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"
    return {"risk_score": score, "severity": severity}


def classify_threat(indicator, indicator_type):
    text = indicator.lower()
    phishing_words = [
        "phishing", "credential", "login", "verify", "signin", "password", "account"
    ]
    ransomware_words = ["ransomware", "ransom", "encrypt", "decrypt"]
    malware_words = ["malware", "trojan", "virus", "backdoor", "payload"]
    ddos_words = ["ddos", "denial-of-service"]
    breach_words = ["breach", "leaked", "stolen", "credentials"]
    vulnerability_words = ["cve", "vulnerability", "exploit"]

    if any(word in text for word in phishing_words):
        return "Phishing"
    if any(word in text for word in ransomware_words):
        return "Ransomware"
    if any(word in text for word in malware_words):
        return "Malware"
    if any(word in text for word in ddos_words):
        return "DDoS"
    if any(word in text for word in breach_words):
        return "Data Breach"
    if any(word in text for word in vulnerability_words):
        return "Vulnerability"
    if indicator_type == "URL":
        return "Suspicious / Unknown"
    if indicator_type == "IP Address":
        return "Suspicious / Unknown"
    if indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        return "Malware"
    return "Suspicious / Unknown"


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data received"}), 400

        indicator = data.get("indicator", "").strip()
        if not indicator:
            return jsonify({"success": False, "message": "Indicator is required"}), 400

        indicator_type = detect_indicator_type(indicator)
        if indicator_type == "Unknown":
            return jsonify({
                "success": False,
                "message": "Unsupported indicator format. Enter a URL, domain, IP address or file hash."
            }), 400

        text = indicator.lower()
        suspicious_keywords = [
            "phishing", "malware", "ransom", "login", "verify",
            "secure-account", "credential", "password", "free-gift",
            "claim-prize", "download", "exploit", "cve", "trojan",
            "payload", "backdoor"
        ]
        keyword_hits = sum(1 for word in suspicious_keywords if word in text)

        if keyword_hits >= 2:
            malicious, suspicious, harmless, undetected = 8, 4, 1, 1
        elif keyword_hits == 1:
            malicious, suspicious, harmless, undetected = 3, 4, 4, 1
        else:
            malicious, suspicious, harmless, undetected = 0, 1, 8, 3

        if indicator_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"] and keyword_hits == 0:
            malicious, suspicious, harmless, undetected = 3, 3, 3, 1

        risk = calculate_risk(malicious, suspicious, harmless, undetected)
        threat_type = classify_threat(indicator, indicator_type)
        if risk["risk_score"] >= 75:
            status = "Malicious / Critical Risk"
        elif risk["risk_score"] >= 50:
            status = "Malicious / High Risk"
        elif risk["risk_score"] >= 25:
            status = "Suspicious"
        else:
            status = "No Significant Threat Detected"
        confidence = min(99, 60 + (risk["risk_score"] // 3))

        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO threats
            (indicator, threat_type, severity, source, description,
             risk_score, confidence, indicator_type, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                indicator, threat_type, risk["severity"],
                "CTIA Analysis Engine", "Automated threat analysis",
                risk["risk_score"], confidence, indicator_type, status
            )
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO iocs
            (indicator, indicator_type, threat_type, severity, risk_score,
             confidence, source, status, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                indicator, indicator_type, threat_type, risk["severity"],
                risk["risk_score"], confidence, "CTIA Analysis Engine",
                "Active", "Automatically analyzed indicator"
            )
        )

        alert_created = False
        if risk["risk_score"] >= 50:
            cursor.execute(
                """
                INSERT INTO alerts
                (title, severity, status, source, indicator, threat_type,
                 risk_score, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{risk['severity']} Threat Detected", risk["severity"],
                    "Open", "CTIA Analysis Engine", indicator, threat_type,
                    risk["risk_score"],
                    "Automatic security alert generated by CTIA."
                )
            )
            alert_created = True

        connection.commit()
        connection.close()
        return jsonify({
            "success": True,
            "message": "Threat analysis completed successfully",
            "result": {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": status,
                "threat_type": threat_type,
                "severity": risk["severity"],
                "risk_score": risk["risk_score"],
                "confidence": confidence,
                "detections": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                },
                "alert_created": alert_created
            }
        })
    except Exception as error:
        print("ANALYSIS ERROR:", error)
        return jsonify({
            "success": False,
            "message": "Analysis failed",
            "error": str(error)
        }), 500


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) AS count FROM threats")
    threats = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) AS count FROM alerts WHERE status != 'Resolved'")
    alerts = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) AS count FROM users")
    users = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) AS count FROM iocs")
    iocs = cursor.fetchone()["count"]

    severity_counts = {}
    for severity in ["Low", "Medium", "High", "Critical"]:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM threats WHERE severity = ?",
            (severity,)
        )
        severity_counts[severity.lower()] = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT threat_type, COUNT(*) AS count FROM threats
        GROUP BY threat_type ORDER BY count DESC
    """)
    threat_types = {}
    for row in cursor.fetchall():
        threat_types[row["threat_type"] or "Unknown"] = row["count"]
    connection.close()
    return jsonify({
        "success": True,
        "statistics": {
            "active_threats": threats,
            "alerts": alerts,
            "users": users,
            "iocs": iocs,
            "severity": severity_counts,
            "threat_types": threat_types
        }
    })


@app.route("/api/threats", methods=["GET"])
def get_threats():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY created_at DESC")
    threats = cursor.fetchall()
    connection.close()
    result = []
    for threat in threats:
        result.append({
            "id": threat["id"],
            "indicator": threat["indicator"],
            "indicator_type": threat["indicator_type"],
            "threat_type": threat["threat_type"],
            "severity": threat["severity"],
            "risk_score": threat["risk_score"],
            "confidence": threat["confidence"],
            "source": threat["source"],
            "status": threat["status"],
            "description": threat["description"],
            "created_at": threat["created_at"]
        })
    return jsonify({"success": True, "threats": result})


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC")
    alerts = cursor.fetchall()
    connection.close()
    return jsonify({"success": True, "alerts": [dict(alert) for alert in alerts]})


@app.route("/api/alerts/<int:alert_id>", methods=["PUT"])
def update_alert(alert_id):
    data = request.get_json() or {}
    status = data.get("status", "Resolved")
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE alerts SET status = ? WHERE id = ?",
        (status, alert_id)
    )
    connection.commit()
    updated = cursor.rowcount > 0
    connection.close()
    return jsonify({
        "success": updated,
        "message": "Alert updated successfully" if updated else "Alert not found"
    })


@app.route("/api/iocs", methods=["GET"])
def get_iocs():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM iocs ORDER BY created_at DESC")
    iocs = cursor.fetchall()
    connection.close()
    return jsonify({"success": True, "iocs": [dict(ioc) for ioc in iocs]})


@app.route("/api/osint/collect", methods=["POST"])
def collect_osint():
    demo_records = [
        {
            "source": "CISA",
            "title": "Cybersecurity Advisory",
            "indicator": "CVE-2026-DEMO",
            "indicator_type": "CVE",
            "threat_type": "Vulnerability",
            "severity": "High",
            "description": "Example OSINT vulnerability intelligence."
        },
        {
            "source": "Threat Intelligence Feed",
            "title": "Suspicious Infrastructure",
            "indicator": "malicious-example.com",
            "indicator_type": "Domain",
            "threat_type": "Phishing",
            "severity": "Medium",
            "description": "Example public threat intelligence record."
        }
    ]
    connection = get_db()
    cursor = connection.cursor()
    inserted = 0
    for record in demo_records:
        cursor.execute(
            """
            INSERT INTO osint_records
            (source, title, indicator, indicator_type, threat_type,
             severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["source"], record["title"], record["indicator"],
                record["indicator_type"], record["threat_type"],
                record["severity"], record["description"]
            )
        )
        inserted += 1
    connection.commit()
    cursor.execute("SELECT * FROM osint_records ORDER BY collected_at DESC")
    records = [dict(row) for row in cursor.fetchall()]
    connection.close()
    return jsonify({
        "success": True,
        "message": f"{inserted} intelligence records collected",
        "records": records
    })


@app.route("/api/osint/records", methods=["GET"])
def get_osint_records():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM osint_records ORDER BY collected_at DESC")
    records = [dict(row) for row in cursor.fetchall()]
    connection.close()
    return jsonify({"success": True, "records": records})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
