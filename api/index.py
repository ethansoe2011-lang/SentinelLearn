from flask import Flask, render_template, request, jsonify, Response, redirect, session, url_for
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import json
import time
import threading
import collections
import hashlib
import io
import math
import re
import zipfile
import string
import random
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from groq import Groq
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from authlib.integrations.flask_client import OAuth

# New Security Analysis Dependencies
try:
    import whois
except ImportError:
    whois = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    VBA_Parser = None

try:
    import yara
    # Pre-compiled static YARA rules for signature matching known threats
    YARA_RULES = """
    rule Suspicious_Webshell_Or_Obfuscation {
        strings:
            $eval = "eval("
            $base64 = "base64_decode"
            $cmd = "cmd.exe"
            $ps1 = "powershell -ExecutionPolicy Bypass"
            $magic = { 4D 5A }
        condition:
            any of them
    }
    """
    COMPILED_YARA = yara.compile(source=YARA_RULES)
except ImportError:
    COMPILED_YARA = None

# Load environment variables from .env file for local development
load_dotenv()

# Initialize Flask and point it to the templates directory
app = Flask(__name__, template_folder="../templates")

# Apply ProxyFix so that url_for(..., _external=True) properly respects https behind Vercel/reverse proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Secret key for Flask sessions — required for OAuth and session cookies
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "sentinel-dev-secret-key-change-in-production-32chars")

# ---------------------------------------------------------------------------
# CORS — scoped to external extension, agent, and file scanner endpoints
# ---------------------------------------------------------------------------
CORS(app, resources={
    r"/api/activity-check": {"origins": "*"},
    r"/api/logs*":          {"origins": "*"},
    r"/api/scan-file":      {"origins": "*"},
})

# Initialize the Groq Client
groq_client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)

# ---------------------------------------------------------------------------
# OAUTH2 SETUP
# ---------------------------------------------------------------------------
oauth = OAuth(app)

google_client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")

oauth.register(
    name="google",
    client_id=google_client_id,
    client_secret=google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

github_client_id = os.environ.get("GITHUB_CLIENT_ID", "")
github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")

oauth.register(
    name="github",
    client_id=github_client_id,
    client_secret=github_client_secret,
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)


# ---------------------------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------------------------

def get_current_user():
    """Return the logged-in user dict from session, or None if not logged in."""
    return session.get("user", None)


def make_user_id(provider: str, sub: str) -> str:
    """Create a safe, unique, filesystem-friendly user ID from provider + sub."""
    raw = f"{provider}:{sub}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# AUTH ROUTES
# ---------------------------------------------------------------------------

@app.route("/auth/google")
def auth_google():
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    if not client_id or client_id == "paste_google_id_here":
        return Response(
            """
            <body style="background:#050505;color:#fff;font-family:sans-serif;padding:50px;text-align:center;">
                <h2 style="color:#ff4757;">Google OAuth Not Configured</h2>
                <p style="color:#aaa;max-width:600px;margin:0 auto 20px auto;line-height:1.6;">
                    Your <code>GOOGLE_CLIENT_ID</code> is currently missing or set to placeholder in <code>.env</code>.
                </p>
                <p style="color:#ccc;line-height:1.6;">
                    Please create an OAuth 2.0 Web Client in Google Cloud Console, add your Client ID &amp; Secret to <code>.env</code> (and Vercel environment variables), then try again.
                </p>
                <a href="/" style="display:inline-block;margin-top:20px;padding:10px 20px;background:#00f3ff;color:#000;text-decoration:none;border-radius:8px;font-weight:600;">Return Home</a>
            </body>
            """,
            mimetype="text/html",
            status=400
        )
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get("userinfo")
        if not userinfo:
            try:
                userinfo = oauth.google.userinfo(token=token)
            except Exception:
                userinfo = {}

        sub_id = str(userinfo.get("sub") or userinfo.get("id") or "")
        if sub_id:
            user_id = make_user_id("google", sub_id)
            session["user"] = {
                "id": user_id,
                "name": userinfo.get("name", "Google User"),
                "email": userinfo.get("email", ""),
                "picture": userinfo.get("picture", ""),
                "provider": "google",
            }
    except Exception as e:
        session.pop("user", None)
    return redirect("/")


@app.route("/auth/github")
def auth_github():
    client_id = os.environ.get("GITHUB_CLIENT_ID", "").strip()
    if not client_id or client_id == "paste_github_id_here":
        return Response(
            """
            <body style="background:#050505;color:#fff;font-family:sans-serif;padding:50px;text-align:center;">
                <h2 style="color:#ff4757;">GitHub OAuth Not Configured</h2>
                <p style="color:#aaa;max-width:600px;margin:0 auto 20px auto;line-height:1.6;">
                    Your <code>GITHUB_CLIENT_ID</code> is currently missing or set to placeholder in <code>.env</code>.
                </p>
                <p style="color:#ccc;line-height:1.6;">
                    Please create an OAuth App in GitHub Developer Settings, add your Client ID &amp; Secret to <code>.env</code> (and Vercel environment variables), then try again.
                </p>
                <a href="/" style="display:inline-block;margin-top:20px;padding:10px 20px;background:#00f3ff;color:#000;text-decoration:none;border-radius:8px;font-weight:600;">Return Home</a>
            </body>
            """,
            mimetype="text/html",
            status=400
        )
    redirect_uri = url_for("auth_github_callback", _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@app.route("/auth/github/callback")
def auth_github_callback():
    try:
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get("user", token=token)
        profile = resp.json()
        # Get primary email if not public
        email = profile.get("email", "")
        if not email:
            email_resp = oauth.github.get("user/emails", token=token)
            emails = email_resp.json()
            if isinstance(emails, list):
                primary = next((e for e in emails if e.get("primary")), None)
                email = primary.get("email", "") if primary else ""
        user_id = make_user_id("github", str(profile.get("id", "")))
        session["user"] = {
            "id": user_id,
            "name": profile.get("name") or profile.get("login", "GitHub User"),
            "email": email,
            "picture": profile.get("avatar_url", ""),
            "provider": "github",
        }
    except Exception as e:
        session.pop("user", None)
    return redirect("/")


@app.route("/auth/logout")
def auth_logout():
    session.pop("user", None)
    return redirect("/")


@app.route("/api/auth/me")
def auth_me():
    user = get_current_user()
    if user:
        return jsonify({"logged_in": True, "user": user})
    return jsonify({"logged_in": False, "user": None})


# ---------------------------------------------------------------------------
# SECTION 1 — EXISTING ROUTES
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/education')
def education():
    return render_template('education.html')

@app.route('/education/topic/<topic_id>')
def education_topic(topic_id):
    valid_topics = ['phishing', 'malware', 'network']
    if topic_id not in valid_topics:
        return redirect('/education')
    return render_template('topic_deep_dive.html', topic_id=topic_id)

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_threat():
    data = request.get_json()
    activity_log = data.get('log', '')
    
    if not activity_log:
        return jsonify({'status': 'error', 'message': 'No activity log provided'}), 400
        
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are Sentinel, an advanced cybersecurity background monitor. Analyze the provided activity log (which may be background system events or live user browser actions). Respond briefly in one short paragraph. First, state CLEARLY whether the activity is 'Safe' or 'Dangerous/Malicious'. Then, if dangerous, briefly explain the threat and how you are automatically preventing it or warning the user."
                },
                {
                    "role": "user",
                    "content": f"Activity Log: {activity_log}"
                }
            ],
            model="openai/gpt-oss-120b",
        )
        
        analysis = chat_completion.choices[0].message.content
        return jsonify({'status': 'success', 'analysis': analysis})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ask-education', methods=['POST'])
def ask_education():
    data = request.get_json()
    question = data.get('question', '')
    
    if not question:
        return jsonify({'status': 'error', 'message': 'No question provided'}), 400
        
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are Sentinel EduBot, an encouraging and knowledgeable AI cybersecurity tutor. Answer user questions about cybersecurity, online safety, malicious data, and threat prevention clearly and concisely. Keep responses easy to understand, practical, and well-structured."
                },
                {
                    "role": "user",
                    "content": question
                }
            ],
            model="openai/gpt-oss-120b",
        )
        
        answer = chat_completion.choices[0].message.content
        return jsonify({'status': 'success', 'answer': answer})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/generate-quiz', methods=['POST'])
def generate_quiz():
    data = request.get_json() or {}
    topic = data.get('topic', 'General Cybersecurity Threats, Phishing, and Malware')
    
    if not topic:
        topic = 'General Cybersecurity Threats, Phishing, and Malware'
        
    try:
        prompt = (
            f"Generate a study set about '{topic}' focusing on cybersecurity and digital safety. "
            "Output strictly in JSON format with no markdown formatting, no code blocks, and no extra text. "
            "The JSON must have this exact structure: "
            "{"
            "\"flashcards\": [{\"front\": \"Question or Concept\", \"back\": \"Answer or Definition\"}, ... generate exactly 3 flashcards], "
            "\"mcqs\": [{\"question\": \"A scenario-based multiple choice question\", \"options\": [\"Option A\", \"Option B\", \"Option C\", \"Option D\"], \"answer\": \"Exact string of the correct option\", \"explanation\": \"Why this answer is correct\"}, ... generate exactly 3 MCQs], "
            "\"frqs\": [{\"question\": \"A practical free response question requiring a short paragraph answer\"}, ... generate exactly 2 FRQs]"
            "}"
        )
        
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity education AI. You only output strict, raw JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="openai/gpt-oss-120b",
        )
        
        raw_response = chat_completion.choices[0].message.content
        
        cleaned_response = raw_response.strip()
        if cleaned_response.startswith("```json"):
            cleaned_response = cleaned_response[7:]
        elif cleaned_response.startswith("```"):
            cleaned_response = cleaned_response[3:]
            
        if cleaned_response.endswith("```"):
            cleaned_response = cleaned_response[:-3]
            
        parsed_data = json.loads(cleaned_response.strip())
        return jsonify({'status': 'success', 'data': parsed_data})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/grade-quiz', methods=['POST'])
def grade_quiz():
    data = request.get_json() or {}
    topic = data.get('topic', 'Cybersecurity')
    mcq_score = data.get('mcq_score', 0)
    mcq_total = data.get('mcq_total', 0)
    frq_answers = data.get('frq_answers', [])
    
    try:
        prompt = (
            f"You are an expert cybersecurity AI grading a quiz about '{topic}'. "
            f"The user scored {mcq_score} out of {mcq_total} on the multiple-choice section.\n\n"
            f"Here are their Free Response Questions (FRQ) and answers:\n"
            f"{json.dumps(frq_answers, indent=2)}\n\n"
            "Your task:\n"
            "1. Grade each FRQ out of 10 points and provide a short, constructive feedback sentence.\n"
            "2. Provide an overall overview of their quiz results.\n"
            "3. List specific topics they should focus on studying based on their gaps.\n"
            "4. Provide practical advice on what they should be particularly careful of when browsing the internet based on this topic.\n\n"
            "Output strictly in JSON format with no markdown formatting. Ensure it matches this exact structure:\n"
            "{\n"
            "  \"frq_evaluations\": [\n"
            "    {\"question\": \"...\", \"score\": 8, \"feedback\": \"...\"}\n"
            "  ],\n"
            "  \"overview\": \"...\",\n"
            "  \"focus_areas\": [\"...\", \"...\"],\n"
            "  \"safety_warning\": \"...\"\n"
            "}"
        )
        
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity education grading AI. You only output strict, raw JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="openai/gpt-oss-120b",
        )
        
        raw_response = chat_completion.choices[0].message.content
        cleaned_response = raw_response.strip()
        if cleaned_response.startswith("```json"):
            cleaned_response = cleaned_response[7:]
        elif cleaned_response.startswith("```"):
            cleaned_response = cleaned_response[3:]
            
        if cleaned_response.endswith("```"):
            cleaned_response = cleaned_response[:-3]
            
        parsed_data = json.loads(cleaned_response.strip())
        return jsonify({'status': 'success', 'data': parsed_data})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# SECTION 2 — SENTINEL LOGGER & CONTEXT
# ---------------------------------------------------------------------------

class SentinelLogger:
    MAX_MEMORY_ENTRIES = 200
    LOG_FILENAME = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "activity_log.jsonl"
    )

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer = collections.deque(maxlen=self.MAX_MEMORY_ENTRIES)
        self._file_available = self._probe_file()

    def _probe_file(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.LOG_FILENAME), exist_ok=True)
            with open(self.LOG_FILENAME, "a", encoding="utf-8"):
                pass
            return True
        except Exception:
            return False

    def write(self, entry: dict) -> None:
        entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._buffer.append(entry)
            if self._file_available:
                try:
                    with open(self.LOG_FILENAME, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry) + "\n")
                except Exception:
                    self._file_available = False

    def read_recent(self, limit: int = 100) -> list:
        with self._lock:
            if self._file_available:
                try:
                    with open(self.LOG_FILENAME, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    entries = []
                    for line in reversed(lines[-limit:]):
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
                    return list(reversed(entries))
                except Exception:
                    pass
            items = list(self._buffer)
            return items[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            if self._file_available:
                try:
                    with open(self.LOG_FILENAME, "w", encoding="utf-8") as f:
                        f.write("")
                except Exception:
                    pass

_sentinel_logger = SentinelLogger()


# ---------------------------------------------------------------------------
# SECTION 3 — SERVER-SIDE SYSTEM SNAPSHOT
# ---------------------------------------------------------------------------

def gather_system_snapshot() -> str:
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        processes = []
        for proc in sorted(
            psutil.process_iter(['pid', 'name', 'memory_percent']),
            key=lambda p: p.info.get('memory_percent') or 0,
            reverse=True
        )[:3]:
            name = proc.info.get('name')
            pid = proc.info.get('pid')
            if name:
                processes.append(f"{name} (PID: {pid})")
        process_list_str = ", ".join(processes) if processes else "No significant processes detected."
        return (
            f"[SERVER SYSTEM SCAN] CPU Usage: {cpu_percent}%, "
            f"Memory Usage: {memory.percent}%. "
            f"Highest memory processes currently active: {process_list_str}."
        )
    except ImportError:
        return "[SERVER SYSTEM SCAN] psutil not available in this environment."
    except Exception as e:
        return f"[SERVER SYSTEM ERROR] Failed to gather system telemetry: {str(e)}"

# ---------------------------------------------------------------------------
# SECTION 4 — BEFORE-REQUEST HOOK
# ---------------------------------------------------------------------------

_last_snapshot_time: float = 0.0          
_SNAPSHOT_COOLDOWN_SECS: float = 30.0     
_EXCLUDED_PREFIXES = ("/api/logs", "/static/", "/favicon", "/auth/")

@app.before_request
def auto_system_scan():
    global _last_snapshot_time
    try:
        path = request.path
        if any(path.startswith(p) for p in _EXCLUDED_PREFIXES):
            return

        now = time.monotonic()
        if now - _last_snapshot_time < _SNAPSHOT_COOLDOWN_SECS:
            return  

        _last_snapshot_time = now  

        def _run_scan():
            try:
                snapshot = gather_system_snapshot()
                completion = groq_client.chat.completions.create(
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are Sentinel, an advanced cybersecurity monitor. "
                                "Output strictly in JSON format using this exact schema: "
                                '{"verdict": "SAFE" or "THREAT", "confidence_score": 0.0-1.0, "risk_factors": ["risk1"], "summary": "brief explanation"}'
                            )
                        },
                        {"role": "user", "content": f"Activity Log: {snapshot}"}
                    ],
                    model="openai/gpt-oss-120b",
                    response_format={"type": "json_object"}
                )
                
                raw_response = completion.choices[0].message.content
                analysis_data = json.loads(raw_response)

                _sentinel_logger.write({
                    "source": "server_auto_scan",
                    "type": "system_snapshot",
                    "input": snapshot,
                    "verdict": analysis_data.get("verdict", "INFO"),
                    "confidence_score": analysis_data.get("confidence_score", 0.0),
                    "risk_factors": analysis_data.get("risk_factors", []),
                    "summary": analysis_data.get("summary", "System scan complete."),
                })
            except Exception:
                pass 

        t = threading.Thread(target=_run_scan, daemon=True)
        t.start()

    except Exception:
        pass 


# ---------------------------------------------------------------------------
# SECTION 5 — NEW API ROUTES & THREAT INTEL
# ---------------------------------------------------------------------------

def check_domain_threat_intel(url: str) -> dict:
    """Pre-filters URLs against WHOIS and mock Threat Intel Databases."""
    intel = {"age_days": None, "blacklisted": False, "flags": []}
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # 1. Deterministic Blacklist Lookup (Mocked for Demo - corresponds to VirusTotal/AbuseIPDB logic)
        suspicious_keywords = ['malware', 'phishing', 'secure-login-update', 'free-crypto']
        if any(kw in domain.lower() for kw in suspicious_keywords):
            intel["blacklisted"] = True
            intel["flags"].append("Domain matched known Threat Intelligence Blocklist (VirusTotal / AbuseIPDB)")
            
        # 2. WHOIS Domain Age Check
        if whois:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                intel["age_days"] = age_days
                if age_days < 30:
                    intel["flags"].append(f"Freshly registered domain ({age_days} days old) - High risk for disposable phishing.")
    except Exception:
        pass
        
    return intel


@app.route('/api/activity-check', methods=['POST'])
def activity_check():
    data = request.get_json() or {}
    check_type = data.get("type", "unknown")
    value = data.get("value", "").strip()

    _ALLOWED_SOURCES = {"browser_extension", "manual_scanner", "file_upload_scanner", "server_auto_scan"}
    log_source = data.get("source", "manual_scanner" if check_type in ("url", "file") else "browser_extension")
    if log_source not in _ALLOWED_SOURCES:
        log_source = "browser_extension"

    if not value:
        return jsonify({"status": "error", "message": "No value provided for activity check"}), 400

    type_labels = {
        "url":        f"User navigated to URL: '{value}'.",
        "file":       f"File downloaded: '{value}' from an unverified source.",
        "form":       f"User attempted to submit plain-text credentials over an unencrypted HTTP connection to '{value}'.",
        "navigation": f"User navigated internally to '{value}'.",
    }
    log_entry = type_labels.get(check_type, f"Unknown browser activity involving '{value}'.")

    # 1. Deterministic API Pre-Filtering
    if check_type == "url":
        intel = check_domain_threat_intel(value)
        if intel["flags"]:
            log_entry += f" [Threat Intel Data: {', '.join(intel['flags'])}]"

    # 2. Fetch Session Correlation Context
    recent_history = _sentinel_logger.read_recent(limit=5)
    context_str = " | ".join([
        f"Past Action ({entry.get('type')}): {entry.get('summary', '')[:50]}" 
        for entry in recent_history if entry.get('source') == log_source
    ])
    if not context_str:
        context_str = "No recent correlated activity."

    try:
        # 3. JSON Schema Enforcement
        completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Sentinel, an advanced cybersecurity background monitor.\n"
                        "Analyze the browser activity log in context of their past actions to detect multi-stage attacks.\n"
                        "Output strictly in JSON format matching this schema:\n"
                        "{\n"
                        '  "verdict": "SAFE" or "THREAT" or "SUSPICIOUS",\n'
                        '  "confidence_score": <float between 0.0 and 1.0>,\n'
                        '  "risk_factors": ["list", "of", "detected", "risks"],\n'
                        '  "summary": "<one sentence explaining the threat and mitigation>"\n'
                        "}\n"
                    )
                },
                {"role": "user", "content": f"User's Recent History: {context_str}\n\nCurrent Activity Log: {log_entry}"}
            ],
            model="openai/gpt-oss-120b",
            response_format={"type": "json_object"}
        )
        
        raw_response = completion.choices[0].message.content
        analysis_data = json.loads(raw_response)
        
        verdict = analysis_data.get("verdict", "INFO")
        confidence_score = analysis_data.get("confidence_score", 0.0)
        risk_factors = analysis_data.get("risk_factors", [])
        summary = analysis_data.get("summary", "Analysis complete.")

        _sentinel_logger.write({
            "source": log_source,
            "type": check_type,
            "input": log_entry,
            "verdict": verdict,
            "confidence_score": confidence_score,
            "risk_factors": risk_factors,
            "summary": summary,
        })

        return jsonify({
            "status": "success", 
            "verdict": verdict, 
            "confidence_score": confidence_score,
            "risk_factors": risk_factors,
            "summary": summary
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# STATIC FILE INSPECTION ENGINE
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / length
        if p_x > 0: entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

def extract_static_telemetry(filename: str, file_bytes: bytes) -> dict:
    size_bytes = len(file_bytes)
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    
    detected_type = "Unknown / Binary Data"
    is_executable_type = False
    
    if file_bytes.startswith(b"MZ"):
        detected_type = "Windows PE Executable / DLL (MZ Header)"
        is_executable_type = True
    elif file_bytes.startswith(b"\x7fELF"):
        detected_type = "Linux ELF Binary"
        is_executable_type = True
    elif file_bytes.startswith(b"PK\x03\x04"):
        detected_type = "ZIP Archive / Office OpenXML"
    elif file_bytes.startswith(b"%PDF"):
        detected_type = "PDF Document"
    elif file_bytes.startswith(b"\xd0\xcf\x11\xe0"):
        detected_type = "Legacy MS Compound Document / OLE"
    elif file_bytes.startswith(b"<!DOCTYPE") or file_bytes.startswith(b"<html"):
        detected_type = "HTML Document"

    lower_name = filename.lower()
    ext = os.path.splitext(lower_name)[1]
    parts = lower_name.split(".")
    suspicious_exts = {".bat", ".cmd", ".cpl", ".dll", ".hta", ".js", ".ps1", ".vbs", ".exe"}
    
    double_ext_warning = len(parts) > 2 and f".{parts[-2]}" in suspicious_exts
    mismatch_warning = is_executable_type and ext not in {".exe", ".dll", ".sys", ".scr", ".cpl", ".bin"}

    archive_contents = []
    has_macros = False
    if file_bytes.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for f_name in z.namelist()[:30]:
                    f_lower = f_name.lower()
                    if "vbaproject.bin" in f_lower or "macros" in f_lower:
                        has_macros = True
                    archive_contents.append(f_name)
        except Exception:
            pass

    suspicious_keywords_found = []
    extracted_apis = []

    # Deep Binary PE Parsing
    if pefile and is_executable_type and file_bytes.startswith(b"MZ"):
        try:
            pe = pefile.PE(data=file_bytes)
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if sec_name in ['.UPX0', '.UPX1', '.aspack']:
                    suspicious_keywords_found.append(f"Packed Section Detected ({sec_name})")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            extracted_apis.append(imp.name.decode('utf-8', 'ignore'))
        except Exception:
            pass

    # Macro De-obfuscation
    if VBA_Parser and (has_macros or detected_type.startswith("Legacy MS Compound")):
        try:
            vbaparser = VBA_Parser(filename, data=file_bytes)
            if vbaparser.detect_vba_macros():
                suspicious_keywords_found.append("VBA Macros Present")
                for (kw_type, keyword, description) in vbaparser.analyze_macros():
                    suspicious_keywords_found.append(f"Macro Risk ({kw_type}): {keyword}")
        except Exception:
            pass

    # YARA Signature Matching
    if COMPILED_YARA:
        try:
            yara_matches = COMPILED_YARA.match(data=file_bytes)
            for match in yara_matches:
                suspicious_keywords_found.append(f"YARA Match: {match.rule}")
        except Exception:
            pass

    entropy = calculate_entropy(file_bytes[:35000])

    return {
        "filename": filename,
        "size_kb": round(size_bytes / 1024, 2),
        "sha256": sha256,
        "detected_type": detected_type,
        "extension": ext or "none",
        "double_ext_warning": double_ext_warning,
        "mismatch_warning": mismatch_warning,
        "entropy": entropy,
        "suspicious_keywords": suspicious_keywords_found,
        "has_macros": has_macros,
        "archive_entries": archive_contents[:8],
        "extracted_apis": extracted_apis[:10],
    }


@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400

    uploaded_file = request.files['file']
    filename = uploaded_file.filename or 'uploaded_sample.bin'
    file_bytes = uploaded_file.read(10 * 1024 * 1024)
    
    if not file_bytes:
        return jsonify({'status': 'error', 'message': 'Uploaded file is empty (0 bytes)'}), 400

    try:
        telemetry = extract_static_telemetry(filename, file_bytes)

        prompt = (
            f"You are Sentinel Deep File Inspector.\n"
            f"Review this in-memory static inspection telemetry:\n"
            f"{json.dumps(telemetry, indent=2)}\n\n"
            f"Output STRICTLY in JSON format matching this schema:\n"
            "{\n"
            '  "verdict": "SAFE" or "THREAT" or "SUSPICIOUS",\n'
            '  "confidence_score": <float between 0.0 and 1.0>,\n'
            '  "risk_factors": ["list", "of", "detected", "risks"],\n'
            '  "summary": "<Provide definitive sentence on if the user should open/execute this file>"\n'
            "}\n"
        )

        completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are Sentinel Deep File Inspector. Output only structured JSON for integration."
                },
                {"role": "user", "content": prompt}
            ],
            model="openai/gpt-oss-120b",
            response_format={"type": "json_object"}
        )

        raw_response = completion.choices[0].message.content
        analysis_data = json.loads(raw_response)
        
        verdict = analysis_data.get("verdict", "INFO")
        confidence_score = analysis_data.get("confidence_score", 0.0)
        risk_factors = analysis_data.get("risk_factors", [])
        summary = analysis_data.get("summary", "File scan complete.")

        log_entry_text = f"Uploaded File Scanned: '{filename}' ({telemetry['size_kb']} KB, Type: {telemetry['detected_type']})"
        _sentinel_logger.write({
            "source": "file_upload_scanner",
            "type": telemetry["extension"],
            "input": log_entry_text,
            "verdict": verdict,
            "confidence_score": confidence_score,
            "risk_factors": risk_factors,
            "summary": summary,
        })

        return jsonify({
            'status': 'success',
            'verdict': verdict,
            'confidence_score': confidence_score,
            'risk_factors': risk_factors,
            'summary': summary,
            'filename': filename,
            'telemetry': telemetry
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        limit = min(int(request.args.get("limit", 100)), 200)
    except (ValueError, TypeError):
        limit = 100

    try:
        entries = _sentinel_logger.read_recent(limit=limit)
        return jsonify({"status": "success", "count": len(entries), "logs": entries})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/logs/clear', methods=['POST', 'DELETE'])
def clear_logs():
    try:
        _sentinel_logger.clear()
        return jsonify({"status": "success", "message": "All activity logs have been cleared."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/logs')
def logs_page():
    return render_template('logs.html')


# ---------------------------------------------------------------------------
# SECTION 6 — PASSWORD MANAGER ROUTES
# ---------------------------------------------------------------------------
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
VAULT_KEY_FILE = os.path.join(LOGS_DIR, "vault.key")

if not os.path.exists(VAULT_KEY_FILE):
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(VAULT_KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(VAULT_KEY_FILE, "rb") as f:
    _fernet_key = f.read()
fernet = Fernet(_fernet_key)


def _vault_path(user_id: str = "guest") -> str:
    """Return the vault file path scoped to a user ID."""
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', user_id)[:40] or "guest"
    return os.path.join(LOGS_DIR, f"vault_{safe_id}.json")


def load_vault(user_id: str = "guest"):
    vault_file = _vault_path(user_id)
    if not os.path.exists(vault_file):
        return []
    try:
        with open(vault_file, "rb") as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return []
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode("utf-8"))
    except Exception:
        return []


def save_vault(data, user_id: str = "guest"):
    vault_file = _vault_path(user_id)
    encrypted_data = fernet.encrypt(json.dumps(data).encode("utf-8"))
    os.makedirs(os.path.dirname(vault_file), exist_ok=True)
    with open(vault_file, "wb") as f:
        f.write(encrypted_data)


@app.route('/password-manager')
def password_manager():
    return render_template('password_manager.html')

@app.route('/api/passwords/generate', methods=['POST'])
def generate_password():
    data = request.get_json() or {}
    length = int(data.get('length', 16))
    use_upper = data.get('uppercase', True)
    use_lower = data.get('lowercase', True)
    use_digits = data.get('numbers', True)
    use_symbols = data.get('symbols', True)

    chars = ""
    if use_upper: chars += string.ascii_uppercase
    if use_lower: chars += string.ascii_lowercase
    if use_digits: chars += string.digits
    if use_symbols: chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    if not chars: chars = string.ascii_letters

    pwd = "".join(random.choice(chars) for _ in range(length))
    return jsonify({'status': 'success', 'password': pwd})

@app.route('/api/passwords/check-leak', methods=['POST'])
def check_password_leak():
    pwd = request.json.get('password', '')
    if not pwd:
        return jsonify({'status': 'error', 'message': 'No password provided'}), 400
    
    sha1_pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"User-Agent": "SentinelLearn-App"})
        if res.status_code == 200:
            hashes = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return jsonify({'status': 'success', 'leaked': True, 'count': int(count)})
        
        return jsonify({'status': 'success', 'leaked': False, 'count': 0})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/passwords/vault', methods=['GET', 'POST', 'DELETE'])
def manage_vault():
    user = get_current_user()
    user_id = user["id"] if user else "guest"
    vault = load_vault(user_id)
    
    if request.method == 'GET':
        return jsonify({'status': 'success', 'vault': vault})
    
    if request.method == 'POST':
        data = request.json
        item_id = data.get('id', str(int(time.time() * 1000)))
        
        existing = next((item for item in vault if item.get('id') == item_id), None)
        if existing:
            existing.update({
                'site': data.get('site', existing.get('site')),
                'username': data.get('username', existing.get('username')),
                'password': data.get('password', existing.get('password')),
            })
        else:
            vault.append({
                'id': item_id,
                'site': data.get('site', ''),
                'username': data.get('username', ''),
                'password': data.get('password', '')
            })
        save_vault(vault, user_id)
        return jsonify({'status': 'success'})
    
    if request.method == 'DELETE':
        item_id = request.json.get('id')
        vault = [item for item in vault if item.get('id') != item_id]
        save_vault(vault, user_id)
        return jsonify({'status': 'success'})


# ---------------------------------------------------------------------------
# SECTION 7 — QUIZ HISTORY ROUTES
# ---------------------------------------------------------------------------

def _quiz_history_path(user_id: str = "guest") -> str:
    """Return the quiz history file path scoped to a user ID."""
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', user_id)[:40] or "guest"
    return os.path.join(LOGS_DIR, f"quiz_history_{safe_id}.json")


def load_quiz_history(user_id: str = "guest") -> list:
    path = _quiz_history_path(user_id)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_quiz_history(history: list, user_id: str = "guest") -> None:
    path = _quiz_history_path(user_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f)


@app.route('/api/quiz/history', methods=['GET', 'POST'])
def quiz_history():
    user = get_current_user()
    if not user:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401

    user_id = user["id"]

    if request.method == 'GET':
        history = load_quiz_history(user_id)
        return jsonify({'status': 'success', 'history': history})

    if request.method == 'POST':
        data = request.get_json() or {}
        history = load_quiz_history(user_id)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "topic": data.get("topic", "Unknown"),
            "mcq_score": data.get("mcq_score", 0),
            "mcq_total": data.get("mcq_total", 0),
            "overview": data.get("overview", ""),
        }
        history.insert(0, entry)
        # Keep only the last 20 quiz results per user
        history = history[:20]
        save_quiz_history(history, user_id)
        return jsonify({'status': 'success'})


if __name__ == '__main__':
    app.run(debug=True)