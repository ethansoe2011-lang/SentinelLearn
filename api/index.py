from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
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
from groq import Groq
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Load environment variables from .env file for local development
load_dotenv()

# Initialize Flask and point it to the templates directory
# We use "../templates" because this file is inside the "api" folder
app = Flask(__name__, template_folder="../templates")

# ---------------------------------------------------------------------------
# CORS — scoped to external extension, agent, and file scanner endpoints
# ---------------------------------------------------------------------------
CORS(app, resources={
    r"/api/activity-check": {"origins": "*"},
    r"/api/logs*":          {"origins": "*"},
    r"/api/scan-file":      {"origins": "*"},
})

# Initialize the Groq Client
# It automatically looks for the GROQ_API_KEY environment variable.
groq_client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)

# ---------------------------------------------------------------------------
# SECTION 1 — EXISTING ROUTES (untouched)
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    """Renders the landing page."""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Renders the interactive dashboard for threat monitoring."""
    return render_template('dashboard.html')

@app.route('/education')
def education():
    """Renders the educational hub to teach users about malicious data and threat prevention."""
    return render_template('education.html')

@app.route('/quiz')
def quiz():
    """Renders the interactive dynamic flashcard and quiz page."""
    return render_template('quiz.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_threat():
    """
    Analyzes incoming system logs or browser activity for malicious behavior using Groq.
    Acts as the intelligence engine for the background cybersecurity program.
    """
    data = request.get_json()
    activity_log = data.get('log', '')
    
    if not activity_log:
        return jsonify({'status': 'error', 'message': 'No activity log provided'}), 400
        
    try:
        # Requesting a chat completion using the Groq SDK
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
    """
    Handles interactive user questions regarding cybersecurity topics in the Education Hub.
    Uses Groq's openai/gpt-oss-120b model to provide educational responses.
    """
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
    """
    Generates dynamic cybersecurity flashcards and a quiz using Groq based on a requested topic.
    """
    data = request.get_json() or {}
    topic = data.get('topic', 'General Cybersecurity Threats, Phishing, and Malware')
    
    if not topic:
        topic = 'General Cybersecurity Threats, Phishing, and Malware'
        
    try:
        prompt = (
            f"Generate a study set about '{topic}'. "
            "Output strictly in JSON format with no markdown formatting, no code blocks, and no extra text. "
            "The JSON must have this exact structure: "
            "{"
            "\"flashcards\": [{\"front\": \"Question or Concept\", \"back\": \"Answer or Definition\"}, ... generate exactly 3 flashcards], "
            "\"quiz\": {\"question\": \"A scenario-based multiple choice question\", \"options\": [\"Option A\", \"Option B\", \"Option C\", \"Option D\"], \"answer\": \"Exact string of the correct option\", \"explanation\": \"Why this answer is correct\"}"
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
        
        # Clean up in case the AI wraps the response in markdown blocks
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
# SECTION 2 — SENTINEL LOGGER
# Thread-safe, append-only JSONL logger with an in-memory ring buffer fallback.
# This is fully isolated from Section 1. If it errors, nothing above breaks.
# ---------------------------------------------------------------------------

class SentinelLogger:
    """
    A thread-safe activity logger that writes to a JSONL file and maintains
    an in-memory ring buffer (last MAX_MEMORY_ENTRIES entries) as a fallback
    for read-only / ephemeral filesystems (e.g., Vercel serverless).
    """
    MAX_MEMORY_ENTRIES = 200   # How many entries the ring buffer holds
    LOG_FILENAME = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "activity_log.jsonl"
    )

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer = collections.deque(maxlen=self.MAX_MEMORY_ENTRIES)
        self._file_available = self._probe_file()

    def _probe_file(self) -> bool:
        """Check whether we can write to the log file. Silently fails if not."""
        try:
            os.makedirs(os.path.dirname(self.LOG_FILENAME), exist_ok=True)
            with open(self.LOG_FILENAME, "a", encoding="utf-8"):
                pass
            return True
        except Exception:
            return False

    def write(self, entry: dict) -> None:
        """
        Append a log entry. Always writes to the ring buffer; also writes
        to disk when the filesystem is available.
        entry must be a plain dict (will be JSON-serialised).
        """
        entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._buffer.append(entry)
            if self._file_available:
                try:
                    with open(self.LOG_FILENAME, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry) + "\n")
                except Exception:
                    # Filesystem write failed; in-memory buffer still has the entry
                    self._file_available = False

    def read_recent(self, limit: int = 100) -> list:
        """
        Return up to `limit` most recent log entries.
        Prefers the on-disk file (richer history); falls back to the ring buffer.
        """
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
            # Fallback: return from ring buffer
            items = list(self._buffer)
            return items[-limit:]

    def clear(self) -> None:
        """
        Clears both the in-memory ring buffer and empties the on-disk activity log file.
        """
        with self._lock:
            self._buffer.clear()
            if self._file_available:
                try:
                    with open(self.LOG_FILENAME, "w", encoding="utf-8") as f:
                        f.write("")
                except Exception:
                    pass


# Single shared logger instance for the entire process lifetime
_sentinel_logger = SentinelLogger()


# ---------------------------------------------------------------------------
# SECTION 3 — SERVER-SIDE SYSTEM SNAPSHOT
# Mirrors the gather_system_data() logic from local_agent.py, but runs
# inside the Flask process. No separate script or process required.
# ---------------------------------------------------------------------------

def gather_system_snapshot() -> str:
    """
    Gather a lightweight system telemetry snapshot using psutil.
    Returns a formatted string matching the format that local_agent.py produced,
    so the existing /api/analyze prompt still works without modification.
    """
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
# SECTION 4 — BEFORE-REQUEST HOOK (replaces local_agent.py polling loop)
# Fires on every qualifying HTTP request with a 30-second cooldown to avoid
# hammering the Groq API on every static asset fetch.
# Wrapped entirely in try/except — any failure is silently swallowed.
# ---------------------------------------------------------------------------

_last_snapshot_time: float = 0.0          # epoch seconds of last scan
_SNAPSHOT_COOLDOWN_SECS: float = 30.0     # minimum gap between auto-scans

# Routes excluded from triggering an auto-scan (static assets, log endpoints)
_EXCLUDED_PREFIXES = ("/api/logs", "/static/", "/favicon")

@app.before_request
def auto_system_scan():
    """
    Server-side replacement for local_agent.py's polling loop.
    On the first qualifying request after the cooldown period expires,
    take a system snapshot, run it through Groq AI, and save to the log.
    This runs in a daemon thread so it never delays the response to the user.
    """
    global _last_snapshot_time
    try:
        # Skip excluded paths (log viewer polling would create infinite loops)
        path = request.path
        if any(path.startswith(p) for p in _EXCLUDED_PREFIXES):
            return

        now = time.monotonic()
        if now - _last_snapshot_time < _SNAPSHOT_COOLDOWN_SECS:
            return  # Cooldown not expired yet

        _last_snapshot_time = now  # Claim the slot immediately (thread-safe enough for this use)

        # Run in a daemon thread so we never block the HTTP response
        def _run_scan():
            try:
                snapshot = gather_system_snapshot()
                completion = groq_client.chat.completions.create(
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are Sentinel, an advanced cybersecurity background monitor. "
                                "Analyze the provided activity log. Respond in one short paragraph. "
                                "First, state CLEARLY whether the activity is 'Safe' or 'Dangerous/Malicious'. "
                                "Then, if dangerous, briefly explain the threat and mitigation."
                            )
                        },
                        {"role": "user", "content": f"Activity Log: {snapshot}"}
                    ],
                    model="openai/gpt-oss-120b",
                )
                analysis = completion.choices[0].message.content
                
                # Look at the first 50 characters to capture the AI's initial declaration
                opening_statement = analysis.lower()[:50]
                
                # Determine verdict based strictly on the opening statement to avoid false positives
                if "safe" in opening_statement and not any(kw in opening_statement for kw in ("dangerous", "malicious")):
                    verdict = "SAFE"
                else:
                    verdict = "THREAT"

                _sentinel_logger.write({
                    "source": "server_auto_scan",
                    "type": "system_snapshot",
                    "input": snapshot,
                    "verdict": verdict,
                    "analysis": analysis,
                })
            except Exception:
                pass  # Never surface background scan errors to the user

        t = threading.Thread(target=_run_scan, daemon=True)
        t.start()

    except Exception:
        pass  # Guarantee: before_request hook NEVER raises


# ---------------------------------------------------------------------------
# SECTION 5 — NEW API ROUTES (additive, no conflicts with existing routes)
# ---------------------------------------------------------------------------

@app.route('/api/activity-check', methods=['POST'])
def activity_check():
    """
    Server-side replacement for local_agent.py's manual check functionality.
    Accepts a URL or file name from the browser sandbox, runs it through
    Groq AI, persists the result to the log, and returns the verdict.
    """
    data = request.get_json() or {}
    check_type = data.get("type", "unknown")
    value = data.get("value", "").strip()

    # Accept a caller-supplied source tag (extension, manual_scanner, etc.)
    # Whitelist to prevent arbitrary strings from being stored
    _ALLOWED_SOURCES = {"browser_extension", "manual_scanner", "file_upload_scanner", "server_auto_scan"}
    log_source = data.get("source", "manual_scanner" if check_type in ("url", "file") else "browser_extension")
    if log_source not in _ALLOWED_SOURCES:
        log_source = "browser_extension"

    if not value:
        return jsonify({"status": "error", "message": "No value provided for activity check"}), 400

    # Build a descriptive log string matching the dashboard sandbox descriptions
    type_labels = {
        "url":        f"User navigated to URL: '{value}'.",
        "file":       f"File downloaded: '{value}' from an unverified source.",
        "form":       f"User attempted to submit plain-text credentials over an unencrypted HTTP connection to '{value}'.",
        "navigation": f"User navigated internally to '{value}'.",
    }
    log_entry = type_labels.get(check_type, f"Unknown browser activity involving '{value}'.")

    try:
        completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Sentinel, an advanced cybersecurity background monitor. "
                        "Analyze the provided browser activity log. Respond in one short paragraph. "
                        "First, state CLEARLY whether the activity is 'Safe' or 'Dangerous/Malicious'. "
                        "Then, if dangerous, briefly explain the threat and how it is being prevented."
                    )
                },
                {"role": "user", "content": f"Activity Log: {log_entry}"}
            ],
            model="openai/gpt-oss-120b",
        )
        analysis = completion.choices[0].message.content
        
        # Look at the first 50 characters to capture the AI's initial declaration
        opening_statement = analysis.lower()[:50]
        
        # Determine verdict based strictly on the opening statement to avoid false positives
        if "safe" in opening_statement and not any(kw in opening_statement for kw in ("dangerous", "malicious")):
            verdict = "SAFE"
        else:
            verdict = "THREAT"

        # Persist to the server-side log
        _sentinel_logger.write({
            "source": log_source,
            "type": check_type,
            "input": log_entry,
            "verdict": verdict,
            "analysis": analysis,
        })

        return jsonify({"status": "success", "verdict": verdict, "analysis": analysis})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# STATIC FILE INSPECTION ENGINE
# Safely inspects file magic bytes, extensions, scripts, macros, entropy, and
# strings in-memory without executing anything on the server or client.
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte array (0.0 to 8.0). High values (>7.2) indicate compression or packing/encryption."""
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

def extract_static_telemetry(filename: str, file_bytes: bytes) -> dict:
    """
    Safely inspects file contents, magic bytes, strings, entropy, and structures
    without executing anything.
    """
    size_bytes = len(file_bytes)
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    
    # 1. Header / Magic Bytes detection
    detected_type = "Unknown / Binary Data"
    is_executable_type = False
    
    if file_bytes.startswith(b"MZ"):
        detected_type = "Windows PE Executable / DLL (MZ Header)"
        is_executable_type = True
    elif file_bytes.startswith(b"\x7fELF"):
        detected_type = "Linux ELF Binary"
        is_executable_type = True
    elif file_bytes.startswith(b"\xca\xfe\xba\xbe") or file_bytes.startswith(b"\xcf\xfa\xed\xfe"):
        detected_type = "Mach-O Executable (macOS)"
        is_executable_type = True
    elif file_bytes.startswith(b"PK\x03\x04"):
        detected_type = "ZIP Archive / Office OpenXML"
    elif file_bytes.startswith(b"%PDF"):
        detected_type = "PDF Document"
    elif file_bytes.startswith(b"\xd0\xcf\x11\xe0"):
        detected_type = "Legacy MS Compound Document / OLE (Common VBA Macro vector)"
    elif file_bytes.startswith(b"\x1f\x8b"):
        detected_type = "GZIP Compressed File"
    elif file_bytes.startswith(b"Rar!\x1a\x07"):
        detected_type = "RAR Archive"
    elif file_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        detected_type = "7-Zip Archive"
    elif file_bytes.startswith(b"{\\rtf"):
        detected_type = "Rich Text Format (RTF)"
    elif file_bytes.startswith(b"<!DOCTYPE") or file_bytes.startswith(b"<html") or file_bytes.startswith(b"<HTML"):
        detected_type = "HTML Document"
    elif file_bytes.startswith(b"<?xml"):
        detected_type = "XML Document"

    # 2. Extension check
    lower_name = filename.lower()
    ext = os.path.splitext(lower_name)[1]
    parts = lower_name.split(".")
    
    suspicious_exts = {".exe", ".bat", ".cmd", ".cpl", ".dll", ".hta", ".img", ".iso", ".jar", ".js", ".pif", ".ps1", ".scr", ".vbs", ".wsf"}
    
    double_ext_warning = False
    # Check for double extension spoofing (e.g., invoice.exe.pdf)
    if len(parts) > 2 and f".{parts[-2]}" in suspicious_exts:
        double_ext_warning = True

    mismatch_warning = False
    if is_executable_type and ext not in {".exe", ".dll", ".sys", ".scr", ".cpl", ".bin"}:
        mismatch_warning = True

    # 3. Archive / ZIP / Office inspection (without execution)
    archive_contents = []
    has_macros = False
    if file_bytes.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for f_name in z.namelist()[:30]:
                    f_lower = f_name.lower()
                    if "vbaproject.bin" in f_lower or "macros" in f_lower:
                        has_macros = True
                    if any(f_lower.endswith(s_ext) for s_ext in suspicious_exts):
                        archive_contents.append(f"[EMBEDDED EXECUTABLE/SCRIPT]: {f_name}")
                    else:
                        archive_contents.append(f_name)
        except Exception:
            pass

    # 4. Text / Script inspection
    suspicious_keywords_found = []
    text_sample = ""
    is_text = False
    try:
        decoded = file_bytes[:15000].decode("utf-8", errors="ignore")
        printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
        if printable_ratio > 0.82:
            is_text = True
            text_sample = decoded[:2000]
            
            patterns = [
                (r"powershell(\.exe)?", "PowerShell Execution"),
                (r"Invoke-Expression|IEX", "In-Memory Script Execution (IEX)"),
                (r"DownloadString|DownloadFile", "Remote Payload Download"),
                (r"WScript\.Shell", "Windows Scripting Host Automation"),
                (r"cmd\.exe(\s+/c)?", "Command Prompt Execution"),
                (r"rundll32(\.exe)?", "DLL Execution Proxy"),
                (r"certutil(\.exe)?\s+(-urlcache|-decode)?", "Living-Off-The-Land Binary (Certutil)"),
                (r"eval\(", "Dynamic Code Evaluation"),
                (r"ActiveXObject", "ActiveX Scripting"),
                (r"RegWrite|RegRead", "Registry Manipulation"),
                (r"base64", "Base64 Encoding/Obfuscation"),
                (r"fromCharCode", "Character Code Obfuscation"),
                (r"vbaProject", "VBA Macro Component")
            ]
            for pat, desc in patterns:
                matches = re.findall(pat, decoded, re.IGNORECASE)
                if matches:
                    suspicious_keywords_found.append(f"{desc} ({len(matches)}x)")
    except Exception:
        pass

    # 5. Binary Strings & Entropy
    entropy = calculate_entropy(file_bytes[:35000])
    extracted_urls = []
    extracted_apis = []
    if not is_text:
        raw_strings = re.findall(b"[A-Za-z0-9_\\.\\:\\/\\-\\\\]{4,}", file_bytes[:50000])
        decoded_strings = [s.decode("latin-1", errors="ignore") for s in raw_strings]
        
        for s in decoded_strings:
            if (s.startswith("http://") or s.startswith("https://") or ".onion" in s) and len(s) < 100:
                if s not in extracted_urls:
                    extracted_urls.append(s)
            for api in ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "URLDownloadToFile", "WinExec", "IsDebuggerPresent", "RegOpenKey", "ShellExecute"]:
                if api.lower() in s.lower() and api not in extracted_apis:
                    extracted_apis.append(api)

    return {
        "filename": filename,
        "size_kb": round(size_bytes / 1024, 2),
        "sha256": sha256,
        "detected_type": detected_type,
        "extension": ext or "none",
        "double_ext_warning": double_ext_warning,
        "mismatch_warning": mismatch_warning,
        "entropy": entropy,
        "is_text_or_script": is_text,
        "suspicious_keywords": suspicious_keywords_found,
        "has_macros": has_macros,
        "archive_entries": archive_contents[:8],
        "extracted_urls": extracted_urls[:5],
        "extracted_apis": extracted_apis[:5],
        "text_sample": text_sample[:600] if is_text else ""
    }


@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    """
    Accepts an uploaded file (any format) via multipart form-data.
    Performs in-memory deep static inspection (magic bytes, headers, scripts, macros, entropy, strings).
    Passes comprehensive telemetry to Groq AI to evaluate if it is safe to open.
    Returns verdict, user-friendly safety recommendation, and telemetry.
    """
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400

    uploaded_file = request.files['file']
    filename = uploaded_file.filename or 'uploaded_sample.bin'
    
    # Read file content safely into memory (up to 10MB)
    file_bytes = uploaded_file.read(10 * 1024 * 1024)
    if not file_bytes:
        return jsonify({'status': 'error', 'message': 'Uploaded file is empty (0 bytes)'}), 400

    try:
        telemetry = extract_static_telemetry(filename, file_bytes)

        # Build prompt for Groq AI
        telemetry_summary = json.dumps(telemetry, indent=2)
        prompt = (
            f"You are Sentinel Deep File Inspector, an elite cybersecurity and malware triage AI.\n"
            f"A user has uploaded a file they downloaded from the internet to know: 'IS IT OK TO OPEN THIS FILE IN MY SYSTEM OR NOT?'.\n\n"
            f"Here is the in-memory static inspection telemetry extracted from the file:\n"
            f"{telemetry_summary}\n\n"
            f"Analyze these static indicators (magic bytes, double extensions, macro indicators, high entropy, suspicious API references, script contents, URLs).\n"
            f"Deliver a clear, definitive, and structured response in Markdown:\n\n"
            f"### 1. 🛡️ VERDICT & CAN YOU OPEN IT?\n"
            f"- State clearly: **[SAFE TO OPEN]** or **[⛔ DANGEROUS / MALICIOUS - DO NOT OPEN]** or **[⚠️ SUSPICIOUS - EXERCISE CAUTION]**\n"
            f"- State definitively in one plain-English sentence whether the user should open/execute this file.\n\n"
            f"### 2. 🔍 THREAT & STATIC ANALYSIS BREAKDOWN\n"
            f"- Explain the detected indicators (e.g. extension spoofing, macro detection, suspicious strings/commands, entropy level, true file format vs extension).\n\n"
            f"### 3. 📋 RECOMMENDED ACTION FOR USER\n"
            f"- Provide immediate practical next steps (e.g. permanently delete, scan with antivirus, open in safe sandbox, or safe to proceed)."
        )

        completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are Sentinel Deep File Inspector. You give clear, direct, and actionable safety guidance on uploaded files to protect everyday users from malware and cyber attacks."
                },
                {"role": "user", "content": prompt}
            ],
            model="openai/gpt-oss-120b",
        )

        analysis = completion.choices[0].message.content
        
        # Determine verdict badge
        lower_analysis = analysis.lower()
        if "safe to open" in lower_analysis and "do not open" not in lower_analysis:
            verdict = "SAFE"
        elif "do not open" in lower_analysis or "dangerous" in lower_analysis or "malicious" in lower_analysis:
            verdict = "THREAT"
        elif "suspicious" in lower_analysis or "caution" in lower_analysis:
            verdict = "SUSPICIOUS"
        else:
            verdict = "INFO"

        # Log this scan to the persistent Sentinel logger
        log_entry_text = f"Uploaded File Scanned: '{filename}' ({telemetry['size_kb']} KB, Type: {telemetry['detected_type']})"
        _sentinel_logger.write({
            "source": "file_upload_scanner",
            "type": telemetry["extension"],
            "input": log_entry_text,
            "verdict": verdict,
            "analysis": analysis,
        })

        return jsonify({
            'status': 'success',
            'verdict': verdict,
            'filename': filename,
            'telemetry': telemetry,
            'analysis': analysis
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """
    Returns the most recent activity log entries as JSON.
    Query param: ?limit=N  (default 100, max 200)
    """
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
    """
    Clears all saved activity logs from memory and the on-disk activity log file.
    """
    try:
        _sentinel_logger.clear()
        return jsonify({"status": "success", "message": "All activity logs have been cleared."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/logs')
def logs_page():
    """Renders the real-time web log viewer for monitoring activity checks."""
    return render_template('logs.html')


# ---------------------------------------------------------------------------
# SECTION 6 — PASSWORD MANAGER ROUTES (NEW)
# ---------------------------------------------------------------------------

# Secure Vault Setup
VAULT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "vault.json")
VAULT_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "vault.key")

# Ensure a stable Fernet encryption key for the vault
if not os.path.exists(VAULT_KEY_FILE):
    os.makedirs(os.path.dirname(VAULT_KEY_FILE), exist_ok=True)
    with open(VAULT_KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(VAULT_KEY_FILE, "rb") as f:
    _fernet_key = f.read()
fernet = Fernet(_fernet_key)

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()
        if not encrypted_data: return []
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode("utf-8"))
    except Exception:
        return []

def save_vault(data):
    encrypted_data = fernet.encrypt(json.dumps(data).encode("utf-8"))
    os.makedirs(os.path.dirname(VAULT_FILE), exist_ok=True)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)

@app.route('/password-manager')
def password_manager():
    """Renders the Password Vault and Generator page."""
    return render_template('password_manager.html')

@app.route('/api/passwords/generate', methods=['POST'])
def generate_password():
    """Generates a strong, random password based on custom criteria."""
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
    
    # Fallback if everything is disabled
    if not chars: chars = string.ascii_letters

    pwd = "".join(random.choice(chars) for _ in range(length))
    return jsonify({'status': 'success', 'password': pwd})

@app.route('/api/passwords/check-leak', methods=['POST'])
def check_password_leak():
    """
    Checks if a password has been compromised using the HaveIBeenPwned API.
    Utilizes k-Anonymity (SHA-1 hashing and prefix sending) so the password is never transmitted.
    """
    pwd = request.json.get('password', '')
    if not pwd:
        return jsonify({'status': 'error', 'message': 'No password provided'}), 400
    
    # K-Anonymity protocol implementation
    sha1_pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    
    try:
        res = requests.get(f"[https://api.pwnedpasswords.com/range/](https://api.pwnedpasswords.com/range/){prefix}", headers={"User-Agent": "SentinelLearn-App"})
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
    """Handles CRUD operations for the encrypted local password vault."""
    vault = load_vault()
    
    if request.method == 'GET':
        return jsonify({'status': 'success', 'vault': vault})
    
    if request.method == 'POST':
        data = request.json
        item_id = data.get('id', str(int(time.time() * 1000)))
        
        # Check if updating an existing record
        existing = next((item for item in vault if item.get('id') == item_id), None)
        if existing:
            existing.update({
                'site': data.get('site', existing.get('site')),
                'username': data.get('username', existing.get('username')),
                'password': data.get('password', existing.get('password')),
            })
        else:
            # Create a new record
            vault.append({
                'id': item_id,
                'site': data.get('site', ''),
                'username': data.get('username', ''),
                'password': data.get('password', '')
            })
        save_vault(vault)
        return jsonify({'status': 'success'})
    
    if request.method == 'DELETE':
        item_id = request.json.get('id')
        vault = [item for item in vault if item.get('id') != item_id]
        save_vault(vault)
        return jsonify({'status': 'success'})

# ---------------------------------------------------------------------------
# END OF FILE — Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # This tells Flask to start the local development server when you run the script directly
    app.run(debug=True)