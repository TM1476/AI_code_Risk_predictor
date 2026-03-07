from flask import Flask, request, jsonify, send_from_directory
import lizard
import os
import sqlite3
import json

# Initialize Flask App
app = Flask(__name__, static_folder='.', template_folder='.')

# --- DATABASE CONFIGURATION ---
DB_PATH = 'sentinel.db'

def init_db():
    """Initializes the SQLite database for history tracking and report persistence."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            complexity_grade TEXT,
            risk_score REAL,
            vulnerabilities TEXT,
            code_smells TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_audit_to_db(grade, score, vulnerabilities, smells):
    """Saves the completed audit findings to the local database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_history (complexity_grade, risk_score, vulnerabilities, code_smells)
            VALUES (?, ?, ?, ?)
        ''', (grade, score, json.dumps(vulnerabilities), json.dumps(smells)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Persistence Error: {e}")

# Initialize DB on startup
init_db()

# --- WEB ROUTES ---

@app.route('/')
def home():
    """Serves the main code ingestion (Analyzer) page."""
    return send_from_directory('.', 'analyzer.html')

@app.route('/audit')
def audit_page():
    """Serves the visual dashboard/audit report page."""
    return send_from_directory('.', 'audit.html')

@app.route('/history')
def history_page():
    """Serves the audit history tracking page."""
    return send_from_directory('.', 'history.html')

@app.route('/main.js')
def serve_js():
    """Serves the unified frontend logic file."""
    return send_from_directory('.', 'main.js')

# --- API ENDPOINTS ---

@app.route('/api/history', methods=['GET'])
def get_audit_history():
    """Retrieves all past audits for history tracking."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_history ORDER BY timestamp DESC')
        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(history)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/audit', methods=['POST'])
def run_forensic_audit():
    """
    Main Analysis Engine:
    Performs Complexity Analysis, Pattern Detection, and Code Smell Checks.
    """
    data = request.json
    code_content = data.get('code', '')

    if not code_content:
        return jsonify({"status": "error", "message": "Buffer empty"}), 400

    try:
        # 1. Complexity Analysis via Lizard
        analysis = lizard.analyze_file.analyze_source_code("input_stream.txt", code_content)
        
        # Calculate Average Cyclomatic Complexity
        if analysis.function_list:
            avg_complexity = sum(f.cyclomatic_complexity for f in analysis.function_list) / len(analysis.function_list)
        else:
            avg_complexity = 1

        grade = "A" if avg_complexity <= 5 else "B" if avg_complexity <= 12 else "C"

        # 2. Code Smell Detection (Roadmap Item)
        smells = []
        for func in analysis.function_list:
            if func.cyclomatic_complexity > 15:
                smells.append(f"High Complexity: {func.name}")
            if func.nloc > 50:
                smells.append(f"Long Method: {func.name}")
            if len(func.parameters) > 5:
                smells.append(f"Excessive Parameters: {func.name}")

        # 3. Vulnerability Pattern Detection
        threat_library = {
            'INJECTION_VECTOR': ['eval(', 'exec(', 'system(', 'SELECT *', 'DROP TABLE'],
            'SENSITIVE_DATA': ['password', 'secret_key', 'api_token', 'ACCESS_KEY'],
            'PERMISSION_RISK': ['chmod 777', 'sudo ', 'os.setuid']
        }

        detected_vulns = [cat for cat, keys in threat_library.items() if any(k.lower() in code_content.lower() for k in keys)]
        
        # 4. Risk Scoring (ML-inspired Heuristics)
        risk_score = round(min((len(detected_vulns) * 0.20) + (len(smells) * 0.10) + (avg_complexity * 0.02), 0.99), 2)

        # 5. Persist Results
        save_audit_to_db(grade, risk_score, detected_vulns, smells)

        return jsonify({
            "status": "success",
            "score": risk_score,
            "complexity": grade,
            "raw_complexity": round(avg_complexity, 1),
            "details": detected_vulns,
            "smells": smells,
            "timestamp": os.popen('date').read().strip()
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Binding to PORT for Render deployment compatibility
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
