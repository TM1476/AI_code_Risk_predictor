from flask import Flask, request, jsonify, send_from_directory
import lizard
import os
import sqlite3

app = Flask(__name__, static_folder='.', template_folder='.')

DB_PATH = 'sentinel.db'

def init_db():
    """Initializes the SQLite database and creates the history table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            complexity_grade TEXT,
            risk_score REAL,
            vulnerabilities TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_audit(grade, score, details):
    """Saves analysis results to the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_history (complexity_grade, risk_score, vulnerabilities)
            VALUES (?, ?, ?)
        ''', (grade, score, ", ".join(details)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Error: {e}")

init_db()

@app.route('/')
def home():
    return send_from_directory('.', 'analyzer.html')

@app.route('/audit')
def audit_page():
    return send_from_directory('.', 'audit.html')

@app.route('/main.js')
def serve_js():
    return send_from_directory('.', 'main.js')

@app.route('/api/history', methods=['GET'])
def get_history():
    """Retrieves all past audit records."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_history ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        history = [dict(row) for row in rows]
        conn.close()
        return jsonify(history)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/audit', methods=['POST'])
def run_polyglot_audit():
    data = request.json
    code_content = data.get('code', '')

    if not code_content:
        return jsonify({"status": "error", "message": "No code provided"}), 400

    try:
        analysis = lizard.analyze_file.analyze_source_code("input_stream.txt", code_content)
        
        if analysis.function_list:
            avg_complexity = sum(f.cyclomatic_complexity for f in analysis.function_list) / len(analysis.function_list)
        else:
            avg_complexity = 1

        grade = "A" if avg_complexity <= 5 else "B" if avg_complexity <= 12 else "C"

        threat_library = {
            'INJECTION_VECTOR': ['eval(', 'exec(', 'system(', 'SELECT *', 'DROP TABLE'],
            'SENSITIVE_DATA': ['password', 'secret_key', 'api_token'],
            'PERMISSION_RISK': ['chmod 777', 'sudo ']
        }

        detected = [cat for cat, keys in threat_library.items() if any(k.lower() in code_content.lower() for k in keys)]
        risk_score = round(min((len(detected) * 0.25) + (avg_complexity * 0.03), 0.99), 2)

        save_audit(grade, risk_score, detected)

        return jsonify({
            "status": "success",
            "score": risk_score,
            "complexity": grade,
            "raw_complexity": round(avg_complexity, 1),
            "vector_count": len(detected),
            "details": detected
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
