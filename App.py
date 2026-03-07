from flask import Flask, request, jsonify, send_from_directory
import lizard
import os
import sqlite3
import json

app = Flask(__name__, static_folder='.', template_folder='.')
DB_PATH = 'sentinel.db'

def init_db():
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

init_db()

@app.route('/')
def home():
    return send_from_directory('.', 'analyzer.html')

@app.route('/audit')
def audit_page():
    return send_from_directory('.', 'audit.html')

@app.route('/history')
def history_page():
    return send_from_directory('.', 'history.html')

@app.route('/main.js')
def serve_js():
    return send_from_directory('.', 'main.js')

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_history ORDER BY timestamp DESC')
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(history)

@app.route('/api/audit', methods=['POST'])
def run_audit():
    data = request.json
    code = data.get('code', '')
    analysis = lizard.analyze_file.analyze_source_code("input.txt", code)
    
    avg_complexity = sum(f.cyclomatic_complexity for f in analysis.function_list) / len(analysis.function_list) if analysis.function_list else 1
    grade = "A" if avg_complexity <= 5 else "B" if avg_complexity <= 12 else "C"

    smells = [f"Long Method: {f.name}" for f in analysis.function_list if f.nloc > 50]
    threats = {'INJECTION': ['eval(', 'SELECT *'], 'SENSITIVE': ['password', 'secret_key']}
    detected = [cat for cat, keys in threats.items() if any(k in code for k in keys)]
    
    risk_score = round(min((len(detected) * 0.2) + (avg_complexity * 0.02), 0.99), 2)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO audit_history (complexity_grade, risk_score, vulnerabilities, code_smells) VALUES (?, ?, ?, ?)',
                   (grade, risk_score, json.dumps(detected), json.dumps(smells)))
    conn.commit()
    conn.close()

    return jsonify({"score": risk_score, "complexity": grade, "details": detected, "smells": smells})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
