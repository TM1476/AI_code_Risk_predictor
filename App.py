from flask import Flask, request, jsonify, send_from_directory
import lizard
import os

# We tell Flask that the 'static' and 'template' files are in the root (.)
app = Flask(__name__, static_folder='.', template_folder='.')

@app.route('/')
def home():
    return send_from_directory('.', 'analyzer.html')

@app.route('/audit')
def audit_page():
    return send_from_directory('.', 'audit.html')

@app.route('/main.js')
def serve_js():
    return send_from_directory('.', 'main.js')

@app.route('/api/audit', methods=['POST'])
def run_polyglot_audit():
    data = request.json
    code_content = data.get('code', '')

    if not code_content:
        return jsonify({"status": "error", "message": "No code provided"}), 400

    try:
        # Lizard analyzes C++, Java, JS, Python, PHP, etc.
        analysis = lizard.analyze_file.analyze_source_code("input_stream.txt", code_content)
        
        if analysis.function_list:
            avg_complexity = sum(f.cyclomatic_complexity for f in analysis.function_list) / len(analysis.function_list)
        else:
            avg_complexity = 1

        grade = "A" if avg_complexity <= 5 else "B" if avg_complexity <= 12 else "C"

        # Multi-language vulnerability patterns
        threat_library = {
            'INJECTION_VECTOR': ['eval(', 'exec(', 'system(', 'SELECT *', 'DROP TABLE'],
            'SENSITIVE_DATA': ['password', 'secret_key', 'api_token'],
            'PERMISSION_RISK': ['chmod 777', 'sudo ']
        }

        detected = [cat for cat, keys in threat_library.items() if any(k.lower() in code_content.lower() for k in keys)]
        risk_score = round(min((len(detected) * 0.25) + (avg_complexity * 0.03), 0.99), 2)

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
    # PORT is required for Render to bind to the correct network interface
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
