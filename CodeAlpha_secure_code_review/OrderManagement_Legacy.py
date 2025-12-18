# ======================================================
# FILE: OrderManagement_Legacy.py
# TYPE: Internal Order Processing API
# STATUS: CRITICAL VULNERABILITIES DETECTED
# ======================================================

import sqlite3
import pickle  # DANGER: Insecure Deserialization
import os
import base64
from flask import Flask, request

app = Flask(__name__)

# [VULNERABILITY 1] Hardcoded API Keys & Debug Mode
AWS_ACCESS_KEY = "AKIA1234567890FAKEKEY" 
app.config['DEBUG'] = True

def db_connect():
    return sqlite3.connect('orders.db')

@app.route('/get_order', methods=['GET'])
def get_order():
    order_id = request.args.get('id')
    
    conn = db_connect()
    cursor = conn.cursor()
    
    # [VULNERABILITY 2] SQL Injection (Classic)
    # Attacker can dump entire database using: ?id=1 OR 1=1
    query = "SELECT * FROM orders WHERE id = " + order_id
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    return str(data)

@app.route('/admin/system_check', methods=['POST'])
def system_check():
    # [VULNERABILITY 3] Command Injection (RCE)
    # Input is passed directly to OS shell.
    # Attacker input: "8.8.8.8; rm -rf /"
    ip_address = request.form['ip']
    stream = os.popen('ping -c 1 ' + ip_address)
    output = stream.read()
    return output

@app.route('/restore_session', methods=['POST'])
def restore_session():
    # [VULNERABILITY 4] Insecure Deserialization
    # 'pickle' allows arbitrary code execution if cookie is modified.
    cookie_data = request.form['session_cookie']
    try:
        decoded = base64.b64decode(cookie_data)
        user_obj = pickle.loads(decoded) # EXECUTES MALICIOUS CODE HERE
        return f"Welcome back, {user_obj['username']}"
    except:
        return "Session Error"

@app.route('/view_receipt', methods=['GET'])
def view_receipt():
    filename = request.args.get('file')
    
    # [VULNERABILITY 5] Path Traversal (LFI)
    # Attacker can read system files: ?file=../../../../etc/passwd
    file_path = os.path.join('receipts/', filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    else:
        return "File not found"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)