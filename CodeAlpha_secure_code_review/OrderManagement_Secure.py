# ======================================================
# FILE: OrderManagement_Secure.py
# STATUS: PATCHED & SECURE
# ======================================================

import sqlite3
import json  # FIX: Replaced pickle with json for safe serialization
import os
import subprocess
import base64
from flask import Flask, request, abort
from werkzeug.utils import secure_filename # FIX: For Path Traversal

app = Flask(__name__)

# FIX: Loaded Secrets from Environment Variables
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
if not AWS_ACCESS_KEY:
    # Fail safe if key is missing in production
    print("Warning: AWS_ACCESS_KEY not set.")

app.config['DEBUG'] = False # FIX: Disabled debug mode

def db_connect():
    return sqlite3.connect('orders.db')

@app.route('/get_order', methods=['GET'])
def get_order():
    order_id = request.args.get('id')
    
    # FIX: Basic Input Validation
    if not order_id or not order_id.isdigit():
        abort(400, "Invalid Order ID")

    try:
        conn = db_connect()
        cursor = conn.cursor()
        
        # FIX: Parameterized Query (Prevents SQL Injection)
        query = "SELECT * FROM orders WHERE id = ?"
        cursor.execute(query, (order_id,))
        data = cursor.fetchall()
        return str(data)
    except Exception as e:
        return "Database Error", 500
    finally:
        conn.close()

@app.route('/admin/system_check', methods=['POST'])
def system_check():
    ip_address = request.form.get('ip')
    
    if not ip_address:
        return "IP Required", 400

    # FIX: Use subprocess without shell=True (Prevents Command Injection)
    try:
        # The user input is treated as an argument, not a command.
        result = subprocess.run(
            ['ping', '-c', '1', ip_address], 
            capture_output=True, 
            text=True,
            timeout=5
        )
        return result.stdout
    except Exception:
        return "Ping Failed"

@app.route('/restore_session', methods=['POST'])
def restore_session():
    cookie_data = request.form.get('session_cookie')
    if not cookie_data:
        return "No cookie provided", 400
        
    try:
        decoded = base64.b64decode(cookie_data)
        
        # FIX: Use JSON instead of Pickle (Prevents RCE)
        user_obj = json.loads(decoded)
        return f"Welcome back, {user_obj.get('username', 'Guest')}"
    except:
        return "Invalid Session"

@app.route('/view_receipt', methods=['GET'])
def view_receipt():
    filename = request.args.get('file')
    if not filename:
        abort(400)
    
    # FIX: Path Traversal Protection
    # secure_filename removes "../" and special characters
    safe_name = secure_filename(filename)
    
    base_dir = os.path.abspath("receipts")
    file_path = os.path.join(base_dir, safe_name)
    
    # Double check: Ensure the file is actually inside the receipts folder
    if not file_path.startswith(base_dir):
        abort(403, "Access Denied")

    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    else:
        return "File not found", 404

if __name__ == '__main__':
    # Bind to 0.0.0.0 is fine for container/server, but debug must be False
    app.run(host='0.0.0.0', port=5000)