from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import sqlite3
from datetime import datetime, timedelta
import subprocess

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for session

print('dashboard/app.py is being executed')

def get_db():
    conn = sqlite3.connect('db/packets.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get basic stats
    cursor.execute('SELECT COUNT(*) as total, SUM(is_malicious) as malicious FROM packets')
    stats = cursor.fetchone()
    malicious_count = stats['malicious'] or 0
    
    # Check for new malicious packets
    last_malicious = session.get('last_malicious', 0)
    new_malicious = malicious_count > last_malicious
    session['last_malicious'] = malicious_count
    
    # Filtering logic
    tab = request.args.get('tab', 'all')
    if tab == 'malicious':
        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, protocol, service, flags, is_malicious, block_reason 
            FROM packets 
            WHERE is_malicious = 1
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
    elif tab == 'normal':
        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, protocol, service, flags, is_malicious, block_reason 
            FROM packets 
            WHERE is_malicious = 0
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
    else:
        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, protocol, service, flags, is_malicious, block_reason 
            FROM packets 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
    recent_activity = cursor.fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                         total_packets=stats['total'],
                         malicious_packets=malicious_count,
                         recent_activity=recent_activity,
                         tab=tab,
                         new_malicious=new_malicious)

@app.route('/send-malicious')
def send_malicious():
    subprocess.Popen(['python', 'send_malicious.py'])
    # Also insert a malicious packet directly for demo
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, prediction, is_malicious, service, flags, block_reason) VALUES (datetime('now'), '10.0.0.99', '10.0.0.1', 6, 60, 0.99, 1, 'http', 'S', 'Manual Insert')''')
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # up to ms
    except Exception:
        return value

if __name__ == "__main__":
    print('Starting Flask app...')
    app.run(debug=True) 