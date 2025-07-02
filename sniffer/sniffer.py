import argparse
from scapy.all import IP, TCP, UDP, sniff
import sqlite3
from datetime import datetime
import pickle
import os
import tensorflow as tf
import pandas as pd
import numpy as np
from collections import defaultdict
import time
from contextlib import contextmanager
import logging
from config import *
from logger import logger

# Global variables
packet_buffer = []
last_commit_time = time.time()
model = None
preprocessor = None
service_label_encoder = None
verbose = False

# Load columns from columns.txt for dynamic feature extraction
COLUMNS_PATH = os.path.join('model', 'columns.txt')
with open(COLUMNS_PATH, 'r') as f:
    MODEL_COLUMNS = [line.strip() for line in f if line.strip()]

# Load ML components
model = tf.keras.models.load_model('model/model_weights.h5')
with open('model/preprocessor.pkl', 'rb') as f:
    preprocessor = pickle.load(f)
with open('model/service_label_encoder.pkl', 'rb') as f:
    service_label_encoder = pickle.load(f)

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    length INTEGER,
                    prediction REAL,
                    is_malicious INTEGER,
                    service TEXT,
                    flags TEXT,
                    block_reason TEXT
                )
            ''')
            conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def extract_features(packet):
    # Define columns as in training
    feature_cols = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
        'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
        'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]
    features = {col: 0.0 for col in feature_cols}
    # Set numeric features
    if packet.haslayer(IP):
        features['src_bytes'] = float(len(packet[IP].payload))
        features['dst_bytes'] = 0.0
        features['land'] = float(packet[IP].src == packet[IP].dst)
        proto = packet[IP].proto
        # Set protocol_type as string for one-hot
        if proto == 6:
            features['protocol_type'] = 'tcp'
        elif proto == 17:
            features['protocol_type'] = 'udp'
        elif proto == 1:
            features['protocol_type'] = 'icmp'
        else:
            features['protocol_type'] = str(proto)
    else:
        features['protocol_type'] = 'OTH'
    # Service mapping
    service_str = 'OTH'
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        port_service_map = {
            80: 'http', 443: 'http_443', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 110: 'pop_3',
            143: 'imap4', 53: 'domain', 3306: 'mysql', 8080: 'http_8001', 20: 'ftp_data', 995: 'pop_3',
        }
        service = port_service_map.get(sport) or port_service_map.get(dport)
        if service:
            service_str = service
    features['service'] = service_label_encoder.transform([service_str])[0] if service_str in service_label_encoder.classes_ else 0
    # Set flag as string for one-hot
    if packet.haslayer(TCP):
        try:
            features['flag'] = str(int(packet[TCP].flags))
        except Exception:
            features['flag'] = '0'
    else:
        features['flag'] = '0'
    # Build DataFrame
    df = pd.DataFrame([features])
    # Pass through preprocessor
    try:
        processed = preprocessor.transform(df)
    except Exception as e:
        logger.error(f"Preprocessing failed: {e}")
        return None, service_str, ''
    # For DB, also log the flag(s) set
    flags_str = features['flag']
    return processed, service_str, flags_str

def process_packet_batch():
    global packet_buffer, last_commit_time
    if not packet_buffer:
        return
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, prediction, is_malicious, service, flags, block_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', packet_buffer)
            conn.commit()
        if verbose:
            logger.info(f"Processed batch of {len(packet_buffer)} packets")
        packet_buffer = []
        last_commit_time = time.time()
    except Exception as e:
        logger.error(f"Error processing packet batch: {e}")

def process_packet(packet):
    try:
        if not packet.haslayer(IP) or len(packet) > MAX_PACKET_SIZE:
            return
        processed, service_name, flags_str = extract_features(packet)
        if processed is None:
            return
        # Model prediction
        prediction = model.predict(processed)
        # Handle binary or multi-class
        if prediction.shape[-1] == 1:
            pred_val = float(prediction[0][0])
            is_malicious = int(pred_val > PREDICTION_THRESHOLD)
            block_reason = 'AI Model' if is_malicious else ''
        else:
            pred_val = float(np.max(prediction[0]))
            is_malicious = int(np.argmax(prediction[0]) != service_label_encoder.transform(['normal'])[0])
            block_reason = 'AI Model' if is_malicious else ''
        # DEMO: Flag all TCP SYN packets as malicious
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            is_malicious = 1
            block_reason = 'SYN Packet'
        # Buffer for batch insert (add block_reason)
        packet_buffer.append((
            datetime.now().isoformat(),
            packet[IP].src,
            packet[IP].dst,
            str(packet[IP].proto),
            len(packet),
            pred_val,
            is_malicious,
            service_name,
            flags_str,
            block_reason
        ))
        # Flush if buffer is large or time elapsed
        if len(packet_buffer) >= 100 or (time.time() - last_commit_time) > 5:
            process_packet_batch()
    except Exception as e:
        logger.error(f"Error processing packet: {str(e)}")
        logger.debug(f"Packet details: {packet.summary()}")

def start_sniffing(interface=None, filter=None):
    try:
        logger.info(f"Starting packet capture on interface: {interface or 'default'}")
        if interface:
            sniff(iface=interface, filter=filter, prn=process_packet, store=0)
        else:
            sniff(filter=filter, prn=process_packet, store=0)
    except Exception as e:
        logger.error(f"Error in packet capture: {e}")
        raise
    finally:
        if packet_buffer:
            process_packet_batch()

def main():
    global verbose
    parser = argparse.ArgumentParser(description='Network Packet Sniffer with ML-based Intrusion Detection')
    parser.add_argument('-i', '--interface', help='Network interface to capture packets from')
    parser.add_argument('-f', '--filter', help='BPF filter for packet capture')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    verbose = args.verbose
    try:
        # Ensure DB is initialized and packets table exists
        init_db()
        logger.info("Database checked/initialized.")
        start_sniffing(interface=args.interface, filter=args.filter)
    except KeyboardInterrupt:
        logger.info("Packet capture stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main() 