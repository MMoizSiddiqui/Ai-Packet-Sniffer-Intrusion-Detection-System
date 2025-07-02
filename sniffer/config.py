import os

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, '..', 'model')
DB_DIR = os.path.join(BASE_DIR, '..', 'db')

# File paths
MODEL_PATH = os.path.join(MODEL_DIR, 'model_weights.h5')
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, 'preprocessor.pkl')
SERVICE_LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, 'service_label_encoder.pkl')
DB_PATH = os.path.join(DB_DIR, 'packets.db')

# Sniffer settings
BATCH_SIZE = 100  # Number of packets to process before database commit
PREDICTION_THRESHOLD = 0.5  # Threshold for malicious classification
MAX_PACKET_SIZE = 65535  # Maximum packet size to process 