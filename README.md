# Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system that combines packet sniffing, AI-based threat detection, and interactive visualization.

## Features

- **Real-Time Packet Capture**: Uses Scapy to intercept and analyze network traffic
- **AI-Based Classification**: Deep learning model to detect malicious traffic patterns
- **Interactive Dashboard**: Real-time visualization of network activity and threats
- **Data Logging**: Stores processed packet data for analysis and model improvement

## Project Structure

```
.
├── sniffer/          # Packet capture and preprocessing
├── model/            # AI model training and inference
├── dashboard/        # Flask web interface
├── data/            # Training data and logs
└── db/              # Database for storing packet data
```

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Train the model:
```bash
python model/train.py
```

3. Start the sniffer:
```bash
python sniffer/sniffer.py
```

4. Run the dashboard:
```bash
python dashboard/app.py
```

## Components

### Packet Sniffer
- Real-time packet capture using Scapy
- Protocol filtering (TCP, UDP, HTTP)
- Feature extraction for AI model

### AI Model
- Deep learning model for threat classification
- Trained on KDD dataset
- Real-time inference on captured packets

### Dashboard
- Real-time network activity visualization
- Threat alerts and statistics
- Historical data analysis

## License

MIT License 