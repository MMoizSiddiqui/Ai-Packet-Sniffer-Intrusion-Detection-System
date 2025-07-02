📁 Project Structure
graphql
Copy
Edit
CN Project/
├── dashboard/
│   ├── app.py                 # Flask-based web dashboard
│   └── templates/
│       └── index.html         # HTML for dashboard UI
├── data/
│   ├── KDDTrain.csv           # Training dataset
│   ├── KDDTest.csv            # Testing dataset
│   └── packets.db             # SQLite DB to store captured packets
├── db/
│   └── packets.db             # Duplicate or backup of database
├── model/
│   ├── train.py               # ML model training script
│   └── model.pkl              # (if present) Trained model
├── sniffer/
│   ├── sniffer.py             # Packet sniffing and classification
│   └── config.py              # Configuration (interface, filters)
├── generate_sample_outputs.py # Simulates output generation
├── send_malicious.py          # Simulates sending malicious packets
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
🚀 Setup Instructions
1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/yourusername/nids-dashboard.git
cd "CN Project"
2. Create a Virtual Environment (Recommended)
bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
4. Prepare the Model
To retrain the model manually:

bash
Copy
Edit
python model/train.py
Note: Pre-trained weights may already be available to start immediately.

🔁 Flow of Execution
Step 1: Start the Packet Sniffer
bash
Copy
Edit
python sniffer/sniffer.py
Captures live packets from the specified interface.

Classifies each packet using the trained ML model.

Stores results in data/packets.db.

⚙️ Configuration can be modified in sniffer/config.py.

Step 2: Run the Dashboard
bash
Copy
Edit
python dashboard/app.py
Launches the dashboard at http://localhost:5000

Shows live traffic summaries, detection alerts, and classified packet history.

Step 3: View Logs & Data
Database: data/packets.db contains all classified packets.

Logs: Any error/output logs will appear in the terminal or logs/ if implemented.

Manual Simulation: Use generate_sample_outputs.py or send_malicious.py to test fake traffic.

🎮 Usage Example
bash
Copy
Edit
# 1. Start the packet sniffer
python sniffer/sniffer.py

# 2. Run the dashboard on another terminal
python dashboard/app.py
Then visit http://localhost:5000 to monitor live intrusion detection.

🛠️ Customization
Train a New Model:
Modify model/train.py to experiment with custom algorithms or additional features.

Network Interface Settings:
Change interface name, filters, or thresholds in sniffer/config.py.

Dashboard UI:
Customize HTML and CSS in dashboard/templates/index.html.

✅ Requirements
Python 3.7+

Required packages are listed in requirements.txt, including:

Flask

scikit-learn

pandas

TensorFlow / Keras (if deep learning is used)

SQLite3

Other utilities

Install with:

bash
Copy
Edit
pip install -r requirements.txt
📊 Dataset
KDD Cup 1999 Dataset

Used to train and test the ML-based intrusion detection model.

Includes various attack types and normal traffic.

🧩 Troubleshooting
Run packet sniffer with admin/root privileges if it fails to access the network interface.

Check venv activation and dependency installation if modules are missing.

Use test scripts (generate_sample_outputs.py, send_malicious.py) to simulate traffic for testing.

📬 Contact
For support, questions, or contributions, feel free to open an issue or contact:

📧 Email: moiz87siddiqui@gmail.com

📝 License
This project is open for educational and academic use only.

