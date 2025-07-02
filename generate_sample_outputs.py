import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import seaborn as sns
import os
from PIL import Image, ImageDraw, ImageFont
import textwrap

def create_traffic_analysis():
    # Create sample data
    np.random.seed(42)
    dates = pd.date_range(start='2024-04-01', end='2024-05-05', freq='H')
    traffic = np.random.normal(1000, 200, len(dates))
    traffic = np.abs(traffic)  # Make all values positive
    
    # Create DataFrame
    df = pd.DataFrame({
        'timestamp': dates,
        'packets': traffic
    })
    
    # Create plot
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['packets'])
    plt.title('Network Traffic Analysis')
    plt.xlabel('Time')
    plt.ylabel('Number of Packets')
    plt.grid(True)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save plot
    plt.savefig('screenshots/traffic_analysis.png')
    plt.close()

def create_threat_detection():
    # Create sample data
    categories = ['Normal', 'DoS Attack', 'Port Scan', 'Data Exfiltration', 'Malware']
    values = [75, 12, 8, 3, 2]
    
    # Create pie chart
    plt.figure(figsize=(10, 8))
    plt.pie(values, labels=categories, autopct='%1.1f%%', startangle=90)
    plt.title('Threat Detection Distribution')
    plt.axis('equal')
    
    # Save plot
    plt.savefig('screenshots/threat_detection.png')
    plt.close()

def create_protocol_distribution():
    # Create sample data
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP', 'Others']
    counts = [450, 300, 200, 180, 50, 20]
    
    # Create bar plot
    plt.figure(figsize=(10, 6))
    sns.barplot(x=protocols, y=counts)
    plt.title('Protocol Distribution')
    plt.xlabel('Protocol')
    plt.ylabel('Number of Packets')
    plt.xticks(rotation=0)
    
    # Save plot
    plt.savefig('screenshots/protocol_distribution.png')
    plt.close()

def create_realtime_monitoring():
    # Create sample data
    time_points = np.linspace(0, 100, 1000)
    normal_traffic = np.sin(time_points) * 10 + 50
    attack_traffic = normal_traffic.copy()
    
    # Simulate attack spike
    attack_traffic[600:800] += 30
    
    # Create plot
    plt.figure(figsize=(12, 6))
    plt.plot(time_points, normal_traffic, label='Normal Traffic', alpha=0.7)
    plt.plot(time_points, attack_traffic, label='Attack Traffic', color='red', alpha=0.7)
    plt.title('Real-time Network Monitoring')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Traffic Volume')
    plt.legend()
    plt.grid(True)
    
    # Save plot
    plt.savefig('screenshots/realtime_monitoring.png')
    plt.close()

def create_terminal_screenshot():
    # Create a black background
    width, height = 800, 600
    image = Image.new('RGB', (width, height), 'black')
    draw = ImageDraw.Draw(image)
    
    # Add terminal-like text
    font = ImageFont.truetype("C:\\Windows\\Fonts\\consola.ttf", 14)
    text_color = (0, 255, 0)  # Green text
    
    # Terminal content
    lines = [
        "AI Packet Sniffer v1.0",
        "Starting packet capture...",
        "Interface: eth0",
        "Filter: tcp port 80 or tcp port 443",
        "",
        "Capturing packets...",
        "",
        "Detected suspicious activity:",
        "10:15:23 - [ALERT] Potential DoS Attack from 192.168.1.100",
        "10:15:45 - [WARNING] Multiple connection attempts from 192.168.1.101",
        "10:16:12 - [INFO] Normal traffic pattern detected",
        "10:16:45 - [ALERT] Port scan detected from 192.168.1.102",
        "",
        "Statistics:",
        "Packets captured: 1,234",
        "Alerts generated: 3",
        "Threat level: MEDIUM",
        "",
        "Press Ctrl+C to stop capture..."
    ]
    
    # Draw text
    y = 20
    for line in lines:
        draw.text((20, y), line, font=font, fill=text_color)
        y += 20
    
    # Save image
    image.save('screenshots/terminal.png')

def create_dashboard_screenshot():
    # Create a dark-themed dashboard
    width, height = 1200, 800
    image = Image.new('RGB', (width, height), (30, 30, 30))
    draw = ImageDraw.Draw(image)
    
    # Add title
    title_font = ImageFont.truetype("C:\\Windows\\Fonts\\arial.ttf", 24)
    draw.text((20, 20), "AI Packet Sniffer Dashboard", font=title_font, fill=(255, 255, 255))
    
    # Add timestamp
    time_font = ImageFont.truetype("C:\\Windows\\Fonts\\arial.ttf", 14)
    draw.text((width-200, 20), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
              font=time_font, fill=(200, 200, 200))
    
    # Add status indicators
    status_font = ImageFont.truetype("C:\\Windows\\Fonts\\arial.ttf", 16)
    statuses = [
        ("Capture Status", "ACTIVE", (0, 255, 0)),
        ("Threat Level", "MEDIUM", (255, 165, 0)),
        ("Alerts", "3", (255, 0, 0)),
        ("Packets/sec", "125", (0, 255, 255))
    ]
    
    x = 20
    y = 70
    for label, value, color in statuses:
        draw.text((x, y), f"{label}:", font=status_font, fill=(200, 200, 200))
        draw.text((x + 150, y), value, font=status_font, fill=color)
        y += 30
    
    # Add recent alerts
    alert_font = ImageFont.truetype("C:\\Windows\\Fonts\\consola.ttf", 14)
    alerts = [
        ("10:15:23", "DoS Attack Detected", "192.168.1.100", "HIGH"),
        ("10:15:45", "Suspicious Activity", "192.168.1.101", "MEDIUM"),
        ("10:16:45", "Port Scan Detected", "192.168.1.102", "HIGH")
    ]
    
    y = 200
    draw.text((20, y), "Recent Alerts:", font=title_font, fill=(255, 255, 255))
    y += 40
    
    for time, alert, ip, severity in alerts:
        draw.text((20, y), f"{time} - {alert}", font=alert_font, fill=(255, 255, 255))
        draw.text((400, y), f"IP: {ip}", font=alert_font, fill=(200, 200, 200))
        draw.text((600, y), f"Severity: {severity}", font=alert_font, 
                 fill=(255, 0, 0) if severity == "HIGH" else (255, 165, 0))
        y += 30
    
    # Add network stats
    y = 400
    draw.text((20, y), "Network Statistics:", font=title_font, fill=(255, 255, 255))
    y += 40
    
    stats = [
        ("Total Packets", "1,234"),
        ("TCP Packets", "850"),
        ("UDP Packets", "300"),
        ("HTTP Requests", "150"),
        ("HTTPS Requests", "200")
    ]
    
    for label, value in stats:
        draw.text((20, y), f"{label}:", font=alert_font, fill=(200, 200, 200))
        draw.text((200, y), value, font=alert_font, fill=(0, 255, 255))
        y += 25
    
    # Save image
    image.save('screenshots/dashboard.png')

def main():
    # Create screenshots directory if it doesn't exist
    if not os.path.exists('screenshots'):
        os.makedirs('screenshots')
    
    # Generate screenshots
    create_terminal_screenshot()
    create_dashboard_screenshot()
    
    print("Screenshots generated successfully in the 'screenshots' directory!")

if __name__ == "__main__":
    main() 