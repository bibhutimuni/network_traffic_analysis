# Network Traffic Analysis

## Overview
This project captures and analyzes network traffic using **Scapy** and applies **Machine Learning (Isolation Forest)** for anomaly detection. Additionally, it provides data visualization with **Matplotlib & Seaborn** and an interactive dashboard using **Dash**.

## Features
- Captures live network packets
- Saves traffic data to CSV
- Visualizes network traffic statistics
- Detects anomalies using Isolation Forest
- Provides a real-time dashboard for monitoring traffic

## Dependencies
Ensure you have **Python 3.7+** installed. Install the required packages using:

```sh
pip install scapy pandas matplotlib seaborn numpy scikit-learn dash
```

### Required Python Libraries:
- **Scapy** – Packet sniffing and analysis
- **Pandas** – Data handling
- **Matplotlib & Seaborn** – Data visualization
- **NumPy** – Numerical processing
- **Scikit-Learn** – Anomaly detection with Isolation Forest
- **Dash** – Real-time web-based dashboard

## Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/bibhutimuni/network_traffic_analysis.git
   cd network_traffic_analysis
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
   (Alternatively, install the dependencies individually as mentioned above.)

## Usage
### 1. Run the script
On Linux/macOS, run the script with **sudo** (to access network interfaces):
```sh
sudo python3 network_traffic_analysis.py
```
On Windows, run normally:
```sh
python network_traffic_analysis.py
```

### 2. Live Dashboard (Optional)
If Dash is installed, a real-time dashboard will be available at:
```
http://127.0.0.1:8050/
```

## Troubleshooting
- **Permission denied (`/dev/bpf0` on macOS)**: Run with `sudo`.
- **No network interface found**: Ensure you specify the correct interface in the script.
- **Dash not available**: Install it using `pip install dash`.

## License
This project is open-source and available under the **MIT License**.

