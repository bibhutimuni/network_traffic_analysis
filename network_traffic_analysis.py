import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from sklearn.ensemble import IsolationForest
import os

try:
    from dash import Dash, dcc, html
    from dash.dependencies import Input, Output
    DASH_AVAILABLE = True
except ImportError:
    print("Dash is not installed. Skipping real-time dashboard.")
    DASH_AVAILABLE = False

data = []

INTERFACE = None
available_interfaces = get_if_list()
if available_interfaces:
    INTERFACE = available_interfaces[0]  # Use the first available interface
else:
    print("No network interfaces found. Packet capture will not work.")

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        src_port, dst_port = None, None
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        data.append([src_ip, dst_ip, protocol, src_port, dst_port, packet_size])

def capture_packets():
    if INTERFACE:
        sniff(prn=process_packet, count=100, iface=INTERFACE)
        save_to_csv()
    else:
        print("No valid network interface found. Skipping packet capture.")

def save_to_csv():
    if data:
        df = pd.DataFrame(data, columns=["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size"])
        df.to_csv("network_traffic.csv", index=False)
    else:
        print("No packets captured.")

def visualize_data():
    if not os.path.exists("network_traffic.csv"):
        print("CSV file not found. Skipping visualization.")
        return
    
    df = pd.read_csv("network_traffic.csv")
    if df.empty:
        print("No data available for visualization.")
        return
    
    sns.countplot(x=df["Protocol"].astype(str))
    plt.title("Protocol Distribution")
    plt.show()

def detect_anomalies():
    if not os.path.exists("network_traffic.csv"):
        print("CSV file not found. Skipping anomaly detection.")
        return
    
    df = pd.read_csv("network_traffic.csv")
    if df.empty:
        print("No data available for anomaly detection.")
        return
    
    df["Source IP"] = df["Source IP"].astype("category").cat.codes
    df["Destination IP"] = df["Destination IP"].astype("category").cat.codes
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    df["Anomaly"] = model.fit_predict(df[["Packet Size", "Source IP", "Destination IP"]])
    
    sns.scatterplot(x=df.index, y=df["Packet Size"], hue=df["Anomaly"])
    plt.title("Anomaly Detection in Network Traffic")
    plt.show()

def run_dashboard():
    if not DASH_AVAILABLE:
        print("Dash is not available. Skipping dashboard.")
        return
    
    app = Dash(__name__)
    app.layout = html.Div([
        dcc.Graph(id="traffic-graph"),
        dcc.Interval(id="interval-update", interval=2000, n_intervals=0)
    ])
    
    @app.callback(Output("traffic-graph", "figure"), Input("interval-update", "n_intervals"))
    def update_graph(n):
        if not os.path.exists("network_traffic.csv"):
            return {"data": [], "layout": {"title": "No Data Available"}}
        
        df = pd.read_csv("network_traffic.csv")
        if df.empty:
            return {"data": [], "layout": {"title": "No Data Available"}}
        
        fig = {
            "data": [{"x": df.index, "y": df["Packet Size"], "type": "line"}],
            "layout": {"title": "Live Network Traffic"}
        }
        return fig
    
    app.run_server(debug=True)

def main():
    print("Starting packet capture...")
    capture_packets()
    
    print("Packets saved to CSV.")
    visualize_data()
    detect_anomalies()
    run_dashboard()

if __name__ == "__main__":
    main()
