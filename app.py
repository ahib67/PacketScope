"""
Network Traffic Monitoring and Analysis Platform
Backend: Flask + simulated traffic dataset
"""

from flask import Flask, jsonify, request, render_template
import random
import time
from datetime import datetime, timedelta
import threading

app = Flask(__name__)

# ─── Port → Service mapping ────────────────────────────────────────────────
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

WELL_KNOWN_PORTS = list(PORT_SERVICES.keys())
PROTOCOLS = ["TCP", "UDP", "ICMP"]
PROTOCOL_WEIGHTS = [0.60, 0.30, 0.10]

SAMPLE_IPS = [
    "192.168.1.1", "192.168.1.5", "192.168.1.10", "192.168.1.50",
    "192.168.0.2", "10.0.0.1", "10.0.0.15", "172.16.0.5",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "142.250.185.46",
    "151.101.1.140", "104.21.8.15", "185.199.108.153",
]

# ─── Global state ────────────────────────────────────────────────────────────
monitoring_active = False
packet_log = []
monitor_thread = None
packet_counter = 0
lock = threading.Lock()

# ─── Traffic simulation ───────────────────────────────────────────────────────
def generate_packet():
    global packet_counter
    protocol = random.choices(PROTOCOLS, weights=PROTOCOL_WEIGHTS)[0]
    src_ip = random.choice(SAMPLE_IPS)
    dst_ip = random.choice([ip for ip in SAMPLE_IPS if ip != src_ip])

    if protocol == "ICMP":
        src_port = 0
        dst_port = 0
        service = "ICMP"
    else:
        dst_port = random.choice(WELL_KNOWN_PORTS + [random.randint(1024, 65535)])
        src_port = random.randint(1024, 65535)
        service = PORT_SERVICES.get(dst_port, f"Unknown({dst_port})")

    packet_counter += 1
    return {
        "id": packet_counter,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "service": service,
        "packet_size": random.randint(40, 1500),
    }

def simulate_traffic():
    global monitoring_active, packet_log
    while monitoring_active:
        packets_this_tick = random.randint(1, 4)
        with lock:
            for _ in range(packets_this_tick):
                pkt = generate_packet()
                packet_log.append(pkt)
                if len(packet_log) > 1000:  # cap memory
                    packet_log = packet_log[-1000:]
        time.sleep(random.uniform(0.4, 1.0))

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/start", methods=["POST"])
def start_monitoring():
    global monitoring_active, monitor_thread, packet_log, packet_counter
    if monitoring_active:
        return jsonify({"status": "already_running"})
    monitoring_active = True
    packet_log = []
    packet_counter = 0
    monitor_thread = threading.Thread(target=simulate_traffic, daemon=True)
    monitor_thread.start()
    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    global monitoring_active
    monitoring_active = False
    return jsonify({"status": "stopped"})

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({"monitoring": monitoring_active})

@app.route("/api/packets", methods=["GET"])
def get_packets():
    protocol = request.args.get("protocol", "").upper()
    src_ip   = request.args.get("src_ip", "").strip()
    dst_ip   = request.args.get("dst_ip", "").strip()
    after_id = int(request.args.get("after_id", 0))

    with lock:
        results = list(packet_log)

    # filter
    if protocol and protocol != "ALL":
        results = [p for p in results if p["protocol"] == protocol]
    if src_ip:
        results = [p for p in results if src_ip in p["src_ip"]]
    if dst_ip:
        results = [p for p in results if dst_ip in p["dst_ip"]]

    # only return new packets (for live polling)
    new_packets = [p for p in results if p["id"] > after_id]

    return jsonify({"packets": new_packets})

@app.route("/api/stats", methods=["GET"])
def get_stats():
    with lock:
        data = list(packet_log)

    total = len(data)
    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    total_size = 0

    for p in data:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        total_size += p["packet_size"]

    avg_size = round(total_size / total, 1) if total else 0

    top_src = {}
    for p in data:
        top_src[p["src_ip"]] = top_src.get(p["src_ip"], 0) + 1
    top_src_sorted = sorted(top_src.items(), key=lambda x: -x[1])[:5]

    top_services = {}
    for p in data:
        top_services[p["service"]] = top_services.get(p["service"], 0) + 1
    top_services_sorted = sorted(top_services.items(), key=lambda x: -x[1])[:5]

    return jsonify({
        "total_packets": total,
        "protocol_counts": proto_counts,
        "avg_packet_size": avg_size,
        "top_sources": top_src_sorted,
        "top_services": top_services_sorted,
        "monitoring": monitoring_active,
    })

@app.route("/api/dataset", methods=["GET"])
def get_dataset():
    """Returns the full raw log as CSV-style for download/report."""
    with lock:
        data = list(packet_log)
    return jsonify({"dataset": data, "count": len(data)})

if __name__ == "__main__":
    app.run(debug=True, port=5050)
