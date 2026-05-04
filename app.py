"""
PacketScope - Real-Time Network Traffic Monitor
Backend: Python + Flask + Scapy (live packet capture)

Run as Administrator on Windows / sudo on Linux:
    Windows: python app.py
    Linux:   sudo python3 app.py

Install dependencies:
    pip install flask scapy
"""

from flask import Flask, jsonify, request, render_template
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading
import time
from datetime import datetime

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

# ─── Global state ────────────────────────────────────────────────────────────
lock            = threading.Lock()
packet_log      = []
packet_counter  = 0
monitoring      = False
sniffer_thread  = None

# ─── Process each captured packet ────────────────────────────────────────────
def process_packet(pkt):
    global packet_counter

    # Only process packets that have an IP layer
    if not pkt.haslayer(IP):
        return

    ip    = pkt[IP]
    proto = ""
    src_port = 0
    dst_port = 0
    service  = "Unknown"

    if pkt.haslayer(TCP):
        proto    = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        service  = PORT_SERVICES.get(dst_port,
                   PORT_SERVICES.get(src_port, "Unknown"))

    elif pkt.haslayer(UDP):
        proto    = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        service  = PORT_SERVICES.get(dst_port,
                   PORT_SERVICES.get(src_port, "Unknown"))

    elif pkt.haslayer(ICMP):
        proto   = "ICMP"
        service = "ICMP"

    else:
        # Skip non TCP/UDP/ICMP packets
        return

    # Get actual packet size
    pkt_size = len(pkt)

    packet_counter += 1
    record = {
        "id":          packet_counter,
        "time":        datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_ip":      ip.src,
        "dst_ip":      ip.dst,
        "protocol":    proto,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "service":     service,
        "packet_size": pkt_size,
    }

    with lock:
        packet_log.append(record)
        if len(packet_log) > 1000:
            packet_log.pop(0)

# ─── Sniffer thread ───────────────────────────────────────────────────────────
def start_sniffing():
    """
    Runs Scapy's sniff() in a background thread.
    stop_filter checks the monitoring flag every packet
    so sniffing stops cleanly when the user clicks Stop.
    """
    sniff(
        prn=process_packet,
        store=False,                          # don't keep packets in memory
        stop_filter=lambda p: not monitoring, # stop when monitoring = False
        filter="ip",                          # only capture IP packets
    )

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/start", methods=["POST"])
def start_monitoring():
    global monitoring, sniffer_thread, packet_log, packet_counter

    if monitoring:
        return jsonify({"status": "already_running"})

    monitoring     = True
    packet_log     = []
    packet_counter = 0

    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    global monitoring
    monitoring = False
    return jsonify({"status": "stopped"})

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({"monitoring": monitoring})

@app.route("/api/packets", methods=["GET"])
def get_packets():
    protocol = request.args.get("protocol", "ALL").upper()
    src_ip   = request.args.get("src_ip", "").strip()
    dst_ip   = request.args.get("dst_ip", "").strip()
    after_id = int(request.args.get("after_id", 0))

    with lock:
        results = list(packet_log)

    if protocol != "ALL":
        results = [p for p in results if p["protocol"] == protocol]
    if src_ip:
        results = [p for p in results if src_ip in p["src_ip"]]
    if dst_ip:
        results = [p for p in results if dst_ip in p["dst_ip"]]

    new_packets = [p for p in results if p["id"] > after_id]

    return jsonify({"packets": new_packets})

@app.route("/api/stats", methods=["GET"])
def get_stats():
    with lock:
        data = list(packet_log)

    total = len(data)
    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
    total_size   = 0
    top_src      = {}
    top_services = {}

    for p in data:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        total_size += p["packet_size"]
        top_src[p["src_ip"]]       = top_src.get(p["src_ip"], 0) + 1
        top_services[p["service"]] = top_services.get(p["service"], 0) + 1

    avg_size = round(total_size / total, 1) if total else 0

    top_src_sorted = sorted(top_src.items(),      key=lambda x: -x[1])[:5]
    top_svc_sorted = sorted(top_services.items(), key=lambda x: -x[1])[:5]

    return jsonify({
        "total_packets":   total,
        "protocol_counts": proto_counts,
        "avg_packet_size": avg_size,
        "top_sources":     top_src_sorted,
        "top_services":    top_svc_sorted,
        "monitoring":      monitoring,
    })

@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Returns list of available network interfaces on this machine."""
    try:
        interfaces = get_if_list()
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        return jsonify({"interfaces": [], "error": str(e)})

if __name__ == "__main__":
    print("=" * 45)
    print("  PacketScope - Real-Time Traffic Monitor")
    print("=" * 45)
    print("  IMPORTANT: Run as Administrator (Windows)")
    print("             or with sudo (Linux/Mac)")
    print("  Open: http://localhost:5050")
    print("=" * 45)
    app.run(debug=False, port=5050)
