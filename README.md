# 📡 PacketScope

**Real-time network traffic monitor** built with Python, Flask, and Scapy. Captures live packets off your network interface and streams them to a browser-based dashboard — with protocol filtering, IP search, per-session stats, and service identification.

> ⚠️ **Requires elevated privileges** — run as Administrator on Windows or with `sudo` on Linux/macOS.

---

## Features

- 🔴 **Live packet capture** via Scapy with start/stop control
- 📊 **Real-time stats** — total packets, protocol breakdown, average size, top sources & services
- 🔍 **Filtering** by protocol (TCP / UDP / ICMP), source IP, and destination IP
- 🏷️ **Service identification** — maps ports to 20+ known services (HTTP, HTTPS, DNS, SSH, MySQL, etc.)
- 🌐 **Network interface discovery** — lists available interfaces on the host machine
- 💾 **Rolling buffer** — keeps the last 1,000 packets in memory

---

## Quick Start

### 1. Install dependencies

```bash
pip install flask scapy
```

Or use the included requirements file:

```bash
pip install -r requirements.txt
```

### 2. Run the server

**Windows (Administrator):**
```cmd
python app.py
```

**Linux / macOS:**
```bash
sudo python3 app.py
```

### 3. Open the dashboard

Navigate to [http://localhost:5050](http://localhost:5050) in your browser.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/start` | Start packet capture |
| `POST` | `/api/stop` | Stop packet capture |
| `GET` | `/api/status` | Check if monitoring is active |
| `GET` | `/api/packets` | Fetch captured packets (supports filters) |
| `GET` | `/api/stats` | Get session statistics |
| `GET` | `/api/interfaces` | List available network interfaces |

### `/api/packets` Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `protocol` | string | `ALL` | Filter by `TCP`, `UDP`, or `ICMP` |
| `src_ip` | string | — | Filter by source IP (partial match) |
| `dst_ip` | string | — | Filter by destination IP (partial match) |
| `after_id` | int | `0` | Return only packets with ID greater than this (for polling) |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Capture | [Scapy](https://scapy.net/) |
| Backend | [Flask](https://flask.palletsprojects.com/) |
| Concurrency | Python `threading` |
| Frontend | HTML/CSS/JS (served via Flask templates) |

---

## Project Structure

```
packetscope/
├── app.py              # Flask app + Scapy sniffer
├── requirements.txt    # Python dependencies
└── templates/
    └── index.html      # Frontend dashboard
```

---

## Notes

- Only **IP packets** (TCP, UDP, ICMP) are captured — non-IP traffic is ignored.
- The packet buffer holds a maximum of **1,000 packets** per session; older entries are dropped automatically.
- The sniffer runs in a **daemon thread** and stops cleanly when the session is ended via `/api/stop`.
- On some systems, Scapy may require [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/macOS) to be installed.

---

## License

MIT
