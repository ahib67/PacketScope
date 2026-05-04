# PacketScope — Network Traffic Monitoring and Analysis Platform

A network traffic monitoring platform built for the Computer Networks course project. The system simulates realistic network traffic, displays it live in a web interface, supports filtering and statistics, and logs all captured packets.

---

## Demo

> Run the project locally and open `http://localhost:5050` in your browser.

---

## Features

- **Live packet capture** — simulates TCP, UDP, and ICMP traffic in real time
- **Packet table** — displays Source IP, Destination IP, Protocol, Source Port, Destination Port, Service, Packet Size, and Timestamp
- **Port → Service mapping** — automatically maps destination ports to service names (Port 80 → HTTP, Port 443 → HTTPS, Port 53 → DNS, etc.)
- **Filtering** — filter by Protocol (TCP/UDP/ICMP), Source IP, and Destination IP
- **Statistics panel** — total packets, per-protocol counts, average packet size, top 5 source IPs, top 5 services
- **System log** — live event feed showing monitoring activity
- **CSV dataset** — 200 pre-generated packet records exported automatically on startup
- **Start / Stop monitoring** — full session control from the UI

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend (Python version) | Python 3, Flask |
| Backend (C++ version) | C++17, WinSock2 (Windows) / libmicrohttpd (Linux) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Data Exchange | JSON (REST API) |
| Dataset | CSV (auto-generated on startup) |

---

## Project Structure

```
PacketScope/
├── app.py                        # Python/Flask backend
├── server.cpp                    # C++ backend (alternative)
├── Makefile                      # For compiling C++ version (Linux)
├── network_traffic_dataset.csv   # Auto-generated dataset (200 records)
├── requirements.txt              # Python dependencies
├── README.md
└── templates/
    └── index.html                # Web frontend (HTML/CSS/JS)
```

---

## Getting Started

### Python Version (Recommended — works on Windows, Linux, Mac)

**1. Install dependencies**
```bash
pip install flask
```

**2. Run the server**
```bash
python app.py
```

**3. Open your browser**
```
http://localhost:5050
```

---

### C++ Version — Windows (using MinGW)

**1. Install MinGW** from https://winlibs.com and add `C:\mingw64\bin` to your system PATH.

**2. Navigate to the project folder**
```cmd
cd C:\path\to\PacketScope
```

**3. Compile**
```cmd
g++ -std=c++17 -o netwatch.exe server.cpp -lws2_32 -lpthread
```

**4. Run**
```cmd
netwatch.exe
```

**5. Open your browser**
```
http://localhost:5050
```

---

### C++ Version — Linux

**1. Install dependency**
```bash
sudo apt install g++ make libmicrohttpd-dev -y
```

**2. Compile and run**
```bash
make
./netwatch
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Serves the web interface |
| POST | `/api/start` | Starts traffic monitoring |
| POST | `/api/stop` | Stops traffic monitoring |
| GET | `/api/packets` | Returns captured packets (supports filters) |
| GET | `/api/stats` | Returns statistics |
| GET | `/api/status` | Returns current monitoring status |
| GET | `/api/dataset` | Returns full packet log as JSON |

### Filter Parameters for `/api/packets`

| Parameter | Example | Description |
|---|---|---|
| `after_id` | `?after_id=50` | Only return packets newer than this ID |
| `protocol` | `?protocol=TCP` | Filter by protocol (TCP/UDP/ICMP/ALL) |
| `src_ip` | `?src_ip=192.168` | Filter by source IP (substring match) |
| `dst_ip` | `?dst_ip=8.8.8.8` | Filter by destination IP |

---

## Dataset

The file `network_traffic_dataset.csv` is generated automatically every time the server starts. It contains 200 simulated packet records with the following fields:

| Field | Example |
|---|---|
| Time | 08:00:05 |
| Source IP | 192.168.1.5 |
| Destination IP | 8.8.8.8 |
| Protocol | TCP |
| Source Port | 52341 |
| Destination Port | 80 |
| Service | HTTP |
| Packet Size | 512 |

---

## Port → Service Mapping

| Port | Service |
|---|---|
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |
| 8080 | HTTP-Alt |

---

## Notes

- This project uses **simulated** network traffic. Real-time packet sniffing requires administrator/root privileges and platform-specific libraries (e.g., libpcap/WinPcap).
- The packet log is capped at 1000 entries in memory to prevent unbounded RAM usage.
- The frontend polls the backend every 800ms for new packets and every 2 seconds for updated statistics.
