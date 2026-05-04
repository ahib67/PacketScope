# Network Traffic Monitoring and Analysis Platform

## Requirements
- Python 3.8+
- Flask (`pip install flask`)

## How to Run

```bash
# 1. Install dependencies
pip install flask

# 2. Start the server
python app.py

# 3. Open your browser at:
http://localhost:5050
```

## Project Structure
```
network_monitor/
├── app.py                      # Flask backend (all API logic)
├── templates/
│   └── index.html              # Web interface (HTML/CSS/JS)
├── generate_dataset.py         # Script to generate sample CSV dataset
├── network_traffic_dataset.csv # Sample dataset (200 records)
└── requirements.txt
```

## Features
- **Start/Stop Monitoring** — begins/ends live traffic simulation
- **Packet Table** — shows ID, Time, Protocol, Source IP, Src Port, Destination IP, Dst Port, Service, Size
- **Filters** — filter by Protocol (TCP/UDP/ICMP), Source IP, Destination IP
- **Statistics** — total packets, per-protocol counts + bar chart, avg packet size, top sources, top services
- **System Log** — live event feed at the bottom

## API Endpoints
| Method | Route            | Description                  |
|--------|------------------|------------------------------|
| POST   | /api/start       | Start monitoring             |
| POST   | /api/stop        | Stop monitoring              |
| GET    | /api/packets     | Get packets (filter support) |
| GET    | /api/stats       | Get statistics               |
| GET    | /api/dataset     | Get full raw log as JSON     |
| GET    | /api/status      | Get monitoring status        |
