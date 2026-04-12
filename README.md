# 🛡️ ARP Spoofing Detector

> Real-time ARP spoofing detection tool with a live Rich terminal UI — built as part of a cybersecurity portfolio.

Monitors ARP traffic on a given network interface, maintains a reference ARP table, and raises alerts whenever an IP is claimed by a new MAC address — a classic indicator of a Man-in-the-Middle (MITM) attack.

---

## 📸 Demo

```
┌─────────────────────────────────────────────────────────────────────┐
│                   🛡️  ARP SPOOFING DETECTOR                         │
├──────────────────────────────────────┬──────────────────────────────┤
│  📡 ARP Table (Reference)            │  📊 Statistics               │
│  ┌──────────────┬───────────────┐    │   Interface : eth0           │
│  │ IP Address   │ MAC Address   │    │   Mode      : Active         │
│  │ 192.168.1.1  │ aa:bb:cc:...  │    │   Uptime    : 00:03:21       │
│  │ 192.168.1.42 │ de:ad:be:...  │    │   Packets   : 214            │
│  └──────────────┴───────────────┘    │   Hosts     : 7              │
│                                      │   Alerts    : 1              │
│  🚨 Detected Incidents               └──────────────────────────────┤
│  ┌────┬──────────────┬────────────────────────────────────────┐     │
│  │ #  │ IP           │ Spoofed MAC                            │     │
│  │ 1  │ 192.168.1.1  │ de:ad:be:ef:00:01 (was aa:bb:cc:...)  │     │
│  └────┴──────────────┴────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

```bash
git clone https://github.com/salemkora/arp-detector
cd arp-detector
pip install -r requirements.txt
```

> ⚠️ Requires Python 3.8+ and root/sudo privileges (raw socket capture).

---

## 💻 Usage

```bash
# Basic usage
sudo python detector.py --interface eth0

# With log file
sudo python detector.py -i eth0 --log alerts.log

# Passive mode (listen only, no active response)
sudo python detector.py -i eth0 --passive

# Verbose mode (show all ARP packets in log panel)
sudo python detector.py -i eth0 --verbose

# Export JSON report on exit (Ctrl+C)
sudo python detector.py -i eth0 --export report.json

# Full options
sudo python detector.py -i eth0 --log alerts.log --verbose --export report.json
```

---

## 🔧 Features

- [x] Real-time ARP packet capture via Scapy
- [x] Reference ARP table (IP → MAC mapping)
- [x] Anomaly detection: same IP claimed by two different MACs
- [x] Live Rich UI: ARP table, incident list, statistics panel
- [x] Timestamped alert logging to file
- [x] Alert deduplication (no log spam for repeated events)
- [x] Passive mode (listen only) vs Active mode
- [x] Verbose mode: all packets shown in live log panel
- [x] JSON incident report export on exit
- [x] Clean exit with Ctrl+C

---

## 📁 Project Structure

```
arp-detector/
├── detector.py       # Entry point — args, validation, launch
├── arp_monitor.py    # Core detection logic + Rich UI
├── alerts.py         # Alert model and file logger
├── requirements.txt
└── README.md
```

---

## 🧠 How it works

1. Scapy sniffs all ARP packets on the specified interface (filter: `arp`)
2. For each ARP request/reply, the tool extracts the sender IP and MAC
3. The IP→MAC mapping is stored in an in-memory reference table
4. If a known IP appears with a **different** MAC address → alert raised
5. Alert is logged (file), displayed in the Rich UI, and deduplicated

**Why this matters:** ARP spoofing is the foundation of most LAN-based MITM attacks (Ettercap, arpspoof, Bettercap). A tool like this would have caught those attacks in real time.

---

## ⚠️ Disclaimer

For **educational and legal use only**. Only run on networks you own or have explicit written permission to monitor. The author is not responsible for any misuse.

---

## 👤 Author

**Salem KORA** — Bachelor Cybersécurité & Ethical Hacking, EFREI Bordeaux  
[GitHub](https://github.com/salemkora) · [LinkedIn](https://linkedin.com/in/salemkora)
