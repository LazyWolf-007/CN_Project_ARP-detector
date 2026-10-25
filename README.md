# ARP Spoofing Detector

A Python-based ARP monitoring and anomaly-detection tool that captures observable ARP traffic, maintains an IP-to-MAC reference table, and flags conflicting mappings through a terminal dashboard.

The project supports two workflows:

- **Live monitoring:** passively observes ARP traffic available to the selected network interface.
- **Demo mode:** processes synthetic ARP packet objects locally to demonstrate the mapping-conflict detection logic without transmitting packets onto a network.


📊 Terminal Dashboard — Example Output

The detector provides a terminal dashboard for monitoring ARP traffic, maintaining IP-to-MAC reference mappings, and reporting potential conflicts.
```
+-----------------------------------------------------------------------+
|                       ARP SPOOFING DETECTOR                           |
|                         SIMULATION MODE                               |
+--------------------------------------+--------------------------------+
| ARP TABLE (REFERENCE)                | STATISTICS                     |
|                                      |                                |
| IP Address      MAC Address          | Interface: SIMULATION          |
| 198.51.100.10   02:00:00:00:00:01    | Mode: SIMULATION               |
|                                      | ARP Packets: 2                 |
|                                      | Hosts: 1                       |
|                                      | Alerts: 1                      |
+--------------------------------------+--------------------------------+
| DETECTED INCIDENTS                                                    |
|                                                                       |
| IP:           198.51.100.10                                           |
| Known MAC:    02:00:00:00:00:01                                       |
| Observed MAC: 02:00:00:00:00:02                                       |
| Type:         Potential IP/MAC Conflict                               |
+-----------------------------------------------------------------------+
| ARP PACKET LOG                                                        |
| [SIMULATION] Initial mapping recorded                                 |
| [SIMULATION] Conflicting mapping detected                             |
+-----------------------------------------------------------------------+
```
Note: This is an illustrative dashboard representation. The incident is generated using synthetic ARP packet objects locally; no spoofed packets are transmitted onto the network
## Features

- Live ARP packet capture using Scapy and Npcap on Windows.
- IP-to-MAC reference table with first-seen and last-updated timestamps.
- Potential-conflict detection when the same IP address is observed with a different MAC address.
- Rich terminal dashboard with packet statistics, host mappings, incident records, and packet logs.
- Alert logging and optional JSON incident-report export.
- Offline synthetic demo for repeatable detection demonstrations.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic |
| Scapy | ARP packet capture and packet-object construction |
| Rich | Terminal dashboard |
| Npcap | Packet capture support on Windows |
| Git and GitHub | Version control and collaboration |

## Requirements

- Python 3.12 recommended for this project.
- Windows for the commands below.
- Npcap installed for live packet capture.
- Administrative privileges may be required for live packet capture.
- Dependencies listed in `requirements.txt`.

## Installation

Clone the repository:

```powershell
git clone https://github.com/LazyWolf-007/CN_Project_ARP-detector.git
cd CN_Project_ARP-detector
```

Create and activate a virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Running the Detector

### 1. Offline Demo Mode

Run the synthetic demonstration:

```powershell
python detector.py --demo --passive --verbose
```

Demo mode constructs synthetic ARP packet objects and passes them through the monitor's packet-processing function. The scenario first establishes a reference IP-to-MAC mapping, then introduces a different MAC for the same IP.

Expected behavior:

- Two synthetic packet objects are processed.
- One host is added to the reference table.
- A potential IP-to-MAC conflict is detected.
- One incident appears in the dashboard.

**Important:** Demo mode is a simulation. It does not transmit spoofed packets, alter other devices, or demonstrate a real network attack. Simulation results must not be presented as live network observations.

### 2. Live Passive Monitoring

Select a network interface available on your computer. On many Windows systems, the adapter name is `Wi-Fi`, while its hardware description may be something like `Intel(R) Wi-Fi 6 AX203`.

To inspect adapters:

```powershell
Get-NetAdapter | Format-List Name, InterfaceDescription, Status, InterfaceGuid
```

Start the detector using the interface name accepted by the application:

```powershell
python detector.py --interface "Intel(R) Wi-Fi 6 AX203" --passive --verbose
```

Replace the interface name with the correct one for your machine.

The live dashboard displays ARP packets visible to the selected interface, observed IP-to-MAC mappings, packet statistics, and potential-conflict alerts.

**Network visibility limitation:** Wi-Fi client isolation, VLAN segmentation, access-point behavior, and packet-capture restrictions may prevent the laptop from observing ARP traffic exchanged between other devices. An active capture session does not guarantee visibility of all network traffic.

### Optional Arguments

| Argument | Purpose |
|---|---|
| `-i`, `--interface` | Select the live-capture interface |
| `-l`, `--log` | Specify the alert log file |
| `--passive` | Select passive monitoring mode |
| `--verbose` | Enable detailed packet logging |
| `--export FILE` | Export an incident report to JSON on exit |
| `--demo` | Run the offline synthetic demonstration |

Use:

```powershell
python detector.py --help
```

to inspect the available command-line options.

## How Detection Works

1. Scapy captures an ARP packet or the demo supplies a synthetic packet object.
2. The monitor extracts the sender IP address and sender MAC address.
3. The monitor checks the IP against its in-memory reference table.
4. A new IP-to-MAC mapping is stored as an observation.
5. If a previously observed IP appears with a different MAC, the monitor records a potential-conflict alert.

### Important Detection Limitations

- The first observed mapping is not independently verified as trustworthy.
- A MAC-address change can have legitimate causes, so a conflict is not conclusive proof of spoofing.
- The detector only sees packets available to its capture interface.
- Reliable live-attack detection and false-positive performance require additional testing.
- The current project does not implement automatic network blocking or attack prevention.

## Project Structure

```text
CN_Project_ARP-detector/
├── detector.py       # CLI arguments and application entry point
├── arp_monitor.py    # Packet processing, detection, capture, and dashboard
├── alerts.py         # Alert records, logging, and deduplication
├── requirements.txt  # Python dependencies
├── COMMANDS.md       # Development command reference
└── README.md         # Project documentation
```

## Responsible
