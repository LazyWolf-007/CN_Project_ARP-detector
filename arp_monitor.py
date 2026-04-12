#!/usr/bin/env python3
"""
arp_monitor.py — Core ARP monitoring and detection logic.
Uses Scapy for packet capture and Rich for live terminal UI.
"""

import json
import signal
import threading
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import ARP, Ether, sniff, get_if_list
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from alerts import AlertManager, Alert


console = Console()


def build_arp_table_widget(arp_table: dict) -> Table:
    table = Table(
        title="📡 ARP Table (Reference)",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("IP Address", style="white", min_width=16)
    table.add_column("MAC Address", style="green", min_width=20)
    table.add_column("First Seen", style="dim")
    table.add_column("Last Updated", style="dim")

    for ip, info in sorted(arp_table.items()):
        table.add_row(
            ip,
            info["mac"],
            info["first_seen"],
            info["last_seen"],
        )
    return table


def build_alerts_widget(alerts: list) -> Table:
    table = Table(
        title="🚨 Detected Incidents",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold red",
        expand=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Timestamp", style="yellow", min_width=20)
    table.add_column("IP", style="white", min_width=16)
    table.add_column("Known MAC", style="green", min_width=20)
    table.add_column("Spoofed MAC", style="red bold", min_width=20)
    table.add_column("Interface", style="cyan")

    for i, alert in enumerate(alerts[-20:], 1):   # show last 20
        table.add_row(
            str(i),
            alert.timestamp,
            alert.ip,
            alert.known_mac,
            alert.spoofed_mac,
            alert.interface,
        )
    return table


def build_stats_widget(stats: dict, interface: str, mode: str) -> Panel:
    elapsed = int(time.time() - stats["start_time"])
    h, rem = divmod(elapsed, 3600)
    m, s = divmod(rem, 60)

    text = Text()
    text.append(f"  Interface : ", style="dim")
    text.append(f"{interface}\n", style="bold white")
    text.append(f"  Mode      : ", style="dim")
    text.append(f"{mode}\n", style="bold yellow")
    text.append(f"  Uptime    : ", style="dim")
    text.append(f"{h:02d}:{m:02d}:{s:02d}\n", style="bold white")
    text.append(f"  Packets   : ", style="dim")
    text.append(f"{stats['packets_seen']}\n", style="bold cyan")
    text.append(f"  Hosts     : ", style="dim")
    text.append(f"{stats['hosts_seen']}\n", style="bold green")
    text.append(f"  Alerts    : ", style="dim")
    color = "red bold" if stats["alerts_count"] > 0 else "green"
    text.append(f"{stats['alerts_count']}\n", style=color)

    return Panel(text, title="📊 Statistics", border_style="blue", box=box.ROUNDED)


def build_layout(arp_table, alerts, stats, interface, mode, verbose_log) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=3),
        Layout(name="main"),
        Layout(name="bottom", size=10),
    )
    layout["main"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1),
    )

    # Header
    title = Text("🛡️  ARP SPOOFING DETECTOR", style="bold white on dark_blue", justify="center")
    layout["top"].update(Panel(title, border_style="blue"))

    # ARP table + alerts
    layout["left"].split_column(
        Layout(build_arp_table_widget(arp_table), name="arp"),
        Layout(build_alerts_widget(alerts), name="incidents"),
    )

    # Stats
    layout["right"].update(build_stats_widget(stats, interface, mode))

    # Verbose log
    if verbose_log:
        log_text = Text()
        for line in verbose_log[-8:]:
            log_text.append(line + "\n", style="dim white")
        layout["bottom"].update(
            Panel(log_text, title="📝 Packet Log", border_style="dim", box=box.ROUNDED)
        )
    else:
        layout["bottom"].update(
            Panel(Text("No packets yet.", style="dim"), title="📝 Packet Log",
                  border_style="dim", box=box.ROUNDED)
        )

    return layout


class ARPMonitor:
    def __init__(
        self,
        interface: str,
        alert_manager: AlertManager,
        passive: bool = False,
        verbose: bool = False,
        export_file: str = None,
    ):
        self.interface = interface
        self.alert_manager = alert_manager
        self.passive = passive
        self.verbose = verbose
        self.export_file = export_file

        self.arp_table: dict = {}        # ip -> {mac, first_seen, last_seen}
        self.alerts: list = []
        self.verbose_log: list = []
        self.lock = threading.Lock()

        self.stats = {
            "start_time": time.time(),
            "packets_seen": 0,
            "hosts_seen": 0,
            "alerts_count": 0,
        }

        self._validate_interface()

    def _validate_interface(self):
        available = get_if_list()
        if self.interface not in available:
            console.print(
                f"[red][!] Interface '{self.interface}' not found.[/red]\n"
                f"    Available: {', '.join(available)}"
            )
            raise SystemExit(1)

    def _process_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        # ARP reply (op=2) or request (op=1)
        if arp.op not in (1, 2):
            return

        ip = arp.psrc
        mac = arp.hwsrc.lower()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not ip or ip == "0.0.0.0":
            return

        with self.lock:
            self.stats["packets_seen"] += 1

            if self.verbose:
                op = "reply" if arp.op == 2 else "request"
                self.verbose_log.append(
                    f"[{now}] ARP {op:7s}  {ip:<16} → {mac}"
                )

            if ip not in self.arp_table:
                # New host, register it
                self.arp_table[ip] = {
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now,
                }
                self.stats["hosts_seen"] += 1
            else:
                known_mac = self.arp_table[ip]["mac"]
                if mac != known_mac:
                    # Anomaly: same IP, different MAC → potential ARP spoofing
                    alert = Alert(
                        timestamp=now,
                        ip=ip,
                        known_mac=known_mac,
                        spoofed_mac=mac,
                        interface=self.interface,
                    )
                    self.alerts.append(alert)
                    self.stats["alerts_count"] += 1
                    self.alert_manager.record(alert)

                    if not self.passive:
                        # Active mode: send a gratuitous ARP to warn the network
                        # (logged, not implemented here to keep it educational)
                        pass
                else:
                    self.arp_table[ip]["last_seen"] = now

    def _sniff_thread(self):
        sniff(
            iface=self.interface,
            filter="arp",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def start(self):
        self._stop_event = threading.Event()
        mode_label = "Passive" if self.passive else "Active"

        sniffer = threading.Thread(target=self._sniff_thread, daemon=True)
        sniffer.start()

        def handle_exit(sig, frame):
            self._stop_event.set()
            if self.export_file:
                self._export_report()
            console.print("\n[bold green][✓] Monitoring stopped. Bye![/bold green]")
            raise SystemExit(0)

        signal.signal(signal.SIGINT, handle_exit)
        signal.signal(signal.SIGTERM, handle_exit)

        with Live(
            build_layout(
                self.arp_table, self.alerts, self.stats,
                self.interface, mode_label, self.verbose_log
            ),
            refresh_per_second=2,
            screen=True,
        ) as live:
            while not self._stop_event.is_set():
                with self.lock:
                    live.update(
                        build_layout(
                            self.arp_table, self.alerts, self.stats,
                            self.interface, mode_label, self.verbose_log
                        )
                    )
                time.sleep(0.5)

    def _export_report(self):
        report = {
            "generated_at": datetime.now().isoformat(),
            "interface": self.interface,
            "duration_seconds": int(time.time() - self.stats["start_time"]),
            "statistics": {
                "packets_seen": self.stats["packets_seen"],
                "hosts_seen": self.stats["hosts_seen"],
                "alerts_count": self.stats["alerts_count"],
            },
            "arp_table": self.arp_table,
            "incidents": [
                {
                    "timestamp": a.timestamp,
                    "ip": a.ip,
                    "known_mac": a.known_mac,
                    "spoofed_mac": a.spoofed_mac,
                    "interface": a.interface,
                }
                for a in self.alerts
            ],
        }
        with open(self.export_file, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green][✓] Report exported to {self.export_file}[/green]")
