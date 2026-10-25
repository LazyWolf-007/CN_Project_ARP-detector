#!/usr/bin/env python3
"""
arp_monitor.py — Core ARP monitoring and detection logic.

Real passive ARP capture with a Rich terminal dashboard.
This module does not generate traffic or perform active network enforcement.
"""

import json
import signal
import threading
import time
from datetime import datetime
from pathlib import Path

from scapy.all import ARP, Ether, conf, sniff
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from alerts import AlertManager, Alert


console = Console()


def _interface_candidates(iface):
    """Return the known names by which Scapy may identify an interface."""
    values = []
    for attr in ("name", "description", "network_name", "guid", "index"):
        value = getattr(iface, attr, None)
        if value is not None:
            values.append(str(value).strip())

    # Some Scapy/Npcap versions expose the NPF path in different attributes.
    try:
        values.append(str(iface).strip())
    except Exception:
        pass

    return {value.casefold() for value in values if value}


def resolve_interface(requested):
    """
    Resolve either a Scapy interface name/description or an NPF device path
    to the Scapy interface object accepted by sniff().
    """
    requested_normalized = str(requested).strip().casefold()
    interfaces = list(conf.ifaces.values())

    # Prefer an exact match.
    for iface in interfaces:
        if requested_normalized in _interface_candidates(iface):
            return iface

    # Accept a unique partial match, useful when the user supplies the
    # friendly adapter description instead of its NPF device path.
    matches = [
        iface for iface in interfaces
        if any(
            requested_normalized in candidate
            or candidate in requested_normalized
            for candidate in _interface_candidates(iface)
        )
    ]
    if len(matches) == 1:
        return matches[0]

    available = []
    for iface in interfaces:
        description = getattr(iface, "description", "")
        name = getattr(iface, "name", "")
        network_name = getattr(iface, "network_name", "")
        available.append(
            f"  description={description!s} | name={name!s} "
            f"| network_name={network_name!s}"
        )

    details = "\n".join(available) if available else "  (no Scapy interfaces found)"
    reason = "No matching interface" if not matches else "Interface name is ambiguous"
    raise ValueError(
        f"{reason}: {requested!r}\nAvailable Scapy interfaces:\n{details}"
    )


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
    table.add_column("Observed MAC", style="red bold", min_width=20)
    table.add_column("Interface", style="cyan")

    for index, alert in enumerate(alerts[-20:], 1):
        table.add_row(
            str(index),
            alert.timestamp,
            alert.ip,
            alert.known_mac,
            alert.spoofed_mac,
            alert.interface,
        )
    return table


def build_stats_widget(stats: dict, interface: str, mode: str) -> Panel:
    # Use a monotonic clock for elapsed time; system clock changes won't
    # make the uptime jump backward or forward.
    elapsed = max(0, int(time.monotonic() - stats["start_time"]))
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)

    text = Text()
    text.append("  Interface : ", style="dim")
    text.append(f"{interface}\n", style="bold white")
    text.append("  Mode      : ", style="dim")
    text.append(f"{mode}\n", style="bold yellow")
    text.append("  Uptime    : ", style="dim")
    text.append(f"{hours:02d}:{minutes:02d}:{seconds:02d}\n", style="bold white")
    text.append("  ARP packets: ", style="dim")
    text.append(f"{stats['packets_seen']}\n", style="bold cyan")
    text.append("  Hosts     : ", style="dim")
    text.append(f"{stats['hosts_seen']}\n", style="bold green")
    text.append("  Alerts    : ", style="dim")
    alert_color = "red bold" if stats["alerts_count"] > 0 else "green"
    text.append(f"{stats['alerts_count']}\n", style=alert_color)
    text.append("  Capture   : ", style="dim")
    status = stats.get("capture_status", "Starting")
    status_color = "green" if status == "Capturing" else "yellow"
    if status.startswith("ERROR"):
        status_color = "red bold"
    text.append(f"{status}\n", style=status_color)

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

    title = Text(
        "🛡️  ARP SPOOFING DETECTOR",
        style="bold white on dark_blue",
        justify="center",
    )
    layout["top"].update(Panel(title, border_style="blue"))

    layout["left"].split_column(
        Layout(build_arp_table_widget(arp_table), name="arp"),
        Layout(build_alerts_widget(alerts), name="incidents"),
    )
    layout["right"].update(build_stats_widget(stats, interface, mode))

    log_text = Text()
    if verbose_log:
        for line in verbose_log[-8:]:
            log_text.append(line + "\n", style="dim white")
    else:
        log_text.append("No ARP packets captured yet.", style="dim")

    layout["bottom"].update(
        Panel(log_text, title="📝 ARP Packet Log", border_style="dim", box=box.ROUNDED)
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
        demo: bool = False,
    ):
        self.interface = interface
        self.alert_manager = alert_manager
        self.passive = passive
        self.verbose = verbose
        self.export_file = export_file
        self.demo = demo

        self.arp_table = {}       # IP -> {mac, first_seen, last_seen}
        self.alerts = []
        self.verbose_log = []
        self.lock = threading.RLock()
        self._stop_event = threading.Event()
        self._anomalies_seen = set()

        self.stats = {
            "start_time": time.monotonic(),
            "packets_seen": 0,     # accepted ARP request/reply packets
            "hosts_seen": 0,
            "alerts_count": 0,
            "capture_status": "Starting",
        }

        if self.demo:
            self.capture_interface = None
            self.display_interface = "SIMULATION (offline)"
        else:
            try:
                self.capture_interface = resolve_interface(interface)
            except ValueError as exc:
                console.print(
                    f"[bold red]Interface resolution failed:[/bold red]\n{exc}"
                )
                raise SystemExit(1) from exc

            self.display_interface = (
                getattr(self.capture_interface, "description", None)
                or getattr(self.capture_interface, "name", None)
                or interface
            )

    def _process_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        if arp.op not in (1, 2):
            return

        ip = str(arp.psrc).strip()
        mac = str(arp.hwsrc).strip().lower()

        # ARP probes have no sender IPv4 address; they aren't a usable
        # IP-to-MAC mapping for this detector.
        if not ip or ip == "0.0.0.0" or not mac:
            return

        now_dt = datetime.now()
        timestamp = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        operation = "reply" if int(arp.op) == 2 else "request"

        with self.lock:
            self.stats["packets_seen"] += 1

            if self.verbose:
                self.verbose_log.append(
                    f"[{timestamp}] ARP {operation:7s} {ip:<16} -> {mac}"
                )
                self.verbose_log = self.verbose_log[-200:]

            if ip not in self.arp_table:
                self.arp_table[ip] = {
                    "mac": mac,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
                self.stats["hosts_seen"] = len(self.arp_table)
                return

            entry = self.arp_table[ip]
            known_mac = entry["mac"]
            entry["last_seen"] = timestamp

            if mac == known_mac:
                return

            # A changed IP-to-MAC mapping is a potential spoofing event,
            # not definitive proof. Report each distinct mapping conflict once.
            anomaly_key = (ip, known_mac, mac)
            if anomaly_key in self._anomalies_seen:
                return

            self._anomalies_seen.add(anomaly_key)
            alert = Alert(
                timestamp=timestamp,
                ip=ip,
                known_mac=known_mac,
                spoofed_mac=mac,
                interface=self.display_interface,
            )
            self.alerts.append(alert)
            self.stats["alerts_count"] = len(self.alerts)

            if self.verbose:
                self.verbose_log.append(
                    f"[ALERT] Possible IP/MAC conflict: {ip} "
                    f"known={known_mac} observed={mac}"
                )
                self.verbose_log = self.verbose_log[-200:]

            # Keep the original mapping as the reference baseline. This
            # makes subsequent conflicting claims visible rather than
            # automatically trusting the new MAC.
            self.alert_manager.record(alert)

    def _run_demo(self):
        """Process synthetic ARP packets locally; never transmit them."""
        console.print(
            "[bold yellow]SIMULATION / NOT REAL NETWORK TRAFFIC[/bold yellow]"
        )

        synthetic_ip = "198.51.100.10"
        original_mac = "02:00:00:00:00:01"
        conflicting_mac = "02:00:00:00:00:02"

        # Establish a synthetic reference mapping.
        first_packet = Ether() / ARP(
            op=2,
            psrc=synthetic_ip,
            hwsrc=original_mac,
        )
        self._process_packet(first_packet)

        # Simulate a conflicting claim for the same IP.
        second_packet = Ether() / ARP(
            op=2,
            psrc=synthetic_ip,
            hwsrc=conflicting_mac,
        )
        self._process_packet(second_packet)

        with self.lock:
            self.stats["capture_status"] = "Simulation complete"
            self.verbose_log.append(
                "[SIMULATION] Two synthetic ARP packet objects processed."
            )
            self.verbose_log = self.verbose_log[-200:]   

    def _sniff_thread(self):
        try:
            with self.lock:
                self.stats["capture_status"] = "Capturing"

            console.print(
                f"[green]Starting ARP capture on: "
                f"{self.display_interface}[/green]"
            )

            sniff(
                iface=self.capture_interface,
                filter="arp",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _packet: self._stop_event.is_set(),
            )

            with self.lock:
                if self._stop_event.is_set():
                    self.stats["capture_status"] = "Stopped"
                else:
                    self.stats["capture_status"] = "Capture ended"

        except Exception as exc:
            message = f"ERROR: {type(exc).__name__}: {exc}"
            with self.lock:
                self.stats["capture_status"] = message
                self.verbose_log.append(f"[CAPTURE ERROR] {message}")
                self.verbose_log = self.verbose_log[-200:]
            console.print(f"[bold red]Capture failed: {message}[/bold red]")

    def start(self):
        if self.demo:
            mode_label = "SIMULATION - NOT REAL NETWORK TRAFFIC"
            with self.lock:
                self.stats["capture_status"] = "Simulation ready"
            self._run_demo()
        else:
            mode_label = (
                "Passive" if self.passive else "Active (detection only)"
            )
            sniffer = threading.Thread(
                target=self._sniff_thread,
                name="arp-capture",
                daemon=True,
            )
            sniffer.start()

        def handle_exit(_sig, _frame):
            self._stop_event.set()
            if self.export_file:
                self._export_report()
            console.print("\n[bold green]Monitoring stopped.[/bold green]")
            raise SystemExit(0)

        signal.signal(signal.SIGINT, handle_exit)
        if hasattr(signal, "SIGTERM"):
            try:
                signal.signal(signal.SIGTERM, handle_exit)
            except (ValueError, OSError):
                pass

        try:
            with Live(
                screen=True,
                refresh_per_second=4,
                console=console,
            ) as live:
                while not self._stop_event.is_set():
                    with self.lock:
                        arp_snapshot = {
                            ip: info.copy()
                            for ip, info in self.arp_table.items()
                        }
                        alerts_snapshot = list(self.alerts)
                        stats_snapshot = self.stats.copy()
                        log_snapshot = list(self.verbose_log)

                    live.update(
                        build_layout(
                            arp_snapshot,
                            alerts_snapshot,
                            stats_snapshot,
                            self.display_interface,
                            mode_label,
                            log_snapshot,
                        )
                    )
                    time.sleep(0.25)
        except KeyboardInterrupt:
            self._stop_event.set()
        finally:
            self._stop_event.set()
            if self.export_file:
                self._export_report()

    def _export_report(self):
        if not self.export_file:
            return

        with self.lock:
            report = {
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "interface": self.display_interface,
                "duration_seconds": max(
                    0, int(time.monotonic() - self.stats["start_time"])
                ),
                "statistics": {
                    "packets_seen": self.stats["packets_seen"],
                    "hosts_seen": self.stats["hosts_seen"],
                    "alerts_count": self.stats["alerts_count"],
                    "capture_status": self.stats.get("capture_status", "Unknown"),
                },
                "arp_table": {
                    ip: info.copy() for ip, info in self.arp_table.items()
                },
                "incidents": [
                    {
                        "timestamp": alert.timestamp,
                        "ip": alert.ip,
                        "known_mac": alert.known_mac,
                        "spoofed_mac": alert.spoofed_mac,
                        "interface": alert.interface,
                    }
                    for alert in self.alerts
                ],
            }

        output_path = Path(self.export_file)
        with output_path.open("w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
        console.print(f"[green]Report exported to {output_path}[/green]")
