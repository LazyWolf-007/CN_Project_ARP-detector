#!/usr/bin/env python3
"""
ARP Spoofing Detector — detector.py
Entry point: argument parsing, interface validation, launch.
"""

import argparse
import sys
import os
from arp_monitor import ARPMonitor
from alerts import AlertManager


def parse_args():
    parser = argparse.ArgumentParser(
        prog="arp-detector",
        description="Real-time ARP spoofing detector with Rich UI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to monitor (e.g. eth0, ens33)"
    )
    parser.add_argument(
        "-l", "--log",
        default="alerts.log",
        help="Log file for alerts (default: alerts.log)"
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Passive mode: listen only, no active network alerts"
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export incident report to JSON file on exit"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all ARP packets, not just anomalies"
    )
    return parser.parse_args()



def check_root():
    """Check whether the process has elevated privileges."""
    import os
    import sys

    if os.name == "nt":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = hasattr(os, "geteuid") and os.geteuid() == 0

    if not is_admin:
        print(
            "Warning: Not running with elevated privileges. "
            "Packet capture may fail."
        )



def main():
    args = parse_args()
    check_root()

    alert_manager = AlertManager(log_file=args.log)
    monitor = ARPMonitor(
        interface=args.interface,
        alert_manager=alert_manager,
        passive=args.passive,
        verbose=args.verbose,
        export_file=args.export,
    )
    monitor.start()


if __name__ == "__main__":
    main()
