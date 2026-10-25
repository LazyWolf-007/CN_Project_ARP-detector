
#!/usr/bin/env python3
"""
ARP Spoofing Detector — detector.py
Entry point: argument parsing, interface validation, and launch.
"""

import argparse
import os
import sys

from arp_monitor import ARPMonitor
from alerts import AlertManager


def parse_args():
    parser = argparse.ArgumentParser(
        prog="arp-detector",
        description="ARP spoofing detector with a Rich terminal dashboard",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to monitor in live mode",
    )
    parser.add_argument(
        "-l", "--log",
        default="alerts.log",
        help="Log file for alerts (default: alerts.log)",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Listen only; do not perform network enforcement",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export incident report to JSON on exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show observed ARP packets in the dashboard",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run an isolated synthetic demonstration; transmit no packets",
    )

    args = parser.parse_args()

    if not args.demo and not args.interface:
        parser.error("--interface is required unless --demo is used")

    return args


def check_privileges():
    """Warn if live packet capture may lack required permissions."""
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
            "Warning: not running with elevated privileges. "
            "Live packet capture may fail.",
            file=sys.stderr,
        )


def main():
    args = parse_args()

    if not args.demo:
        check_privileges()

    alert_manager = AlertManager(log_file=args.log)

    monitor = ARPMonitor(
        interface=args.interface or "SIMULATION",
        alert_manager=alert_manager,
        passive=args.passive,
        verbose=args.verbose,
        export_file=args.export,
        demo=args.demo,
    )

    monitor.start()


if __name__ == "__main__":
    main()
