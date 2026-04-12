#!/usr/bin/env python3
"""
alerts.py — Alert data model and manager (logging, deduplication).
"""

import logging
from dataclasses import dataclass


@dataclass
class Alert:
    timestamp: str
    ip: str
    known_mac: str
    spoofed_mac: str
    interface: str


class AlertManager:
    def __init__(self, log_file: str = "alerts.log"):
        self.log_file = log_file
        self._seen: set = set()

        logging.basicConfig(
            filename=log_file,
            level=logging.WARNING,
            format="%(asctime)s [ALERT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger("arp-detector")

    def record(self, alert: Alert):
        """Log alert, deduplicate within the same session."""
        key = (alert.ip, alert.known_mac, alert.spoofed_mac)
        if key in self._seen:
            return  # already logged this exact event

        self._seen.add(key)
        msg = (
            f"ARP SPOOFING DETECTED | "
            f"IP={alert.ip} | "
            f"KNOWN_MAC={alert.known_mac} | "
            f"SPOOFED_MAC={alert.spoofed_mac} | "
            f"IFACE={alert.interface}"
        )
        self.logger.warning(msg)
