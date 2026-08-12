"""Detector package — continuous priv-esc / anomaly scanners."""

from detectors.audit_parser import AuditParserDetector
from detectors.base import BaseDetector, Finding
from detectors.capability_check import CapabilityCheckDetector
from detectors.cron_check import CronCheckDetector
from detectors.sudoers_check import SudoersCheckDetector
from detectors.suid_check import SuidCheckDetector
from detectors.version_scanner import VersionScannerDetector

__all__ = [
    "BaseDetector",
    "Finding",
    "AuditParserDetector",
    "CapabilityCheckDetector",
    "CronCheckDetector",
    "SudoersCheckDetector",
    "SuidCheckDetector",
    "VersionScannerDetector",
]
