"""Static code scanning: reads package files and never runs them."""

from pkgguard_analyzer.code_scan.scan import CodeScanResult, scan_code

__all__ = ["CodeScanResult", "scan_code"]
