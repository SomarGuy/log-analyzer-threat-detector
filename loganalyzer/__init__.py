"""Log Analyzer and Threat Detector: a small, dependency-free blue-team toolkit.

Parses Linux auth.log (SSH), Windows Security event exports (CSV/JSON) and
nginx/Apache combined access logs, applies rule-driven detections mapped to
MITRE ATT&CK, and writes JSON + Markdown incident reports.
"""

__version__ = "1.0.0"
