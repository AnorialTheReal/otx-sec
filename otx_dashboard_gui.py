#!/opt/otx-sec/venv/bin/python

import os
import json
import subprocess
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QListWidget, QMessageBox
)
from PySide6.QtCore import QTimer

LOG_DIR = "/var/log/otx-sec"
QUARANTINE_DIR = "/var/quarantine/otx-sec"

LOGS = {
    "Malware/File Scanner": "report.jsonl",
    "Processes": "process_report.jsonl",
    "Network": "network_report.jsonl",
    "Persistence": "persistence_report.jsonl",
    "Integrity": "integrity_report.jsonl",
}

SERVICES = [
    "otx-sec",
    "otx-process-monitor",
    "otx-network-monitor",
    "otx-persistence-monitor",
    "clamav-daemon",
    "clamav-freshclam",
    "auditd",
]


class OTXDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OTX-Sec Local Dashboard")
        self.resize(1200, 800)

        layout = QVBoxLayout()

        self.status_label = QLabel("OTX-Sec Dashboard")
        layout.addWidget(self.status_label)

        btns = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)

        self.integrity_btn = QPushButton("Run Integrity Check")
        self.integrity_btn.clicked.connect(self.run_integrity)

        self.baseline_btn = QPushButton("Rebuild Baseline")
        self.baseline_btn.clicked.connect(self.rebuild_baseline)

        self.open_quarantine_btn = QPushButton("Open Quarantine")
        self.open_quarantine_btn.clicked.connect(self.open_quarantine)

        self.restart_services_btn = QPushButton("Restart OTX Services")
        self.restart_services_btn.clicked.connect(self.restart_services)

        btns.addWidget(self.refresh_btn)
        btns.addWidget(self.integrity_btn)
        btns.addWidget(self.baseline_btn)
        btns.addWidget(self.open_quarantine_btn)
        btns.addWidget(self.restart_services_btn)

        layout.addLayout(btns)

        content = QHBoxLayout()

        self.left = QListWidget()
        self.left.itemClicked.connect(self.show_selected_log)
        content.addWidget(self.left, 2)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        content.addWidget(self.details, 5)

        layout.addLayout(content)
        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(15000)

        self.refresh()

    def run_cmd(self, cmd):
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            return r.stdout + r.stderr
        except Exception as e:
            return str(e)

    def service_status(self):
        out = []
        for s in SERVICES:
            code = subprocess.call(
                ["systemctl", "is-active", "--quiet", s]
            )
            status = "ACTIVE" if code == 0 else "INACTIVE"
            out.append(f"{s}: {status}")
        return "\n".join(out)

    def read_jsonl(self, filename, limit=100):
        path = os.path.join(LOG_DIR, filename)
        if not os.path.exists(path):
            return []

        rows = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass

        return rows[-limit:]

    def refresh(self):
        self.left.clear()
        self.left.addItem("== SERVICES ==")
        self.left.addItem(self.service_status())

        self.left.addItem("== QUARANTINE ==")
        if os.path.exists(QUARANTINE_DIR):
            for f in os.listdir(QUARANTINE_DIR):
                self.left.addItem(f"[QUARANTINE] {f}")

        for title, file in LOGS.items():
            rows = self.read_jsonl(file)
            self.left.addItem(f"== {title} ==")

            for r in reversed(rows[-30:]):
                event = r.get("event", r.get("status", "EVENT"))
                obj = r.get("file", r.get("exe", r.get("process", "")))
                self.left.addItem(f"[{title}] {event} | {obj}")

        self.status_label.setText("OTX-Sec Dashboard refreshed")

    def show_selected_log(self, item):
        text = item.text()

        if text.startswith("==") or ": ACTIVE" in text or ": INACTIVE" in text:
            self.details.setPlainText(text)
            return

        if text.startswith("[QUARANTINE]"):
            name = text.replace("[QUARANTINE] ", "")
            path = os.path.join(QUARANTINE_DIR, name)

            self.details.setPlainText(
                f"Quarantined file:\n{path}\n\n"
                f"Actions:\n"
                f"- Upload hash manually to VirusTotal\n"
                f"- Keep quarantined\n"
                f"- Delete only if you are 100% sure"
            )
            return

        found = None
        for title, file in LOGS.items():
            rows = self.read_jsonl(file)
            for r in rows:
                raw = json.dumps(r, indent=2, ensure_ascii=False)
                obj = r.get("file", r.get("exe", r.get("process", "")))
                event = r.get("event", r.get("status", "EVENT"))

                if event in text and str(obj) in text:
                    found = raw
                    break

        self.details.setPlainText(found or text)

    def run_integrity(self):
        out = self.run_cmd([
            "sudo",
            "/opt/otx-sec/venv/bin/python",
            "/opt/otx-sec/integrity_check.py"
        ])
        QMessageBox.information(self, "Integrity Check", out)
        self.refresh()

    def rebuild_baseline(self):
        msg = QMessageBox.question(
            self,
            "Rebuild Baseline",
            "Only do this after trusted system updates. Continue?"
        )

        if msg == QMessageBox.Yes:
            out = self.run_cmd([
                "sudo",
                "/opt/otx-sec/venv/bin/python",
                "/opt/otx-sec/baseline.py"
            ])
            QMessageBox.information(self, "Baseline", out)
            self.refresh()

    def open_quarantine(self):
        subprocess.Popen(["xdg-open", QUARANTINE_DIR])

    def restart_services(self):
        out = self.run_cmd([
            "sudo",
            "systemctl",
            "restart",
            "otx-sec",
            "otx-process-monitor",
            "otx-network-monitor",
            "otx-persistence-monitor"
        ])
        QMessageBox.information(self, "Restart Services", out or "Services restarted.")
        self.refresh()


app = QApplication([])
window = OTXDashboard()
window.show()
app.exec()
