#!/opt/otx-sec/venv/bin/python

import sys
import json
import subprocess

from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QAction

import backend


class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("OTX-Sec Antivirus Console")
        self.resize(1750, 1000)

        self.events = []
        self.visible_events = []
        self.threat_rows = []
        self.process_rows = []
        self.network_rows = []
        self.current_filter = "ALL"

        root = QWidget()
        main = QVBoxLayout(root)

        title = QLabel("OTX-Sec Antivirus Console")
        title.setFont(QFont("Fira Sans", 22, QFont.Bold))
        main.addWidget(title)

        self.cards = {}
        cards = QHBoxLayout()

        for name in ["Events", "High Risk", "Suspicious", "Clean", "Quarantine"]:
            lbl = QLabel()
            lbl.setMinimumHeight(86)
            lbl.setStyleSheet(
                "background:#1e1e2e;border-radius:14px;padding:16px;color:white;"
            )
            self.cards[name] = lbl
            cards.addWidget(lbl)

        main.addLayout(cards)

        buttons = QHBoxLayout()

        for text, func in [
            ("Refresh", self.refresh),
            ("All", lambda: self.set_filter("ALL")),
            ("High Risk", lambda: self.set_filter("HIGH")),
            ("Suspicious", lambda: self.set_filter("SUSPICIOUS")),
            ("Clean", lambda: self.set_filter("CLEAN")),
            ("Integrity Check", self.run_integrity),
            ("Restart Services", self.restart_services),
        ]:
            b = QPushButton(text)
            b.clicked.connect(func)
            buttons.addWidget(b)

        main.addLayout(buttons)

        self.tabs = QTabWidget()
        main.addWidget(self.tabs)

        self.tab_events = QWidget()
        self.tab_threats = QWidget()
        self.tab_processes = QWidget()
        self.tab_network = QWidget()
        self.tab_manual = QWidget()
        self.tab_action = QWidget()
        self.tab_quarantine = QWidget()
        self.tab_services = QWidget()
        self.tab_settings = QWidget()
        self.tab_recs = QWidget()

        self.tabs.addTab(self.tab_events, "Security Events")
        self.tabs.addTab(self.tab_threats, "Threat Center")
        self.tabs.addTab(self.tab_processes, "Process Analyzer")
        self.tabs.addTab(self.tab_network, "Network Analyzer")
        self.tabs.addTab(self.tab_manual, "Manual Scan")
        self.tabs.addTab(self.tab_action, "Action Center")
        self.tabs.addTab(self.tab_quarantine, "Quarantine")
        self.tabs.addTab(self.tab_services, "Services")
        self.tabs.addTab(self.tab_settings, "Settings")
        self.tabs.addTab(self.tab_recs, "Recommendations")

        self.setup_events()
        self.setup_threat_center()
        self.setup_processes()
        self.setup_network()
        self.setup_manual()
        self.setup_action()
        self.setup_quarantine()
        self.setup_services()
        self.setup_settings()
        self.setup_recs()

        self.setCentralWidget(root)
        self.apply_style()

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(15000)

        self.refresh()

    def apply_style(self):
        self.setStyleSheet("""
        QWidget {
            background:#11111b;
            color:#eeeeee;
            font-family:Fira Sans;
        }

        QPushButton {
            background:#313244;
            color:white;
            border:1px solid #45475a;
            padding:8px;
            border-radius:8px;
        }

        QPushButton:hover {
            background:#45475a;
        }

        QTabBar::tab {
            background:#1e1e2e;
            color:white;
            padding:10px;
            border:1px solid #313244;
        }

        QTabBar::tab:selected {
            background:#313244;
            color:#8cff8c;
        }

        QTableWidget, QTextEdit, QLineEdit {
            background:#181825;
            color:white;
            border:1px solid #313244;
        }

        QHeaderView::section {
            background:#313244;
            color:white;
            padding:6px;
        }

        QMenu {
            background:#1e1e2e;
            color:white;
            border:1px solid #45475a;
        }

        QMenu::item:selected {
            background:#45475a;
        }
        """)

    def setup_events(self):
        layout = QVBoxLayout(self.tab_events)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search events, files, hashes, processes, IPs...")
        self.search.textChanged.connect(self.populate_events)
        layout.addWidget(self.search)

        self.event_table = QTableWidget()
        self.event_table.setColumnCount(6)
        self.event_table.setHorizontalHeaderLabels(
            ["Severity", "Time", "Source", "Event", "Object", "Details"]
        )
        self.event_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.event_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.event_table.customContextMenuRequested.connect(self.event_menu)
        self.event_table.cellClicked.connect(self.show_event)
        layout.addWidget(self.event_table, 4)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details, 2)

    def setup_threat_center(self):
        layout = QVBoxLayout(self.tab_threats)

        row = QHBoxLayout()

        for label, severity in [
            ("High Risk", "HIGH"),
            ("Suspicious", "SUSPICIOUS"),
            ("Clean", "CLEAN"),
            ("Info", "INFO"),
        ]:
            button = QPushButton(label)
            button.clicked.connect(
                lambda checked=False, s=severity: self.load_threats(s)
            )
            row.addWidget(button)

        layout.addLayout(row)

        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(5)
        self.threat_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Source", "Event", "Object"]
        )
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.threat_table.customContextMenuRequested.connect(self.threat_menu)
        self.threat_table.cellClicked.connect(self.show_threat)
        layout.addWidget(self.threat_table, 4)

        self.threat_details = QTextEdit()
        self.threat_details.setReadOnly(True)
        layout.addWidget(self.threat_details, 2)

    def setup_processes(self):
        layout = QVBoxLayout(self.tab_processes)

        top = QHBoxLayout()

        refresh_btn = QPushButton("Refresh Processes")
        refresh_btn.clicked.connect(self.populate_processes)

        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("Search process, path, user...")
        self.process_search.textChanged.connect(self.populate_processes)

        top.addWidget(self.process_search)
        top.addWidget(refresh_btn)

        layout.addLayout(top)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(7)
        self.process_table.setHorizontalHeaderLabels(
            ["Risk", "PID", "Name", "User", "CPU", "RAM %", "Executable"]
        )
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.process_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.process_menu)
        self.process_table.cellClicked.connect(self.show_process)
        layout.addWidget(self.process_table, 4)

        self.process_details = QTextEdit()
        self.process_details.setReadOnly(True)
        layout.addWidget(self.process_details, 2)

    def setup_network(self):
        layout = QVBoxLayout(self.tab_network)

        top = QHBoxLayout()

        refresh_btn = QPushButton("Refresh Network")
        refresh_btn.clicked.connect(self.populate_network)

        self.network_search = QLineEdit()
        self.network_search.setPlaceholderText("Search process, IP, port, user...")
        self.network_search.textChanged.connect(self.populate_network)

        top.addWidget(self.network_search)
        top.addWidget(refresh_btn)

        layout.addLayout(top)

        self.network_table = QTableWidget()
        self.network_table.setColumnCount(7)
        self.network_table.setHorizontalHeaderLabels(
            ["Risk", "PID", "Process", "User", "Remote IP", "Port", "Status"]
        )
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.network_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.network_table.customContextMenuRequested.connect(self.network_menu)
        self.network_table.cellClicked.connect(self.show_network)
        layout.addWidget(self.network_table, 4)

        self.network_details = QTextEdit()
        self.network_details.setReadOnly(True)
        layout.addWidget(self.network_details, 2)

    def setup_manual(self):
        layout = QVBoxLayout(self.tab_manual)

        row = QHBoxLayout()

        self.scan_path = QLineEdit()
        self.scan_path.setPlaceholderText("/path/to/file-or-folder")
        row.addWidget(self.scan_path)

        for text, func in [
            ("Scan File", self.scan_file),
            ("Scan Folder", self.scan_folder),
            ("Hash File", self.hash_manual),
        ]:
            button = QPushButton(text)
            button.clicked.connect(func)
            row.addWidget(button)

        layout.addLayout(row)

        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        layout.addWidget(self.scan_output)

    def setup_action(self):
        layout = QVBoxLayout(self.tab_action)

        grid = QGridLayout()

        actions = [
            ("Restart Inactive Services", "restart_inactive"),
            ("Run Full Integrity Check", "integrity"),
            ("Rebuild Baseline", "baseline"),
            ("Analyze High Risk", "analyze_high"),
            ("Export Full Report", "export"),
            ("Clear Logs", "clear_logs"),
        ]

        for index, (label, action) in enumerate(actions):
            button = QPushButton(label)
            button.setMinimumHeight(55)
            button.clicked.connect(
                lambda checked=False, a=action: self.run_action(a)
            )
            grid.addWidget(button, index // 2, index % 2)

        layout.addLayout(grid)

        self.action_output = QTextEdit()
        self.action_output.setReadOnly(True)
        layout.addWidget(self.action_output)

    def setup_quarantine(self):
        layout = QVBoxLayout(self.tab_quarantine)

        row = QHBoxLayout()

        for text, func in [
            ("Open Folder", self.open_quarantine),
            ("Restore Selected", self.restore_quarantine),
            ("Delete Selected", self.delete_quarantine),
        ]:
            button = QPushButton(text)
            button.clicked.connect(func)
            row.addWidget(button)

        layout.addLayout(row)

        self.qtable = QTableWidget()
        self.qtable.setColumnCount(3)
        self.qtable.setHorizontalHeaderLabels(["Name", "Size", "Path"])
        self.qtable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.qtable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.qtable.customContextMenuRequested.connect(self.quarantine_menu)
        layout.addWidget(self.qtable)

    def setup_services(self):
        layout = QVBoxLayout(self.tab_services)

        self.stable = QTableWidget()
        self.stable.setColumnCount(3)
        self.stable.setHorizontalHeaderLabels(["Service", "Status", "Actions"])
        self.stable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.stable.customContextMenuRequested.connect(self.service_menu)
        layout.addWidget(self.stable)

    def setup_settings(self):
        layout = QVBoxLayout(self.tab_settings)

        settings = backend.load_settings()

        self.otx = QLineEdit(settings.get("otx_api_key", ""))
        self.vt = QLineEdit(settings.get("virustotal_api_key", ""))
        self.autoq = QLineEdit(str(settings.get("auto_quarantine", True)))

        for label, widget in [
            ("OTX API Key", self.otx),
            ("VirusTotal API Key", self.vt),
            ("Auto Quarantine true/false", self.autoq),
        ]:
            layout.addWidget(QLabel(label))
            layout.addWidget(widget)

        button = QPushButton("Save Settings")
        button.clicked.connect(self.save_settings)
        layout.addWidget(button)

    def setup_recs(self):
        layout = QVBoxLayout(self.tab_recs)

        self.rec_text = QTextEdit()
        self.rec_text.setReadOnly(True)
        layout.addWidget(self.rec_text)

    def refresh(self):
        summary = backend.make_summary()

        for key, value in [
            ("Events", summary["events"]),
            ("High Risk", summary["high"]),
            ("Suspicious", summary["suspicious"]),
            ("Clean", summary["clean"]),
            ("Quarantine", summary["quarantine"]),
        ]:
            self.cards[key].setText(
                f"<b>{key}</b><br><span style='font-size:28px'>{value}</span>"
            )

        self.events = backend.all_events()
        self.populate_events()
        self.populate_quarantine()
        self.populate_services()
        self.populate_processes()
        self.populate_network()
        self.rec_text.setPlainText(
            "\n\n".join("- " + item for item in backend.recommendations())
        )

    def set_filter(self, filter_name):
        self.current_filter = filter_name
        self.populate_events()

    def obj(self, event):
        return str(
            event.get("file")
            or event.get("exe")
            or event.get("process")
            or event.get("remote_ip")
            or ""
        )

    def populate_events(self):
        query = self.search.text().lower()
        rows = []

        for event in self.events:
            severity = backend.classify(event)
            raw = json.dumps(event).lower()

            if self.current_filter != "ALL" and severity != self.current_filter:
                continue

            if query and query not in raw:
                continue

            rows.append(event)

        self.visible_events = rows
        self.event_table.setRowCount(len(rows))

        for row, event in enumerate(rows):
            values = [
                backend.classify(event),
                event.get("time", ""),
                event.get("_source", ""),
                event.get("event", event.get("status", "EVENT")),
                self.obj(event),
                str(event.get("recommendation", event.get("verdict", ""))),
            ]

            for col, value in enumerate(values):
                self.event_table.setItem(row, col, QTableWidgetItem(str(value)))

    def show_event(self, row, col):
        if row < len(self.visible_events):
            self.details.setPlainText(
                json.dumps(self.visible_events[row], indent=2, ensure_ascii=False)
            )

    def load_threats(self, severity):
        rows = backend.db_events(limit=1000, severity=severity)

        self.threat_rows = rows
        self.threat_table.setRowCount(len(rows))

        for row, event in enumerate(rows):
            values = [
                event.get("time", ""),
                event.get("severity", ""),
                event.get("source", ""),
                event.get("event", ""),
                event.get("object", ""),
            ]

            for col, value in enumerate(values):
                self.threat_table.setItem(row, col, QTableWidgetItem(str(value)))

    def show_threat(self, row, col):
        if row < len(self.threat_rows):
            self.threat_details.setPlainText(
                json.dumps(self.threat_rows[row], indent=2, ensure_ascii=False)
            )

    def populate_processes(self):
        query = self.process_search.text().lower()
        rows = backend.list_processes()

        if rows and "error" in rows[0]:
            self.process_details.setPlainText(rows[0]["error"])
            return

        filtered = []

        for process in rows:
            raw = json.dumps(process).lower()

            if query and query not in raw:
                continue

            filtered.append(process)

        self.process_rows = filtered
        self.process_table.setRowCount(len(filtered))

        for row, process in enumerate(filtered):
            values = [
                process.get("risk", ""),
                process.get("pid", ""),
                process.get("name", ""),
                process.get("user", ""),
                process.get("cpu", ""),
                process.get("ram", ""),
                process.get("exe", ""),
            ]

            for col, value in enumerate(values):
                self.process_table.setItem(row, col, QTableWidgetItem(str(value)))

    def show_process(self, row, col):
        if row < len(self.process_rows):
            self.process_details.setPlainText(
                json.dumps(self.process_rows[row], indent=2, ensure_ascii=False)
            )

    def populate_network(self):
        query = self.network_search.text().lower()
        rows = backend.list_network_connections()

        if rows and "error" in rows[0]:
            self.network_details.setPlainText(rows[0]["error"])
            return

        filtered = []

        for connection in rows:
            raw = json.dumps(connection).lower()

            if query and query not in raw:
                continue

            filtered.append(connection)

        self.network_rows = filtered
        self.network_table.setRowCount(len(filtered))

        for row, connection in enumerate(filtered):
            values = [
                connection.get("risk", ""),
                connection.get("pid", ""),
                connection.get("process", ""),
                connection.get("user", ""),
                connection.get("remote_ip", ""),
                connection.get("remote_port", ""),
                connection.get("status", ""),
            ]

            for col, value in enumerate(values):
                self.network_table.setItem(row, col, QTableWidgetItem(str(value)))

    def show_network(self, row, col):
        if row < len(self.network_rows):
            self.network_details.setPlainText(
                json.dumps(self.network_rows[row], indent=2, ensure_ascii=False)
            )

    def shared_event_actions(self, menu, raw, obj, details_widget):
        real_path = backend.resolve_event_path(raw)

        actions = [
            ("Show Details", lambda: details_widget.setPlainText(json.dumps(raw, indent=2, ensure_ascii=False))),
            ("Allow File", lambda: QMessageBox.information(self, "Allow", backend.allow_path(real_path))),
            ("Block File", lambda: QMessageBox.information(self, "Block", backend.block_path(real_path))),
            ("Analyze File", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(real_path))),
            ("Investigate", lambda: QMessageBox.information(self, "Investigate", backend.investigate_path(real_path))),
            ("Hash", lambda: QMessageBox.information(self, "Hash", backend.hash_file(real_path))),
            ("Quarantine", lambda: QMessageBox.information(self, "Quarantine", backend.quarantine_path(real_path))),
            ("Open Folder", lambda: subprocess.Popen(["xdg-open", real_path.rsplit("/", 1)[0] if real_path and real_path.startswith("/") else "/var/log/otx-sec"])),
            ("Copy Object", lambda: QApplication.clipboard().setText(str(obj))),
        ]

        for label, function in actions:
            action = QAction(label, self)
            action.triggered.connect(function)
            menu.addAction(action)

    def event_menu(self, pos):
        row = self.event_table.currentRow()

        if row < 0 or row >= len(self.visible_events):
            return

        event = self.visible_events[row]
        menu = QMenu()
        self.shared_event_actions(menu, event, self.obj(event), self.details)
        menu.exec(self.event_table.viewport().mapToGlobal(pos))
        self.refresh()

    def threat_menu(self, pos):
        row = self.threat_table.currentRow()

        if row < 0 or row >= len(self.threat_rows):
            return

        event = self.threat_rows[row]
        raw = event.get("raw", {})

        menu = QMenu()
        self.shared_event_actions(menu, raw, event.get("object", ""), self.threat_details)
        menu.exec(self.threat_table.viewport().mapToGlobal(pos))
        self.refresh()

    def process_menu(self, pos):
        row = self.process_table.currentRow()

        if row < 0 or row >= len(self.process_rows):
            return

        process = self.process_rows[row]
        exe = process.get("exe", "")
        pid = process.get("pid", "")

        menu = QMenu()

        actions = [
            ("Show Details", lambda: self.process_details.setPlainText(json.dumps(process, indent=2, ensure_ascii=False))),
            ("Kill Process", lambda: QMessageBox.information(self, "Kill", backend.kill_process(pid))),
            ("Hash Binary", lambda: QMessageBox.information(self, "Hash", backend.hash_file(exe))),
            ("Analyze Binary", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(exe))),
            ("Quarantine Binary", lambda: QMessageBox.information(self, "Quarantine", backend.quarantine_path(exe))),
            ("Show Connections", lambda: QMessageBox.information(self, "Connections", backend.process_connections(pid))),
            ("Open Binary Folder", lambda: subprocess.Popen(["xdg-open", exe.rsplit("/", 1)[0] if exe and exe.startswith("/") else "/"])),
            ("Copy Path", lambda: QApplication.clipboard().setText(exe)),
        ]

        for label, function in actions:
            action = QAction(label, self)
            action.triggered.connect(function)
            menu.addAction(action)

        menu.exec(self.process_table.viewport().mapToGlobal(pos))
        self.refresh()

    def network_menu(self, pos):
        row = self.network_table.currentRow()

        if row < 0 or row >= len(self.network_rows):
            return

        connection = self.network_rows[row]
        ip = str(connection.get("remote_ip", ""))
        pid = str(connection.get("pid", ""))
        exe = str(connection.get("exe", ""))

        menu = QMenu()

        actions = [
            ("Show Details", lambda: self.network_details.setPlainText(json.dumps(connection, indent=2, ensure_ascii=False))),
            ("Copy IP", lambda: QApplication.clipboard().setText(ip)),
            ("Copy Process Path", lambda: QApplication.clipboard().setText(exe)),
            ("Show Process Connections", lambda: QMessageBox.information(self, "Connections", backend.process_connections(pid))),
            ("Hash Process Binary", lambda: QMessageBox.information(self, "Hash", backend.hash_file(exe))),
            ("Analyze Process Binary", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(exe))),
            ("Quarantine Process Binary", lambda: QMessageBox.information(self, "Quarantine", backend.quarantine_path(exe))),
            ("Open Process Folder", lambda: subprocess.Popen(["xdg-open", exe.rsplit("/", 1)[0] if exe and exe.startswith("/") else "/"])),
        ]

        for label, function in actions:
            action = QAction(label, self)
            action.triggered.connect(function)
            menu.addAction(action)

        menu.exec(self.network_table.viewport().mapToGlobal(pos))
        self.refresh()

    def populate_quarantine(self):
        files = backend.quarantine_files()
        self.qtable.setRowCount(len(files))

        for row, file in enumerate(files):
            self.qtable.setItem(row, 0, QTableWidgetItem(file["name"]))
            self.qtable.setItem(row, 1, QTableWidgetItem(str(file["size"])))
            self.qtable.setItem(row, 2, QTableWidgetItem(file["path"]))

    def quarantine_menu(self, pos):
        row = self.qtable.currentRow()

        if row < 0:
            return

        path = self.qtable.item(row, 2).text()
        menu = QMenu()

        actions = [
            ("Hash", lambda: QMessageBox.information(self, "Hash", backend.hash_file(path))),
            ("Analyze", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(path))),
            ("Restore", lambda: QMessageBox.information(self, "Restore", backend.restore_quarantine_file(path))),
            ("Delete", lambda: QMessageBox.information(self, "Delete", backend.delete_quarantine_file(path))),
            ("Copy Path", lambda: QApplication.clipboard().setText(path)),
        ]

        for label, function in actions:
            action = QAction(label, self)
            action.triggered.connect(function)
            menu.addAction(action)

        menu.exec(self.qtable.viewport().mapToGlobal(pos))
        self.refresh()

    def populate_services(self):
        services = backend.service_status()
        self.stable.setRowCount(len(services))

        for row, (service, active) in enumerate(services.items()):
            self.stable.setItem(row, 0, QTableWidgetItem(service))
            self.stable.setItem(row, 1, QTableWidgetItem("ACTIVE" if active else "INACTIVE"))
            self.stable.setItem(row, 2, QTableWidgetItem("Right-click"))

    def service_menu(self, pos):
        row = self.stable.currentRow()

        if row < 0:
            return

        service = self.stable.item(row, 0).text()
        menu = QMenu()

        for label, action_name in {
            "Start": "start",
            "Stop": "stop",
            "Restart": "restart",
            "Enable Boot": "enable",
            "Disable Boot": "disable",
            "Status": "status",
            "Logs": "logs",
        }.items():
            action = QAction(label, self)
            action.triggered.connect(
                lambda checked=False, s=service, a=action_name:
                QMessageBox.information(self, f"{s} {a}", backend.service_action(s, a))
            )
            menu.addAction(action)

        menu.exec(self.stable.viewport().mapToGlobal(pos))
        self.refresh()

    def scan_file(self):
        self.scan_output.setPlainText(
            backend.manual_scan_file(self.scan_path.text().strip())
        )

    def scan_folder(self):
        self.scan_output.setPlainText(
            backend.manual_scan_folder(self.scan_path.text().strip())
        )

    def hash_manual(self):
        self.scan_output.setPlainText(
            backend.hash_file(self.scan_path.text().strip())
        )

    def run_action(self, action):
        self.action_output.setPlainText(backend.action_center(action))
        self.refresh()

    def open_quarantine(self):
        subprocess.Popen(["xdg-open", str(backend.QUARANTINE_DIR)])

    def delete_quarantine(self):
        row = self.qtable.currentRow()

        if row >= 0:
            QMessageBox.information(
                self,
                "Delete",
                backend.delete_quarantine_file(self.qtable.item(row, 2).text()),
            )
            self.refresh()

    def restore_quarantine(self):
        row = self.qtable.currentRow()

        if row >= 0:
            QMessageBox.information(
                self,
                "Restore",
                backend.restore_quarantine_file(self.qtable.item(row, 2).text()),
            )
            self.refresh()

    def run_integrity(self):
        QMessageBox.information(self, "Integrity", backend.run_integrity_check())
        self.refresh()

    def restart_services(self):
        QMessageBox.information(self, "Services", backend.restart_services())
        self.refresh()

    def save_settings(self):
        backend.save_settings({
            "otx_api_key": self.otx.text().strip(),
            "virustotal_api_key": self.vt.text().strip(),
            "auto_quarantine": self.autoq.text().strip().lower()
            in ["1", "true", "yes", "on"],
        })

        QMessageBox.information(self, "Settings", "Saved.")


def main():
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
