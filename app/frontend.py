#!/opt/otx-sec/venv/bin/python

import sys, json, subprocess
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
            lbl.setStyleSheet("background:#1e1e2e;border-radius:14px;padding:16px;color:white;")
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
        QWidget { background:#11111b; color:#eeeeee; font-family:Fira Sans; }
        QPushButton { background:#313244; color:white; border:1px solid #45475a; padding:8px; border-radius:8px; }
        QPushButton:hover { background:#45475a; }
        QTabBar::tab { background:#1e1e2e; color:white; padding:10px; border:1px solid #313244; }
        QTabBar::tab:selected { background:#313244; color:#8cff8c; }
        QTableWidget, QTextEdit, QLineEdit { background:#181825; color:white; border:1px solid #313244; }
        QHeaderView::section { background:#313244; color:white; padding:6px; }
        QMenu { background:#1e1e2e; color:white; border:1px solid #45475a; }
        QMenu::item:selected { background:#45475a; }
        """)

    def setup_events(self):
        l = QVBoxLayout(self.tab_events)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search events, files, hashes, processes, IPs...")
        self.search.textChanged.connect(self.populate_events)
        l.addWidget(self.search)

        self.event_table = QTableWidget()
        self.event_table.setColumnCount(6)
        self.event_table.setHorizontalHeaderLabels(["Severity","Time","Source","Event","Object","Details"])
        self.event_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.event_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.event_table.customContextMenuRequested.connect(self.event_menu)
        self.event_table.cellClicked.connect(self.show_event)
        l.addWidget(self.event_table, 4)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        l.addWidget(self.details, 2)

    def setup_threat_center(self):
        l = QVBoxLayout(self.tab_threats)

        row = QHBoxLayout()
        for label, sev in [("High Risk","HIGH"),("Suspicious","SUSPICIOUS"),("Clean","CLEAN"),("Info","INFO")]:
            b = QPushButton(label)
            b.clicked.connect(lambda checked=False, s=sev: self.load_threats(s))
            row.addWidget(b)
        l.addLayout(row)

        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(5)
        self.threat_table.setHorizontalHeaderLabels(["Time","Severity","Source","Event","Object"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.threat_table.customContextMenuRequested.connect(self.threat_menu)
        self.threat_table.cellClicked.connect(self.show_threat)
        l.addWidget(self.threat_table, 4)

        self.threat_details = QTextEdit()
        self.threat_details.setReadOnly(True)
        l.addWidget(self.threat_details, 2)

    def setup_processes(self):
        l = QVBoxLayout(self.tab_processes)

        top = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Processes")
        refresh_btn.clicked.connect(self.populate_processes)

        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("Search process, path, user...")
        self.process_search.textChanged.connect(self.populate_processes)

        top.addWidget(self.process_search)
        top.addWidget(refresh_btn)
        l.addLayout(top)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(7)
        self.process_table.setHorizontalHeaderLabels(["Risk", "PID", "Name", "User", "CPU", "RAM %", "Executable"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.process_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.process_menu)
        self.process_table.cellClicked.connect(self.show_process)
        l.addWidget(self.process_table, 4)

        self.process_details = QTextEdit()
        self.process_details.setReadOnly(True)
        l.addWidget(self.process_details, 2)

    def setup_network(self):
    l = QVBoxLayout(self.tab_network)

    top = QHBoxLayout()

    refresh_btn = QPushButton("Refresh Network")
    refresh_btn.clicked.connect(self.populate_network)

    self.network_search = QLineEdit()
    self.network_search.setPlaceholderText("Search process, IP, port, user...")

    self.network_search.textChanged.connect(self.populate_network)

    top.addWidget(self.network_search)
    top.addWidget(refresh_btn)

    l.addLayout(top)

    self.network_table = QTableWidget()
    self.network_table.setColumnCount(7)
    self.network_table.setHorizontalHeaderLabels(
        ["Risk", "PID", "Process", "User", "Remote IP", "Port", "Status"]
    )
    self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    self.network_table.setContextMenuPolicy(Qt.CustomContextMenu)
    self.network_table.customContextMenuRequested.connect(self.network_menu)
    self.network_table.cellClicked.connect(self.show_network)

    l.addWidget(self.network_table, 4)

    self.network_details = QTextEdit()
    self.network_details.setReadOnly(True)

    l.addWidget(self.network_details, 2)

    def setup_manual(self):
        l = QVBoxLayout(self.tab_manual)

        row = QHBoxLayout()
        self.scan_path = QLineEdit()
        self.scan_path.setPlaceholderText("/path/to/file-or-folder")

        for text, fn in [
            ("Scan File", self.scan_file),
            ("Scan Folder", self.scan_folder),
            ("Hash File", self.hash_manual),
        ]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)

        row.insertWidget(0, self.scan_path)
        l.addLayout(row)

        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        l.addWidget(self.scan_output)

    def setup_action(self):
        l = QVBoxLayout(self.tab_action)

        grid = QGridLayout()
        actions = [
            ("Restart Inactive Services","restart_inactive"),
            ("Run Full Integrity Check","integrity"),
            ("Rebuild Baseline","baseline"),
            ("Analyze High Risk","analyze_high"),
            ("Export Full Report","export"),
            ("Clear Logs","clear_logs"),
        ]

        for i, (label, action) in enumerate(actions):
            b = QPushButton(label)
            b.setMinimumHeight(55)
            b.clicked.connect(lambda checked=False, a=action: self.run_action(a))
            grid.addWidget(b, i//2, i%2)

        l.addLayout(grid)

        self.action_output = QTextEdit()
        self.action_output.setReadOnly(True)
        l.addWidget(self.action_output)

    def setup_quarantine(self):
        l = QVBoxLayout(self.tab_quarantine)

        row = QHBoxLayout()
        for text, fn in [
            ("Open Folder", self.open_quarantine),
            ("Restore Selected", self.restore_quarantine),
            ("Delete Selected", self.delete_quarantine),
        ]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)

        l.addLayout(row)

        self.qtable = QTableWidget()
        self.qtable.setColumnCount(3)
        self.qtable.setHorizontalHeaderLabels(["Name","Size","Path"])
        self.qtable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.qtable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.qtable.customContextMenuRequested.connect(self.quarantine_menu)
        l.addWidget(self.qtable)

    def setup_services(self):
        l = QVBoxLayout(self.tab_services)

        self.stable = QTableWidget()
        self.stable.setColumnCount(3)
        self.stable.setHorizontalHeaderLabels(["Service","Status","Actions"])
        self.stable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.stable.customContextMenuRequested.connect(self.service_menu)
        l.addWidget(self.stable)

    def setup_settings(self):
        l = QVBoxLayout(self.tab_settings)

        s = backend.load_settings()

        self.otx = QLineEdit(s.get("otx_api_key",""))
        self.vt = QLineEdit(s.get("virustotal_api_key",""))
        self.autoq = QLineEdit(str(s.get("auto_quarantine", True)))

        for label, widget in [
            ("OTX API Key", self.otx),
            ("VirusTotal API Key", self.vt),
            ("Auto Quarantine true/false", self.autoq),
        ]:
            l.addWidget(QLabel(label))
            l.addWidget(widget)

        b = QPushButton("Save Settings")
        b.clicked.connect(self.save_settings)
        l.addWidget(b)

    def setup_recs(self):
        l = QVBoxLayout(self.tab_recs)

        self.rec_text = QTextEdit()
        self.rec_text.setReadOnly(True)
        l.addWidget(self.rec_text)

    def refresh(self):
        s = backend.make_summary()

        for key, value in [
            ("Events", s["events"]),
            ("High Risk", s["high"]),
            ("Suspicious", s["suspicious"]),
            ("Clean", s["clean"]),
            ("Quarantine", s["quarantine"]),
        ]:
            self.cards[key].setText(f"<b>{key}</b><br><span style='font-size:28px'>{value}</span>")

        self.events = backend.all_events()
        self.populate_events()
        self.populate_quarantine()
        self.populate_services()
        self.populate_processes()
        self.populate_network()
        self.rec_text.setPlainText("\n\n".join("- "+r for r in backend.recommendations()))

    def set_filter(self, f):
        self.current_filter = f
        self.populate_events()

    def obj(self, e):
        return str(e.get("file") or e.get("exe") or e.get("process") or e.get("remote_ip") or "")

    def populate_events(self):
        q = self.search.text().lower()
        rows = []

        for e in self.events:
            sev = backend.classify(e)
            raw = json.dumps(e).lower()

            if self.current_filter != "ALL" and sev != self.current_filter:
                continue

            if q and q not in raw:
                continue

            rows.append(e)

        self.visible_events = rows
        self.event_table.setRowCount(len(rows))

        for r, e in enumerate(rows):
            vals = [
                backend.classify(e),
                e.get("time",""),
                e.get("_source",""),
                e.get("event", e.get("status","EVENT")),
                self.obj(e),
                str(e.get("recommendation", e.get("verdict",""))),
            ]

            for c, v in enumerate(vals):
                self.event_table.setItem(r, c, QTableWidgetItem(str(v)))

    def show_event(self, row, col):
        if row < len(self.visible_events):
            self.details.setPlainText(json.dumps(self.visible_events[row], indent=2, ensure_ascii=False))

    def load_threats(self, severity):
        rows = backend.db_events(limit=1000, severity=severity)
        self.threat_rows = rows
        self.threat_table.setRowCount(len(rows))

        for r, e in enumerate(rows):
            vals = [
                e.get("time",""),
                e.get("severity",""),
                e.get("source",""),
                e.get("event",""),
                e.get("object",""),
            ]

            for c, v in enumerate(vals):
                self.threat_table.setItem(r, c, QTableWidgetItem(str(v)))

    def show_threat(self, row, col):
        if row < len(self.threat_rows):
            self.threat_details.setPlainText(json.dumps(self.threat_rows[row], indent=2, ensure_ascii=False))

    def populate_processes(self):
        query = self.process_search.text().lower()
        rows = backend.list_processes()

        if rows and "error" in rows[0]:
            self.process_details.setPlainText(rows[0]["error"])
            return

        filtered = []
        for p in rows:
            raw = json.dumps(p).lower()
            if query and query not in raw:
                continue
            filtered.append(p)

        self.process_rows = filtered
        self.process_table.setRowCount(len(filtered))

        for r, p in enumerate(filtered):
            vals = [
                p.get("risk", ""),
                p.get("pid", ""),
                p.get("name", ""),
                p.get("user", ""),
                p.get("cpu", ""),
                p.get("ram", ""),
                p.get("exe", ""),
            ]

            for c, v in enumerate(vals):
                self.process_table.setItem(r, c, QTableWidgetItem(str(v)))

    def populate_network(self):
    query = self.network_search.text().lower()
    rows = backend.list_network_connections()

    if rows and "error" in rows[0]:
        self.network_details.setPlainText(rows[0]["error"])
        return

    filtered = []

    for n in rows:
        raw = json.dumps(n).lower()

        if query and query not in raw:
            continue

        filtered.append(n)

    self.network_rows = filtered
    self.network_table.setRowCount(len(filtered))

    for r, n in enumerate(filtered):
        vals = [
            n.get("risk", ""),
            n.get("pid", ""),
            n.get("process", ""),
            n.get("user", ""),
            n.get("remote_ip", ""),
            n.get("remote_port", ""),
            n.get("status", ""),
        ]

        for c, v in enumerate(vals):
            self.network_table.setItem(r, c, QTableWidgetItem(str(v)))


def show_network(self, row, col):
    if row < len(self.network_rows):
        self.network_details.setPlainText(
            json.dumps(self.network_rows[row], indent=2, ensure_ascii=False)
        )


def network_menu(self, pos):
    row = self.network_table.currentRow()

    if row < 0 or row >= len(self.network_rows):
        return

    n = self.network_rows[row]
    ip = str(n.get("remote_ip", ""))
    pid = str(n.get("pid", ""))
    exe = str(n.get("exe", ""))

    menu = QMenu()

    actions = [
        ("Show Details", lambda: self.network_details.setPlainText(json.dumps(n, indent=2, ensure_ascii=False))),
        ("Copy IP", lambda: QApplication.clipboard().setText(ip)),
        ("Copy Process Path", lambda: QApplication.clipboard().setText(exe)),
        ("Show Process Connections", lambda: QMessageBox.information(self, "Connections", backend.process_connections(pid))),
        ("Hash Process Binary", lambda: QMessageBox.information(self, "Hash", backend.hash_file(exe))),
        ("Analyze Process Binary", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(exe))),
        ("Quarantine Process Binary", lambda: QMessageBox.information(self, "Quarantine", backend.quarantine_path(exe))),
        ("Open Process Folder", lambda: subprocess.Popen(["xdg-open", exe.rsplit("/", 1)[0] if exe and exe.startswith("/") else "/"])),
    ]

    for label, fn in actions:
        a = QAction(label, self)
        a.triggered.connect(fn)
        menu.addAction(a)

    menu.exec(self.network_table.viewport().mapToGlobal(pos))
      self.refresh()


    def show_process(self, row, col):
        if row < len(self.process_rows):
            self.process_details.setPlainText(json.dumps(self.process_rows[row], indent=2, ensure_ascii=False))

    def shared_event_actions(self, menu, raw, obj, details_widget):
        real = backend.resolve_event_path(raw)

        actions = [
            ("Show Details", lambda: details_widget.setPlainText(json.dumps(raw, indent=2, ensure_ascii=False))),
            ("Allow File", lambda: QMessageBox.information(self,"Allow", backend.allow_path(real))),
            ("Block File", lambda: QMessageBox.information(self,"Block", backend.block_path(real))),
            ("Analyze File", lambda: QMessageBox.information(self,"Analyze", backend.analyze_path(real))),
            ("Investigate", lambda: QMessageBox.information(self,"Investigate", backend.investigate_path(real))),
            ("Hash", lambda: QMessageBox.information(self,"Hash", backend.hash_file(real))),
            ("Quarantine", lambda: QMessageBox.information(self,"Quarantine", backend.quarantine_path(real))),
            ("Open Folder", lambda: subprocess.Popen(["xdg-open", real.rsplit("/",1)[0] if real and real.startswith("/") else "/var/log/otx-sec"])),
            ("Copy Object", lambda: QApplication.clipboard().setText(str(obj))),
        ]

        for label, fn in actions:
            a = QAction(label, self)
            a.triggered.connect(fn)
            menu.addAction(a)

    def event_menu(self, pos):
        row = self.event_table.currentRow()

        if row < 0 or row >= len(self.visible_events):
            return

        e = self.visible_events[row]
        menu = QMenu()
        self.shared_event_actions(menu, e, self.obj(e), self.details)
        menu.exec(self.event_table.viewport().mapToGlobal(pos))
        self.refresh()

    def threat_menu(self, pos):
        row = self.threat_table.currentRow()

        if row < 0 or row >= len(self.threat_rows):
            return

        e = self.threat_rows[row]
        raw = e.get("raw", {})
        menu = QMenu()
        self.shared_event_actions(menu, raw, e.get("object",""), self.threat_details)
        menu.exec(self.threat_table.viewport().mapToGlobal(pos))
        self.refresh()

    def process_menu(self, pos):
        row = self.process_table.currentRow()

        if row < 0 or row >= len(self.process_rows):
            return

        p = self.process_rows[row]
        exe = p.get("exe", "")
        pid = p.get("pid", "")

        menu = QMenu()

        actions = [
            ("Show Details", lambda: self.process_details.setPlainText(json.dumps(p, indent=2, ensure_ascii=False))),
            ("Kill Process", lambda: QMessageBox.information(self, "Kill", backend.kill_process(pid))),
            ("Hash Binary", lambda: QMessageBox.information(self, "Hash", backend.hash_file(exe))),
            ("Analyze Binary", lambda: QMessageBox.information(self, "Analyze", backend.analyze_path(exe))),
            ("Quarantine Binary", lambda: QMessageBox.information(self, "Quarantine", backend.quarantine_path(exe))),
            ("Show Connections", lambda: QMessageBox.information(self, "Connections", backend.process_connections(pid))),
            ("Open Binary Folder", lambda: subprocess.Popen(["xdg-open", exe.rsplit("/",1)[0] if exe and exe.startswith("/") else "/"])),
            ("Copy Path", lambda: QApplication.clipboard().setText(exe)),
        ]

        for label, fn in actions:
            a = QAction(label, self)
            a.triggered.connect(fn)
            menu.addAction(a)

        menu.exec(self.process_table.viewport().mapToGlobal(pos))
        self.refresh()

    def populate_quarantine(self):
        fs = backend.quarantine_files()
        self.qtable.setRowCount(len(fs))

        for r, f in enumerate(fs):
            self.qtable.setItem(r, 0, QTableWidgetItem(f["name"]))
            self.qtable.setItem(r, 1, QTableWidgetItem(str(f["size"])))
            self.qtable.setItem(r, 2, QTableWidgetItem(f["path"]))

    def quarantine_menu(self, pos):
        row = self.qtable.currentRow()

        if row < 0:
            return

        path = self.qtable.item(row,2).text()
        menu = QMenu()

        actions = [
            ("Hash", lambda: QMessageBox.information(self,"Hash", backend.hash_file(path))),
            ("Analyze", lambda: QMessageBox.information(self,"Analyze", backend.analyze_path(path))),
            ("Restore", lambda: QMessageBox.information(self,"Restore", backend.restore_quarantine_file(path))),
            ("Delete", lambda: QMessageBox.information(self,"Delete", backend.delete_quarantine_file(path))),
            ("Copy Path", lambda: QApplication.clipboard().setText(path)),
        ]

        for label, fn in actions:
            a = QAction(label, self)
            a.triggered.connect(fn)
            menu.addAction(a)

        menu.exec(self.qtable.viewport().mapToGlobal(pos))
        self.refresh()

    def populate_services(self):
        s = backend.service_status()
        self.stable.setRowCount(len(s))

        for r, (svc, active) in enumerate(s.items()):
            self.stable.setItem(r, 0, QTableWidgetItem(svc))
            self.stable.setItem(r, 1, QTableWidgetItem("ACTIVE" if active else "INACTIVE"))
            self.stable.setItem(r, 2, QTableWidgetItem("Right-click"))

    def service_menu(self, pos):
        row = self.stable.currentRow()

        if row < 0:
            return

        svc = self.stable.item(row,0).text()
        menu = QMenu()

        for label, action in {
            "Start":"start",
            "Stop":"stop",
            "Restart":"restart",
            "Enable Boot":"enable",
            "Disable Boot":"disable",
            "Status":"status",
            "Logs":"logs",
        }.items():
            a = QAction(label, self)
            a.triggered.connect(
                lambda checked=False, s=svc, ac=action:
                QMessageBox.information(self, f"{s} {ac}", backend.service_action(s, ac))
            )
            menu.addAction(a)

        menu.exec(self.stable.viewport().mapToGlobal(pos))
        self.refresh()

    def scan_file(self):
        self.scan_output.setPlainText(backend.manual_scan_file(self.scan_path.text().strip()))

    def scan_folder(self):
        self.scan_output.setPlainText(backend.manual_scan_folder(self.scan_path.text().strip()))

    def hash_manual(self):
        self.scan_output.setPlainText(backend.hash_file(self.scan_path.text().strip()))

    def run_action(self,a):
        self.action_output.setPlainText(backend.action_center(a))
        self.refresh()

    def open_quarantine(self):
        subprocess.Popen(["xdg-open", str(backend.QUARANTINE_DIR)])

    def delete_quarantine(self):
        r = self.qtable.currentRow()
        if r >= 0:
            QMessageBox.information(self, "Delete", backend.delete_quarantine_file(self.qtable.item(r,2).text()))
            self.refresh()

    def restore_quarantine(self):
        r = self.qtable.currentRow()
        if r >= 0:
            QMessageBox.information(self, "Restore", backend.restore_quarantine_file(self.qtable.item(r,2).text()))
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
            "auto_quarantine": self.autoq.text().strip().lower() in ["1","true","yes","on"],
        })
        QMessageBox.information(self, "Settings", "Saved.")

def main():
    app = QApplication(sys.argv)
    w = App()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
