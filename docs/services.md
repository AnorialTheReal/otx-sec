# OTX-Sec Services

## User GUI
- app/frontend.py
- Runs as normal user.
- Must not require root.

## User notification
- incident_alerts.py
- Runs as normal user.
- Uses notify-send if available.

## Root/system services
These may need elevated privileges depending on distro and config:

- agent.py
  - scans configured paths
  - may need root for /etc, /boot, /root
  - writes reports to data/logs by default

- process_monitor.py
  - process inspection
  - may work as user, root gives fuller visibility

- network_monitor.py
  - connection inspection
  - may work as user, root gives fuller visibility

- persistence_monitor.py
  - checks autostart/systemd/cron paths

- audit_exporter.py
  - requires auditd/ausearch access

- db_writer.py
  - imports JSONL logs into SQLite

- incident_engine.py
  - builds incidents from events database

## Security rules
- No hardcoded usernames.
- No hardcoded /opt paths in source code.
- No shell=True.
- GUI must not run as root.
- Root actions should be isolated into services or helper scripts.
