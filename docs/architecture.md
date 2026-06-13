# OTX-Sec Architecture

## Components

### GUI
- app/frontend.py
- app/backend.py

Provides:
- Dashboard
- Settings
- Incident View
- Quarantine Management

### Agent
- tools/agent.py

Responsible for:
- File scanning
- Hashing
- OTX lookups
- Quarantine actions

### Monitors

#### monitors/process_monitor.py
Detects suspicious processes.

#### monitors/network_monitor.py
Detects suspicious network connections.

#### persistence_monitor.py
Detects persistence mechanisms.

#### monitors/audit_exporter.py
Imports auditd events.

### Incident System

engines/incident_engine.py

Creates incidents from collected events.

### Database

db/events.db
db/incidents.db

### Configuration

config/settings.json

Contains:
- API keys
- Scan paths
- Exclusions
- Scan intervals
