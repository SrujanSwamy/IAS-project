# IAS Project 2: SDN-Based Intrusion Prevention System (IPS)

An intelligent anomaly detection and intrusion prevention system for Software Defined Networks (SDN) using OpenFlow and Ryu controller.

## Table of Contents
- [Project Overview](#project-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Running the Project](#running-the-project)
- [Configuration](#configuration)
- [Evaluation and Monitoring](#evaluation-and-monitoring)
- [Troubleshooting](#troubleshooting)

## Project Overview

This project implements an SDN-based IPS that:
- Monitors network traffic in real-time
- Detects anomalies and potential intrusions using machine learning
- Applies automated mitigation strategies (blocking malicious flows, rate-limiting)
- Provides comprehensive network telemetry through sFlow
- Evaluates system performance with live metrics and graphs

## Prerequisites

### System Requirements
- Linux (Ubuntu 18.04 or later recommended)
- Python 3.7+
- OpenFlow-compatible SDN environment
- Mininet (optional, for network emulation)
- OpenVSwitch (OVS)

### Required Python Libraries
All dependencies are listed and pre-installed in the virtual environment (`sdn-env-39/`):
- Ryu (OpenFlow controller framework)
- NumPy, Matplotlib (data processing and visualization)
- Scapy (packet manipulation)
- netaddr (network address utilities)
- oslo-config (configuration management)
- Other SDN-related libraries

## Installation

### 1. Clone/Extract the Project
```bash
cd /home/srujan_tss/Desktop/IAS\ PROJECT2
```

### 2. Activate Virtual Environment
```bash
source sdn-env-39/bin/activate
```

Your prompt should now show `(sdn-env-39)` prefix.

### 3. Verify Installation
```bash
python --version
pip list | grep ryu
ryu-manager --version
```

## Project Structure

```
├── controller/                 # Main IPS controller implementation
│   ├── ips_controller.py      # Primary IPS control logic
│   ├── anomaly_controller.py  # Anomaly detection module
│   └── __pycache__/           # Python cache files
├── attacks/                    # Attack simulation scripts
│   └── syn_flood.sh           # SYN flood attack simulation
├── topology/                   # Network topology setup
│   └── network_topology.py    # Mininet topology definition
├── telemetry/                  # Network monitoring and telemetry
│   └── enable_sflow.sh        # sFlow configuration for metrics collection
├── evaluation/                 # Performance evaluation
│   ├── live_graph.py          # Real-time metrics visualization
│   └── metrics.csv            # Collected performance metrics
├── sdn-env-39/                # Virtual environment
└── .gitignore                 # Git ignore rules
```

## Running the Project

### Step 1: Activate the Virtual Environment
```bash
source sdn-env-39/bin/activate
```

### Step 2: Set Up Network Topology
Using Mininet to create an SDN environment:
```bash
cd topology/
sudo python3 network_topology.py
```

This creates a virtual network with switches and hosts connected via OpenFlow.

### Step 3: Start the IPS Controller (In a New Terminal)
```bash
# Terminal 1 (with venv activated)
source sdn-env-39/bin/activate
cd controller/
ryu-manager ips_controller.py --observe-links
```

The controller will:
- Connect to OpenFlow switches
- Initialize anomaly detection
- Begin monitoring network traffic

### Step 4: Enable Telemetry/sFlow (In Another Terminal)
```bash
# Terminal 2
cd telemetry/
sudo bash enable_sflow.sh
```

This enables sFlow monitoring for real-time metrics collection.

### Step 5: Monitor with Live Graphs (In Another Terminal)
```bash
# Terminal 3 (with venv activated)
source sdn-env-39/bin/activate
cd evaluation/
python3 live_graph.py
```

This displays real-time performance metrics and detection statistics.

### Step 6: Simulate Attacks (In Another Terminal)
```bash
# Terminal 4
cd attacks/
sudo bash syn_flood.sh
```

This generates attack traffic that the IPS should detect and mitigate.

## Configuration

### IPS Controller Configuration
Edit `controller/ips_controller.py` to modify:
- **Detection sensitivity**: Adjust thresholds for anomaly detection
- **Mitigation strategies**: Block, rate-limit, or quarantine flows
- **Monitoring intervals**: Change traffic analysis frequency

### Network Topology Configuration
Edit `topology/network_topology.py` to customize:
- Number and types of switches/hosts
- Network bandwidth and latency
- Host placement and connections

### Telemetry Configuration
Modify `telemetry/enable_sflow.sh` to:
- Change collector IP/port
- Adjust sampling rates
- Select monitored interfaces

## Evaluation and Monitoring

### Live Metrics
Run `evaluation/live_graph.py` to view:
- Real-time traffic volume
- Detected anomalies
- Blocked/mitigated flows
- System latency

### Performance Metrics
Collected metrics are stored in `evaluation/metrics.csv`:
- Detection accuracy
- False positive rate
- Response time
- Throughput impact

### Analyzing Results
```bash
cd evaluation/
python3 -c "import pandas as pd; df = pd.read_csv('metrics.csv'); print(df.describe())"
```

## Troubleshooting

### Common Issues

**1. Virtual Environment Activation Issues**
```bash
# Recreate virtual environment if needed
python3.9 -m venv sdn-env-39
source sdn-env-39/bin/activate
pip install -r requirements.txt  # if requirements.txt exists
```

**2. Controller Won't Connect to Switches**
- Verify OpenVSwitch is running: `sudo ovs-vsctl show`
- Check connectivity: `sudo ovs-ofctl version br0`
- Review controller logs for connection errors

**3. Permission Denied Errors**
- Use `sudo` for commands accessing network interfaces
- Consider network configuration: `sudo visudo` to allow specific commands without password

**4. Port Already in Use**
```bash
# Default Ryu controller port is 6633
lsof -i :6633
kill -9 <PID>
```

**5. Metrics Not Updating**
- Verify sFlow collector is running
- Check network interfaces: `ip link show`
- Ensure metrics.csv is writable: `chmod 666 evaluation/metrics.csv`

### Debug Mode
Enable verbose logging:
```bash
ryu-manager controller/ips_controller.py --verbose --log-config-file=<log_config>
```

## Additional Notes

- **Root Privileges**: Network operations require root access
- **Multiple Terminals**: The project uses 4-5 terminals simultaneously
- **Performance**: System performance depends on network size and traffic volume
- **Customization**: Modify Python files to adapt detection algorithms and mitigation strategies

## Support and Development

For issues or modifications:
1. Check logs in each terminal
2. Review inline comments in controller code
3. Test with smaller topologies first
4. Verify each component independently

---

**Last Updated**: April 2026
