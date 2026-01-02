# IoT Security Monitoring & Threat Intelligence Dashboard

A professional-grade, lightweight security monitoring tool designed to detect and visualize malicious activity in IoT environments (DNS Tunneling, SSH Abuse, beaconing) from FortiGate-style logs.

## 🚀 Overview

This system provides an end-to-end pipeline for:
1.  **Synthetic Data Generation**: Creating realistic network traffic and attack patterns.
2.  **Log Ingestion & Detection**: Normalizing raw logs and running them through a rule-based detection engine.
3.  **Visual Analytics**: A high-density Streamlit dashboard for real-time monitoring and threat inventory.

---

## 🛠️ Prerequisites

*   **Python 3.10+**
*   **MySQL Server** (Local or Remote)
*   **Virtual Environment** (Recommended)

---

## ⚙️ Setup Instructions

### 1. Environment Preparation
Clone the repository and install the required dependencies:
```powershell
pip install -r requirements.txt
```

### 2. Database Initialization
Create the database and required tables using the provided schema. In your MySQL terminal or via PowerShell:
```powershell
# In MySQL:
CREATE DATABASE iot_security;
USE iot_security;
SOURCE schema.sql;
```

### 3. Configuration
Update `config.py` with your local MySQL credentials:
```python
class Config:
    DB_HOST = 'localhost'
    DB_USER = 'root'
    DB_PASSWORD = 'your_password_here'
    DB_NAME = 'iot_security'
```

---

## 🖱️ Running the Project

Follow these steps in order to see the system in action:

### Step 1: Generate Synthetic Traffic
Run the generator to create simulated baseline traffic and specific attack patterns (SSH, DNS, Beaconing).
```powershell
python traffic_generator.py
```
> [!TIP]
> This generates `simulated_fortigate_logs.json` which is used in the next step.

### Step 2: Ingest Logs & Detect Threats
Process the generated logs to normalize them into the database and trigger the detection engine.
```powershell
python ingest_logs.py
```

### Step 3: Launch the Dashboard
Start the Streamlit analytics interface to visualize the results.
```powershell
streamlit run dashboard.py
```

---

## 📂 Project Structure

*   `traffic_generator.py`: Engine for generating synthetic FortiGate logs.
*   `ingest_logs.py`: Script to process logs and store them in MySQL.
*   `dashboard.py`: Streamlit application for visualization.
*   `detection/`: Logic modules for identifying specific threat patterns.
*   `attack_profiles.py`: Definitions for various attack behaviors.
*   `schema.sql`: Database structure definitions.

---

## 🛡️ Detection Capabilities

*   **IoT SSH Brute Force**: Detects high-frequency failed login attempts.
*   **DNS Tunneling**: Identifies anomalous data exfiltration via DNS queries.
*   **Malicious Beaconing**: Flags rhythmic communication patterns to C2 servers.
*   **Traffic Anomalies**: Monitors for byte-count spikes and unusual protocols.

