# 🔎 Threat Hunting Queries | Splunk & Sigma

## 🎯 Objective
This repository contains practical threat hunting queries and Sigma detection rules focused on identifying brute-force authentication activity and suspicious PowerShell execution commonly seen in SOC environments.

---

## 🛡️ Use Cases
- Failed login burst detection
- Brute-force activity hunting
- Encoded PowerShell execution
- Suspicious command-line activity
- Windows log anomaly review

---

## 📊 Splunk Detections

### Failed Login Burst
```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
```

### Encoded PowerShell Hunt
```spl
index=wineventlog EventCode=4104
| search "-enc" OR "FromBase64String"
```

---

## 📐 Sigma Rules

### Failed Login Brute Force
```yaml
logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625
  condition: selection
```

### Suspicious PowerShell
```yaml
logsource:
  product: windows
  service: powershell

detection:
  keywords:
    - "-enc"
    - "FromBase64String"
  condition: keywords
```

---

## 🧠 MITRE ATT&CK Mapping
- T1110 – Brute Force
- T1059.001 – PowerShell
- T1027 – Obfuscated/Encoded Files

---

## 🛠️ Tools Used
- Splunk
- Sigma
- Windows Event Logs
- Kali Linux
- MITRE ATT&CK
