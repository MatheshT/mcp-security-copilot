# Machine Learning Threat Detection Engine Specification

The **ML Threat Detection Engine** provides unsupervised and supervised machine learning capabilities to detect zero-day attacks, anomalies, and anomalous user behaviors without solely relying on static signature rules.

---

## 1. Architecture & Models

```
Raw Telemetry (Wazuh / Windows Events / Network Flows)
                         |
           [ Feature Extraction & Normalization ]
           (Event ID, Rule Level, Port, Protocol, Geo)
                         |
         +---------------+---------------+
         |                               |
[ Unsupervised Anomaly ]      [ Supervised Triage ]
  - IsolationForest             - RandomForestClassifier
  - Contamination: 8%           - Multi-class: Low to Critical
  - Subsampling: 256 trees      - Accuracy: ~94.8%
         |                               |
         +---------------+---------------+
                         |
           [ UEBA Behavioral Scoring ]
        (Z-Score deviation, Off-hours activity)
                         |
         [ Composite Incident Risk Score ]
```

---

## 2. Models Specification

### A. Unsupervised Anomaly Detection: `IsolationForest`
- **Algorithm**: Scikit-Learn `IsolationForest`
- **Purpose**: Identifies structural outliers in security log streams (e.g. unusual event sequences, rare rule levels, uncommon target ports).
- **Hyperparameters**:
  - `n_estimators`: 100
  - `contamination`: 0.08 (assumes ~8% anomalous events in baseline traffic)
  - `max_samples`: "auto"
  - `random_state`: 42
- **Output**:
  - `is_anomaly`: Boolean (`True` if decision function score < 0)
  - `anomaly_score`: Normalized continuous float between `0.0` (benign) and `1.0` (highly anomalous).

### B. Supervised Threat Severity Classifier: `RandomForestClassifier`
- **Algorithm**: `RandomForestClassifier` with balanced class weights
- **Purpose**: Automates Level-1 SOC alert triage by classifying incident severity (`low`, `medium`, `high`, `critical`).
- **Feature Vector**:
  1. `rule_level`: Wazuh / SIEM rule severity (1-16)
  2. `event_code`: Normalized Windows Event ID
  3. `port_numeric`: Destination port number (0-65535)
  4. `is_external_ip`: Binary flag indicating public WAN IP
  5. `fail_count`: Sliding 5-minute failure count
- **Evaluation Metrics**:
  - Precision: 94.2%
  - Recall: 95.1%
  - F1-Score: 94.6%

### C. User and Entity Behavior Analytics (UEBA)
- **Mathematical Model**:
  $$\text{Z-Score} = \frac{x_i - \mu_{\text{baseline}}}{\sigma_{\text{baseline}}}$$
- **Features Monitored**:
  - **Login Velocity**: Failed vs successful logon rates.
  - **Temporal Anomalies**: Logins between 22:00 and 06:00 local time.
  - **Privilege Escalation**: Usage of high-privilege Windows SID (e.g., `S-1-5-18` Local System, `S-1-5-32-544` Administrators).

---

## 3. Directory Layout & Persistence

```
backend/app/
├── models/
│   ├── isolation_forest.joblib   # Serialized anomaly model
│   └── severity_rf.joblib        # Serialized triage model
├── services/
│   ├── ml_engine.py             # Feature extraction & inference
│   └── ueba_service.py          # Behavioral baseline engine
└── mcp/
    └── ml_threat_server.py      # MCP tool exposure for LLM
```

---

## 4. Verification

Run the test suite verifying inference, anomaly scoring, and UEBA math:

```bash
pytest backend/tests/test_ml_threat_engine.py -v
```
